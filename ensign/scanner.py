"""
    Core scanning pipeline.

    The pipeline for a tree is a single pass:

        walk -> prune unchanged snapshot subtrees -> stat each file
            -> skip files whose (size, mtime) match the DB
            -> hash + clamd-scan the rest in a thread pool -> upsert

    Each file is visited exactly once per run. Unchanged files cost one
    stat() call and nothing else — no reads, no hashing, no clamd.

    Symlinks to regular files ARE followed and scanned (via safe_stat, not
    safe_lstat) -- a symlink is a common, low-effort way for something to
    end up outside a scanner's reach, and this is a security tool, so that
    blind spot isn't acceptable by default. Symlinked directories are never
    descended into (os.walk(followlinks=False)), so this can't loop or
    wander outside the configured scan_targets at the directory level.
"""
from __future__ import annotations

import logging
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

from rich import print
from sqlalchemy.orm import Session

from . import secrets
from .clamd import ClamdClient, ScanOutcome, clamscan_cli_available, is_permission_error, is_size_limit_error, scan_with_clamscan_cli
from .config import Config
from .db import make_engine
from .fsutil import is_scannable, safe_lstat, safe_stat, sha256_file
from .models import DirectoryRecord, FileRecord, ScanStatus, utcnow

log = logging.getLogger(__name__)

_STATUS_SYMBOLS = {
    ScanStatus.CLEAN.value: "[green]✓[/green]",
    ScanStatus.INFECTED.value: "[red]![/red]",
    ScanStatus.ERROR.value: "[yellow]✗[/yellow]",
    ScanStatus.PENDING.value: "?",
    ScanStatus.CLASSIFIED.value: "[dim]•[/dim]",
}


@dataclass
class TreeStats:
    seen: int = 0
    unchanged: int = 0
    processed: int = 0
    failed: int = 0
    pruned_dirs: int = 0
    excluded_dirs: int = 0
    snapshot_dirs: list[tuple[str, int]] = field(default_factory=list)


class Scanner:
    def __init__(self, config: Config, clamd: ClamdClient | None = None):
        self.config = config
        self.engine = make_engine(config.db_url)
        self.clamd = clamd or ClamdClient(config.clamd_socket)
        self._workers: int | None = None
        self._warned_no_clamscan_cli = False

    @property
    def workers(self) -> int:
        """
        Resolved lazily on first access, so maintenance commands
        that never scan (--purge-missing, --suggest-fixes) don't pay
        for a clamd connection they don't need."""
        if self._workers is None:
            self._workers = self._resolve_workers()
        return self._workers

    def _resolve_workers(self) -> int:
        """
        Pick the worker-pool size for this machine.

        An explicit max_workers in the config always wins. Otherwise
        (max_workers = 0, "auto"), size to the real bottleneck: clamd's
        own MaxThreads, minus headroom so the daemon stays responsive
        to other clients, capped by CPU count and a sane floor/ceiling.

        The floor is always 1 -- even on a single-core machine, or if
        clamd reports a very low MaxThreads, this never returns 0 or
        negative. Ensign always runs; a heavily constrained machine just
        processes files one at a time through the same ThreadPoolExecutor
        path rather than needing a separate non-threaded code path.
        """
        if self.config.max_workers > 0:
            return self.config.max_workers
        clamd_max = self.clamd.max_threads()
        if clamd_max is None:
            return 5  # daemon unreachable or unparseable; safe default
        cpus = os.cpu_count() or 4
        return max(1, min(clamd_max - 2, cpus, 12))

    # ------------------------------------------------------------------
    # Tree scanning
    # ------------------------------------------------------------------

    def scan_tree(self, root: Path | str, scan: bool = True) -> TreeStats:
        """Scan every new or changed regular file under `root`."""
        root = Path(root)
        stats = TreeStats()
        if not root.is_dir():
            print(f"[yellow]Skipping {root}: not a directory[/yellow]")
            return stats

        known = self._load_known_files(root)
        candidates = self._collect_changed_files(root, known, stats)

        print(
            f"  {stats.seen} files seen · "
            f"{stats.unchanged} unchanged · "
            f"{stats.pruned_dirs} snapshot subtrees pruned · "
            f"{stats.excluded_dirs} excluded · "
            f"[bold]{len(candidates)} to process[/bold]"
        )
        if candidates:
            with ThreadPoolExecutor(max_workers=self.workers) as pool:
                results = list(pool.map(lambda p: self.process_file(p, scan=scan), candidates))
            stats.processed = sum(1 for r in results if r is not None)
            stats.failed = len(results) - stats.processed
            print(f"  Completed: {stats.processed}/{len(candidates)} files processed")

        # Only record snapshot mtimes once the tree finished, so a crash
        # mid-run can't mark an unscanned subtree as done.
        self._record_snapshot_dirs(stats.snapshot_dirs)
        return stats

    def _is_excluded(self, path: Path) -> bool:
        """True if path is inside any configured exclude tree."""
        text = str(path)
        return any(
            text == ex or text.startswith(ex + "/")
            for ex in self.config.excludes
        )

    def _collect_changed_files(
        self, root: Path, known: dict[str, tuple[int, int]], stats: TreeStats
    ) -> list[Path]:
        """Walk once, top-down, returning files that need hashing/scanning."""
        candidates: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
            # Pruning dirnames in place stops os.walk from descending —
            # excluded trees and unchanged snapshot subtrees are never
            # entered at all. followlinks=False above also means a
            # symlinked directory is never descended into, regardless.
            kept = []
            for name in dirnames:
                subdir = Path(dirpath) / name
                if self._is_excluded(subdir):
                    stats.excluded_dirs += 1
                elif self._should_prune(subdir, stats):
                    stats.pruned_dirs += 1
                else:
                    kept.append(name)
            dirnames[:] = kept

            for name in filenames:
                path = Path(dirpath) / name
                if self._is_excluded(path):
                    continue
                # safe_stat (not safe_lstat) so a symlink to a regular
                # file is followed and scanned through to its target;
                # a broken symlink or one pointing at a socket/device
                # just becomes None or fails is_scannable, same as any
                # other unreadable/unsuitable path.
                st = safe_stat(path)
                if st is None or not is_scannable(st):
                    continue
                stats.seen += 1
                if known.get(str(path)) == (st.st_size, st.st_mtime_ns):
                    stats.unchanged += 1
                else:
                    candidates.append(path)
        return candidates

    def _load_known_files(self, root: Path) -> dict[str, tuple[int, int]]:
        # One query up front instead of one query per file during the walk.
        prefix = str(root).rstrip("/") + "/"
        with Session(self.engine) as session:
            rows = session.query(
                FileRecord.filepath, FileRecord.file_size, FileRecord.mtime_ns
            ).filter(FileRecord.filepath.like(f"{prefix}%")).all()
        return {path: (size, mtime) for path, size, mtime in rows if mtime is not None}

    # ------------------------------------------------------------------
    # Snapshot-subtree pruning
    # ------------------------------------------------------------------

    def _is_snapshot_dir(self, path: Path) -> bool:
        return any(str(path).startswith(r) for r in self.config.snapshot_roots)

    def _should_prune(self, path: Path, stats: TreeStats) -> bool:
        if not self._is_snapshot_dir(path):
            return False
        st = safe_lstat(path)
        if st is None:
            return False
        with Session(self.engine) as session:
            record = session.query(DirectoryRecord).filter(
                DirectoryRecord.directory_path == str(path)
            ).first()
            if record and record.mtime_ns == st.st_mtime_ns:
                return True
        stats.snapshot_dirs.append((str(path), st.st_mtime_ns))
        return False

    def _record_snapshot_dirs(self, entries: list[tuple[str, int]]) -> None:
        if not entries:
            return
        with Session(self.engine) as session:
            try:
                for path, mtime_ns in entries:
                    record = session.query(DirectoryRecord).filter(
                        DirectoryRecord.directory_path == path
                    ).first()
                    if record is None:
                        record = DirectoryRecord(
                            directory_path=path,
                            directory_name=os.path.basename(path),
                        )
                        session.add(record)
                    record.mtime_ns = mtime_ns
                    record.last_scanned = utcnow()
                session.commit()
            except Exception as exc:
                session.rollback()
                log.error("recording snapshot dirs failed: %s", exc)

    # ------------------------------------------------------------------
    # Single-file pipeline
    # ------------------------------------------------------------------

    def process_file(self, path: Path | str, scan: bool = True) -> str | None:
        """
        Hash one file, optionally clamd-scan it, and upsert the record.

        Returns the hash on success, None on any failure. Safe to call
        from worker threads: it opens its own short-lived session.
        """
        path = Path(path)
        st = safe_stat(path)
        if st is None or not is_scannable(st):
            return None

        digest = sha256_file(path)
        if digest is None:
            return None

        outcome = self.clamd.scan(path) if scan else None

        if (
            outcome is not None
            and outcome.status == ScanStatus.ERROR
            and is_size_limit_error(outcome.raw)
        ):
            # clamd rejected this file for size, not content -- fall back
            # to the clamscan CLI with limits explicitly disabled, so a
            # legitimately large file still gets a real verdict instead
            # of a permanent, unfixable-by-setfacl error.
            if clamscan_cli_available():
                print(f"[dim]→ {path.name} exceeds clamd's size limit, falling back to clamscan CLI…[/dim]")
                outcome = scan_with_clamscan_cli(path)
            elif not self._warned_no_clamscan_cli:
                print("[yellow]! Some files exceed clamd's size limit and the 'clamscan' CLI "
                      "isn't installed to fall back on — install clamav's clamscan for full coverage.[/yellow]")
                self._warned_no_clamscan_cli = True

        if (
            outcome is not None
            and outcome.status == ScanStatus.ERROR
            and is_permission_error(outcome.raw)
            and secrets.is_high_confidence_secrets_path(str(path))
        ):
            # clamd was refused access, and the path looks like a
            # secrets store (wallet, SSH/GPG keys, ...) -- that's very
            # likely correct, not a gap to close. Reactive, not
            # presumptive: this only fires on an actual denial, so if
            # permissions ever change, the next real scan attempt just
            # succeeds normally instead of staying stuck here.
            outcome = ScanOutcome(ScanStatus.CLASSIFIED, outcome.raw, outcome.threat_name)

        try:
            self._upsert_file(path, st, digest, outcome)
        except Exception as exc:
            print(f"[red]✗ DB error on {path.name}: {exc}[/red]")
            log.error("%s: %s", path, exc)
            return None

        status = outcome.status.value if outcome else ScanStatus.PENDING.value
        symbol = _STATUS_SYMBOLS.get(status, "?")
        print(f"{symbol} {path.name:.<50} {digest[:16]}… {status}")
        return digest

    def _upsert_file(
        self, path: Path, st: os.stat_result, digest: str, outcome: ScanOutcome | None
    ) -> None:
        with Session(self.engine) as session:
            try:
                record = session.query(FileRecord).filter(
                    FileRecord.filepath == str(path)
                ).first()
                if record is None:
                    record = FileRecord(filepath=str(path), filename=path.name, file_hash=digest)
                    session.add(record)
                record.file_hash = digest
                record.file_size = st.st_size
                record.mtime_ns = st.st_mtime_ns
                if outcome is not None:
                    record.scan_status = outcome.status.value
                    record.scan_result = outcome.raw
                    record.threat_name = outcome.threat_name
                    record.last_scanned = utcnow()
                session.commit()
            except Exception:
                session.rollback()
                raise

    def purge_missing(self) -> int:
        """
        Delete records whose files no longer exist on disk.

        Temp files that vanished between scans otherwise sit in the DB
        forever — often with ERROR status — and pollute every report
        and rescan pass. Returns the number of records removed.
        """
        with Session(self.engine) as session:
            paths = [row[0] for row in session.query(FileRecord.filepath)]
        missing = [p for p in paths if not os.path.lexists(p)]
        if not missing:
            print("No missing files to purge.")
            return 0
        with Session(self.engine) as session:
            try:
                for chunk_start in range(0, len(missing), 500):
                    chunk = missing[chunk_start:chunk_start + 500]
                    session.query(FileRecord).filter(
                        FileRecord.filepath.in_(chunk)
                    ).delete(synchronize_session=False)
                session.commit()
            except Exception as exc:
                session.rollback()
                log.error("purge_missing failed: %s", exc)
                raise
        print(f"Purged {len(missing)} records for files that no longer exist.")
        return len(missing)

    # ------------------------------------------------------------------
    # Rescans — one generic helper instead of three near-copies
    # ------------------------------------------------------------------

    def rescan_infected(self) -> None:
        self._rescan("infected", FileRecord.scan_status == ScanStatus.INFECTED.value)

    def rescan_errors(self) -> None:
        self._rescan("errored", FileRecord.scan_status == ScanStatus.ERROR.value)

    def rescan_stale(self, days: int | None = None) -> None:
        days = days if days is not None else self.config.rescan_after_days
        cutoff = utcnow() - timedelta(days=days)
        self._rescan(
            f"stale (>{days} days)",
            (FileRecord.last_scanned < cutoff) | (FileRecord.last_scanned.is_(None)),
        )

    def _rescan(self, label: str, *criteria) -> None:
        # Fetch plain path strings, not ORM objects — detached instances
        # outliving their session is a bug waiting to happen.
        with Session(self.engine) as session:
            paths = [row[0] for row in session.query(FileRecord.filepath).filter(*criteria)]
        print(f"\nRescanning {len(paths)} {label} files…")
        if not paths:
            return
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            list(pool.map(lambda p: self.process_file(p, scan=True), paths))

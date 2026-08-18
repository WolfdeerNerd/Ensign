"""Read-only reporting queries. Nothing in here mutates the database."""
from __future__ import annotations

import os

from rich import print
from sqlalchemy import func, or_
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from . import secrets
from .models import FileRecord, ScanStatus


def _scope_filter(paths: list[str] | None):
    """Restrict a query to files under the given paths, or None for no
    restriction. Each path can be a directory (matches everything under
    it) or an exact file. Used so a run scoped to specific targets
    reports on just those targets, not the entire tracked system."""
    if not paths:
        return None
    conditions = []
    for p in paths:
        text = str(p).rstrip("/")
        conditions.append(FileRecord.filepath == text)
        conditions.append(FileRecord.filepath.like(f"{text}/%"))
    return or_(*conditions)


def suggest_fixes(engine: Engine, top: int = 10, paths: list[str] | None = None) -> None:
    """Print copy-pasteable setfacl commands for permission error hotspots.

    Purely advisory — nothing here runs a permission change. Directories
    are flagged for manual review instead of getting a suggested command
    if EITHER the directory name OR any individual file inside it matches
    a secrets pattern — checking only the directory name would miss a
    wallet file sitting in a generically-named folder, and checking only
    the file would miss dotfiles (like .netrc) living loose in $HOME
    whose "directory" is just the home folder itself.

    If `paths` is given, only errors under those paths are considered —
    otherwise this reports on every error in the whole database,
    regardless of what this particular run scanned.
    """
    with Session(engine) as session:
        query = session.query(FileRecord.filepath, FileRecord.scan_result).filter(
            FileRecord.scan_status == ScanStatus.ERROR.value
        )
        scope = _scope_filter(paths)
        if scope is not None:
            query = query.filter(scope)
        rows = query.all()

    hotspots: dict[str, list[str]] = {}
    for filepath, result in rows:
        text = (result or "").lower()
        if "denied" in text or "permission" in text:
            parent = os.path.dirname(filepath)
            hotspots.setdefault(parent, []).append(filepath)

    if not hotspots:
        return

    print(f"\n=== SUGGESTED FIXES ({len(hotspots)} directories) ===")
    print("Advisory only — review each command before running it.\n")

    for parent, paths in sorted(hotspots.items(), key=lambda kv: -len(kv[1]))[:top]:
        missing = [p for p in  paths if not os.path.lexists(p)]
        present = [p for p in paths if p not in missing]

        if missing and not present:
            # Every file in this hotspot is gone -- a setfacl fix would
            # be useless advice. Point at --purge-missing instead.
            count = len(missing)
            label = f"{count} file" + ("s" if count != 1 else "")
            print(f"    {parent} ({label})")
            print(f"        File{'s' if count != 1 else ''} no longer ")
            print(f"        exist{'s' if count == 1 else ''} on disk - this looks like ")
            print(f"        a stale record, not a permission issue.")
            print(f"        Run: python3 main.py --purge-missing\n")
            continue

        count = len(paths)
        label = f"{count} file" + ("s" if count != 1 else "")
        dir_match = secrets.is_likely_secrets_path(parent)
        file_match = next((p for p in paths if secrets.is_likely_secrets_path(p)), None)
        if dir_match or file_match:
            print(f"  [yellow]! {parent}[/yellow]  ({label})")
            reason = f"directory name" if dir_match else f"contains {os.path.basename(file_match)}"
            print(f"    Looks like a secrets/credentials store ({reason}) — review manually.\n")
        else:
            print(f"  {parent}  ({label})")
            print(f"    sudo setfacl -R -m g:clamav:rX '{parent}'")
            print(f"    sudo setfacl -R -d -m g:clamav:rX '{parent}'\n")


def error_summary(engine: Engine, top: int = 10, paths: list[str] | None = None) -> None:
    """Group ERROR files by cause and by directory hotspot.

    Thousands of individual error rows are unreadable; almost all of
    them collapse into a handful of causes (usually clamd permission
    denials) concentrated in a few directory trees.

    If `paths` is given, only errors under those paths are counted.
    """
    with Session(engine) as session:
        query = session.query(
            FileRecord.filepath, FileRecord.scan_result
        ).filter(FileRecord.scan_status == ScanStatus.ERROR.value)
        scope = _scope_filter(paths)
        if scope is not None:
            query = query.filter(scope)
        rows = query.all()

    if not rows:
        return

    causes: dict[str, int] = {}
    dirs: dict[str, int] = {}
    for filepath, result in rows:
        # clamd replies look like "/path: message ERROR" — strip the
        # path so identical causes group together.
        raw = result or "unknown"
        message = raw.split(": ", 1)[1] if ": " in raw else raw
        causes[message] = causes.get(message, 0) + 1
        parent = os.path.dirname(filepath)
        dirs[parent] = dirs.get(parent, 0) + 1

    print(f"\n=== ERROR BREAKDOWN ({len(rows)} files) ===")
    print("By cause:")
    for message, count in sorted(causes.items(), key=lambda kv: -kv[1])[:top]:
        print(f"  {count:>6}  {message[:90]}")
    print("Directory hotspots:")
    for parent, count in sorted(dirs.items(), key=lambda kv: -kv[1])[:top]:
        print(f"  {count:>6}  {parent}")


def pacman_report(engine: Engine, result) -> None:
    """Print pacman -Qkk mismatches, cross-referenced against Ensign's
    own tracked files where possible. Purely informational."""
    if result is None:
        print("[yellow]pacman is not installed on this system — skipping.[/yellow]")
        return
    if result.error:
        print(f"[red]✗ pacman verification failed: {result.error}[/red]")
        return

    print(f"\n=== PACMAN FILE INTEGRITY ({len(result.mismatches)} of {result.candidate_line_count} candidate lines parsed) ===")
    if result.candidate_line_count and not result.mismatches:
        print("[yellow]! pacman reported mismatch-shaped lines but none matched the expected "
              "format — the parser may need updating for this pacman version. Run 'pacman -Qkk' "
              "directly to see the raw output.[/yellow]")
        return
    if not result.mismatches:
        print("No mismatches — all installed files match pacman's records.")
        return

    with Session(engine) as session:
        known = {
            row[0]: row[1]
            for row in session.query(FileRecord.filepath, FileRecord.scan_status)
        }

    real = [m for m in result.mismatches if not m.is_backup]
    backups = [m for m in result.mismatches if m.is_backup]

    if real:
        print(f"\n-- {len(real)} file{'s' if len(real) != 1 else ''} differ from pacman's records --")
        for m in real:
            status = known.get(m.filepath)
            tracked = f"Ensign last saw this file: {status}" if status else "not tracked by Ensign"
            print(f"  {m.package}: {m.filepath}")
            print(f"    {m.reason} — {tracked}")

    if backups:
        # pacman marks these files "backup" specifically so it won't
        # complain when you edit them -- a mismatch here means "you
        # configured your system," not "something is wrong."
        print(f"\n-- {len(backups)} backup/config file{'s' if len(backups) != 1 else ''} "
              f"locally modified (expected, not a concern) --")
        by_path: dict[str, list[str]] = {}
        for m in backups:
            by_path.setdefault(m.filepath, []).append(m.reason)
        for path, reasons in by_path.items():
            print(f"  {path}  ({', '.join(reasons)})")


def scan_summary(engine: Engine, paths: list[str] | None = None) -> dict[str, int]:
    """If `paths` is given, only files under those paths are counted —
    otherwise this summarizes the entire database."""
    scope = _scope_filter(paths)
    with Session(engine) as session:
        total_q = session.query(func.count(FileRecord.id))
        status_q = session.query(FileRecord.scan_status, func.count(FileRecord.id)).group_by(FileRecord.scan_status)
        if scope is not None:
            total_q = total_q.filter(scope)
            status_q = status_q.filter(scope)
        total = total_q.scalar() or 0
        rows = status_q.all()
    counts = dict(rows)

    print("\n=== SCAN SUMMARY ===")
    print(f"Total files:     {total}")
    print(f"✓ Clean:         {counts.get(ScanStatus.CLEAN.value, 0)}")
    print(f"! Infected:      {counts.get(ScanStatus.INFECTED.value, 0)}")
    print(f"✗ Errors:        {counts.get(ScanStatus.ERROR.value, 0)}")
    print(f"? Pending:       {counts.get(ScanStatus.PENDING.value, 0)}")
    print(f"• Classified:    {counts.get(ScanStatus.CLASSIFIED.value, 0)}")

    return {"total": total, **{s.value: counts.get(s.value, 0) for s in ScanStatus}}


def list_infected(engine: Engine, paths: list[str] | None = None) -> list[dict]:
    with Session(engine) as session:
        query = session.query(
            FileRecord.filepath,
            FileRecord.threat_name,
            FileRecord.last_scanned,
            FileRecord.scan_result,
        ).filter(FileRecord.scan_status == ScanStatus.INFECTED.value)
        scope = _scope_filter(paths)
        if scope is not None:
            query = query.filter(scope)
        rows = query.all()

    if not rows:
        print("No infected files found")
        return []

    print("\n=== INFECTED FILES ===")
    results = []
    for filepath, threat, scanned, detail in rows:
        print(f"\nFile: {filepath}")
        print(f"Threat: {threat}")
        print(f"Scanned: {scanned}")
        print(f"Details: {(detail or '')[:200]}")
        results.append({"filepath": filepath, "threat": threat, "scanned": scanned})
    return results


def file_info(engine: Engine, filepath: str) -> None:
    with Session(engine) as session:
        record = session.query(FileRecord).filter(
            FileRecord.filepath == filepath
        ).first()
        if record is None:
            print(f"File not found in database: {filepath}")
            return
        print("\n=== FILE INFO ===")
        print(f"Path: {record.filepath}")
        print(f"Hash: {record.file_hash}")
        print(f"Size: {record.file_size} bytes")
        print(f"Scan Status: {record.scan_status}")
        if record.threat_name:
            print(f"Threat: {record.threat_name}")
        print(f"Last Scanned: {record.last_scanned}")

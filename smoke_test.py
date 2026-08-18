"""Smoke test: fake clamd server + temp tree, verifies the full pipeline.

Run: python3 smoke_test.py
"""
from __future__ import annotations

import os
import socket
import socketserver
import tempfile
import threading
import time
from pathlib import Path

from ensign.clamd import ClamdClient
from ensign.config import Config
from ensign.models import ScanStatus
from ensign.reports import scan_summary
from ensign.scanner import Scanner

import re

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


class FakeClamdHandler(socketserver.StreamRequestHandler):
    def handle(self):
        data = self.rfile.readline().decode().strip()
        if data.startswith("n"):
            data = data[1:]
        if data == "PING":
            self.wfile.write(b"PONG\n")
        elif data == "STATS":
            self.wfile.write(b"POOLS: 1\nTHREADS: live 1 idle 0 max 12 idle-timeout 30\nEND\n")
        elif data == "VERSION":
            from datetime import datetime, timedelta
            build_date = (datetime.now() - timedelta(days=5)).strftime("%a %b %d %H:%M:%S %Y")
            self.wfile.write(f"ClamAV 1.2.0/27455/{build_date}\n".encode())
        elif data.startswith("SCAN "):
            path = data[5:]
            if "toolarge" in path:
                self.wfile.write(f"{path}: size limit exceeded. ERROR\n".encode())
            elif "evil" in path:
                self.wfile.write(f"{path}: Eicar-Test-Signature FOUND\n".encode())
            else:
                self.wfile.write(f"{path}: OK\n".encode())


def main():
    tmp = Path(tempfile.mkdtemp(prefix="ensign_test_"))
    sock_path = str(tmp / "clamd.sock")

    server = socketserver.ThreadingUnixStreamServer(sock_path, FakeClamdHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    # Build a small tree, including a snapshot subtree and a fifo.
    tree = tmp / "tree"
    (tree / "docs").mkdir(parents=True)
    (tree / "snapshots" / "snap1").mkdir(parents=True)
    (tree / "docs" / "a.txt").write_text("hello")
    (tree / "docs" / "evil.bin").write_text("pretend malware")
    (tree / "snapshots" / "snap1" / "frozen.txt").write_text("immutable")
    os.mkfifo(tree / "docs" / "pipe.fifo")  # must be skipped, not hang

    # Symlink to a regular file must be followed and scanned -- this is
    # the whole point of switching is_scannable/process_file from
    # safe_lstat to safe_stat.
    real_target = tmp / "outside_tree" / "real_secret.txt"
    real_target.parent.mkdir(parents=True)
    real_target.write_text("actual content")
    (tree / "docs" / "link_to_real.txt").symlink_to(real_target)

    # A symlink whose target doesn't exist must be skipped cleanly, not
    # raise or hang.
    (tree / "docs" / "broken_link.txt").symlink_to(tmp / "does_not_exist")

    config = Config(
        db_url=f"sqlite:///{tmp / 'test.db'}",
        log_file=tmp / "errors.log",
        clamd_socket=sock_path,
        max_workers=3,
        snapshot_roots=(str(tree / "snapshots"),),
        scan_targets=(tree,),
    )
    scanner = Scanner(config)

    assert scanner.clamd.ping(), "fake clamd should answer PING"
    assert scanner.clamd.max_threads() == 12, "STATS parsing"
    assert scanner.workers == 3, "explicit max_workers should win"

    auto_scanner = Scanner(Config(
        db_url=f"sqlite:///{tmp / 'auto.db'}",
        log_file=tmp / "errors2.log",
        clamd_socket=sock_path,
        max_workers=0,
    ), clamd=scanner.clamd)
    expected = max(1, min(10, os.cpu_count() or 4, 12))
    assert auto_scanner.workers == expected, f"auto sizing: {auto_scanner.workers} != {expected}"

    print("--- First run (everything new) ---")
    stats1 = scanner.scan_tree(tree)
    assert stats1.processed == 4, f"expected 4 processed (3 originals + symlink), got {stats1}"
    assert stats1.unchanged == 0

    from sqlalchemy.orm import Session as _SymSession
    from ensign.models import FileRecord as _FRSym
    with _SymSession(scanner.engine) as session:
        link_record = session.query(_FRSym).filter(
            _FRSym.filepath == str(tree / "docs" / "link_to_real.txt")
        ).first()
        assert link_record is not None, "symlink to a regular file should be recorded, not skipped"
        assert link_record.scan_status == ScanStatus.CLEAN.value, \
            "symlink target should actually be scanned (fake clamd returns OK for non-evil paths)"

        broken_record = session.query(_FRSym).filter(
            _FRSym.filepath == str(tree / "docs" / "broken_link.txt")
        ).first()
        assert broken_record is None, "a broken symlink must be skipped cleanly, not recorded or errored"

    print("\n--- Second run (nothing changed) ---")
    stats2 = scanner.scan_tree(tree)
    assert stats2.processed == 0, f"expected 0 processed, got {stats2}"
    assert stats2.unchanged >= 2, f"expected unchanged files, got {stats2}"
    assert stats2.pruned_dirs >= 1, f"expected snapshot pruning, got {stats2}"

    print("\n--- Third run (one file modified) ---")
    time.sleep(0.01)
    (tree / "docs" / "a.txt").write_text("hello, changed")
    stats3 = scanner.scan_tree(tree)
    assert stats3.processed == 1, f"expected 1 processed, got {stats3}"

    summary = scan_summary(scanner.engine)
    assert summary["infected"] == 1, f"expected 1 infected, got {summary}"
    assert summary["clean"] == 3, f"expected 3 clean (a.txt, link_to_real.txt, and... wait, evil.bin is infected), got {summary}"

    print("\n--- Rescan infected ---")
    scanner.rescan_infected()

    print("\n--- suggest_fixes: secrets-path guard ---")
    from ensign.models import FileRecord, ScanStatus as SS, utcnow
    from ensign.reports import suggest_fixes
    from sqlalchemy.orm import Session as _Session
    import io, contextlib

    # suggest_fixes() checks lexists() before suggesting a command, so
    # these need to be real files on disk -- not just DB rows -- or
    # they'll be (correctly) routed to the stale-record/--purge-missing
    # branch instead of the command-suggestion branch this test checks.
    cache_file = tmp / "home_u" / ".cache" / "app" / "reg.bin"
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text("cached data")

    wallet_file = tmp / "home_u" / ".local" / "share" / "kwalletd" / "kdewallet.kwl"
    wallet_file.parent.mkdir(parents=True, exist_ok=True)
    wallet_file.write_text("encrypted wallet data")

    with _Session(scanner.engine) as session:
        session.add(FileRecord(filepath=str(cache_file), filename="reg.bin",
                                file_hash="x", scan_status=SS.ERROR.value,
                                scan_result=f"{cache_file}: Access denied. ERROR",
                                last_scanned=utcnow()))
        session.add(FileRecord(filepath=str(wallet_file),
                                filename="kdewallet.kwl", file_hash="x",
                                scan_status=SS.ERROR.value,
                                scan_result=f"{wallet_file}: Access denied. ERROR",
                                last_scanned=utcnow()))
        session.commit()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        suggest_fixes(scanner.engine)
    output = " ".join(_strip_ansi(buf.getvalue()).split())  # normalize whitespace: rich wraps lines to console width
    assert "setfacl" in output and str(cache_file.parent) in output, "should suggest a command for a normal cache dir"
    assert "kwalletd" in output and "review manually" in output.lower(), "should flag, not suggest, a wallet-like path"
    assert "setfacl" not in output.split("kwalletd")[1].split("!")[0], "must not print a command for the wallet path"

    print("\n--- signature_age_days ---")
    assert scanner.clamd.signature_age_days() == 5, scanner.clamd.signature_age_days()

    print("\n--- clamscan CLI fallback for size-limit rejections ---")
    fakebin = tmp / "fakebin"
    fakebin.mkdir()
    fake_clamscan = fakebin / "clamscan"
    fake_clamscan.write_text(
        "#!/bin/bash\n"
        'path="${@: -1}"\n'
        'if [[ "$path" == *evil* ]]; then\n'
        '  echo "$path: Eicar-Test-Signature FOUND"\n'
        "  exit 1\n"
        "else\n"
        '  echo "$path: OK"\n'
        "  exit 0\n"
        "fi\n"
    )
    fake_clamscan.chmod(0o755)
    old_path = os.environ.get("PATH", "")
    os.environ["PATH"] = f"{fakebin}{os.pathsep}{old_path}"
    try:
        sock_path2 = str(tmp / "clamd2.sock")
        server2 = socketserver.ThreadingUnixStreamServer(sock_path2, FakeClamdHandler)
        threading.Thread(target=server2.serve_forever, daemon=True).start()
        config2 = Config(
            db_url=f"sqlite:///{tmp / 'sizelimit.db'}",
            log_file=tmp / "errors3.log",
            clamd_socket=sock_path2,
            max_workers=2,
        )
        scanner2 = Scanner(config2)

        big_clean = tmp / "toolarge_clean.bin"
        big_clean.write_bytes(b"x" * 100)
        big_evil = tmp / "toolarge_evil.bin"
        big_evil.write_bytes(b"x" * 100)

        scanner2.process_file(big_clean, scan=True)
        scanner2.process_file(big_evil, scan=True)

        from ensign.models import FileRecord
        from sqlalchemy.orm import Session as _S
        with _S(scanner2.engine) as session:
            clean_rec = session.query(FileRecord).filter(FileRecord.filepath == str(big_clean)).first()
            evil_rec = session.query(FileRecord).filter(FileRecord.filepath == str(big_evil)).first()
            assert clean_rec.scan_status == ScanStatus.CLEAN.value, \
                "daemon's size-limit error should be overridden by the CLI fallback's clean verdict"
            assert evil_rec.scan_status == ScanStatus.INFECTED.value, \
                "CLI fallback should still catch a real infection"
            assert evil_rec.threat_name == "Eicar-Test-Signature"
        server2.shutdown()
    finally:
        os.environ["PATH"] = old_path

    print("\n--- secrets-pattern reclassification (CLASSIFIED, not ERROR) ---")

    class DenyHandler(socketserver.StreamRequestHandler):
        def handle(self):
            data = self.rfile.readline().decode().strip()
            if data.startswith("n"):
                data = data[1:]
            if data == "PING":
                self.wfile.write(b"PONG\n")
            elif data.startswith("SCAN "):
                self.wfile.write(f"{data[5:]}: Access denied. ERROR\n".encode())

    sock_path3 = str(tmp / "clamd3.sock")
    server3 = socketserver.ThreadingUnixStreamServer(sock_path3, DenyHandler)
    threading.Thread(target=server3.serve_forever, daemon=True).start()

    config3 = Config(
        db_url=f"sqlite:///{tmp / 'classify.db'}",
        log_file=tmp / "errors4.log",
        clamd_socket=sock_path3,
        max_workers=2,
    )
    scanner3 = Scanner(config3)

    wallet_dir = tmp / ".local" / "share" / "kwalletd"
    wallet_dir.mkdir(parents=True)
    wallet_file = wallet_dir / "kdewallet.kwl"
    wallet_file.write_text("encrypted stuff")

    normal_dir = tmp / "documents"
    normal_dir.mkdir()
    normal_file = normal_dir / "regular_document.txt"
    normal_file.write_text("nothing special")

    scanner3.process_file(wallet_file, scan=True)
    scanner3.process_file(normal_file, scan=True)

    from ensign.models import FileRecord as _FR
    from ensign.reports import error_summary as _es, suggest_fixes as _sf, scan_summary as _ss
    from sqlalchemy.orm import Session as _S2
    with _S2(scanner3.engine) as session:
        wrec = session.query(_FR).filter(_FR.filepath == str(wallet_file)).first()
        nrec = session.query(_FR).filter(_FR.filepath == str(normal_file)).first()
        assert wrec.scan_status == ScanStatus.CLASSIFIED.value, \
            "permission-denied on a secrets-pattern path should be reclassified"
        assert nrec.scan_status == ScanStatus.ERROR.value, \
            "permission-denied on an ordinary path must stay a real error"

    buf2 = io.StringIO()
    with contextlib.redirect_stdout(buf2):
        _es(scanner3.engine)
        _sf(scanner3.engine)
        _ss(scanner3.engine)
    combined = " ".join(_strip_ansi(buf2.getvalue()).split())
    assert "kwalletd" not in combined, "classified path must not appear in error_summary or suggest_fixes"
    assert str(normal_dir) in combined, "the real error must still be reported"
    assert "Classified: 1" in combined

    server3.shutdown()

    server.shutdown()
    print("\nAll smoke tests passed ✓")


if __name__ == "__main__":
    main()

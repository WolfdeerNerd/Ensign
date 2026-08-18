"""Tests for the pacman integrity parser and notification message logic.

Both are pure functions with no clamd/DB dependency, so these run fast
and standalone. Run: python3 integrations_test.py
"""
from ensign.pacman import PacmanMismatch, PacmanVerifyResult, _MISMATCH_RE
from ensign.reports import pacman_report
from ensign.notify import build_message
from ensign import secrets
from ensign.secrets import Confidence
from ensign.clamd import is_permission_error, is_size_limit_error

# --- secrets.py: tiered confidence matching --------------------------

# HIGH confidence: exact/canonical names, matched regardless of caller.
assert secrets.classify("/home/user/.local/share/kwalletd/kdewallet.kwl") == Confidence.HIGH
assert secrets.classify("/home/user/.bitcoin/wallet.dat") == Confidence.HIGH, \
    "should match on canonical directory name"
assert secrets.classify("/home/user/.netrc") == Confidence.HIGH, \
    "canonical dotfile in $HOME should match on filename alone"
assert secrets.classify("/home/user/.ssh/id_rsa") == Confidence.HIGH
assert secrets.classify("/home/user/.aws/credentials") == Confidence.HIGH, \
    "scoped filename (credentials) inside its expected parent dir (.aws)"

# Scoped filenames must NOT match outside their expected parent -- this
# is the whole point of scoping them instead of matching bare "credentials"
# or "config" anywhere.
assert secrets.classify("/home/user/Documents/credentials") == Confidence.NONE, \
    "'credentials' outside .aws/ must not match -- that's the false-positive risk being avoided"
assert secrets.classify("/home/user/projects/myapp/config") == Confidence.NONE, \
    "'config' outside .ssh//.kube//.docker/ must not match"

# MEDIUM confidence: conventions that need directory context.
assert secrets.classify("/home/user/.ethereum/keystore/UTC--2024-01-01T00-00-00.000Z--abc123") == Confidence.MEDIUM
assert secrets.classify("/home/user/random/UTC--fake") == Confidence.NONE, \
    "UTC-- prefix outside a keystore/ dir must not match -- context is required"
assert secrets.classify("/home/user/notes/mykey.pem") == Confidence.MEDIUM

# NONE: the old substring-bleed false positives must be gone.
assert secrets.classify("/home/user/Documents/notes.txt") == Confidence.NONE
assert secrets.classify("/home/user/projects/no-secrets-here/readme.md") == Confidence.NONE, \
    "generic word 'secrets' embedded in an unrelated name must not match"
assert secrets.classify("/home/user/projects/android-keystore-docs/notes.md") == Confidence.NONE, \
    "generic word 'keystore' embedded in an unrelated name must not match"
assert secrets.classify("/home/user/MyWalletApp/screenshots/img.png") == Confidence.NONE, \
    "generic word 'wallet' embedded in an unrelated name must not match"

# The two call-site thresholds behave differently, as designed.
assert secrets.is_likely_secrets_path("/home/user/notes/mykey.pem"), \
    "suggest_fixes() uses the wider threshold (HIGH or MEDIUM)"
assert not secrets.is_high_confidence_secrets_path("/home/user/notes/mykey.pem"), \
    "scanner.py's reclassification uses the narrower threshold (HIGH only)"
assert secrets.is_high_confidence_secrets_path("/home/user/.ssh/id_rsa")

assert secrets.matching_reason("/home/user/Documents/notes.txt") is None
assert secrets.matching_reason("/home/user/.ssh/id_rsa") is not None

# --- clamd.py: permission vs size-limit error detection ---------------

assert is_permission_error("/x: Access denied. ERROR")
assert is_permission_error("/x: File path check failure: Permission denied. ERROR")
assert not is_permission_error("/x: size limit exceeded. ERROR")
assert not is_size_limit_error("/x: Access denied. ERROR")
assert is_size_limit_error("/x: size limit exceeded. ERROR")

# --- pacman.py: line-format parsing ---------------------------------
# Real -Qkk wording wasn't verified against a live pacman install (no
# Arch system available while building this) -- these check the regex
# handles the plausible shapes, and that a total non-match is visible
# as "0 parsed" rather than silently looking like a clean system.

cases = [
    ("coreutils: /usr/bin/ls (Size mismatch)",
     (None, "coreutils", "/usr/bin/ls", "Size mismatch")),
    ("openssh: /etc/ssh/sshd_config (Modification time mismatch)",
     (None, "openssh", "/etc/ssh/sshd_config", "Modification time mismatch")),
    ("warning: linux: /boot/vmlinuz-linux (UID mismatch)",
     ("warning", "linux", "/boot/vmlinuz-linux", "UID mismatch")),
    ("backup file: filesystem: /etc/fstab (SHA256 checksum mismatch)",
     ("backup file", "filesystem", "/etc/fstab", "SHA256 checksum mismatch")),
]
for line, expected in cases:
    m = _MISMATCH_RE.match(line)
    assert m is not None, f"should match: {line!r}"
    assert m.groups() == expected, f"{line!r} -> {m.groups()} != {expected}"

assert _MISMATCH_RE.match("not a mismatch line") is None
assert _MISMATCH_RE.match("") is None
assert _MISMATCH_RE.match("coreutils: 444 total files, 0 altered files") is None, \
    "per-package summary lines must never be mistaken for a mismatch"

# --- pacman_report(): the four branches -------------------------------
import tempfile
from pathlib import Path
from ensign.config import Config
from ensign.scanner import Scanner

tmp = Path(tempfile.mkdtemp())
cfg = Config(db_url=f"sqlite:///{tmp / 't.db'}", log_file=tmp / "e.log", clamd_socket="/nonexistent")
s = Scanner(cfg)

import io, contextlib

def captured(*args):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        pacman_report(*args)
    return buf.getvalue()

assert "not installed" in captured(s.engine, None)
# The bug that caused real confusion: a subprocess failure (timeout,
# permission issue) must NOT print the same "not installed" message as
# pacman genuinely being absent -- these are different problems with
# different fixes, and collapsing them into one message is misleading.
out = captured(s.engine, PacmanVerifyResult(mismatches=[], candidate_line_count=0, error="pacman -Qkk did not finish within 600s."))
assert "not installed" not in out, "a ran-but-failed result must not look like 'not installed'"
assert "verification failed" in out and "600s" in out
assert "No mismatches" in captured(s.engine, PacmanVerifyResult(mismatches=[], candidate_line_count=0))
out = captured(s.engine, PacmanVerifyResult(
    mismatches=[PacmanMismatch("coreutils", "/usr/bin/ls", "Size mismatch")], candidate_line_count=1,
))
assert "/usr/bin/ls" in out and "not tracked by Ensign" in out
out = captured(s.engine, PacmanVerifyResult(mismatches=[], candidate_line_count=5))
assert "may need updating" in out, "0-parsed-but-nonzero-lines should surface a parser warning, not look clean"

# --- notify.py: message building --------------------------------------

empty_summary = {"total": 0, "clean": 0, "infected": 0, "error": 0, "pending": 0}
title, body, urgency = build_message(empty_summary, [])
assert urgency == "normal"
assert "Infected: 0" in body

infected_summary = {"total": 2, "clean": 0, "infected": 1, "error": 1, "pending": 0}
infected_list = [{"filepath": "/home/user/nasty.exe", "threat": "Test.Virus", "scanned": None}]
title, body, urgency = build_message(infected_summary, infected_list)
assert urgency == "critical", "any infection should escalate urgency"
assert "nasty.exe" in body
assert "1 infected" in title

error_only_summary = {"total": 5, "clean": 4, "infected": 0, "error": 1, "pending": 0}
title, body, urgency = build_message(error_only_summary, [])
assert urgency == "normal", "errors alone should not escalate to critical"
assert "1 error" in title

# many infections -> body should truncate the name list, not dump them all
many_infected = [{"filepath": f"/tmp/bad{i}.exe", "threat": "X", "scanned": None} for i in range(10)]
_, body, _ = build_message({"total": 10, "clean": 0, "infected": 10, "error": 0, "pending": 0}, many_infected)
assert "+7 more" in body, body

print("All pacman/notify/secrets tests passed ✓")

# --- real-world data regression test ---------------------------------
# [unchanged -- see previous version]
_REAL_DUMP = """\
aide: /etc/aide.conf
7zip: 17 total files, 0 altered files
aide: 22 total files, 1 altered file
backup file: filesystem: /etc/fstab (Modification time mismatch)
backup file: filesystem: /etc/fstab (Size mismatch)
backup file: filesystem: /etc/fstab (SHA256 checksum mismatch)
backup file: filesystem: /etc/group (Modification time mismatch)
backup file: filesystem: /etc/passwd (SHA256 checksum mismatch)
backup file: glibc: /etc/locale.gen (Modification time mismatch)
backup file: grub: /etc/default/grub (Modification time mismatch)
backup file: pacman: /etc/pacman.conf (SHA256 checksum mismatch)
backup file: ufw: /etc/ufw/user6.rules (SHA256 checksum mismatch)
warning: filesystem: /etc/crypttab (failed to calculate SHA256 checksum)
warning: filesystem: /root (Permissions mismatch)
warning: intel-ucode: /boot/intel-ucode.img (Permissions mismatch)
warning: java-runtime-common: /usr/lib/jvm/default (Symlink path mismatch)
warning: libutempter: /usr/lib/utempter/utempter (GID mismatch)
warning: modemmanager: /usr/share/ModemManager/connection.available.d/99-log-event (failed to calculate SHA256 checksum)
warning: rkhunter: /etc/rkhunter.conf (failed to calculate SHA256 checksum)
warning: systemd: /var/log/journal (GID mismatch)
filesystem: 127 total files, 7 altered files
rkhunter: 58 total files, 39 altered files
"""

_mismatches = []
_candidates = 0
for _line in _REAL_DUMP.splitlines():
    _line = _line.strip()
    if not _line or "(" not in _line:
        continue
    _candidates += 1
    _m = _MISMATCH_RE.match(_line)
    assert _m, f"real-world line failed to parse: {_line!r}"
    _mismatches.append(PacmanMismatch(_m.group("pkg"), _m.group("path"), _m.group("reason"),
                                       is_backup=(_m.group("kind") == "backup file")))

assert _candidates == len(_mismatches) == 17, \
    "every parenthetical line in real pacman output should parse -- zero silent drops"
_backups = [m for m in _mismatches if m.is_backup]
_warnings = [m for m in _mismatches if not m.is_backup]
assert len(_backups) == 9, len(_backups)
assert len(_warnings) == 8, len(_warnings)

_result = PacmanVerifyResult(mismatches=_mismatches, candidate_line_count=_candidates)
_out = captured(s.engine, _result)
assert "backup/config file" in _out and "not a concern" in _out
assert "differ from pacman's records" in _out
assert _out.index("differ from pacman's records") < _out.index("backup/config file"), \
    "real anomalies should print before the expected/benign backup-file section"

print("Real-world pacman dump regression test passed ✓")

# --- report scoping: the "targeted scan showed unrelated errors" bug -----
from ensign.models import FileRecord as _FR2, ScanStatus as _SS2, utcnow as _utcnow
from ensign.reports import scan_summary, error_summary, list_infected
from sqlalchemy.orm import Session

_tmp2 = Path(tempfile.mkdtemp())
_cfg2 = Config(db_url=f"sqlite:///{_tmp2 / 't.db'}", log_file=_tmp2 / "e.log", clamd_socket="/nonexistent")
_s2 = Scanner(_cfg2)

with Session(_s2.engine) as session:
    session.add(_FR2(filepath="/home/user/Downloads/bad.txt", filename="bad.txt", file_hash="x",
                      scan_status=_SS2.ERROR.value, scan_result="/home/user/Downloads/bad.txt: Access denied. ERROR",
                      last_scanned=_utcnow()))
    session.add(_FR2(filepath="/home/user/Steam/other.txt", filename="other.txt", file_hash="x",
                      scan_status=_SS2.ERROR.value, scan_result="/home/user/Steam/other.txt: Access denied. ERROR",
                      last_scanned=_utcnow()))
    session.add(_FR2(filepath="/home/user/Steam/nasty.exe", filename="nasty.exe", file_hash="x",
                      scan_status=_SS2.INFECTED.value, threat_name="Test.Virus", scan_result="FOUND",
                      last_scanned=_utcnow()))
    session.commit()

def _cap(fn, *a, **kw):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn(*a, **kw)
    return buf.getvalue()

_scoped_err = _cap(error_summary, _s2.engine, paths=["/home/user/Downloads"])
_scoped_inf = _cap(list_infected, _s2.engine, paths=["/home/user/Downloads"])
_scoped_sum = _cap(scan_summary, _s2.engine, paths=["/home/user/Downloads"])

assert "Steam" not in _scoped_err, "a scoped report must not leak errors from outside its scope"
assert "No infected files found" in _scoped_inf, "a scoped report must not leak infections from outside its scope"
assert "Total files:     1" in _scoped_sum

_full_err = _cap(error_summary, _s2.engine)
assert "Steam" in _full_err, "an unscoped report must still show everything (no regression)"

print("Report scoping regression test passed ✓")

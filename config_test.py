"""Tests for the multi-machine config loader. Run: python3 config_test.py"""
import os
import tempfile
from pathlib import Path

from ensign.config import HOSTNAME, Config, _expand, HOME

# 1. No file at all -> built-in defaults
cfg = Config()
assert cfg.max_workers == 0  # 0 = auto
assert cfg.signature_max_age_days == 3
assert "ensign/system.db" in cfg.db_url

# 2. TOML with global values + a hosts section for THIS machine
toml = f"""
data_dir = "~/Scripts/Ensign"
max_workers = 3
scan_targets = ["~/Downloads"]
signature_max_age_days = 7
bogus_key = true

[hosts.{HOSTNAME}]
max_workers = 8
snapshot_roots = ["~/snaps"]
excludes = ["~/.cache/", "/tmp"]

[hosts.some-other-box]
max_workers = 1
"""
with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
    f.write(toml)
    path = f.name

cfg = Config.load(path)
assert cfg.max_workers == 8, f"host override should win, got {cfg.max_workers}"
assert cfg.signature_max_age_days == 7, cfg.signature_max_age_days
assert cfg.scan_targets == (HOME / "Downloads",), cfg.scan_targets
assert cfg.snapshot_roots == (str(HOME / "snaps"),), cfg.snapshot_roots
assert cfg.excludes == (str(HOME / ".cache"), "/tmp"), cfg.excludes
assert str(HOME / "Scripts/Ensign/system.db") in cfg.db_url, cfg.db_url
assert cfg.source == path

# 3. Explicitly requested missing file -> error (silent fallback is worse)
try:
    Config.load("/nonexistent/ensign.toml")
    raise AssertionError("should have raised FileNotFoundError")
except FileNotFoundError:
    pass

# 4. Tilde expansion
assert _expand("~") == HOME
assert _expand("~/x") == HOME / "x"
assert _expand("/abs/path") == Path("/abs/path")

os.unlink(path)
print("All config tests passed ✓")

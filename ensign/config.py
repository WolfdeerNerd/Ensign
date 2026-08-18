"""Configuration for Ensign.

Design for multi-machine use:

  * The code contains NO machine-specific values. Everything lives in a
    TOML file, so any user on any box gets sane defaults out of the box.
  * Config search order: --config flag > $ENSIGN_CONFIG > 
    ~/.config/ensign/config.toml > built-in defaults.
  * Per-machine differences go in [hosts.<hostname>] sections of the
    SAME file, so you can sync one config across all your machines and
    each one picks up its own overrides.
  * "~" in the config file always means the *invoking* user's home,
    even under sudo (resolved via SUDO_USER + the passwd database, so
    it also works for homes outside /home).
"""
from __future__ import annotations

import os
import pwd
import socket
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path


# ----------------------------------------------------------------------
# Identity: who is really running this, and on which machine?
# ----------------------------------------------------------------------

def real_home() -> Path:
    """Home directory of the invoking user, even under sudo.

    Path.home() returns /root under sudo. SUDO_USER preserves the real
    account, and the passwd database gives its true home directory —
    no assumption that homes live under /home.
    """
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            pass  # SUDO_USER set but unknown; fall through
    return Path.home()


HOME = real_home()
HOSTNAME = socket.gethostname()

DEFAULT_DATA_DIR = HOME / ".local" / "share" / "ensign"
DEFAULT_CONFIG_PATH = HOME / ".config" / "ensign" / "config.toml"

_DEFAULT_TARGETS = ("~/Downloads", "~/Documents", "~/Pictures", "~")


def _expand(value: str | Path) -> Path:
    """Expand ~ and environment variables relative to the invoking user."""
    text = os.path.expandvars(str(value))
    if text == "~":
        return HOME
    if text.startswith("~/"):
        return HOME / text[2:]
    return Path(text)


# ----------------------------------------------------------------------
# The config object
# ----------------------------------------------------------------------

@dataclass(frozen=True)
class Config:
    db_url: str = f"sqlite:///{DEFAULT_DATA_DIR / 'system.db'}"
    log_file: Path = DEFAULT_DATA_DIR / "error_logs.txt"
    clamd_socket: str = "/var/run/clamav/clamd.ctl"
    # 0 = auto: sized from clamd's MaxThreads and CPU count at startup.
    max_workers: int = 0
    rescan_after_days: int = 90
    # Warn (not block) if the loaded virus-signature database is older
    # than this. Usually means freshclam has silently stopped running.
    signature_max_age_days: int = 3
    snapshot_roots: tuple[str, ...] = ()
    # Path prefixes to skip entirely (high-churn temp/cache trees).
    excludes: tuple[str, ...] = ()
    scan_targets: tuple[Path, ...] = tuple(_expand(t) for t in _DEFAULT_TARGETS)

    # Where this config came from, for the startup banner. Not a setting.
    source: str = field(default="built-in defaults", compare=False)

    # -- loading ------------------------------------------------------

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Config":
        """Load config: explicit path > $ENSIGN_CONFIG > default location.

        An explicitly requested file that doesn't exist is an error; the
        default location merely falling back to defaults is not.
        """
        explicit = path or os.environ.get("ENSIGN_CONFIG")
        cfg_path = Path(explicit) if explicit else DEFAULT_CONFIG_PATH

        if not cfg_path.is_file():
            if explicit:
                raise FileNotFoundError(f"Config file not found: {cfg_path}")
            return cls()

        with open(cfg_path, "rb") as f:
            data = tomllib.load(f)

        # Per-machine overrides: [hosts.<hostname>] beats top level.
        host_overrides = data.pop("hosts", {}).get(HOSTNAME, {})
        merged = {**data, **host_overrides}
        return cls._from_dict(merged, source=str(cfg_path))

    @classmethod
    def _from_dict(cls, raw: dict, source: str) -> "Config":
        known = {
            "data_dir", "clamd_socket", "max_workers",
            "rescan_after_days", "scan_targets", "snapshot_roots",
            "excludes", "signature_max_age_days",
        }
        for key in raw.keys() - known:
            print(f"[ensign] Warning: unknown config key {key!r} ignored")

        data_dir = _expand(raw.get("data_dir", DEFAULT_DATA_DIR))
        kwargs: dict = {
            "db_url": f"sqlite:///{data_dir / 'system.db'}",
            "log_file": data_dir / "error_logs.txt",
            "source": source,
        }
        for key in ("clamd_socket", "max_workers", "rescan_after_days", "signature_max_age_days"):
            if key in raw:
                kwargs[key] = raw[key]
        if "scan_targets" in raw:
            kwargs["scan_targets"] = tuple(_expand(t) for t in raw["scan_targets"])
        if "snapshot_roots" in raw:
            kwargs["snapshot_roots"] = tuple(str(_expand(t)) for t in raw["snapshot_roots"])
        if "excludes" in raw:
            kwargs["excludes"] = tuple(str(_expand(t)).rstrip("/") for t in raw["excludes"])
        return cls(**kwargs)

    @property
    def data_dir(self) -> Path:
        return self.log_file.parent


# ----------------------------------------------------------------------
# First-run template
# ----------------------------------------------------------------------

EXAMPLE_CONFIG = """\
# Ensign configuration.
# Paths may use "~" (the invoking user's home, sudo-safe) and $VARS.
# Anything set under [hosts.<hostname>] overrides the values above it
# on that machine only — so this one file can be synced everywhere.

# Where the database and error log live.
# data_dir = "~/.local/share/ensign"

# Worker threads. 0 = auto (sized from clamd's MaxThreads and CPU count).
max_workers = 0
rescan_after_days = 90

# Warn if the virus-signature database is older than this many days
# (usually means freshclam has silently stopped running). 0 disables.
signature_max_age_days = 3
clamd_socket = "/var/run/clamav/clamd.ctl"

scan_targets = [
    "~/Downloads",
    "~/Documents",
    "~/Pictures",
    "~",
]

# Directory trees whose contents never change in place (e.g. proton
# prefix snapshots). Unchanged subtrees under these are skipped by mtime.
snapshot_roots = []

# Trees to skip entirely. High-churn temp/cache directories mostly
# produce "file vanished mid-scan" errors and no security value.
# If you use snapper (or another btrfs snapshot tool) on a subvolume
# under your home directory, its .snapshots dir holds full copies of
# your whole home tree per snapshot -- left un-excluded, Ensign will
# walk every file once per snapshot, and the count balloons with each
# new snapshot snapper takes.
excludes = [
    "~/.cache",
    "~/.local/share/Trash",
    "~/.snapshots",
]

# --- Per-machine overrides (section name = `hostname` output) ---------
#
# [hosts.gaming-rig]
# scan_targets = ["~/Downloads", "~/.local/share/Steam", "~"]
# snapshot_roots = [
#     "~/.local/share/Steam/steamapps/compatdata/<app_id>/pfx/dosdevices/z:/snapshots",
# ]
# (max_workers isn't set per-host -- it's auto-sized from clamd's live
# MaxThreads at startup, so a static override here would just go stale.)
#
# [hosts.old-laptop]
# scan_targets = ["~/Downloads", "~"]
"""


def ensure_default_config() -> None:
    """Write the commented template on first run so users have something
    to edit instead of reading source code to learn the options."""
    if DEFAULT_CONFIG_PATH.exists():
        return
    DEFAULT_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_CONFIG_PATH.write_text(EXAMPLE_CONFIG)
    print(f"[ensign] Wrote starter config to {DEFAULT_CONFIG_PATH}")

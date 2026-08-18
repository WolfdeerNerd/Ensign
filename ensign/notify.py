"""Desktop notification for scan completion, via notify-send.

Best-effort only: if there's no notification daemon (headless server,
SSH session, minimal install), this silently does nothing rather than
error out the whole run over a cosmetic feature.
"""
from __future__ import annotations

import shutil
import subprocess

_MAX_NAMES_SHOWN = 3


def available() -> bool:
    return shutil.which("notify-send") is not None


def build_message(summary: dict, infected: list[dict]) -> tuple[str, str, str]:
    """Build (title, body, urgency) for a scan-completion notification.

    Pure function, no subprocess -- kept separate from send() so the
    message logic can be tested without notify-send installed.
    """
    infected_count = summary.get("infected", 0)
    error_count = summary.get("error", 0) or summary.get("errors", 0)

    if infected_count:
        title = f"! Ensign: {infected_count} infected file" + ("s" if infected_count != 1 else "")
        urgency = "critical"
    elif error_count:
        title = f"Ensign scan complete — {error_count} error" + ("s" if error_count != 1 else "")
        urgency = "normal"
    else:
        title = "Ensign scan complete"
        urgency = "normal"

    body_lines = [
        f"Total: {summary.get('total', 0)}  ·  "
        f"Clean: {summary.get('clean', 0)}  ·  "
        f"Infected: {infected_count}  ·  "
        f"Errors: {error_count}"
    ]
    if infected:
        names = [i["filepath"].split("/")[-1] for i in infected[:_MAX_NAMES_SHOWN]]
        line = "Infected: " + ", ".join(names)
        if len(infected) > _MAX_NAMES_SHOWN:
            line += f" (+{len(infected) - _MAX_NAMES_SHOWN} more)"
        body_lines.append(line)

    return title, "\n".join(body_lines), urgency


def send(summary: dict, infected: list[dict]) -> bool:
    """Fire the notification. Returns True only if notify-send actually
    ran and exited successfully. Returns False if skipped (no
    notify-send), if the call itself failed, or if notify-send ran but
    exited nonzero (commonly caused by missing DBUS_SESSION_BUS_ADDRESS
    when run under sudo/cron outside the user's own session -- in that
    case notify-send fails silently from Ensign's point of view unless
    the return code is checked)."""
    if not available():
        return False
    title, body, urgency = build_message(summary, infected)
    try:
        result = subprocess.run(
            ["notify-send", "-u", urgency, "-a", "Ensign", title, body],
            capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False

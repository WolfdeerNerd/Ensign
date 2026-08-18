#!/usr/bin/env python3
"""Ensign entry point.

All side effects (greeting, logging setup, the scan itself) happen in
main(), not at import time, so the package can be imported by tests or
other scripts without launching a full system scan.
"""
from __future__ import annotations

import sys

if sys.version_info < (3, 11):
    v = sys.version_info
    print(f"Ensign requires Python 3.11 or newer (found {v.major}.{v.minor}).")
    print("It uses the standard-library 'tomllib' module for config parsing.")
    raise SystemExit(1)

import argparse
import logging
import time

from rich import print

from ensign.config import HOME, HOSTNAME, Config, ensure_default_config
from ensign import notify, pacman
from ensign.reports import error_summary, list_infected, pacman_report, scan_summary, suggest_fixes
from ensign.scanner import Scanner


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Hash and ClamAV-scan the system.")
    parser.add_argument("targets", nargs="*",
                        help="Directories to scan (default: scan_targets from config)")
    parser.add_argument("--config", metavar="PATH",
                        help="Config file (default: ~/.config/ensign/config.toml)")
    parser.add_argument("--no-scan", action="store_true",
                        help="Hash and record files without ClamAV scanning")
    parser.add_argument("--skip-rescans", action="store_true",
                        help="Skip the infected/error/stale rescan passes")
    parser.add_argument("--purge-missing", action="store_true",
                        help="Remove DB records for files that no longer exist, then exit")
    parser.add_argument("--rescan-errors", action="store_true",
                        help="Retry only files currently marked ERROR, then exit (no full scan)")
    parser.add_argument("--verify-pacman", action="store_true",
                        help="Check installed files against pacman's records, then exit (Arch only, can be slow)")
    parser.add_argument("--suggest-fixes", action="store_true",
                        help="Print suggested setfacl fixes for current errors, then exit (no full scan). "
                             "Scoped to any targets given.")
    return parser.parse_args()


def setup_logging(config: Config) -> None:
    config.log_file.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        filename=config.log_file,
        level=logging.ERROR,
        format="\n    %(asctime)s - %(name)s - %(message)s",
    )


def greet(config: Config) -> None:
    print()
    print(f" Greetings, {HOME.name}!")
    print("-" * 71)
    print(" I, Ensign, will start scanning your system shortly…")
    print(f" Host:     {HOSTNAME}")
    print(f" Config:   {config.source}")
    print(f" Database: {config.data_dir / 'system.db'}")
    print("-" * 71)


def main() -> int:
    args = parse_args()
    if not args.config:
        ensure_default_config()
    config = Config.load(args.config)
    setup_logging(config)
    greet(config)

    scanner = Scanner(config)
    if args.purge_missing:
        scanner.purge_missing()
        return 0
    if args.rescan_errors:
        if not scanner.clamd.ping():
            print("[red]✗ clamd is not answering on its socket.[/red]")
            return 1
        scanner.rescan_errors()
        return 0
    if args.verify_pacman:
        pacman_report(scanner.engine, pacman.verify_all())
        return 0
    if args.suggest_fixes:
        suggest_fixes(scanner.engine, paths=args.targets or None)
        return 0
    auto = " (auto)" if config.max_workers <= 0 else ""
    print(f" Workers:  {scanner.workers}{auto}")
    scan = not args.no_scan

    if scan and not scanner.clamd.ping():
        print("[red]✗ clamd is not answering on its socket.[/red]")
        print(f"  Socket: {config.clamd_socket}")
        print("  Start it with: sudo systemctl start clamav-daemon")
        return 1
    if scan:
        print("[green]✓ clamd is up.[/green]")
        if config.signature_max_age_days > 0:
            sig_age = scanner.clamd.signature_age_days()
            if sig_age is not None and sig_age > config.signature_max_age_days:
                print(f"[yellow]! Virus signatures are {sig_age} days old "
                      f"(threshold: {config.signature_max_age_days}). Run: sudo freshclam[/yellow]")
        print()

    targets = args.targets or config.scan_targets
    start = time.time()
    print("=== Starting Scan ===")
    for target in targets:
        print(f"\nChecking [violet]{target}[/violet]:")
        scanner.scan_tree(target, scan=scan)

    print(f"\nExecution time: {time.time() - start:.1f} seconds")

    if scan and not args.skip_rescans:
        print("\n=== Processing Rescans ===")
        scanner.rescan_infected()
        scanner.rescan_errors()
        scanner.rescan_stale()

    summary = scan_summary(scanner.engine, paths=args.targets or None)
    error_summary(scanner.engine, paths=args.targets or None)
    infected = list_infected(scanner.engine, paths=args.targets or None)
    suggest_fixes(scanner.engine, paths=args.targets or None)
    notify.send(summary, infected)

    print("\n=== All Scans Finished ===")
    print("-" * 71)
    print(" All finished.")
    print(" Feel free to call upon me again.")
    print("     — Ensign")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# Ensign

Greetings!

Ensign was originally a personal project. I liked clamscan, but I noticed it would keep breaking on certain files in my system — permission denials when clamd's own user couldn't read a path, files rejected outright for exceeding clamd's size limit, files that simply couldn't be hashed, and a genuinely bizarre recursive mess with Steam's Proton Z: drive that kept re-scanning snapshots of snapshots of itself (more on that further down). On top of that, temp files have a way of vanishing between one moment and the next — the world of seemingly quantum temp files is terrifying.

I decided to make a logic brain for this madness, Ensign. The idea was for Ensign to walk the entire system and log every file in an SQLAlchemy database. That database file is kept locally on **your** system. The db includes the id, filepath, filename, file hash, file size, modification time (mtime_ns), scan status, scan result, threat name, last time file was scanned, file creation time, and 'last updated at time' of each file logged in the db.

The idea was to be as paranoid as possible when designing this. That being said, it is completely possible that someone one else will notice something I missed and that in itself, is okay.

## Disclaimer
Parts of this repo were written with assistance of Claude. The architecture and design decisions were made by me. Feel free to scrutinize this code, I welcome any flaws that are found. This project is not perfect, the same way I am not. A wise man loves correction, a fool abhors it.

## Requirements

To get started with Ensign you need Python 3.11 or newer, SQLAlchemy, and rich. Ensign requires Python 3.11+ specifically for the `tomllib` module, used for config parsing.

A `requirements.txt` file is included.

If you have pip installed, the command is:
```
pip install -r requirements.txt
```

If you have pacman installed, the command is:
```
sudo pacman -S --needed python-sqlalchemy python-rich
```

### A note for non-Arch users

Ensign's core scanning, hashing, and database tracking are plain Python + SQLAlchemy + ClamAV — nothing Arch-specific. It should run on any Linux distro with Python 3.11+ and ClamAV installed.

The one exception is `--verify-pacman`, which cross-checks files against `pacman -Qkk`'s own integrity data — that's an Arch-only feature by nature (there's no equivalent on Debian/Fedora/etc.). If `pacman` isn't found on the system, Ensign detects that and skips the check cleanly rather than erroring; every other command works the same regardless of distro.

`setfacl` (used for the permission-fix suggestions) and `notify-send` (desktop notifications) aren't Arch-specific either — both are standard Linux tooling available on most major distros, just under different package names (e.g. Debian/Ubuntu: `acl` and `libnotify-bin`).

## Permissions Setup

When building Ensign, I ran into errors concerning file permissions. Turns out that the ClamAV daemon requires permissions, as it operates under the user `clamav`. The daemon needs this whenever it needs to traverse directories.

To solve this I had to run the two following commands:
```
sudo setfacl -R -m g:clamav:rX /path/to/hotspot
sudo setfacl -R -d -m g:clamav:rX /path/to/hotspot
```
- The first command allows the group `clamav` to read the files in the directory.
- The second command makes it default for any new files in the same directory.

**A note on updates:** Permissions can get reset when programs or games update, because an update may replace files or directories with fresh copies that don't carry the ACL you set. If permission errors come back after an update, run the two commands again on the affected folder (`python3 main.py --suggest-fixes` prints the right commands for the current errors).

## Threading & Worker Sizing

Ensign scans files concurrently using a thread pool, since the work per file (hashing, then a clamd socket round-trip) is I/O-bound, not CPU-bound — the Python GIL isn't a bottleneck here the way it would be for CPU-heavy parallel work.

Worker count is either set explicitly (`max_workers` in config) or resolved automatically (`max_workers = 0`, the default): Ensign asks clamd for its own `MaxThreads` limit, subtracts a little headroom so the daemon stays responsive to other clients, and caps the result by your CPU count.

If clamd can't be reached to ask, Ensign falls back to a safe default of 5 workers rather than guessing wildly. And no matter how constrained the machine — single core, a very low `MaxThreads` on clamd — the worker count can never drop below 1. **Ensign will always run, even on modest hardware;** it just scans one file at a time in that case rather than failing or requiring a separate no-threading mode.

## Usage

**First run: don't use `sudo`.** Run Ensign under your own username the first time. Ensign creates its config, database and log files on first run, and whoever runs it owns them. If the first run is as root, those files end up owned by root and your username can't use them afterwards. If that happens, delete the root-created files (the database in `~/.local/share/ensign/` and the config in `~/.config/ensign/`) and run Ensign once under your own username to recreate them.

**First quick scan:** Before scanning everything, test your setup on one folder.

1. Make sure ClamAV's daemon is running (Ensign tells you if it isn't):
   ```
   sudo systemctl start clamav-daemon
   ```
2. Run Ensign on a small tree, as your own username:
   ```
   python3 path/to/main.py ~/Downloads
   ```
3. If you see permission errors, see Permissions Setup above, then run it again.

For a full scan, you only need to run:
```
python3 path/to/main.py
```

This scans everything listed in your config's `scan_targets`, runs the infected/error/stale rescan passes, prints a summary and error breakdown, and sends a desktop notification when it's done (if one is available).

### Targeting and behavior flags

| Command | What it does |
|---|---|
| `python3 main.py --help` | Show all available flags and exit |
| `python3 main.py ~/Downloads` | Scan just that one tree instead of everything in config |
| `python3 main.py --no-scan` | Hash and record files, skip ClamAV entirely |
| `python3 main.py --skip-rescans` | Skip the infected/error/stale rescan passes at the end |
| `python3 main.py --config PATH` | Use an alternate config file (default: `~/.config/ensign/config.toml`) |

### Standalone maintenance commands

These run one job and exit — no full scan.

| Command | What it does |
|---|---|
| `python3 main.py --purge-missing` | Remove DB records for files that no longer exist on disk |
| `python3 main.py --rescan-errors` | Retry only files currently marked `ERROR` |
| `python3 main.py --verify-pacman` | Cross-check installed files against pacman's own checksums, flag mismatches (Arch only, can be slow) |
| `python3 main.py --suggest-fixes` | Print setfacl commands for current permission errors, optionally scoped to given targets |

### If a suggested fix doesn't seem to work

If you apply a suggested 'setfactl' command and the same error keeps popping showing up on a later run, the file may have been deleted since Ensign last saw it - common with temp files, downloads that get cleaned up, or build artifacts. A permission fix can't help a file that no longer exists. 

Run: 
    `python3 main.py --purge-missing`
to clear out stale records, then run a normal scan again to re-establish a clean baseline. 


## Querying the Database Directly

Most day-to-day questions are covered by the commands above. But the database is just SQLite, kept locally at the path printed in the `Database:` line when Ensign starts (`~/.local/share/ensign/system.db` unless you've set a custom `data_dir`) — for anything the built-in reports don't cover, `sqlite3` gets you there directly.

The `files` table's `scan_status` column is one of: `clean`, `infected`, `error`, `pending`, `classified`.

See the details behind current errors:
```
sqlite3 ~/.local/share/ensign/system.db "SELECT filepath, scan_result FROM files WHERE scan_status='error';"
```

See what's been classified (permission denied on a path that looks like a secrets store — expected, not chased as an error):
```
sqlite3 ~/.local/share/ensign/system.db "SELECT filepath, scan_result FROM files WHERE scan_status='classified';"
```

The list of paths/filenames/extensions used to make that call isn't arbitrary — see `docs/Classified_Paths_Research.md` for the sourcing behind each entry, and `ensign/secrets.py` for the confidence tiers and how the two different call sites use them.

See infected files and what triggered them:
```
sqlite3 ~/.local/share/ensign/system.db "SELECT filepath, threat_name FROM files WHERE scan_status='infected';"
```

Look up everything Ensign knows about one specific file:
```
sqlite3 ~/.local/share/ensign/system.db "SELECT * FROM files WHERE filepath='/full/path/to/file';"


```

### A note on infected results

ClamAV includes heuristic signatures (like `SVGDynamicFunction`) that can match on legitimate code patterns — for example, JS build tools that generate functions at runtime from template/markup content (Vue's `compiler-sfc`, Vite's dependency cache) can trigger a phishing-heuristic match despite being ordinary framework code. An `infected` status is worth investigating, not treating as an automatic threat. Check what the file actually is and, if it looks like legitimate tooling, search the threat name plus the library name before assuming compromise.

### For Steam users,
### A note on Proton's 'Z:' drive

When developing Ensign, there wasn't anything to stop the walk from wandering and rescanning symlinks since I didn't understand them. You can imagine my surprise when the db was gradually growing in size despite not installing any updates or playing any new games. After some digging I found the culprit. Steam's Z: drive in Proton. The Z: drive allows steam to see and interact with your file system on linux. Nothing wrong with that. What I had failed to understand was that it included the ENTIRE system. INCLUDING ALL THE SNAPSHOTS (system backups)! So as a result, the db was seemingly growing by hundreds of thousands of files as it identifies files by the file paths. Example: ~/Pictures/IMG001.jpg would also show up as ~/.steam/path/to/z:/home/user/Pictures/IMG0001.jpg. A duplicate entry despite being the same file. Now take into account all the usual games that are in a user's steam library and all of those individual files, the walk would take literally days, going onto weeks, just to finish one sweep of the system.

The reason it kept compounding wasn't just that Z: mirrored the whole filesystem — it's that Z: pointing back at `/` meant it also mirrored itself. A snapshot taken of the system would include a copy of the Z: drive, which pointed back at `/`, which contained the Steam compatdata folder, which contained more snapshots, each with their own Z: drive pointing back at `/` again. So the walk wasn't just duplicating files — it was recursively duplicating its own duplicates, with the depth compounding on every snapshot layer. For a time it was quite literally logging backups of the backups of the backups, REGARDLESS OF HOW MANY LAYERS DEEP IT WENT.

Hence why for this build, I've opted to set followlinks to False in the walk function itself:

`for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):`

That way there's no endless cascade of walking a single directory. Symlinked directories are skipped entirely now — the walk sees them but never descends in. Individual files that happen to be symlinks (like a shortcut to a document) are still followed and scanned through to their real target, same as before — it's only symlinked directories that stopped getting wandered into.


### Last Note
This readme will be updated when needed. IE. FAQ questions that keep getting asked, or something needs further explanation.

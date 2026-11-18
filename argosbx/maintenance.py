"""Bounded recovery decisions, firewall integrity and owned cache retention."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat


def process_identity(pid=None):
    pid = pid or os.getpid()
    try:
        start = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
        return {'pid': pid, 'start': start,
                'boot': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    except (OSError, IndexError):
        return None


def owner_alive(tx):
    owner = tx.get('owner')
    return bool(owner and process_identity(owner['pid']) == owner)


def firewall_digest(payload):
    def clean(value):
        if isinstance(value, dict):
            return {key: clean(item) for key, item in value.items() if key not in ("handle", "index", "position")}
        if isinstance(value, list):
            return [clean(item) for item in value]
        return value
    objects = [clean(item) for item in payload.get("nftables", []) if "metainfo" not in item]
    return hashlib.sha256(json.dumps(objects, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def recent_attempts(history, timestamp):
    return [attempt for attempt in history.get("attempts", []) if timestamp - attempt < 86400]


def recovery_allowed(fault, attempts, timestamp, cost=1):
    return (fault.get("seen", 0) >= 2 and timestamp >= fault.get("next_at", 0)
            and len(attempts) + cost <= 8)


def defer(fault, timestamp, delays):
    failures = fault.get("failures", 0)
    delay = delays[min(failures, len(delays) - 1)]
    fault.update(failures=failures + 1, next_at=timestamp + delay)
    return delay


def cleanup_cache(directory, timestamp, keep=6):
    """Only digest-named own archives/partials; never follow symlinks."""
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        return 0
    owner = directory.stat().st_uid
    if hasattr(os, "geteuid") and owner != os.geteuid():
        return 0
    def owned_file(path):
        info = path.lstat()
        return stat.S_ISREG(info.st_mode) and info.st_uid == owner and info.st_nlink == 1
    removed = 0
    archives = sorted((p for p in directory.iterdir() if re.fullmatch(r"[0-9a-f]{64}\.tar\.gz", p.name)
                       and owned_file(p)),
                      key=lambda p: p.stat().st_mtime, reverse=True)
    for path in archives[keep:]:
        if timestamp - path.stat().st_mtime > 7 * 86400:
            path.unlink()
            removed += 1
    for path in directory.iterdir():
        if ((re.fullmatch(r"[0-9a-f]{64}\.tar\.gz\.partial", path.name) or
                 re.fullmatch(r"\.download-[A-Za-z0-9_-]{8}", path.name)) and
                owned_file(path) and timestamp - path.stat().st_mtime > 86400):
            path.unlink()
            removed += 1
    return removed

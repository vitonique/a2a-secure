"""Simple stats persistence for A2A (v0.5.1).

Stores counters in JSON at ~/.a2a/stats.json.
- atomic write (temp file + rename)
- best-effort file locking (fcntl on Unix)

This is intentionally lightweight (no extra deps). If we outgrow JSON,
we can migrate to SQLite later.
"""

from __future__ import annotations

import json
import os
import time
from contextlib import contextmanager
from typing import Any, Dict, Optional


DEFAULT_PATH = os.path.expanduser("~/.a2a/stats.json")


def _ensure_dir(path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)


@contextmanager
def _file_lock(fp):
    """Best-effort exclusive lock."""
    try:
        import fcntl  # Unix only

        fcntl.flock(fp.fileno(), fcntl.LOCK_EX)
        yield
    except Exception:
        yield
    finally:
        try:
            import fcntl

            fcntl.flock(fp.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass


def load_stats(path: str = DEFAULT_PATH) -> Dict[str, Any]:
    try:
        with open(path, "r") as f:
            return json.load(f) or {}
    except FileNotFoundError:
        return {}
    except Exception:
        return {}


def atomic_write_json(path: str, data: Dict[str, Any]) -> None:
    _ensure_dir(path)
    tmp = f"{path}.tmp"
    with open(tmp, "w") as f:
        with _file_lock(f):
            json.dump(data, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
    os.replace(tmp, path)


def now_ts() -> int:
    return int(time.time())


def bump(stats: Dict[str, Any], key: str, n: int = 1) -> None:
    stats[key] = int(stats.get(key, 0) or 0) + int(n)


def set_if_missing(stats: Dict[str, Any], key: str, value: Any) -> None:
    if key not in stats or stats[key] is None:
        stats[key] = value


def update_running_avg(stats: Dict[str, Any], key_avg: str, key_count: str, sample: float) -> None:
    """Update running average stored as avg + count."""
    count = int(stats.get(key_count, 0) or 0)
    avg = float(stats.get(key_avg, 0.0) or 0.0)
    new_count = count + 1
    new_avg = (avg * count + float(sample)) / new_count
    stats[key_count] = new_count
    stats[key_avg] = new_avg

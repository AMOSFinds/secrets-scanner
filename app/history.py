# app/history.py
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import json
import threading

# Where we'll store scan history
DATA_DIR = Path(__file__).resolve().parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
HISTORY_FILE = DATA_DIR / "scan_history.json"

_lock = threading.Lock()


def _load_history() -> Dict[str, Any]:
    if not HISTORY_FILE.exists():
        return {"scans": []}
    try:
        with HISTORY_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {"scans": []}
        data.setdefault("scans", [])
        return data
    except Exception:
        # Corrupted file or unreadable; don't crash the app
        return {"scans": []}


def _save_history(data: Dict[str, Any]) -> None:
    tmp = HISTORY_FILE.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    tmp.replace(HISTORY_FILE)


def summarize_findings(findings: List[Any]) -> Dict[str, Any]:
    """
    Compute a lightweight summary from a list of Finding-like objects.
    We avoid tight coupling to the Finding model and rely on getattr/keys.
    """
    total = len(findings)
    jwt_count = 0
    entropy_count = 0
    severity_counts: Dict[str, int] = {}

    for f in findings:
        # Try attribute, then dict access
        pattern = getattr(f, "pattern", None)
        if pattern is None and isinstance(f, dict):
            pattern = f.get("pattern")

        entropy = getattr(f, "entropy", None)
        if entropy is None and isinstance(f, dict):
            entropy = f.get("entropy")

        severity = getattr(f, "severity", None)
        if severity is None and isinstance(f, dict):
            severity = f.get("severity")

        if isinstance(pattern, str) and "jwt" in pattern.lower():
            jwt_count += 1

        try:
            if entropy is not None and float(entropy) >= 4.0:
                entropy_count += 1
        except Exception:
            pass

        sev = (severity or "UNKNOWN")
        if isinstance(sev, str):
            sev = sev.upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "total_findings": total,
        "jwt_count": jwt_count,
        "entropy_count": entropy_count,
        "severity_counts": severity_counts,
    }


def add_scan_entry(
    *,
    source: str,
    repo_url: str,
    branch: str,
    findings: List[Any],
    api_key: Optional[str] = None,
) -> None:
    """
    Append a single scan entry (web or CLI) to the JSON history file.
    Reading history will be Pro-only, but we can happily record all scans.
    """
    ts = datetime.now(timezone.utc)
    summary = summarize_findings(findings)

    entry: Dict[str, Any] = {
        "id": f"{int(ts.timestamp() * 1000)}-{source}",
        "timestamp": ts.isoformat(),
        "source": source,        # "web" or "cli"
        "repo_url": repo_url,
        "branch": branch,
        "api_key": api_key,      # may be None
        **summary,
    }

    with _lock:
        data = _load_history()
        scans = data.get("scans", [])
        scans.append(entry)
        # keep the last 500 entries to avoid unbounded growth
        data["scans"] = scans[-500:]
        _save_history(data)


def list_scans(limit: int = 100) -> List[Dict[str, Any]]:
    """Return recent scans (most recent first)."""
    data = _load_history()
    scans = data.get("scans", [])
    if not isinstance(scans, list):
        return []
    scans = scans[-limit:]
    # reverse so newest first
    return list(reversed(scans))


def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    """(Optional for later) fetch a single scan entry by id."""
    data = _load_history()
    for s in data.get("scans", []):
        if s.get("id") == scan_id:
            return s
    return None

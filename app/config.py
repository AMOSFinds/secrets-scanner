from __future__ import annotations
import json, os, hashlib, fnmatch
from typing import Dict, Any, List
from .models import Finding  # uses your existing Finding model
from pathlib import Path
from typing import Dict, Any, List

DEFAULT_CONFIG: Dict[str, Any] = {
    # Paths/patterns to skip. Supports substring and glob (e.g. "node_modules/*")
    "ignore_patterns": [
        ".git/",
        "node_modules/",
        "vendor/",
        "dist/",
        "build/",
        "*.min.js",
        "*.lock",
        "*.png",
        "*.jpg",
        "*.jpeg",
        "*.gif",
        "*.pdf",
        "*.zip",
        "*.tar",
        "*.gz",
    ],
    # Optional custom regex names to extend scanning later
    "custom_patterns": [],
    # Baseline is a dict of file_path -> list of finding hashes
    "baseline": {}
}

def load_config() -> Dict[str, Any]:
    path = ".secrets-scanner.json"
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                user_conf = json.load(f)
            cfg = DEFAULT_CONFIG.copy()
            # shallow-merge for simple keys
            for k, v in user_conf.items():
                if isinstance(v, list) and isinstance(cfg.get(k), list):
                    cfg[k] = v
                elif isinstance(v, dict) and isinstance(cfg.get(k), dict):
                    tmp = cfg[k].copy()
                    tmp.update(v)
                    cfg[k] = tmp
                else:
                    cfg[k] = v
            return cfg
        except Exception as e:
            print(f"⚠️ Failed to load .secrets-scanner.json: {e}")
    return DEFAULT_CONFIG.copy()

def finding_hash(f: Finding) -> str:
    # Stable hash for a finding (file + line + pattern + snippet)
    s = f"{f.file_path}:{f.line}:{f.pattern}:{f.snippet}"
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()

def path_ignored(path: str, ignore_patterns: List[str]) -> bool:
    """
    Return True if 'path' matches any ignore pattern.
    We support substring OR fnmatch-style globs.
    """
    for pat in ignore_patterns:
        if pat in path:
            return True
        if fnmatch.fnmatch(path, pat):
            return True
    return False

def baseline_contains(baseline: Dict[str, List[str]], f: Finding) -> bool:
    h = finding_hash(f)
    return h in baseline.get(f.file_path, [])

def load_policy(root: Path | None = None) -> Dict[str, Any]:
    """
    Loads optional .secrets-policy.json (organization rules).
    Structure (all optional):
    {
      "ignore": {
        "paths": ["tests/**", "vendor/**"],
        "patterns": ["DUMMY_API_KEY=.*"]
      },
      "forbid": { "patterns": ["AKIA[0-9A-Z]{16}"] },
      "severity_overrides": { "GENERIC_PASSWORD": "HIGH", "JWT": "HIGH" },
      "min_entropy": { "LOW": 3.5, "MED": 4.0, "HIGH": 4.5 },
      "allow_env_names": ["DUMMY_API_KEY"]
    }
    """
    root = root or Path(".").resolve()
    p = root / ".secrets-policy.json"
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        # normalize shapes
        data.setdefault("ignore", {})
        data["ignore"].setdefault("paths", [])
        data["ignore"].setdefault("patterns", [])
        data.setdefault("forbid", {})
        data["forbid"].setdefault("patterns", [])
        data.setdefault("severity_overrides", {})
        data.setdefault("min_entropy", {})
        data.setdefault("allow_env_names", [])
        return data
    except Exception:
        return {}

def path_ignored_by_policy(path_str: str, policy: Dict[str, Any]) -> bool:
    # Reuse your own glob ignore in CLI; here we only handle policy-level ignores
    import fnmatch
    for pat in policy.get("ignore", {}).get("paths", []) or []:
        if fnmatch.fnmatch(path_str, pat):
            return True
    return False

def pattern_is_forbidden(text: str, policy: Dict[str, Any]) -> bool:
    import re
    for pat in policy.get("forbid", {}).get("patterns", []) or []:
        if re.search(pat, text):
            return True
    return False
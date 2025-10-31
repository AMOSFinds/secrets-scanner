# app/config.py
import json, os, hashlib, fnmatch
from typing import Dict, Any, List
from .models import Finding  # uses your existing Finding model

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

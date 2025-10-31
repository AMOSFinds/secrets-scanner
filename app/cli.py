# app/cli.py
import argparse, os, sys, json, subprocess, fnmatch
from pathlib import Path
from typing import Iterable, List
from .scanner import scan_text
from .models import Finding
from .utils_github import RAW_SKIP_EXTS  # reuse your existing skip list
from .config import (
    load_config,
    path_ignored,
    baseline_contains,
    finding_hash,
)

DEFAULT_MAX_SIZE = 1024 * 1024  # 1 MB per file
DEFAULT_EXCLUDES = [
    "node_modules/**", "dist/**", "build/**", "**/*.min.js", "**/*.map",
    "**/.git/**", "**/.venv/**", "**/__pycache__/**", "**/*.lock", "**/*.bin",
]

# ---------- UI helpers ----------
def _supports_unicode() -> bool:
    enc = (getattr(sys.stdout, "encoding", "") or "").lower()
    return "utf" in enc

OK_MARK = "✅" if _supports_unicode() else "[OK]"
ALERT_MARK = "❗" if _supports_unicode() else "[!]"

# ---------- file helpers ----------
def is_probably_text(path: Path, chunk_size: int = 4096) -> bool:
    try:
        with open(path, "rb") as f:
            chunk = f.read(chunk_size)
        if b"\x00" in chunk:
            return False
        # try decode
        chunk.decode("utf-8", errors="ignore")
        return True
    except Exception:
        return False

def read_text(path: Path, max_bytes: int) -> str | None:
    try:
        size = path.stat().st_size
        if size > max_bytes:
            return None
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return None

def should_skip_path_by_ext(path: Path) -> bool:
    p = str(path).replace("\\", "/")
    if any(p.endswith(ext) for ext in RAW_SKIP_EXTS):
        return True
    parts = [part.lower() for part in path.parts]
    if ".git" in parts:
        return True
    return False

def iter_repo_files(root: Path, include: List[str], exclude: List[str]) -> Iterable[Path]:
    """Walk the repo tree with include/exclude globs (fast local-only mode)."""
    for dirpath, dirnames, filenames in os.walk(root):
        # speed: drop .git subtrees
        if ".git" in [d.lower() for d in dirnames]:
            dirnames[:] = [d for d in dirnames if d.lower() != ".git"]
        for name in filenames:
            p = Path(dirpath) / name
            # include/exclude (globs)
            sp = str(p).replace("\\", "/")
            if exclude and any(fnmatch.fnmatch(sp, pat) for pat in exclude):
                continue
            if include and not any(fnmatch.fnmatch(sp, pat) for pat in include):
                continue
            yield p

def get_staged_files() -> List[Path]:
    """Return staged files (pre-commit context)."""
    try:
        out = subprocess.check_output(
            ["git", "diff", "--cached", "--name-only"],
            stderr=subprocess.STDOUT,
            universal_newlines=True,
        )
        files = [Path(line.strip()) for line in out.splitlines() if line.strip()]
        return [f for f in files if f.exists()]
    except Exception:
        return []

def get_all_tracked_files() -> List[Path]:
    """Return all tracked files (CI-style)."""
    try:
        out = subprocess.check_output(
            ["git", "ls-files"],
            stderr=subprocess.STDOUT,
            universal_newlines=True,
        )
        files = [Path(line.strip()) for line in out.splitlines() if line.strip()]
        return [f for f in files if f.exists()]
    except Exception:
        return []

# ---------- scanning ----------
def scan_paths(paths: List[Path], max_size: int, cfg: dict) -> List[Finding]:
    findings: List[Finding] = []
    ignores = cfg.get("ignore_patterns", []) or []

    for p in paths:
        sp = str(p).replace("\\", "/")

        # config ignore (substring or glob) + hard ext/.git skip
        if path_ignored(sp, ignores) or should_skip_path_by_ext(p):
            continue

        if not is_probably_text(p):
            continue
        content = read_text(p, max_size)
        if content is None:
            continue

        for f in scan_text(sp, content):
            # baseline filtering
            if baseline_contains(cfg.get("baseline", {}), f):
                continue
            findings.append(f)

    return findings

# ---------- output ----------
def print_text(findings: List[Finding]) -> None:
    if not findings:
        print(f"{OK_MARK} No secrets found.")
        return
    print(f"{ALERT_MARK} Found {len(findings)} potential secret(s):\n")
    for f in findings:
        print(f"- {f.severity} · {f.pattern} · {f.file_path}:{f.line}")
        if f.snippet:
            snippet = (f.snippet or "").replace("\n", "\\n")
            # redacted preview to avoid dumping full secret
            red = snippet[:4] + "..." if len(snippet) > 4 else snippet
            print(f"    snippet: {red}")

def write_sarif(findings: List[Finding], dest: str):
    sarif = {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "runs": [{
            "tool": {"driver": {"name": "secrets-scanner", "informationUri": "https://github.com/AMOSFinds/secrets-scanner"}},
            "results": [],
        }],
    }
    results = sarif["runs"][0]["results"]
    for f in findings:
        results.append({
            "ruleId": f.pattern,
            "level": "error" if (f.severity or "").upper() == "HIGH" else "warning",
            "message": {"text": f"Potential secret: {f.pattern}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file_path},
                    "region": {"startLine": f.line or 1}
                }
            }],
            "properties": {"redactedSnippet": (f.snippet[:4] + "...") if f.snippet else ""},
        })
    data = json.dumps(sarif, indent=2)
    if dest == "-":
        sys.stdout.write(data + "\n")
    else:
        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(data)

# ---------- main ----------
def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="secrets-scan",
        description="Local secrets scanner (pre-commit & CI friendly).",
    )
    parser.add_argument("path", nargs="?", default=".", help="Folder to scan (default: current directory)")
    parser.add_argument("--staged", action="store_true", help="Scan staged files only (pre-commit mode)")
    parser.add_argument("--all", action="store_true", help="Scan all tracked files (git ls-files)")
    parser.add_argument("--include", action="append", default=[], help="Glob to include (repeatable)")
    parser.add_argument("--exclude", action="append", default=[], help="Glob to exclude (repeatable)")
    parser.add_argument("--max-size", type=int, default=DEFAULT_MAX_SIZE, help="Max file size to scan (bytes)")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    parser.add_argument("--sarif", default=None, help="Write SARIF to file (or '-' for stdout)")
    parser.add_argument("--update-baseline", action="store_true", help="Add current findings to baseline (.secrets-scanner.json)")
    args = parser.parse_args(argv)

    cfg = load_config()

    # choose file set
    if args.staged:
        paths = get_staged_files()
    elif args.all:
        paths = get_all_tracked_files()
    else:
        root = Path(args.path).resolve()
        # merge user excludes with sensible defaults
        merged_excludes = list(set((args.exclude or []) + DEFAULT_EXCLUDES))
        paths = list(iter_repo_files(root, include=args.include, exclude=merged_excludes))

    findings = scan_paths(paths, max_size=args.max_size, cfg=cfg)

    # optional: update baseline and exit success
    if args.update_baseline and findings:
        # write hashes into baseline
        cfg.setdefault("baseline", {})
        for f in findings:
            h = finding_hash(f)
            cfg["baseline"].setdefault(f.file_path, [])
            if h not in cfg["baseline"][f.file_path]:
                cfg["baseline"][f.file_path].append(h)
        with open(".secrets-scanner.json", "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, indent=2)
        print("Baseline updated in .secrets-scanner.json")
        return 0

    # SARIF output (independent of text/json)
    if args.sarif:
        write_sarif(findings, args.sarif)

    if args.format == "json":
        payload = [f.model_dump() for f in findings]
        print(json.dumps(payload, indent=2))
    else:
        print_text(findings)

    # Non-zero exit if we found anything (good for CI/pre-commit)
    return 1 if findings else 0

if __name__ == "__main__":
    raise SystemExit(main())

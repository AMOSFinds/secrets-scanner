# app/cli.py
import argparse, os, sys, json, subprocess, fnmatch, io
from pathlib import Path
from typing import Iterable, List, Tuple
from .scanner import scan_text
from .models import Finding
from .utils_github import RAW_SKIP_EXTS  # reuse your existing skip list

DEFAULT_MAX_SIZE = 1024 * 1024  # 1 MB per file

def _supports_unicode() -> bool:
    enc = (getattr(sys.stdout, "encoding", "") or "").lower()
    return "utf" in enc

OK_MARK = "✅" if _supports_unicode() else "[OK]"
ALERT_MARK = "❗" if _supports_unicode() else "[!]"

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

def should_skip(path: Path, include: List[str], exclude: List[str]) -> bool:
    p = str(path).replace("\\", "/")
    if any(fnmatch.fnmatch(p, pat) for pat in exclude):
        return True
    if include and not any(fnmatch.fnmatch(p, pat) for pat in include):
        return True
    if any(p.endswith(ext) for ext in RAW_SKIP_EXTS):
        return True
    parts = [part.lower() for part in path.parts]
    if ".git" in parts:
        return True
    return False

DEFAULT_EXCLUDES = [
    "node_modules/**", "dist/**", "build/**", "**/*.min.js", "**/*.map",
    "**/.git/**", "**/.venv/**", "**/__pycache__/**", "**/*.lock", "**/*.bin",
]

def iter_repo_files(root: Path, include: List[str], exclude: List[str]) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        # skip .git dirs quickly
        if ".git" in [d.lower() for d in dirnames]:
            dirnames[:] = [d for d in dirnames if d.lower() != ".git"]
        for name in filenames:
            p = Path(dirpath) / name
            if should_skip(p, include, exclude):
                continue
            yield p

def get_staged_files() -> List[Path]:
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

def scan_paths(paths: List[Path], max_size: int) -> List[Finding]:
    findings: List[Finding] = []
    for p in paths:
        if not is_probably_text(p):
            continue
        content = read_text(p, max_size)
        if content is None:
            continue
        findings.extend(scan_text(str(p), content))
    return findings

def print_text(findings: List[Finding]) -> None:
    if not findings:
        print(f"{OK_MARK} No secrets found.")
        return
    print(f"{ALERT_MARK} Found {len(findings)} potential secret(s):\n")
    for f in findings:
        print(f"- {f.severity} · {f.pattern} · {f.file_path}:{f.line}")
        if f.snippet:
            snippet = f.snippet.replace("\n", "\\n")
            print(f"    snippet: {snippet[:200]}{'...' if len(snippet) > 200 else ''}")


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="secrets-scan",
        description="Local secrets scanner (pre-commit friendly). Scans staged files or a directory.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Folder to scan (default: current directory)")
    parser.add_argument("--staged", action="store_true", help="Scan staged files only (pre-commit mode)")
    parser.add_argument("--include", action="append", default=[], help="Glob to include (repeatable)")
    parser.add_argument("--exclude", action="append", default=[], help="Glob to exclude (repeatable)")
    parser.add_argument("--max-size", type=int, default=DEFAULT_MAX_SIZE, help="Max file size to scan (bytes)")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    args = parser.parse_args(argv)

    if args.staged:
        paths = get_staged_files()
    else:
        root = Path(args.path).resolve()
        paths = list(iter_repo_files(root, include=args.include, exclude=args.exclude))

    findings = scan_paths(paths, max_size=args.max_size)

    if args.format == "json":
        # Convert Pydantic model to dicts
        payload = [f.model_dump() for f in findings]
        print(json.dumps(payload, indent=2))
    else:
        print_text(findings)

    # Non-zero exit if we found anything (good for CI/pre-commit)
    return 1 if findings else 0

if __name__ == "__main__":
    raise SystemExit(main())

def load_config(root: Path) -> dict:
    cfg = root / ".secrets-scanner.json"
    if cfg.exists():
        try:
            return json.load(cfg.open("r", encoding="utf-8"))
        except Exception:
            return {}
    return {}

def should_fail(findings, levels):
    levels = {lvl.strip().upper() for lvl in levels.split(",")}
    return any(f.severity.upper() in levels for f in findings)
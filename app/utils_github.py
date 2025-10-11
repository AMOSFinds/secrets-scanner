import httpx, hmac, hashlib, os, asyncio
from typing import List, Tuple, Dict, Any
from .ratelimit import limiter, sema

RAW_BASE = "https://raw.githubusercontent.com"
RAW_SKIP_EXTS = [
".png",".jpg",".jpeg",".gif",".pdf",".exe",".dll",".so",".dylib",".zip",".tar",".gz",".lock",".min.js"
]

async def _request(client: httpx.AsyncClient, method: str, url: str, headers: dict):
    # simple throttle + naive backoff
    await limiter.wait()
    r = await client.request(method, url, headers=headers)
    if r.status_code in (403, 429):
        retry = int(r.headers.get("Retry-After", "1"))
        await asyncio.sleep(min(retry, 5))
        await limiter.wait()
        r = await client.request(method, url, headers=headers)
    r.raise_for_status()
    return r

async def verify_github_signature(body: bytes, signature_header: str | None, secret: str | None) -> bool:
    if not (signature_header and secret):
        return False
    try:
        algo, sig = signature_header.split("=", 1)
    except ValueError:
        return False
    if algo not in ("sha256", "sha1"):
        return False
    mac = hmac.new(secret.encode(), msg=body, digestmod=hashlib.sha256 if algo=="sha256" else hashlib.sha1)
    expected = mac.hexdigest()
    # constant-time compare
    return hmac.compare_digest(expected, sig)

def changed_paths_from_push(payload: Dict[str, Any]) -> List[str]:
    paths: List[str] = []
    for commit in payload.get("commits", []):
        paths.extend(commit.get("added", []))
        paths.extend(commit.get("modified", []))
        # we ignore deleted for scanning
    # de-dup
    return sorted(set(paths))

async def list_repo_tree(owner: str, repo: str, branch: str = "main", token: str | None = None, max_files: int | None = None) -> List[Tuple[str, str]]:
    base = f"https://api.github.com/repos/{owner}/{repo}"
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    async with httpx.AsyncClient(timeout=30) as client:
        r = await _request(client, "GET", f"{base}/git/trees/{branch}?recursive=1", headers)
        tree = r.json().get("tree", [])
        out = []
        for item in tree:
            if item.get("type") == "blob":
                path = item["path"]
                if any(path.endswith(ext) for ext in RAW_SKIP_EXTS):
                    continue
                out.append((path, f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"))
                if max_files and len(out) >= max_files:
                    break
        return out


async def fetch_file(url: str, token: str | None = None) -> str:
    headers = {}
    if token:
        headers["Authorization"] = f"token {token}"
    async with httpx.AsyncClient(timeout=30) as client:
        async with sema:
            r = await _request(client, "GET", url, headers)
        # r = await client.get(url, headers=headers)
        # r.raise_for_status()
            return r.text


async def fetch_file_at_ref(owner: str, repo: str, ref: str, path: str, token: str | None = None) -> str | None:
    url = f"{RAW_BASE}/{owner}/{repo}/{ref}/{path}"
    headers = {}
    if token:
        headers["Authorization"] = f"token {token}"
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(url, headers=headers)
        if r.status_code == 200:
            return r.text
    return None
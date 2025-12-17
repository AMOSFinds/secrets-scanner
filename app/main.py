# app/main.py
from dotenv import load_dotenv
load_dotenv()

from fastapi import (
    FastAPI,
    HTTPException,
    Form,
    Request,
    Header,
    Depends,
    Response,
)
from fastapi.responses import RedirectResponse, HTMLResponse, StreamingResponse, JSONResponse
from pathlib import Path
from fastapi.templating import Jinja2Templates
from .payments import init_transaction, verify_transaction, assign_key_to_email
from .notify import send_slack, send_email
from .config import load_config, path_ignored, baseline_contains, load_policy
from .models import ScanRequest, ScanResult, Finding
from .scanner import scan_text, set_scanner_policy
from .history import add_scan_entry, list_scans
from .utils_github import (
    list_repo_tree,
    fetch_file,
    verify_github_signature,
    changed_paths_from_push,
    fetch_file_at_ref,
    fetch_repo_config,
)
from starlette.middleware.sessions import SessionMiddleware
from urllib.parse import urlencode

import csv, os, json, secrets, httpx, time, traceback
from datetime import datetime
from httpx import HTTPStatusError, RequestError
from typing import List, Tuple

# --- env + globals ---
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")

TEST_KEYS_JSON = os.getenv("TEST_KEYS_JSON")
TEST_KEYS_FILE = os.getenv("TEST_KEYS_FILE")
API_KEY = os.getenv("API_KEY")

GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
GITHUB_OAUTH_REDIRECT_URL = os.getenv("GITHUB_OAUTH_REDIRECT_URL")

GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"

cfg = load_config()
set_scanner_policy(load_policy())

# --- Pro users store (JSON file) ---
DATA_FILE = Path(__file__).parent / "data" / "pro_users.json"
DATA_FILE.parent.mkdir(exist_ok=True)
if not DATA_FILE.exists():
    DATA_FILE.write_text(json.dumps({"users": {}}, indent=2))


def load_users() -> dict:
    return json.loads(DATA_FILE.read_text())


def save_users(d: dict) -> None:
    DATA_FILE.write_text(json.dumps(d, indent=2))


def find_pro_key_record(key: str) -> dict | None:
    try:
        db = load_users()
        for email, rec in (db.get("users") or {}).items():
            if rec.get("api_key") == key:
                return rec
    except Exception:
        pass
    return None


def pro_key_valid_now(key: str) -> bool:
    rec = find_pro_key_record(key)
    if not rec:
        return False
    exp = rec.get("expires_at")
    if not exp:
        return True
    try:
        ts = datetime.fromisoformat(exp.replace("Z", "+00:00")).timestamp()
        return ts > time.time()
    except Exception:
        return False


_cached_keys: dict[str, float] = {}


def _parse_iso(dt: str) -> float:
    try:
        return datetime.fromisoformat(dt.replace("Z", "+00:00")).timestamp()
    except Exception:
        return 1e12


def _load_allowed_keys() -> dict[str, float]:
    data = None
    if TEST_KEYS_JSON:
        try:
            data = json.loads(TEST_KEYS_JSON)
        except Exception:
            data = None
    elif TEST_KEYS_FILE and os.path.exists(TEST_KEYS_FILE):
        try:
            with open(TEST_KEYS_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:
            data = None

    keys: dict[str, float] = {}
    if isinstance(data, dict) and isinstance(data.get("keys"), list):
        for item in data["keys"]:
            k = item.get("key")
            exp = _parse_iso(item.get("expires") or "2099-12-31T00:00:00Z")
            if k:
                keys[k] = exp
    return keys


def _ensure_keys_loaded():
    global _cached_keys
    if not _cached_keys:
        _cached_keys = _load_allowed_keys()


def _is_key_allowed(k: str | None) -> bool:
    if not k:
        return False
    if API_KEY and k == API_KEY:
        return True
    _ensure_keys_loaded()
    exp = _cached_keys.get(k)
    if exp and exp > time.time():
        return True
    # Also allow Pro keys from pro_users.json
    if pro_key_valid_now(k):
        return True
    return False


async def require_api_key(
    request: Request,
    x_api_key: str | None = Header(default=None),
):
    has_any_protection = bool(API_KEY or TEST_KEYS_JSON or TEST_KEYS_FILE)
    if not has_any_protection:
        return

    supplied = (
        x_api_key
        or request.cookies.get("api_key")
        or request.query_params.get("key")
    )

    if _is_key_allowed(supplied):
        return

    raise HTTPException(status_code=401, detail="Invalid or missing API key")


def dedupe_findings(items: List[Finding]) -> List[Finding]:
    seen: set[Tuple[str, int, str, str]] = set()
    out: List[Finding] = []
    for f in items:
        key = (f.file_path, f.line, f.pattern, f.snippet)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out

async def require_pro_api_key(
    request: Request,
    x_api_key: str | None = Header(default=None),
):
    supplied = x_api_key or request.cookies.get("api_key") or request.query_params.get("key")
    if supplied and pro_key_valid_now(supplied):
        return
    raise HTTPException(status_code=402, detail="Pro key required")

app = FastAPI(title="Secrets Scanner MVP")
TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
SESSION_SECRET = os.getenv("SESSION_SECRET", "dev-secret")
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)


# --- basic routes ---
@app.get("/")
def landing(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.head("/health")
@app.get("/health")
def health():
    return {"ok": True, "service": "secrets-scanner"}


@app.get("/ui", response_class=HTMLResponse)
async def ui_form(request: Request, _: None = Depends(require_api_key)):
    return templates.TemplateResponse("base.html", {"request": request})


# --- core scanning ---
@app.post("/scan", response_model=ScanResult)
async def scan_repo(req: ScanRequest):
    try:
        parts = req.repo_url.rstrip("/").split("github.com/")[1].split("/")
        owner, repo = parts[0], parts[1]
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Invalid repo_url. Use https://github.com/owner/repo",
        )

    token = req.github_token or os.getenv("GITHUB_PAT")

    cfg = await fetch_repo_config(owner, repo, req.branch, token)
    ignore_patterns = cfg.get("ignore_patterns", []) or []
    baseline = cfg.get("baseline", {}) or {}

    files = await list_repo_tree(
        owner,
        repo,
        branch=req.branch,
        token=token,
        max_files=getattr(req, "max_files", None),
    )

    findings: list[Finding] = []
    scanned = 0

    for path, url in files:
        if ignore_patterns and path_ignored(path, ignore_patterns):
            continue
        try:
            content = await fetch_file(url, token=token)
        except Exception:
            continue

        scanned += 1

        for f in scan_text(path, content):
            if baseline and baseline_contains(baseline, f):
                continue
            findings.append(f)

    if "dedupe_findings" in globals():
        findings = dedupe_findings(findings)

    total = len(findings)
    page = max(1, getattr(req, "page", 1))
    page_size = max(1, min(getattr(req, "page_size", 100), 1000))
    start = (page - 1) * page_size
    end = start + page_size
    paged = findings[start:end]

    return ScanResult(
        repo_url=req.repo_url,
        findings=paged,
        scanned_files=scanned,
        total_findings=total,
        page=page,
        page_size=page_size,
    )


@app.post("/scan-ui", response_class=HTMLResponse)
async def scan_ui(
    request: Request,
    repo_url: str = Form(...),
    page: int = Form(1),
    page_size: int = Form(100),
    branch: str = Form("main"),
    _: None = Depends(require_api_key),
):
    """
    UI endpoint: runs a scan and renders results.html.
    Now also records scan history (summary) for later Pro viewing.
    """
    gh_token = request.session.get("gh_token")

    try:
        res: ScanResult = await scan_repo(
            ScanRequest(
                repo_url=repo_url,
                branch=branch,
                page=page,
                page_size=page_size,
                github_token=gh_token,
            )
        )

        # Try to record history (non-fatal if it fails)
        try:
            add_scan_entry(
                source="web",
                repo_url=repo_url,
                branch=branch,
                findings=res.findings,
                api_key=request.cookies.get("api_key"),
            )
        except Exception as hx:
            print("HISTORY-ERROR (web):", hx)

        return templates.TemplateResponse(
            "results.html",
            {
                "request": request,
                "result": res,
                "error": None,
            },
        )

    except Exception as e:
        print("SCAN-UI ERROR:", e)
        traceback.print_exc()

        error_msg = (
            f"Unable to scan repository: {str(e)}. "
            "This may be due to a private repo, invalid URL, missing permissions, "
            "or GitHub rate limiting."
        )

        return templates.TemplateResponse(
            "results.html",
            {
                "request": request,
                "result": None,
                "error": error_msg,
            },
        )



# --- CSV download (unchanged) ---
@app.post("/scan.csv")
async def scan_csv_form(
    repo_url: str = Form(...),
    branch: str = Form("main"),
    _: None = Depends(require_pro_api_key),
):
    res: ScanResult = await scan_repo(ScanRequest(repo_url=repo_url, branch=branch))

    from io import StringIO

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(
        ["file_path", "line", "pattern", "entropy", "severity", "snippet"]
    )
    for f in res.findings:
        writer.writerow(
            [f.file_path, f.line, f.pattern, f.entropy, f.severity, f.snippet]
        )
    output.seek(0)

    headers = {"Content-Disposition": "attachment; filename=findings.csv"}
    return StreamingResponse(output, media_type="text/csv", headers=headers)


# --- GitHub webhook (unchanged) ---

# --- GitHub webhook ---


@app.post("/webhook/github")
async def github_webhook(
    request: Request, x_hub_signature_256: str | None = Header(default=None)
):
    body = await request.body()
    if not await verify_github_signature(
        body, x_hub_signature_256, GITHUB_WEBHOOK_SECRET
    ):
        raise HTTPException(status_code=401, detail="Invalid signature")

    payload = json.loads(body)
    if payload.get("hook", {}).get("type") == "Repository":
        return {"ok": True}

    owner = (
        payload.get("repository", {}).get("owner", {}).get("name")
        or payload.get("repository", {}).get("owner", {}).get("login")
    )
    repo = payload.get("repository", {}).get("name")
    after = payload.get("after")
    if not (owner and repo and after):
        raise HTTPException(status_code=400, detail="Missing repo/after in payload")

    paths = changed_paths_from_push(payload)
    findings: List[Finding] = []
    scanned = 0
    for p in paths:
        content = await fetch_file_at_ref(owner, repo, after, p)
        if content is None:
            continue
        scanned += 1
        findings.extend(scan_text(p, content))

    findings = dedupe_findings(findings) if "dedupe_findings" in globals() else findings

    if findings:
        repo_url = f"https://github.com/{owner}/{repo}"
        await send_slack(repo_url, findings)
        await send_email(repo_url, findings)

    return {"ok": True, "scanned_files": scanned, "findings": len(findings)}


# --- Access / API key login ---


@app.get("/access", response_class=HTMLResponse)
def access_form(request: Request):
    return templates.TemplateResponse("access.html", {"request": request})


@app.post("/access")
def access_submit(key: str = Form(...)):
    if not API_KEY or key != API_KEY:
        raise HTTPException(status_code=401, detail="Bad key")
    resp = RedirectResponse(url="/ui", status_code=302)
    resp.set_cookie(
        "api_key", key, httponly=True, samesite="lax", max_age=60 * 60 * 24 * 7
    )
    return resp


@app.get("/login")
def login(key: str, response: Response):
    # Accept either the master API_KEY or any valid Pro key
    if not _is_key_allowed(key):
        raise HTTPException(status_code=401, detail="Bad key")

    resp = RedirectResponse(url="/ui", status_code=302)
    # 7-day cookie; HttpOnly so JS can’t read it
    resp.set_cookie(
        "api_key",
        key,
        httponly=True,
        samesite="lax",
        max_age=60 * 60 * 24 * 7,
    )
    return resp


# --- GitHub OAuth for private repos ---


@app.get("/auth/github/login")
async def github_login(request: Request):
    if not (GITHUB_CLIENT_ID and GITHUB_OAUTH_REDIRECT_URL):
        raise HTTPException(status_code=500, detail="OAuth not configured")
    state = secrets.token_urlsafe(24)
    request.session["oauth_state"] = state
    params = {
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": GITHUB_OAUTH_REDIRECT_URL,
        "scope": "repo",
        "state": state,
        "allow_signup": "false",
    }
    url = f"{GITHUB_AUTHORIZE_URL}?{urlencode(params)}"
    return {"authorize_url": url}


@app.get("/auth/github/callback")
async def github_callback(
    request: Request, code: str | None = None, state: str | None = None
):
    if not (code and state):
        raise HTTPException(status_code=400, detail="Missing code/state")
    expected = request.session.get("oauth_state")
    if not expected or expected != state:
        raise HTTPException(status_code=400, detail="Invalid state")
    async with httpx.AsyncClient(timeout=20) as client:
        headers = {"Accept": "application/json"}
        data = {
            "client_id": GITHUB_CLIENT_ID,
            "client_secret": GITHUB_CLIENT_SECRET,
            "code": code,
            "redirect_uri": GITHUB_OAUTH_REDIRECT_URL,
            "state": state,
        }
        r = await client.post(GITHUB_TOKEN_URL, data=data, headers=headers)
        r.raise_for_status()
        token = r.json().get("access_token")
        if not token:
            raise HTTPException(
                status_code=400, detail="Failed to obtain access token"
            )
        request.session["gh_token"] = token
    return HTMLResponse(
        "<h1>GitHub connected.</h1><p>You can now scan private repos.</p>"
        "<p><a href='/ui'>Back to UI</a></p>"
    )


# --- Exception handlers for GitHub errors ---


@app.exception_handler(HTTPStatusError)
async def httpx_status_handler(request, exc):
    detail = "GitHub API error."
    if exc.response.status_code == 403:
        detail = "GitHub rate limit. Connect GitHub (OAuth) or supply a token."
    elif exc.response.status_code == 404:
        detail = "Repo or branch not found. Double-check the URL/branch."
    return templates.TemplateResponse(
        "error.html",
        {"request": request, "detail": detail},
        status_code=exc.response.status_code,
    )


@app.exception_handler(RequestError)
async def httpx_request_handler(request, exc):
    return templates.TemplateResponse(
        "error.html",
        {"request": request, "detail": "Network error. Please retry."},
        status_code=502,
    )


# --- Pro checkout + callback ---
@app.get("/pro", response_class=HTMLResponse)
async def pro_page(request: Request):
    price_cents = int(os.getenv("PRO_PRICE_CENTS", "10000"))
    price_human = f"R{price_cents/100:.2f}"
    approx_usd = f"{price_cents/100/18:.2f}"  # assuming ~R18 = $1
    return templates.TemplateResponse(
        "pro.html", {"request": request, "price_human": price_human, "approx_usd": approx_usd}
    )


@app.post("/pro/checkout")
async def pro_checkout(email: str = Form(...)):
    data = await init_transaction(email=email)
    return RedirectResponse(url=data["authorization_url"], status_code=302)


@app.get("/pro/callback", response_class=HTMLResponse)
async def pro_callback(request: Request, reference: str | None = None):
    if not reference:
        raise HTTPException(status_code=400, detail="Missing reference")
    tx = await verify_transaction(reference)
    status = tx.get("status")
    if status != "success":
        return HTMLResponse("<h1>Payment not successful.</h1>", status_code=400)

    email = (tx.get("customer") or {}).get("email") or "unknown@example.com"

    key = assign_key_to_email(email)
    if not key:
        return HTMLResponse(
            "<h1>Payment ok, but no keys available. Please contact support.</h1>",
            status_code=500,
        )

    # Persist to pro_users.json so the API key is recognised later
    db = load_users()
    db.setdefault("users", {})
    db["users"][email] = {
        "api_key": key.get("key"),
        "label": key.get("label", ""),
        "expires_at": key.get("expires"),
    }
    save_users(db)

    return templates.TemplateResponse(
        "pro_success.html",
        {"request": request, "key": key},
    )


# --- Scan history (Pro-only UI) ---


@app.get("/history", response_class=HTMLResponse)
async def history_page(request: Request):
    try:
        require_pro_api_key(request)
    except HTTPException:
        return RedirectResponse(url="/pro?reason=history", status_code=302)

    scans = list_scans(limit=100)
    return templates.TemplateResponse(
        "history.html",
        {"request": request, "scans": scans},
    )

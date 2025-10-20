from dotenv import load_dotenv
load_dotenv()
from fastapi import FastAPI, HTTPException, Form, Request, BackgroundTasks, Header, Depends, Response
from fastapi.responses import RedirectResponse
from .notify import send_slack, send_email
from pathlib import Path
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from io import StringIO
import csv, os, json, secrets, httpx


from typing import List, Tuple
from .models import ScanRequest, ScanResult, Finding
from .scanner import scan_text
from .utils_github import list_repo_tree, fetch_file, verify_github_signature, changed_paths_from_push, fetch_file_at_ref
from starlette.middleware.sessions import SessionMiddleware
from urllib.parse import urlencode


GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")

API_KEY = os.getenv("API_KEY")

GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
GITHUB_OAUTH_REDIRECT_URL = os.getenv("GITHUB_OAUTH_REDIRECT_URL")


GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"

async def require_api_key(
    request: Request,
    x_api_key: str | None = Header(default=None),
):
    # If no API_KEY set, protection is off
    if not API_KEY:
        return
    supplied = x_api_key or request.cookies.get("api_key") or request.query_params.get("key")
    if supplied != API_KEY:
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


app = FastAPI(title="Secrets Scanner MVP")
TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
SESSION_SECRET = os.getenv("SESSION_SECRET", "dev-secret")
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)
# templates = Jinja2Templates(directory="app/templates")


@app.get("/")
def landing(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/health")
def health():
    return {"ok": True, "service": "secrets-scanner"}


@app.get("/ui", response_class=HTMLResponse)
# def ui_form(request: Request):
async def ui_form(request: Request, _: None = Depends(require_api_key)):
    return templates.TemplateResponse("base.html", {"request": request})


@app.post("/scan", response_model=ScanResult)
async def scan_repo(req: ScanRequest, background_tasks: BackgroundTasks = None):
    # Parse owner/repo
    try:
        parts = req.repo_url.rstrip("/").split("github.com/")[1].split("/")
        owner, repo = parts[0], parts[1]
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid repo_url. Use https://github.com/owner/repo")

    

    token = req.github_token or os.getenv("GITHUB_PAT")
    files = await list_repo_tree(owner, repo, branch=req.branch, token=token, max_files=getattr(req, "max_files", None))

    findings = []
    scanned = 0
    for path, url in files:
        try:
            content = await fetch_file(url, token=token)
        except Exception:
            continue
        scanned += 1
        findings.extend(scan_text(path, content))

    # Optional dedupe
    if "dedupe_findings" in globals():
        findings = dedupe_findings(findings)

    # Pagination
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
async def scan_ui(request: Request, repo_url: str = Form(...), page: int = Form(1), page_size: int = Form(100), branch: str = Form("main"), _: None = Depends(require_api_key)):
    gh_token = request.session.get("gh_token")
    res = await scan_repo(ScanRequest(repo_url=repo_url, branch=branch, page=page, page_size=page_size, github_token=gh_token))
    return templates.TemplateResponse("results.html", {"request": request, "result": res})


@app.post("/scan.csv")
async def scan_csv_form(
    repo_url: str = Form(...),
    branch: str = Form("main"),
):
    # Reuse the JSON route logic under the hood
    res: ScanResult = await scan_repo(ScanRequest(repo_url=repo_url, branch=branch))

    # Stream CSV
    from io import StringIO
    import csv
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["file_path", "line", "pattern", "entropy", "severity", "snippet"])
    for f in res.findings:
        writer.writerow([f.file_path, f.line, f.pattern, f.entropy, f.severity, f.snippet])
    output.seek(0)

    headers = {"Content-Disposition": "attachment; filename=findings.csv"}
    return StreamingResponse(output, media_type="text/csv", headers=headers)

@app.post("/webhook/github")
async def github_webhook(request: Request, x_hub_signature_256: str | None = Header(default=None)):
    body = await request.body()
    if not await verify_github_signature(body, x_hub_signature_256, GITHUB_WEBHOOK_SECRET):
        raise HTTPException(status_code=401, detail="Invalid signature")


    payload = json.loads(body)
    if payload.get("hook", {}).get("type") == "Repository":
        # ping events etc.
        return {"ok": True}


    owner = payload.get("repository", {}).get("owner", {}).get("name") or payload.get("repository", {}).get("owner", {}).get("login")
    repo = payload.get("repository", {}).get("name")
    after = payload.get("after") # commit SHA
    if not (owner and repo and after):
        raise HTTPException(status_code=400, detail="Missing repo/after in payload")


    paths = changed_paths_from_push(payload)
    findings = []
    scanned = 0
    for p in paths:
        content = await fetch_file_at_ref(owner, repo, after, p)
        if content is None:
            continue
        scanned += 1
        findings.extend(scan_text(p, content))


    findings = dedupe_findings(findings) if 'dedupe_findings' in globals() else findings


    # alert if needed
    if findings:
        # repo URL
        repo_url = f"https://github.com/{owner}/{repo}"
        await send_slack(repo_url, findings)
        await send_email(repo_url, findings)


    return {"ok": True, "scanned_files": scanned, "findings": len(findings)}


@app.get("/access", response_class=HTMLResponse)
def access_form(request: Request):
    return templates.TemplateResponse("access.html", {"request": request})

@app.post("/access")
def access_submit(key: str = Form(...)):
    if not API_KEY or key != API_KEY:
        raise HTTPException(status_code=401, detail="Bad key")
    resp = RedirectResponse(url="/ui", status_code=302)
    resp.set_cookie("api_key", key, httponly=True, samesite="lax", max_age=60*60*24*7)
    return resp

@app.get("/auth/github/login")
async def github_login(request: Request):
    if not (GITHUB_CLIENT_ID and GITHUB_OAUTH_REDIRECT_URL):
        raise HTTPException(status_code=500, detail="OAuth not configured")
    state = secrets.token_urlsafe(24)
    request.session["oauth_state"] = state
    params = {
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": GITHUB_OAUTH_REDIRECT_URL,
        "scope": "repo", # access to private repos for reading
        "state": state,
        "allow_signup": "false",
    }
    url = f"{GITHUB_AUTHORIZE_URL}?{urlencode(params)}"
    return {"authorize_url": url}


@app.get("/auth/github/callback")
async def github_callback(request: Request, code: str | None = None, state: str | None = None):
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
            raise HTTPException(status_code=400, detail="Failed to obtain access token")
        request.session["gh_token"] = token
    # simple success page
    return HTMLResponse("<h1>GitHub connected.</h1><p>You can now scan private repos.</p><p><a href='/ui'>Back to UI</a></p>")

@app.get("/login")
def login(key: str, response: Response):
    if not API_KEY or key != API_KEY:
        raise HTTPException(status_code=401, detail="Bad key")
    resp = RedirectResponse(url="/ui", status_code=302)
    # 7-day cookie; HttpOnly so JS can’t read it
    resp.set_cookie("api_key", key, httponly=True, samesite="lax", max_age=60*60*24*7)
    return resp
from __future__ import annotations
import re, base64, json
from typing import List, Dict, Any
from .patterns import PATTERNS, SUSPECT_EXTENSIONS, SUSPECT_FILENAMES
from .entropy import shannon_entropy
from .models import Finding


ENTROPY_THRESHOLD = 3.5 # tune


RECOMMENDATIONS = {
    "AWS_ACCESS_KEY_ID": "Rotate the key in AWS IAM, remove from repo, use env vars or secret manager.",
    "AWS_SECRET_ACCESS_KEY": "Rotate AWS secrets immediately. Use AWS Secrets Manager or env vars.",
    "RSA_PRIVATE_KEY": "Remove private keys from repo. Store in a secrets manager. Rotate if exposed.",
    "STRIPE_SECRET_KEY": "Revoke and rotate Stripe keys. Use restricted keys. Keep in env.",
    "SLACK_WEBHOOK": "Regenerate webhook URL and restrict scopes. Store outside of code.",
    "GENERIC_PASSWORD": "Never commit passwords. Use env vars or a secrets manager and rotate now.",
}

_POLICY: Dict[str, Any] = {}

# ---- JWT detection helpers ----
_B64URL_RE = re.compile(r'^[A-Za-z0-9_-]+$')
JWT_REGEX = re.compile(r'(?:^|[\s\'"])(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})(?:$|[\s\'"])')



def severity_for(match_text: str, path: str, pattern_name: str) -> str:
    sev = "MED"
    ent = shannon_entropy(match_text)
    if ent > ENTROPY_THRESHOLD:
        sev = "HIGH"
    if any(path.endswith(ext) for ext in SUSPECT_EXTENSIONS):
        sev = "HIGH"
    for name in SUSPECT_FILENAMES:
        if name in path:
            sev = "HIGH"
    if pattern_name == "GENERIC_PASSWORD":
        sev = "MED"
    return sev




def scan_text(path: str, text: str) -> List[Finding]:
    findings: List[Finding] = []
    lines = text.splitlines()
    for idx, line in enumerate(lines, start=1):
        for name, pattern in PATTERNS.items():
            for m in pattern.finditer(line):
                snippet = line.strip()
                ent = shannon_entropy(m.group(0))
                sev = severity_for(m.group(0), path, name)
                findings.append(Finding(
                    file_path=path,
                    line=idx,
                    snippet=snippet[:240],
                    pattern=name,
                    entropy=ent,
                    severity=sev,
                    recommendation=RECOMMENDATIONS.get(name, "Remove and rotate. Store in a secrets manager."),
                ))
    # Policy path-level ignore (cheap check)
    from .config import path_ignored_by_policy
    if path_ignored_by_policy(path, _POLICY):
        return findings

    # New detectors:
    findings.extend(detect_jwt(path, text))
    findings.extend(detect_generic_passwords(path, text))            
    return findings


def set_scanner_policy(policy: Dict[str, Any] | None) -> None:
    global _POLICY
    _POLICY = policy or {}


def _b64url_decode(s: str) -> bytes | None:
    try:
        if not _B64URL_RE.match(s):
            return None
        pad = '=' * (-len(s) % 4)
        return base64.urlsafe_b64decode(s + pad)
    except Exception:
        return None

def _looks_like_jwt(token: str) -> bool:
    parts = token.split(".")
    if len(parts) != 3:
        return False
    h, p, _sig = parts
    hd = _b64url_decode(h)
    pd = _b64url_decode(p)
    if not hd or not pd:
        return False
    try:
        hjson = json.loads(hd.decode("utf-8", errors="ignore") or "{}")
        pjson = json.loads(pd.decode("utf-8", errors="ignore") or "{}")
        # Heuristics: has alg in header, some typical claims in payload
        if isinstance(hjson, dict) and "alg" in hjson and isinstance(pjson, dict):
            if any(k in pjson for k in ("sub", "iss", "exp", "iat", "aud")):
                return True
    except Exception:
        return False
    return False

# ---- Generic password/secret assignment detection ----
GENERIC_PASSWORD_RE = re.compile(
    r"""(?ix)
    (?P<key>\b(pass(word)?|pwd|secret|api[_-]?key|token|auth|credential)s?\b)   # key names
    \s*[:=]\s*
    (?P<val>["']?([A-Za-z0-9_\-+/=]{10,})["']?)                                 # value
    """
)

def detect_jwt(file_path: str, content: str) -> List[Finding]:
    findings: List[Finding] = []
    for lineno, line in enumerate(content.splitlines(), start=1):
        for m in JWT_REGEX.finditer(line):
            token = m.group(1).strip('\'"')
            if _looks_like_jwt(token):
                sev = (_POLICY.get("severity_overrides", {}).get("JWT") or "HIGH").upper()
                findings.append(Finding(
                    file_path=file_path,
                    line=lineno,
                    pattern="JWT",
                    entropy=0.0,
                    severity=sev,
                    snippet=token[:12] + "...",
                ))
    return findings

def _shannon_entropy(s: str) -> float:
    from math import log2
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * log2(p) for p in probs)

def detect_generic_passwords(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for i, line in enumerate(text.splitlines(), start=1):
        m = GENERIC_PASSWORD_RE.search(line)
        if not m:
            continue
        val = m.group("val").strip("\"'")
        # Heuristics: require at least 1 letter and 1 digit
        if not (re.search(r"[A-Za-z]", val) and re.search(r"\d", val)):
            continue
        findings.append(Finding(
            file_path=path,
            line=i,
            pattern="GENERIC_PASSWORD",
            severity="MED",
            snippet=line.strip()[:120],
            recommendation="Remove hardcoded secrets. Load from env/secret manager and add file to .gitignore. Rotate the key."
        ))
    return findings

def pattern_is_forbidden_line(line: str) -> bool:
    import re
    for pat in _POLICY.get("forbid", {}).get("patterns", []) or []:
        try:
            if re.search(pat, line):
                return True
        except re.error:
            continue
    return False

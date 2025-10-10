import re
from typing import List
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
    return findings
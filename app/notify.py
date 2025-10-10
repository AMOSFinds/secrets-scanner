import json
import os
from typing import List


import httpx
import aiosmtplib
from email.message import EmailMessage


from .models import Finding


SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
ALERT_FROM = os.getenv("ALERT_FROM", "scanner@localhost")
ALERT_TO = os.getenv("ALERT_TO")




def _summarize(repo_url: str, findings: List[Finding]) -> str:
    high = sum(1 for f in findings if f.severity == "HIGH")
    med = sum(1 for f in findings if f.severity == "MED")
    low = sum(1 for f in findings if f.severity == "LOW")
    lines = [
        f"Secrets Scanner Findings for {repo_url}",
        f"Total: {len(findings)} (HIGH {high} · MED {med} · LOW {low})",
        "",
    ]
    sample = findings[:10]
    for f in sample:
        lines.append(f"- {f.severity} · {f.pattern} · {f.file_path}:{f.line}")
    if len(findings) > len(sample):
        lines.append(f"...and {len(findings) - len(sample)} more")
    return "\n".join(lines)




async def send_slack(repo_url: str, findings: List[Finding]) -> None:
    if not SLACK_WEBHOOK_URL:
        return
    text = _summarize(repo_url, findings)
    payload = {"text": text}
    async with httpx.AsyncClient(timeout=15) as client:
        await client.post(SLACK_WEBHOOK_URL, json=payload)




async def send_email(repo_url: str, findings: List[Finding]) -> None:
    if not (SMTP_HOST and SMTP_USERNAME and SMTP_PASSWORD and ALERT_TO):
        return
    msg = EmailMessage()
    msg["Subject"] = f"Secrets Scanner: {len(findings)} findings for {repo_url}"
    msg["From"] = ALERT_FROM
    msg["To"] = ALERT_TO
    msg.set_content(_summarize(repo_url, findings))
    await aiosmtplib.send(
        msg,
        hostname=SMTP_HOST,
        port=SMTP_PORT,
        start_tls=True,
        username=SMTP_USERNAME,
        password=SMTP_PASSWORD,
    )
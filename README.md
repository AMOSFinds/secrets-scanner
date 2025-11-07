# 🔐 Secrets Scanner

**A fast, local-first, open-source secrets detection tool for developers, DevOps, and security teams.**  
Detect API keys, credentials, JWTs, passwords, and high-entropy secrets *before* they ever reach GitHub.

<p align="left">
  <img src="https://img.shields.io/github/v/release/AMOSFinds/secrets-scanner" />
  <img src="https://img.shields.io/github/stars/AMOSFinds/secrets-scanner?style=social" />
  <img src="https://img.shields.io/badge/Local-First-No%20Cloud%20Upload-brightgreen" />
  <img src="https://img.shields.io/badge/SARIF-Supported-blue" />
  <img src="https://img.shields.io/badge/License-MIT-lightgrey" />
</p>

---

##  Screenshots

![UI Screenshot](https://github.com/AMOSFinds/secrets-scanner/blob/main/git1.PNG?raw=true)
![Scan Result](https://github.com/AMOSFinds/secrets-scanner/blob/main/git2.PNG?raw=true)

---

#  Overview

**Secrets Scanner** is a lightweight, pre-commit & CI-friendly tool for detecting leaked secrets in codebases.

 **Runs locally** — code never leaves your machine  
 **Instant pre-commit scanning**  
 **Self-hostable web UI (Docker / Render)**  
 **Optional Slack alerts**  
 **No cloud storage, no telemetry, no vendor lock-in**

Ideal for:

- solo developers  
- bootstrapped teams  
- privacy-critical teams  
- students learning AppSec  
- anyone who wants a *simple but powerful* secrets scanner  

---

#  What's New (v1.1.0 — Community Feedback Release)

Huge improvements driven by feedback from **/r/devsecops**, **/r/selfhosted**, and senior AppSec engineers.

###  **Generic JWT & Password Detection**
The scanner now detects:

- JWTs (`header.payload.signature`)
- generic API tokens
- accidental plaintext passwords
- suspicious `KEY=value` patterns
- high-entropy strings

> This closes the major gap highlighted by users who said most scanners “only detect provider-pattern secrets.”

###  **`.secrets-policy.json` — Configurable Rules**
New configuration file for org-level policies:

```json
{
  "ignore": { "paths": ["tests/**"], "patterns": ["DUMMY_KEY=.*"] },
  "forbid": { "patterns": ["AKIA[0-9A-Z]{16}"] },
  "severity_overrides": { "JWT": "HIGH" },
  "min_entropy": { "LOW": 3.5 }
}

Includes:

 -ignore rules
 -severity overrides
 -forbidden patterns
 -entropy tuning
 -whitelisted environment names

 Improved Baseline + SARIF Output

Perfect for CI workflows and GitHub Advanced Security integrations.

 Features

 -Local scanning — never uploads code anywhere

 -Fast async scanning (httpx + optimized file walker)

 -CLI, pre-commit hook, or web UI

 -Policy rules via .secrets-policy.json

 -High-entropy detection

 -OAuth GitHub login for private repos

 -Slack alerts for new leaks (optional)

 -Docker + Render deployment

 -SARIF export for CI and GitHub code scanning

 -Baseline support to suppress known findings

 Quick Start
1. Clone the repository
git clone https://github.com/AMOSFinds/secrets-scanner.git
cd secrets-scanner

2. Create .env
API_KEY=choose-any-random-secret
SESSION_SECRET=your-session-key
GITHUB_CLIENT_ID=your-id
GITHUB_CLIENT_SECRET=your-secret
GITHUB_OAUTH_REDIRECT_URL=https://yourdomain.com/auth/github/callback
SLACK_WEBHOOK_URL=optional-slack-url
GITHUB_PAT=your-personal-access-token


Never commit .env. Add it to .gitignore.

3. Run with Docker
docker build -t secrets-scanner .
docker run -p 8000:8000 --env-file .env secrets-scanner

4. Open the UI
http://127.0.0.1:8000/ui


Or your hosted Render URL.

 Pre-Commit Usage (Local-First)

Scan only staged files:

python -m app.cli --staged

Option A — Simple Git Hook

.git/hooks/pre-commit:

set -e
python -m app.cli --staged


Make executable:

chmod +x .git/hooks/pre-commit

Option B — Using pre-commit Framework

.pre-commit-config.yaml:

repos:
  - repo: local
    hooks:
      - id: secrets-scan
        name: secrets-scan
        entry: python -m app.cli --staged
        language: system
        pass_filenames: false


Install:

pre-commit install

 Configuration
.secrets-scanner.json

Used by CLI + Web UI:

{
  "ignore_patterns": ["node_modules/**", "*.lock"],
  "baseline": {}
}

.secrets-policy.json

For rule customization (new in v1.1):

{
  "ignore": { "patterns": ["DUMMY_KEY=.*"] },
  "forbid": { "patterns": ["AKIA[0-9A-Z]{16}"] },
  "severity_overrides": { "JWT": "HIGH" },
  "min_entropy": { "LOW": 3.5 },
  "allow_env_names": ["DUMMY_KEY"]
}

 Architecture

Backend: FastAPI

Frontend: Jinja2

Scanner Engine: Python + regex + entropy heuristics

HTTP: httpx async client

Storage: None (memory only)

Deployment: Docker / Render

 Privacy & Security

 -No logs stored
 -No code uploaded anywhere
 -GitHub tokens used only for temporary read access
 -All scans fully in memory
 -Self-host option for complete control

 Roadmap

-GitLab / Bitbucket support

-Inline ignore comments (# secrets-scan:ignore)

-CI dashboard

-Multi-repo scanning

-Custom rule definitions via YAML

-Browser extension for scanning pasted text

 Community Feedback

“A simple tool for solo devs and small teams who don’t want cloud dependence.”
— r/selfhosted user

“This fills the gap where GitHub’s push protection and pattern-based tools fall short.”
— Security engineer

“JWT detection + policy config is exactly what I wanted.”
— r/devsecops member

 Contributing

-PRs, ideas, and issue reports are welcome.

-Fork repo

-Create feature branch

-Commit changes

-Submit PR

 License

-MIT — free to use, modify, self-host, or integrate.

 Links

-Live Demo: https://secrets-scanner-jlw2.onrender.com/ui

-GitHub Repo: https://github.com/AMOSFinds/secrets-scanner

If this project helps you, please leave a ⭐ — it means a lot!

#  Secrets Scanner

Fast, open-source tool to detect API keys, credentials, and other secrets inside GitHub repositories — before they cause damage.

---

##  Overview

**Secrets Scanner** is a lightweight, self-hostable solution for finding leaked secrets in your codebase.  
Unlike heavy enterprise tools, it runs instantly, stores nothing, and can be deployed anywhere — including your own Render instance.

Built for developers, security engineers, and DevOps teams who want **visibility without complexity.**

---

##  Features

-  Scan any **public or private GitHub repository**
-  Detect API keys, tokens, passwords, and high-entropy strings
-  Asynchronous scanning for speed and scale
-  Optional **Slack alerts** for new leaks
-  No data storage — all scans run in memory
-  Easily deployable via Docker or Render
-  GitHub OAuth login for private repo access

---

##  Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/secrets-scanner.git
cd secrets-scanner

2. Create .env

Create a .env file in the project root using the example below:

API_KEY=choose-any-random-secret-key
SESSION_SECRET=another-secret-key
GITHUB_CLIENT_ID=your-oauth-id
GITHUB_CLIENT_SECRET=your-oauth-secret
GITHUB_OAUTH_REDIRECT_URL=https://yourdomain.com/auth/github/callback
SLACK_WEBHOOK_URL=your-slack-webhook-url
GITHUB_PAT=your-personal-access-token
Tip: Rename .env.example to .env and fill in your values.
Make sure .env is in your .gitignore file — never commit it.

3. Run with Docker
docker build -t secrets-scanner .
docker run -p 8000:8000 --env-file .env secrets-scanner

4. Open your browser

Visit:
http://127.0.0.1:8000/ui

Or your deployed URL (e.g. Render, Railway, etc.)

Self-Hosting (Render Example)

Connect this repo to Render

Choose New Web Service → Environment: Docker

Add your environment variables under Environment Variables

Click Deploy

Your app will be live within minutes 
Example demo: https://secrets-scanner-jlw2.onrender.com/ui

 Architecture

Backend: FastAPI (Python)

Frontend: Jinja2 templates

HTTP Client: httpx for async GitHub API requests

Alerts: Slack Webhook integration

Containerization: Docker for portability

 Privacy & Security

Secrets Scanner follows a privacy-first philosophy:

No logs or code content are stored.

GitHub tokens are used only for read-access and expire automatically.

Scans occur fully in memory and results are rendered directly to you.

Optional self-hosting ensures you control all data flow.

 API Endpoints
Method	Endpoint	Description
GET	/ui	Main web UI for scanning repositories
POST	/scan	JSON API for programmatic scans
POST	/scan.csv	Download scan results as CSV
POST	/webhook/github	GitHub webhook endpoint
GET	/auth/github/login	Start GitHub OAuth flow
GET	/auth/github/callback	Receive OAuth token
🧠 Roadmap

 GitLab and Bitbucket integration

 CLI mode for local scanning

 Pre-commit hook support

 Continuous Monitoring dashboard

 Multi-repo scanning support

 Advanced pattern configuration

❤️ Contributing

Pull requests, feature ideas, and issue reports are always welcome!

To contribute:

Fork this repo

Create a feature branch

Commit your changes

Submit a pull request 🎯

📜 License

MIT License — free to use, modify, and self-host for any purpose.
Please credit the project if you use it commercially.

🌐 Links

Demo: https://secrets-scanner-jlw2.onrender.com/ui

Docs: coming soon

Slack Alerts Setup Guide: /docs/slack.md (planned)

⭐ Support the Project

If you find this tool useful:

Give it a ⭐ on GitHub

Share feedback or ideas via issues

Contribute to the next release

Together we can make open-source security faster, simpler, and safer for everyone.

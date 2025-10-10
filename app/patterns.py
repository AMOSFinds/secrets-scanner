import re
from typing import Dict, Pattern


# Minimal initial set. Expand over time.
PATTERNS: Dict[str, Pattern] = {
"AWS_ACCESS_KEY_ID": re.compile(r"AKIA[0-9A-Z]{16}"),
"AWS_SECRET_ACCESS_KEY": re.compile(r"(?i)aws(.{0,20})?(secret|access)?.{0,3}['\"]([0-9a-zA-Z/+]{40})['\"]"),
"RSA_PRIVATE_KEY": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
"STRIPE_SECRET_KEY": re.compile(r"sk_(live|test)_[0-9a-zA-Z]{24,}"),
"SLACK_WEBHOOK": re.compile(r"https://hooks.slack.com/services/[A-Z0-9]{9,}/[A-Z0-9]{9,}/[a-zA-Z0-9]{24,}"),
"GENERIC_PASSWORD": re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?[^'\"\s]{8,}['\"]?"),
}


# File path hints to weight severity (reduce false positives)
SUSPECT_FILENAMES = [
"id_rsa", ".env", "credentials", "config.yml", "config.yaml", "settings.py", "secrets.yml", "secrets.yaml"
]


# Extensions likely to contain secrets
SUSPECT_EXTENSIONS = {".env", ".yml", ".yaml", ".json", ".ini", ".cfg", ".pem", ".key", ".txt", ".py", ".js", ".ts"}
from pydantic import BaseModel
from typing import List, Optional
import os


class ScanRequest(BaseModel):
    repo_url: str
    branch: str = "main"
    include_binary: bool = False
    github_token: Optional[str] = None
    # new knobs
    page: int = 1
    page_size: int = 100
    max_files: int = int(os.getenv("MAX_FILES", "2000")) if 'os' in globals() else 2000


class Finding(BaseModel):
    file_path: str
    line: int
    snippet: str
    pattern: str
    entropy: float
    severity: str
    recommendation: str


class ScanResult(BaseModel):
    repo_url: str
    findings: List[Finding]
    scanned_files: int
    total_findings: int
    page: int
    page_size: int
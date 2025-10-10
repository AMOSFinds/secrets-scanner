#!/usr/bin/env bash
export $(grep -v '^#' .env 2>/dev/null | xargs -I{} echo {})
uvicorn app.main:app --reload --port 8000
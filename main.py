
from datetime import datetime, timezone
from pathlib import Path
import uuid

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from engine import scan_url


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title="PhishingGuard",
    description="AI-Powered Phishing & Website Threat Intelligence",
    version="1.0.0"
)

app.mount(
    "/static",
    StaticFiles(directory=STATIC_DIR),
    name="static"
)


class ScanRequest(BaseModel):
    url: str


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "PhishingGuard",
        "version": "1.0.0",
        "engine": "CNN + URL Intelligence + Live Website Analysis"
    }


@app.post("/api/scan")
def api_scan(data: ScanRequest):

    try:
        result = scan_url(data.url)

        result["report_id"] = (
            "PG-" + uuid.uuid4().hex[:10].upper()
        )

        result["scan_time"] = datetime.now(
            timezone.utc
        ).isoformat()

        return result

    except Exception as exc:

        return JSONResponse(
            status_code=400,
            content={
                "error": "Analysis failed",
                "detail": str(exc)
            }
        )


@app.get("/")
def homepage():
    return FileResponse(
        STATIC_DIR / "index.html"
    )

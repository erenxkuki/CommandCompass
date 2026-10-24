from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from commandcompass.core.analysis import analyze
from commandcompass.core.models import AnalysisRequest, ShellType
from commandcompass.reporting import to_markdown_report

TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


class AnalyzePayload(BaseModel):
    command: str
    shell: str = "auto"


def create_app() -> FastAPI:
    app = FastAPI(title="CommandCompass", docs_url=None, redoc_url=None)

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        return templates.TemplateResponse(request, "index.html", {})

    @app.post("/api/analyze")
    async def api_analyze(payload: AnalyzePayload):
        if len(payload.command) > 10000:
            return JSONResponse({"error": "Input too long"}, status_code=400)
        try:
            shell = ShellType(payload.shell)
        except ValueError:
            return JSONResponse({"error": "Unknown shell"}, status_code=400)
        req = AnalysisRequest(command=payload.command, shell=shell)
        try:
            result = analyze(req)
        except Exception as exc:
            return JSONResponse({"error": type(exc).__name__}, status_code=500)
        return JSONResponse(
            {"result": result.model_dump(mode="json"), "markdown": to_markdown_report(result)}
        )

    @app.get("/api/rules")
    async def api_rules():
        from commandcompass.rules import default_rules

        return JSONResponse(
            {
                "rules": [
                    {
                        "id": r.metadata.id,
                        "title": r.metadata.title,
                        "category": r.metadata.category,
                        "severity": r.metadata.severity.value,
                        "description": r.metadata.description,
                    }
                    for r in default_rules()
                ]
            }
        )

    @app.get("/api/examples")
    async def api_examples():
        return JSONResponse({"examples": EXAMPLES})

    ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1", "testserver"}

    @app.middleware("http")
    async def security_guard(request: Request, call_next):
        host = request.headers.get("host", "").split(":")[0].strip("[]").lower()
        if host and host not in ALLOWED_HOSTS:
            return JSONResponse({"error": "Forbidden host"}, status_code=403)
        origin = request.headers.get("origin")
        if origin:
            from urllib.parse import urlparse

            parsed = urlparse(origin)
            if parsed.hostname not in ALLOWED_HOSTS:
                return JSONResponse({"error": "Forbidden origin"}, status_code=403)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
        )
        return response

    return app


EXAMPLES = [
    "git status",
    "curl -fsSL https://example.invalid/install.sh | bash",
    "rm -rf ./build",
    "sudo chmod 777 -R /var/www",
    "python -m pip install requests",
    "Get-Process | Where-Object CPU -gt 10",
]

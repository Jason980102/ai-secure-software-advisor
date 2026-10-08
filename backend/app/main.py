from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv

# Explicit project path works when started from either root or backend.
# Existing process environment variables take precedence over .env values.
load_dotenv(Path(__file__).resolve().parents[2] / '.env', override=False)

from app.api.scan import router as scan_router


app = FastAPI(
    title="AI Secure Software Advisor API",
    description=(
        "Backend API for dependency security analysis "
        "and vulnerability-aware recommendations."
    ),
    version="0.1.0",
)

app.include_router(scan_router)


@app.get("/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "service": "ai-secure-software-advisor",
    }

FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"
app.mount("/assets", StaticFiles(directory=FRONTEND_DIR), name="frontend-assets")

@app.get("/", include_in_schema=False)
def frontend_home():
    return FileResponse(FRONTEND_DIR / "index.html")

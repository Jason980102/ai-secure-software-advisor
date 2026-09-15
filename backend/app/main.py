from fastapi import FastAPI

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
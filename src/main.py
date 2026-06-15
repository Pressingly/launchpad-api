"""launchpad-api — FastAPI service for email collection and verification."""
from fastapi import FastAPI

app = FastAPI(title="launchpad-api", docs_url=None, redoc_url=None)


@app.get("/api/health")
async def health():
    return {"status": "ok"}

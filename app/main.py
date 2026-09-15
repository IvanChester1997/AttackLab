from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.routes import router
from app.database.db import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="AttackLab",
    description=(
        "Automated security assessment platform for authorized defensive "
        "security testing. Provides network discovery, service enumeration, "
        "vulnerability mapping, Linux security auditing, risk scoring, and "
        "JSON/HTML reporting."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)


app.include_router(router)


@app.get(
    "/",
    summary="AttackLab service status",
    description="Returns the basic runtime status of the AttackLab API.",
)
async def root():
    return {
        "project": "AttackLab",
        "status": "running",
    }


@app.get(
    "/health",
    summary="Health check",
    description="Returns HTTP 200 when the AttackLab API process is healthy.",
)
async def health():
    return {
        "status": "healthy",
    }


if __name__ == "__main__":
    from app.cli.main import app as cli_app

    cli_app()

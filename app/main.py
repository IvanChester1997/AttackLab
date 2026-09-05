from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.database.db import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="AttackLab",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/")
async def root():
    return {
        "project": "AttackLab",
        "status": "running",
    }


if __name__ == "__main__":
    from app.cli.main import app as cli_app

    cli_app()

"""Lantern backend entrypoint: FastAPI app serving the ingest + analyst API
and the static dashboard."""
from __future__ import annotations
import asyncio, os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

import db, engine
from config import config, start_watcher
from hub import hub
from api import router

DASHBOARD_DIR = os.path.join(os.path.dirname(__file__), "..", "dashboard")


async def _retention_loop():
    while True:
        await asyncio.sleep(3600)
        try:
            await asyncio.to_thread(engine.scrub_old)
        except Exception:
            pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.get_conn()
    hub.bind_loop(asyncio.get_running_loop())
    start_watcher(60)
    task = asyncio.create_task(_retention_loop())
    yield
    task.cancel()


app = FastAPI(title="Lantern", version="0.1.0", lifespan=lifespan)
app.include_router(router)


@app.get("/healthz")
async def healthz():
    return {"ok": True}


# Serve the dashboard at / (mounted last so it doesn't shadow the API routes).
if os.path.isdir(DASHBOARD_DIR):
    app.mount("/", StaticFiles(directory=DASHBOARD_DIR, html=True), name="dashboard")

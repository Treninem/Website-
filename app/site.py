from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from .db import init_db
from .main import app as api_app
from .bootstrap import router as bootstrap_router

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "web"

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="Website Portal", version="0.4.0", lifespan=lifespan)
app.include_router(api_app.router)
app.include_router(bootstrap_router)
app.mount("/static", StaticFiles(directory=WEB), name="static")

@app.get("/", include_in_schema=False)
def index():
    return FileResponse(WEB / "index.html")

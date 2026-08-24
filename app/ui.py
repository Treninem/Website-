from pathlib import Path
from fastapi import APIRouter
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

BASE = Path(__file__).resolve().parent.parent
WEB_DIR = BASE / "web"

router = APIRouter()

@router.get("/", include_in_schema=False)
def index():
    return FileResponse(WEB_DIR / "index.html")

def install_web(app):
    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")
    app.include_router(router)

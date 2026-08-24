from pathlib import Path
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from .main import app
from .bootstrap import router as bootstrap_router

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "web"

# The API and website deliberately share one ASGI application.
# This avoids maintaining two lifespans and keeps mobile/web clients on one backend.
app.include_router(bootstrap_router)
app.mount("/static", StaticFiles(directory=WEB), name="static")

@app.get("/", include_in_schema=False)
def index():
    return FileResponse(WEB / "index.html")

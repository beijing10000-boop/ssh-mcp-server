"""独立 Web 控制台 + Streamable HTTP MCP，同端口 9099。"""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
import secrets
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse

from . import store
from .api import router
from .auth import router as auth_router
from .mcp_tools import mcp

STATIC_DIR = Path(__file__).resolve().parent.parent / "web"

# Mounted child lifespan is not started automatically: the top-level lifespan owns it.
mcp_app = mcp.streamable_http_app()


@asynccontextmanager
async def lifespan(app: FastAPI):
    store.init_db()
    async with mcp.session_manager.run():
        yield


app = FastAPI(
    title="Linux 智能诊断 MCP 服务器",
    version="0.1.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.include_router(auth_router)
app.include_router(router)


@app.middleware("http")
async def secure_transport(request: Request, call_next):
    path = request.url.path
    if path == "/mcp" or path.startswith("/mcp/"):
        authorization = request.headers.get("authorization", "")
        expected = "Bearer " + store.token("mcp.token")
        if not secrets.compare_digest(authorization, expected):
            return JSONResponse({"detail": "MCP 服务令牌无效"}, status_code=401)
        origin = request.headers.get("origin")
        # Refuse cross-origin browser requests; non-browser MCP clients do not set Origin.
        if origin and urlsplit(origin).netloc != request.headers.get("host", ""):
            return JSONResponse({"detail": "跨站请求来源未经授权"}, status_code=403)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    return response


@app.get("/healthz")
def healthz():
    return {"ok": True, "version": "0.1.0", "service": "ssh-mcp-server"}


@app.get("/setup")
def setup_page():
    return FileResponse(STATIC_DIR / "setup.html", media_type="text/html",
        headers={"Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"})


@app.get("/static/setup.js")
def setup_script():
    return FileResponse(STATIC_DIR / "setup.js", media_type="application/javascript")


@app.get("/")
def homepage():
    return FileResponse(
        STATIC_DIR / "index.html", media_type="text/html",
        headers={"Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"},
    )


@app.get("/static/app.css")
def css():
    return FileResponse(STATIC_DIR / "app.css", media_type="text/css")


@app.get("/static/app.js")
def js():
    return FileResponse(STATIC_DIR / "app.js", media_type="application/javascript")


# Keep this final: Mount('/') matches every route after it.
app.mount("/", mcp_app)

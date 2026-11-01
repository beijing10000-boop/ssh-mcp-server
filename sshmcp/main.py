"""独立 Web 控制台 + Streamable HTTP MCP，同端口 9099。"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, suppress
from pathlib import Path
import sqlite3
import threading

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse

from . import __version__, store, access, jobs, console_api, zabbix, maintenance
from . import diagnostics
from .api import router
from .auth import router as auth_router, trusted_origin
from .mcp_tools import mcp

STATIC_DIR = Path(__file__).resolve().parent.parent / "web"

# Mounted child lifespan is not started automatically: the top-level lifespan owns it.
mcp_app = mcp.streamable_http_app()


class CallerWatch:
    """The MCP endpoint, watching for a client that leaves before its answer.

    In JSON-response mode the MCP SDK reads the request body and never looks
    at the connection again, so a client that gave up (closed the connection)
    kept its diagnostic waiting for, or holding, the host's slot. Once the
    body is read this wrapper waits for the disconnect; one before the
    response is sent sets the call's diagnostics.CALLER_GONE event, which the
    diagnostic checks while it waits for its slot and while it reads.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        gone = threading.Event()
        body_read = asyncio.Event()
        responded = False

        async def receive_body():
            message = await receive()
            if message["type"] == "http.request" and not message.get("more_body"):
                body_read.set()
            elif message["type"] == "http.disconnect":
                gone.set()
            return message

        async def send_response(message):
            nonlocal responded
            if message["type"] == "http.response.body" and not message.get("more_body"):
                responded = True
            await send(message)

        async def watch():
            await body_read.wait()
            with suppress(Exception):
                if (await receive())["type"] == "http.disconnect" and not responded:
                    gone.set()

        token = diagnostics.CALLER_GONE.set(gone)
        watcher = asyncio.create_task(watch())
        try:
            await self.app(scope, receive_body, send_response)
        finally:
            watcher.cancel()
            diagnostics.CALLER_GONE.reset(token)


@asynccontextmanager
async def lifespan(app: FastAPI):
    store.init_db()
    access.extend_client_actions()
    async with mcp.session_manager.run():
        task = asyncio.create_task(maintenance.periodic())
        try:
            yield
        finally:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task


app = FastAPI(
    title="Linux 智能诊断 MCP 服务器",
    version=__version__,
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.include_router(auth_router)
app.include_router(router)
app.include_router(access.router)
app.include_router(jobs.router)
app.include_router(console_api.router)
app.include_router(zabbix.router)
app.include_router(maintenance.router)


@app.middleware("http")
async def secure_transport(request: Request, call_next):
    path = request.url.path
    if path == "/mcp" or path.startswith("/mcp/"):
        authorization = request.headers.get("authorization", "")
        try:
            # SQLite (and the token file) off the event loop: a locked
            # database must not stall the Web console and the other clients.
            who = await asyncio.to_thread(access.authenticate, authorization)
        except HTTPException as exc:
            return JSONResponse(
                {"detail": exc.detail},
                status_code=exc.status_code,
                headers={"WWW-Authenticate": "Bearer"},
            )
        except sqlite3.OperationalError:
            return JSONResponse(
                {"detail": "服务繁忙，请稍后重试"},
                status_code=503,
                headers={"Retry-After": "2"},
            )
        # Refuse cross-origin browser requests; non-browser MCP clients do not set Origin.
        if not trusted_origin(request):
            return JSONResponse({"detail": "跨站请求来源未经授权"}, status_code=403)
        token = access.principal.set(who)
        try:
            response = await call_next(request)
        finally:
            access.principal.reset(token)
    else:
        response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    if path.startswith("/api/") or path.startswith("/mcp"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/healthz")
def healthz():
    return {"ok": True, "version": __version__, "service": "ssh-mcp-server"}


@app.get("/setup")
def setup_page():
    return FileResponse(
        STATIC_DIR / "setup.html",
        media_type="text/html",
        headers={
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        },
    )


@app.get("/")
def homepage():
    return FileResponse(
        STATIC_DIR / "index.html",
        media_type="text/html",
        headers={
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        },
    )


# Only these files are served; the HTML pages above carry their own CSP.
STATIC_FILES = {
    "ui-kit.css": "text/css",
    "app.css": "text/css",
    "ui-kit.js": "application/javascript",
    "inventory.js": "application/javascript",
    "presentation.js": "application/javascript",
    "interactions.js": "application/javascript",
    "app.js": "application/javascript",
    "setup.js": "application/javascript",
    "favicon.svg": "image/svg+xml",
}


@app.get("/static/{name}")
def static_file(name: str):
    if name not in STATIC_FILES:
        raise HTTPException(status_code=404)
    return FileResponse(STATIC_DIR / name, media_type=STATIC_FILES[name])


# Keep this final: Mount('/') matches every route after it.
app.mount("/", CallerWatch(mcp_app))

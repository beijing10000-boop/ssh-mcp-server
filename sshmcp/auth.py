"""一次性初始化 + 飞书 OAuth + HttpOnly session / CSRF。Web 不接受永久管理员 Token。"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
import time
from urllib.parse import urlencode, urlsplit

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from . import store

router = APIRouter(prefix="/api/v1")
log = logging.getLogger(__name__)
COOKIE = "ssh_mcp_web_session"
STATE_COOKIE = "ssh_mcp_oauth_state"
TTL = 8 * 3600
STATE_TTL = 300
OPEN_ID = re.compile(r"^ou_[A-Za-z0-9_-]{2,128}$")
APP_ID = re.compile(r"^cli_[A-Za-z0-9]{8,64}$")
SETUP_KEYS = (
    "web_protocol",
    "web_public_host",
    "lark_app_id",
    "lark_app_secret",
    "feishu_admin_open_ids",
)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def is_initialized() -> bool:
    return all(store.setting(key) for key in SETUP_KEYS)


def admins() -> set[str]:
    return {
        x.strip()
        for x in store.setting("feishu_admin_open_ids").split(",")
        if x.strip()
    }


def redirect_uri() -> str:
    protocol = store.setting("web_protocol")
    host = store.setting("web_public_host")
    if protocol not in {"http", "https"} or not host:
        raise HTTPException(503, "请先完成飞书登录初始化")
    parts = urlsplit(protocol + "://" + host)
    if (
        not parts.hostname
        or parts.username
        or parts.password
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
        or (parts.port is not None and not 1 <= parts.port <= 65535)
    ):
        raise HTTPException(503, "配置的 Web 外部地址格式不正确")
    return protocol + "://" + parts.netloc + "/api/v1/auth/callback"


def secure_cookie() -> bool:
    return store.setting("web_protocol") == "https"


def trusted_origin(request: Request) -> bool:
    origin = request.headers.get("origin")
    if not origin:
        return True
    try:
        value = urlsplit(origin)
        return (
            value.scheme == request.url.scheme
            and value.netloc == request.headers.get("host")
            and not value.username
            and not value.password
            and not value.path
            and not value.query
            and not value.fragment
        )
    except ValueError:
        return False


def authorize(request: Request) -> dict:
    if not is_initialized():
        raise HTTPException(503, "尚未初始化，请打开 /setup 完成飞书配置")
    raw = request.cookies.get(COOKIE, "")
    if not raw:
        raise HTTPException(401, "请先使用飞书账号登录")
    with store.db() as c:
        row = c.execute(
            "SELECT open_id,name,csrf,expires FROM web_sessions WHERE token_hash=?",
            (_hash(raw),),
        ).fetchone()
    if not row or row["expires"] <= int(time.time()) or row["open_id"] not in admins():
        raise HTTPException(401, "登录状态已失效或当前账号无管理员权限")
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        value = request.headers.get("X-CSRF-Token", "")
        if (
            not value
            or not value.isascii()
            or not hmac.compare_digest(row["csrf"], value)
        ):
            raise HTTPException(403, "操作校验失败（CSRF）：请刷新页面后重试")
        if not trusted_origin(request):
            raise HTTPException(403, "请求来源不受信任")
    return {
        "open_id": row["open_id"],
        "name": row["name"],
        "csrf": row["csrf"],
        "role": "super_admin",
        "permissions": ["*"],
    }


def admin(request: Request):
    return authorize(request)["open_id"]


class SetupRequest(BaseModel):
    bootstrap_token: str = Field(min_length=1, max_length=512)
    web_protocol: str
    web_public_host: str
    lark_app_id: str
    lark_app_secret: str
    feishu_admin_open_ids: str


@router.get("/setup/status")
def setup_status():
    return {"setup_required": not is_initialized()}


@router.post("/setup")
def setup(body: SetupRequest):
    if is_initialized():
        raise HTTPException(409, "初始化已完成，请使用飞书登录")
    expected = store.token("bootstrap.token")
    if not body.bootstrap_token.isascii() or not hmac.compare_digest(
        expected, body.bootstrap_token
    ):
        raise HTTPException(403, "一次性初始化凭据错误")
    if body.web_protocol not in {"http", "https"}:
        raise HTTPException(422, "访问协议只支持 http 或 https")
    raw = body.web_public_host.strip()
    parsed = urlsplit(body.web_protocol + "://" + raw)
    try:
        port = parsed.port
    except ValueError:
        raise HTTPException(422, "外部端口格式错误") from None
    if (
        any(c.isspace() for c in raw)
        or not parsed.hostname
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or port is not None
        and not 1 <= port <= 65535
    ):
        raise HTTPException(422, "Web 外部地址只能填写域名或 IP 及可选端口")
    if not APP_ID.fullmatch(body.lark_app_id):
        raise HTTPException(422, "飞书应用 App ID 格式不正确")
    if not 8 <= len(body.lark_app_secret) <= 512:
        raise HTTPException(422, "飞书应用 App Secret 长度不正确")
    ids = [x.strip() for x in body.feishu_admin_open_ids.split(",") if x.strip()]
    if not ids or len(ids) > 100 or any(not OPEN_ID.fullmatch(i) for i in ids):
        raise HTTPException(422, "管理员 Open ID 格式不正确")
    values = {
        "web_protocol": body.web_protocol,
        "web_public_host": parsed.netloc,
        "lark_app_id": body.lark_app_id,
        "lark_app_secret": body.lark_app_secret,
        "feishu_admin_open_ids": ",".join(dict.fromkeys(ids)),
    }
    # Serialize initial setup across concurrent requests and never overwrite a
    # configuration that was completed by another request.
    with store.db() as c:
        c.execute("BEGIN IMMEDIATE")
        configured = c.execute(
            "SELECT COUNT(*) FROM settings WHERE key IN ("
            + ",".join("?" for _ in SETUP_KEYS)
            + ") AND value!=''",
            SETUP_KEYS,
        ).fetchone()[0]
        if configured:
            raise HTTPException(409, "已有初始化配置，拒绝覆盖；请联系管理员")
        for key, value in values.items():
            c.execute(
                "INSERT INTO settings(key,value,encrypted) VALUES (?,?,?)",
                (
                    key,
                    store.seal(value) if key == "lark_app_secret" else value,
                    int(key == "lark_app_secret"),
                ),
            )
    store.audit("bootstrap", "initial_setup", "feishu_login", "success")
    return {"ok": True, "redirect": "/api/v1/auth/login"}


@router.get("/auth/login")
def feishu_login():
    if not is_initialized():
        return RedirectResponse("/setup", status_code=302)
    state = secrets.token_urlsafe(32)
    with store.db() as c:
        c.execute("DELETE FROM oauth_states WHERE expires < ?", (int(time.time()),))
        c.execute(
            "INSERT INTO oauth_states(state_hash,expires) VALUES (?,?)",
            (_hash(state), int(time.time()) + STATE_TTL),
        )
    response = RedirectResponse(
        "https://open.feishu.cn/open-apis/authen/v1/index?"
        + urlencode(
            {
                "app_id": store.setting("lark_app_id"),
                "redirect_uri": redirect_uri(),
                "state": state,
            }
        ),
        status_code=302,
    )
    response.set_cookie(
        STATE_COOKIE,
        state,
        max_age=STATE_TTL,
        httponly=True,
        secure=secure_cookie(),
        samesite="lax",
        path="/api/v1/auth",
    )
    return response


async def exchange_profile(code: str) -> dict:
    """Only the application server talks to Feishu; never expose the app secret to JS."""
    app_id, app_secret = store.setting("lark_app_id"), store.setting("lark_app_secret")
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            first = await client.post(
                "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal",
                json={"app_id": app_id, "app_secret": app_secret},
            )
            first.raise_for_status()
            data = first.json()
            if data.get("code") != 0:
                raise ValueError("app token rejected")
            second = await client.post(
                "https://open.feishu.cn/open-apis/authen/v1/access_token",
                headers={"Authorization": "Bearer " + data["app_access_token"]},
                json={"grant_type": "authorization_code", "code": code},
            )
            second.raise_for_status()
            data = second.json()
            if data.get("code") != 0:
                raise ValueError("auth code rejected")
            token = data["data"]["access_token"]
            third = await client.get(
                "https://open.feishu.cn/open-apis/authen/v1/user_info",
                headers={"Authorization": "Bearer " + token},
            )
            third.raise_for_status()
            data = third.json()
            if data.get("code") != 0:
                raise ValueError("profile rejected")
            return data["data"]
    except Exception as exc:
        log.warning("FEISHU_OAUTH_FAILED type=%s", type(exc).__name__)
        raise HTTPException(
            502, "飞书登录验证失败，请核对应用权限、密钥和回调地址"
        ) from None


@router.get("/auth/callback")
async def feishu_callback(request: Request, code: str = "", state: str = ""):
    cookie_state = request.cookies.get(STATE_COOKIE, "")
    if (
        not state
        or not state.isascii()
        or not cookie_state
        or not cookie_state.isascii()
        or not code
        or not hmac.compare_digest(state, cookie_state)
    ):
        raise HTTPException(403, "飞书登录状态校验失败，请重新登录")
    with store.db() as c:
        c.execute("BEGIN IMMEDIATE")
        found = c.execute(
            "SELECT expires FROM oauth_states WHERE state_hash=?", (_hash(state),)
        ).fetchone()
        c.execute("DELETE FROM oauth_states WHERE state_hash=?", (_hash(state),))
        if not found or found["expires"] <= int(time.time()):
            raise HTTPException(403, "授权已经过期或使用过")
    profile = await exchange_profile(code)
    open_id = profile.get("open_id", "")
    if not open_id or open_id not in admins():
        log.warning("FEISHU_LOGIN_DENIED open_id_hash=%s", _hash(open_id)[:10])
        store.audit("oauth", "feishu_login", _hash(open_id)[:10], "denied")
        raise HTTPException(403, "当前飞书账号不是指定管理员")
    session = secrets.token_urlsafe(48)
    csrf = secrets.token_urlsafe(32)
    with store.db() as c:
        c.execute("DELETE FROM web_sessions WHERE expires < ?", (int(time.time()),))
        c.execute(
            "INSERT INTO web_sessions(token_hash,open_id,name,csrf,expires) VALUES (?,?,?,?,?)",
            (
                _hash(session),
                open_id,
                str(profile.get("name") or "管理员")[:100],
                csrf,
                int(time.time()) + TTL,
            ),
        )
    store.audit(_hash(open_id)[:12], "feishu_login", "web", "success")
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        COOKIE,
        session,
        max_age=TTL,
        httponly=True,
        secure=secure_cookie(),
        samesite="lax",
        path="/",
    )
    response.delete_cookie(STATE_COOKIE, path="/api/v1/auth")
    return response


@router.get("/auth/me")
def me(request: Request):
    return authorize(request)


@router.post("/auth/logout")
def logout(request: Request):
    actor = authorize(request)
    raw = request.cookies.get(COOKIE, "")
    with store.db() as c:
        c.execute("DELETE FROM web_sessions WHERE token_hash=?", (_hash(raw),))
    store.audit(_hash(actor["open_id"])[:12], "feishu_logout", "web", "success")
    response = JSONResponse({"ok": True})
    response.delete_cookie(COOKIE, path="/")
    return response


class AdminsUpdate(BaseModel):
    open_ids: str = Field(min_length=1, max_length=8192)


@router.get("/settings/feishu")
def feishu_settings(request: Request):
    authorize(request)
    return {
        "web_protocol": store.setting("web_protocol"),
        "web_public_host": store.setting("web_public_host"),
        "lark_app_id": store.setting("lark_app_id"),
        "feishu_admin_open_ids": store.setting("feishu_admin_open_ids"),
        "lark_app_secret_configured": bool(store.setting("lark_app_secret")),
    }


@router.put("/settings/admins")
def update_admins(body: AdminsUpdate, request: Request):
    identity = authorize(request)
    ids = [x.strip() for x in body.open_ids.split(",") if x.strip()]
    if not ids or len(ids) > 100 or any(not OPEN_ID.fullmatch(i) for i in ids):
        raise HTTPException(422, "管理员 Open ID 无效")
    if identity["open_id"] not in ids:
        raise HTTPException(422, "不能从授权列表中移除当前登录的管理员")
    store.save_settings({"feishu_admin_open_ids": ",".join(dict.fromkeys(ids))})
    store.audit(
        _hash(identity["open_id"])[:12], "admin_list_updated", "feishu", "success"
    )
    return {"ok": True}

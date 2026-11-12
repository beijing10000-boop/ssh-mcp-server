"""Named, expiring MCP credentials. Raw tokens are returned exactly once."""

from contextvars import ContextVar
import hashlib
import json
import logging
import secrets
import sqlite3
import threading
import time
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt

from . import store
from .auth import admin
from .catalog import RECOMMENDED, TITLES, entries

router = APIRouter(prefix="/api/v1")
log = logging.getLogger(__name__)
principal = ContextVar("mcp_principal", default=None)
# mcp_clients.last_used_at only informs the console: it is written at most
# once a minute per client, waiting at most a second for a locked database
# (and then skipped), so authenticating an MCP request is a read.
LAST_USED_INTERVAL = 60
LAST_USED_WAIT = 1
_last_used = {}
_last_used_lock = threading.Lock()


def legacy_enabled():
    return store.setting("legacy_mcp_enabled") != "false"


def authenticate(authorization):
    if not authorization.startswith("Bearer ") or len(authorization) > 512:
        raise HTTPException(401, "MCP 接入令牌无效")
    raw = authorization[7:]
    if not raw.isascii():
        raise HTTPException(401, "MCP 接入令牌无效")
    if legacy_enabled() and secrets.compare_digest(raw, store.token("mcp.token")):
        return {
            "id": "legacy",
            "name": "原始 MCP 令牌",
            "all_hosts": True,
            "group_ids": [],
            "actions": list(TITLES),
        }
    digest = hashlib.sha256(raw.encode()).hexdigest()
    with store.db() as c:
        row = c.execute(
            "SELECT * FROM mcp_clients WHERE token_hash=? AND enabled=1 AND expires_at>?",
            (digest, int(time.time())),
        ).fetchone()
    if not row:
        raise HTTPException(401, "MCP 令牌无效、已过期或已撤销")
    _touch(row["id"])
    data = dict(row)
    data.pop("token_hash")
    data["actions"] = json.loads(data["actions"])
    data["group_ids"] = json.loads(data["group_ids"])
    return data


def _touch(client_id):
    """Record the client's last use, throttled and best effort."""
    now = time.monotonic()
    with _last_used_lock:
        last = _last_used.get(client_id)
        if last is not None and now - last < LAST_USED_INTERVAL:
            return
        _last_used[client_id] = now
    try:
        with store.db(timeout=LAST_USED_WAIT) as c:
            c.execute(
                "UPDATE mcp_clients SET last_used_at=CURRENT_TIMESTAMP WHERE id=?",
                (client_id,),
            )
    except sqlite3.OperationalError as exc:
        # A long write (VACUUM, a large job batch) holds the database: the
        # request goes on, the next interval writes the time.
        log.debug("last_used_at of %s not written: %s", client_id, exc)


def identity():
    value = principal.get()
    if not value:
        raise PermissionError("缺少授权的 MCP 会话")
    return value


def host_allowed(host_id):
    who = identity()
    return bool(
        who["all_hosts"] or set(store.groups_for(host_id)) & set(who["group_ids"])
    )


def enforce(host_id, action):
    who = identity()
    if action not in who["actions"] or not host_allowed(host_id):
        raise PermissionError("该 MCP 客户端无权访问此主机或诊断动作")
    return "mcp:" + who["id"]


class ClientIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=80)
    all_hosts: StrictBool = False
    group_ids: list[StrictInt] = Field(default_factory=list, max_length=100)
    actions: list[str] = Field(min_length=1, max_length=100)
    valid_days: StrictInt = Field(default=90, ge=1, le=365)


class ClientUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    actions: list[str] = Field(min_length=1, max_length=100)
    all_hosts: StrictBool | None = None
    group_ids: list[StrictInt] | None = Field(default=None, max_length=100)


class LegacyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: StrictBool


# Implied extension actions and the already-granted actions that imply them.
# A client allowed to read service logs may read system/Nginx logs and Java
# command lines too; `jvm` attaches to a JVM and is granted explicitly only.
# A later release adds its own implied actions here.
EXTENDS = {
    "nginx": ("logs",),
    "nginx_access": ("logs",),
    "syslog": ("logs", "log_errors"),
    "java": ("logs",),
    "service_detail": ("logs",),
    "service_map": ("sockets", "service"),
}
# mcp_clients.actions_extended records, per action, the implied actions a
# client has been considered for, so each is granted at most once and one an
# administrator removes is never granted again: "" (none), a JSON list of
# action ids, or EXTENDS_RELEASE for exactly the v0.6.0 set. That set keeps
# the old single marker, which a release before per-action records reads too.
EXTENDS_RELEASE = "v0.6.0"
EXTENDS_V060 = frozenset(
    ("nginx", "nginx_access", "syslog", "java", "service_detail", "service_map")
)


def _considered(marker):
    """Implied actions a stored actions_extended value already covers."""
    if marker == EXTENDS_RELEASE:
        return set(EXTENDS_V060)
    try:
        value = json.loads(marker or "[]")
    except ValueError:
        value = None
    if not isinstance(value, list):
        # A marker this release cannot read never widens a client's scope.
        return set(EXTENDS)
    return {action for action in value if isinstance(action, str)}


def _marker(considered):
    if considered == EXTENDS_V060:
        return EXTENDS_RELEASE
    return json.dumps(sorted(considered))


def extend_client_actions():
    """Grant implied extension actions to each client once, with an audit row.

    Every enabled client is marked with each implied action it was considered
    for, whether or not anything was added, so actions an administrator later
    removes or leaves out stay that way across restarts and later releases;
    an action added to EXTENDS later is considered once on its own. Clients
    extended before the marker existed are recognised by the audit row
    written at the time.
    """
    changed = []
    with store.db() as c:
        c.execute("BEGIN IMMEDIATE")
        c.execute(
            "UPDATE mcp_clients SET actions_extended=? WHERE actions_extended='' "
            "AND id IN (SELECT target FROM audit WHERE actor='platform' "
            "AND action='mcp_client_actions_extended' AND detail LIKE ?)",
            (EXTENDS_RELEASE, EXTENDS_RELEASE + ":%"),
        )
        for row in c.execute(
            "SELECT id,actions,actions_extended FROM mcp_clients WHERE enabled=1"
        ).fetchall():
            considered = _considered(row["actions_extended"])
            pending = set(EXTENDS) - considered
            if not pending:
                continue
            actions = json.loads(row["actions"])
            added = sorted(
                action
                for action in pending
                if action in TITLES
                and action not in actions
                and any(parent in actions for parent in EXTENDS[action])
            )
            c.execute(
                "UPDATE mcp_clients SET actions=?,actions_extended=? WHERE id=?",
                (
                    json.dumps(sorted(set(actions) | set(added))),
                    _marker(considered | pending),
                    row["id"],
                ),
            )
            if added:
                changed.append((row["id"], added))
    for ident, added in changed:
        store.audit(
            "platform",
            "mcp_client_actions_extended",
            ident,
            "success",
            EXTENDS_RELEASE + ":" + ",".join(added),
        )
    return changed


def _require_groups(c, group_ids):
    known = {r[0] for r in c.execute("SELECT id FROM groups")}
    if set(group_ids) - known:
        raise HTTPException(422, "授权主机组不存在")


@router.get("/tools")
def tools(actor=Depends(admin)):
    # `recommended` drives 「按 AI Ops Platform 推荐勾选」 in the console.
    return [{**entry, "recommended": entry["id"] in RECOMMENDED} for entry in entries()]


@router.get("/mcp/clients")
def clients(actor=Depends(admin)):
    with store.db() as c:
        rows = c.execute(
            "SELECT id,name,prefix,all_hosts,group_ids,actions,expires_at,enabled,created_at,last_used_at "
            "FROM mcp_clients ORDER BY created_at DESC,rowid DESC"
        ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["group_ids"] = json.loads(item["group_ids"])
        item["actions"] = json.loads(item["actions"])
        item["expired"] = item["expires_at"] <= int(time.time())
        result.append(item)
    return {"items": result, "legacy_enabled": legacy_enabled()}


@router.post("/mcp/clients", status_code=201)
def create(body: ClientIn, actor=Depends(admin)):
    if not body.name.strip() or set(body.actions) - TITLES.keys():
        raise HTTPException(422, "客户端名称或工具范围无效")
    if not body.all_hosts and not body.group_ids:
        raise HTTPException(422, "请选择授权主机组，或明确勾选全部主机")
    raw = "sshmcp_" + secrets.token_urlsafe(36)
    ident = uuid.uuid4().hex
    with store.db() as c:
        c.execute("BEGIN IMMEDIATE")
        _require_groups(c, body.group_ids)
        if c.execute(
            "SELECT 1 FROM mcp_clients WHERE name=?", (body.name.strip(),)
        ).fetchone():
            raise HTTPException(409, "客户端名称已经存在")
        # A new client's actions are what the administrator picked from the full
        # current list, so the startup extension never applies to it.
        c.execute(
            "INSERT INTO mcp_clients(id,name,token_hash,prefix,group_ids,actions,all_hosts,expires_at,actions_extended) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (
                ident,
                body.name.strip(),
                hashlib.sha256(raw.encode()).hexdigest(),
                raw[:14],
                json.dumps(sorted(set(body.group_ids))),
                json.dumps(sorted(set(body.actions))),
                int(body.all_hosts),
                int(time.time()) + body.valid_days * 86400,
                _marker(set(EXTENDS)),
            ),
        )
    store.audit(actor, "mcp_client_create", ident, "success")
    return {
        "id": ident,
        "token": raw,
        "note": "令牌仅显示一次，请保存到 AI 平台的加密配置中",
    }


@router.put("/mcp/clients/{client_id}")
def update(client_id: str, body: ClientUpdate, actor=Depends(admin)):
    """Change a client's actions or host scope; the token itself never changes."""
    if set(body.actions) - TITLES.keys():
        raise HTTPException(422, "工具范围无效")
    with store.db() as c:
        c.execute("BEGIN IMMEDIATE")
        row = c.execute(
            "SELECT all_hosts,group_ids FROM mcp_clients WHERE id=? AND enabled=1",
            (client_id,),
        ).fetchone()
        if not row:
            raise HTTPException(404, "MCP 客户端不存在或已撤销")
        all_hosts = row["all_hosts"] if body.all_hosts is None else int(body.all_hosts)
        if body.group_ids is None:
            # Keep the saved scope minus groups deleted since: group ids are never
            # reused (AUTOINCREMENT), so a deleted id matches no host and dropping
            # it narrows nothing. Explicitly given ids are still checked below.
            known = {r[0] for r in c.execute("SELECT id FROM groups")}
            group_ids = [g for g in json.loads(row["group_ids"]) if g in known]
        else:
            group_ids = body.group_ids
        if not all_hosts and not group_ids:
            raise HTTPException(422, "请选择授权主机组，或明确勾选全部主机")
        _require_groups(c, group_ids)
        c.execute(
            "UPDATE mcp_clients SET actions=?,all_hosts=?,group_ids=? WHERE id=?",
            (
                json.dumps(sorted(set(body.actions))),
                all_hosts,
                json.dumps(sorted(set(group_ids))),
                client_id,
            ),
        )
    store.audit(
        actor,
        "mcp_client_update",
        client_id,
        "success",
        "actions=" + str(len(set(body.actions))),
    )
    return {"ok": True}


@router.post("/mcp/clients/{client_id}/revoke")
def revoke(client_id: str, actor=Depends(admin)):
    with store.db() as c:
        if not c.execute(
            "UPDATE mcp_clients SET enabled=0 WHERE id=?", (client_id,)
        ).rowcount:
            raise HTTPException(404, "MCP 客户端不存在")
    store.audit(actor, "mcp_client_revoke", client_id, "success")
    return {"ok": True}


class RotateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    valid_days: StrictInt = Field(default=90, ge=1, le=365)


@router.post("/mcp/clients/{client_id}/rotate")
def rotate(client_id: str, body: RotateIn | None = None, actor=Depends(admin)):
    """A new token for the same client (for one that was lost, or leaked):
    its name, actions and host scope stay, the old token stops working at
    once and the validity starts over. A revoked client gets none."""
    days = (body or RotateIn()).valid_days
    raw = "sshmcp_" + secrets.token_urlsafe(36)
    with store.db() as c:
        c.execute("BEGIN IMMEDIATE")
        row = c.execute(
            "SELECT name FROM mcp_clients WHERE id=? AND enabled=1", (client_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "MCP 客户端不存在或已撤销")
        # last_used_at starts over too: it then says whether the new token is in use.
        c.execute(
            "UPDATE mcp_clients SET token_hash=?,prefix=?,expires_at=?,last_used_at=NULL WHERE id=?",
            (
                hashlib.sha256(raw.encode()).hexdigest(),
                raw[:14],
                int(time.time()) + days * 86400,
                client_id,
            ),
        )
    with _last_used_lock:
        _last_used.pop(client_id, None)
    store.audit(actor, "mcp_client_rotate", client_id, "success", "name=" + row["name"])
    return {
        "id": client_id,
        "token": raw,
        "note": "令牌仅显示一次，旧令牌已失效，请更新到使用它的系统中",
    }


@router.delete("/mcp/clients/{client_id}")
def delete(client_id: str, actor=Depends(admin)):
    """Remove a client that can no longer be used (revoked or expired), which
    frees its name; one that still works must be revoked first. Its jobs and
    audit rows stay (they name it by id; the delete row keeps its name)."""
    with store.db() as c:
        c.execute("BEGIN IMMEDIATE")
        row = c.execute(
            "SELECT name,enabled,expires_at FROM mcp_clients WHERE id=?", (client_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "MCP 客户端不存在")
        if row["enabled"] and row["expires_at"] > int(time.time()):
            raise HTTPException(409, "客户端仍然有效：请先撤销，再删除")
        c.execute("DELETE FROM mcp_clients WHERE id=?", (client_id,))
    with _last_used_lock:
        _last_used.pop(client_id, None)
    store.audit(actor, "mcp_client_delete", client_id, "success", "name=" + row["name"])
    return {"ok": True}


@router.put("/settings/mcp-legacy")
def legacy(body: LegacyIn, actor=Depends(admin)):
    store.save_settings({"legacy_mcp_enabled": "true" if body.enabled else "false"})
    store.audit(
        actor, "legacy_mcp_token", "enabled" if body.enabled else "disabled", "success"
    )
    return {"ok": True}

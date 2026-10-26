"""Zabbix MCP inventory discovery: bounded ID catalogue, adaptive detail batches.

Zabbix host.get has no offset. Never simulate pagination by increasing limit.
Discovery writes an encrypted preview; registration is a separate atomic action.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from datetime import timedelta
import hashlib
import ipaddress
import json
import re
import time
from urllib.parse import urlsplit
import uuid

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from mcp import ClientSession
from mcp.client.sse import sse_client
from mcp.client.streamable_http import streamablehttp_client
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt

from . import store
from .auth import admin, admins

router = APIRouter(prefix="/api/v1/zabbix")
POOL = ThreadPoolExecutor(max_workers=1, thread_name_prefix="zabbix-discovery")
INDEX_LIMIT = 1000  # <= ~25 KiB for hostid-only responses; overflow fails closed.
MAX_HOSTS = 10000


class SyncError(ValueError):
    pass


class ResponseTooLarge(SyncError):
    pass


class RetryableError(SyncError):
    pass


class ConfigIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(min_length=8, max_length=500)
    token: str | None = Field(default=None, max_length=512)
    server: str = Field(default="", max_length=80)
    transport: str = "http"
    verify_tls: StrictBool = True
    batch_size: StrictInt = Field(default=20, ge=1, le=100)
    interval_ms: StrictInt = Field(default=400, ge=200, le=5000)


class DiscoverIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    group_ids: list[str] = Field(min_length=1, max_length=100)
    asset_types: list[str] = Field(
        default_factory=lambda: ["linux"], min_length=1, max_length=4
    )
    monitored_only: StrictBool = True


class RegisterIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hostids: list[str] | None = Field(default=None, min_length=1, max_length=1000)
    username: str = Field(default="ai-diagnostic", min_length=1, max_length=32)
    port: StrictInt = Field(default=22, ge=1, le=65535)
    credential_id: StrictInt | None = Field(default=None, ge=1)
    proxy_id: StrictInt | None = Field(default=None, ge=1)
    adopt_existing: StrictBool = False


def config():
    raw = store.setting("zabbix_mcp_config")
    return json.loads(raw) if raw else None


def source_key(cfg):
    return hashlib.sha256(
        (cfg["url"].rstrip("/") + "|" + cfg["server"]).encode()
    ).hexdigest()


def validate_config(body):
    value = body.model_dump()
    value["url"] = value["url"].strip()
    value["server"] = value["server"].strip()
    url = urlsplit(value["url"])
    if (
        url.scheme not in {"http", "https"}
        or not url.hostname
        or url.username
        or url.password
        or url.query
        or url.fragment
        or any(ch.isspace() for ch in value["url"])
    ):
        raise SyncError(
            "请填写 HTTP/HTTPS MCP 地址，认证令牌单独填写；地址不能包含密码、查询或片段"
        )
    try:
        address = ipaddress.ip_address(url.hostname)
    except ValueError:
        address = None
    if address and (
        address.is_link_local or address.is_multicast or address.is_unspecified
    ):
        raise SyncError("MCP 地址不能使用链路本地、元数据或组播地址")
    try:
        url.port
    except ValueError:
        raise SyncError("MCP 端口无效") from None
    if value["transport"] not in {"http", "sse"}:
        raise SyncError("请选择 Streamable HTTP 或 SSE")
    old = config()
    if value["token"] is None:
        value["token"] = old["token"] if old else ""
    if any(ch.isspace() for ch in value["token"]) or not value["token"].isascii():
        raise SyncError("令牌不能包含空白或非 ASCII 字符；请勿填写 Bearer 前缀")
    if old and source_key(old) != source_key(value):
        with store.db() as c:
            bound = c.execute(
                "SELECT 1 FROM hosts WHERE zabbix_hostid IS NOT NULL AND zabbix_hostid!='' LIMIT 1"
            ).fetchone()
        if bound:
            raise SyncError(
                "已有 Zabbix Host ID 关联，不能切换到其他源；请先核对并解除原映射"
            )
    return value


def public_config(cfg):
    return (
        {
            **{k: v for k, v in cfg.items() if k != "token"},
            "has_token": bool(cfg["token"]),
        }
        if cfg
        else None
    )


def decode_result(result):
    """Accept MCP structured and text JSON. Reject truncation/error envelopes."""
    texts = [b.text for b in result.content if b.type == "text"]
    if result.isError:
        message = " ".join(texts).lower()
        if any(x in message for x in ("truncat", "too large", "response_max", "截断")):
            raise ResponseTooLarge("MCP 响应超限")
        if any(
            x in message for x in ("rate limit", "too many requests", "429", "限流")
        ):
            raise RetryableError("Zabbix MCP 限流，请稍后重试或提高请求间隔")
        raise SyncError("Zabbix MCP 工具拒绝请求；请检查只读权限、工具范围和参数兼容性")
    data = result.structuredContent
    if data is None:
        data = "\n".join(texts)
    for _ in range(6):
        if isinstance(data, str):
            # initMAX wraps text JSON in a single security notice line; never
            # interpret this external text as instructions or enable raw_json.
            if data.startswith("[System: The following is raw data from Zabbix."):
                first, _, data = data.partition("\n")
                if len(first) > 2048 or not first.endswith("]"):
                    raise SyncError("MCP 数据声明格式无效")
            try:
                data = json.loads(data)
            except (ValueError, TypeError):
                raise ResponseTooLarge("MCP 响应不是完整 JSON，可能已被截断") from None
        if isinstance(data, list) and any(
            isinstance(r, dict) and (r.get("_truncated") or r.get("truncated"))
            for r in data
        ):
            raise ResponseTooLarge("MCP 列表已截断")
        if not isinstance(data, dict):
            return data
        if data.get("truncated") or data.get("_truncated") or data.get("has_more"):
            raise ResponseTooLarge("MCP 响应已截断")
        if data.get("error") or data.get("status") in {"error", "failed"}:
            raise SyncError("Zabbix MCP 返回错误；请检查上游访问权限和工具参数")
        wrapper = next((k for k in ("result", "data", "results") if k in data), None)
        if wrapper:
            data = data[wrapper]
        else:
            return data
    raise SyncError("无法识别 MCP 响应结构")


class Gateway:
    def __init__(self, session, cfg):
        self.session, self.cfg = session, cfg
        self.tools = {}
        self.last_call = 0

    async def initialize(self):
        cursor = None
        for _ in range(20):
            result = await self.session.list_tools(cursor=cursor)
            self.tools.update({t.name: t.inputSchema for t in result.tools})
            if not result.nextCursor:
                break
            if result.nextCursor == cursor:
                raise SyncError("MCP 工具列表游标未前进")
            cursor = result.nextCursor
        else:
            raise SyncError("MCP 工具列表超过安全页数")
        if not {"host_get", "hostgroup_get"} <= self.tools.keys():
            raise SyncError(
                "未找到 host_get / hostgroup_get，请在 Zabbix MCP 中授权这两个只读工具"
            )

    def arguments(self, name, native):
        schema = self.tools[name]
        props = schema.get("properties", {})
        if "params" in props and "output" not in props:
            result = {"params": native}
        else:
            result, extra = {}, {}
            for key, value in native.items():
                if key in props:
                    if key in {"output", "sortfield"} and isinstance(value, list):
                        spec = json.dumps(props[key])
                        if '"array"' not in spec:
                            value = ",".join(value)
                    result[key] = value
                else:
                    extra[key] = value
            if extra:
                if "extra_params" not in props:
                    raise SyncError(
                        "上游工具不支持所需原生参数，请升级兼容 initMAX 的 Zabbix MCP"
                    )
                result["extra_params"] = extra
        if self.cfg["server"]:
            if "server" not in props:
                raise SyncError(
                    "此 Zabbix MCP 不支持指定 server，请清空服务器名称或升级"
                )
            result["server"] = self.cfg["server"]
        return result

    async def get(self, name, native):
        for attempt in range(3):
            delay = self.cfg["interval_ms"] / 1000 - (time.monotonic() - self.last_call)
            if delay > 0:
                await asyncio.sleep(delay)
            self.last_call = time.monotonic()
            try:
                return decode_result(
                    await self.session.call_tool(name, self.arguments(name, native))
                )
            except (RetryableError, httpx.TimeoutException):
                if attempt == 2:
                    raise SyncError(
                        "Zabbix MCP 持续限流或超时，请提高请求间隔后重试"
                    ) from None
                await asyncio.sleep(2**attempt)

    async def index(self, name, params, field):
        count = await self.get(name, {**params, "countOutput": True})
        if isinstance(count, bool) or not str(count).isdigit():
            raise SyncError("上游未返回可靠的资产数量，已停止发现")
        count = int(count)
        if count > INDEX_LIMIT:
            raise SyncError(
                f"单个主机组包含 {count} 项，超过精简索引上限 {INDEX_LIMIT}；请在 Zabbix 细分主机组后分组拉取"
            )
        if not count:
            return []
        rows = await self.get(
            name, {**params, "output": [field], "limit": INDEX_LIMIT + 1}
        )
        if not isinstance(rows, list) or any(
            not isinstance(r, dict)
            or not re.fullmatch(r"[0-9]{1,32}", str(r.get(field, "")))
            for r in rows
        ):
            raise SyncError("上游返回的 ID 索引格式无效")
        ids = [str(r[field]) for r in rows]
        if len(ids) != count or len(set(ids)) != count:
            raise SyncError(
                "ID 索引数量与计数不一致，可能截断或资产发生变化；请缩小主机组并重新拉取"
            )
        return ids

    async def details(self, ids, name="host_get", field="hostid", selections=None):
        params = {
            "hostids" if field == "hostid" else "groupids": ids,
            "output": ["hostid", "host", "name", "status"]
            if field == "hostid"
            else ["groupid", "name"],
            "limit": len(ids),
            **(selections or {}),
        }
        try:
            rows = await self.get(name, params)
            if (
                not isinstance(rows, list)
                or {str(r.get(field)) for r in rows if isinstance(r, dict)} != set(ids)
                or len(rows) != len(ids)
            ):
                raise ResponseTooLarge("返回详情不完整或资产在同步期间发生变化")
            return rows
        except ResponseTooLarge:
            if len(ids) == 1:
                raise SyncError(
                    "单台资产详情仍不完整；请提高 Zabbix MCP 响应上限，或检查资产是否已被删除"
                ) from None
            middle = len(ids) // 2
            return await self.details(
                ids[:middle], name, field, selections
            ) + await self.details(ids[middle:], name, field, selections)


@asynccontextmanager
async def gateway(cfg):
    def factory(headers=None, timeout=None, auth=None):
        return httpx.AsyncClient(
            headers=headers,
            timeout=timeout or 25,
            auth=auth,
            verify=cfg["verify_tls"],
            follow_redirects=False,
            trust_env=False,
        )

    transport = sse_client if cfg["transport"] == "sse" else streamablehttp_client
    async with transport(
        cfg["url"],
        headers={"Authorization": "Bearer " + cfg["token"]} if cfg["token"] else {},
        timeout=25,
        sse_read_timeout=30,
        httpx_client_factory=factory,
    ) as streams:
        async with ClientSession(
            streams[0], streams[1], read_timeout_seconds=timedelta(seconds=30)
        ) as session:
            await session.initialize()
            client = Gateway(session, cfg)
            await client.initialize()
            yield client


async def fetch_groups(client):
    ids = await client.index("hostgroup_get", {}, "groupid")
    rows = []
    for start in range(0, len(ids), client.cfg["batch_size"]):
        rows.extend(
            await client.details(
                ids[start : start + client.cfg["batch_size"]],
                "hostgroup_get",
                "groupid",
            )
        )
    return sorted(rows, key=lambda r: r["name"])


def classify(raw):
    groups = raw.get("hostgroups", raw.get("groups", []))
    text = " ".join(
        str(r.get("name", "")) for r in groups + raw.get("parentTemplates", [])
    )
    inventory = raw.get("inventory") or {}
    if isinstance(inventory, dict):
        text += " " + str(inventory.get("os", ""))
    for tag in raw.get("tags", []):
        if str(tag.get("tag", "")).lower() in {
            "os",
            "os_type",
            "operating_system",
            "type",
        }:
            text += " " + str(tag.get("value", ""))
    if re.search(r"windows", text, re.I):
        return "windows"
    if re.search(r"linux|rocky|centos|ubuntu|debian|red\s?hat|almalinux", text, re.I):
        return "linux"
    if any(str(r.get("type")) == "2" for r in raw.get("interfaces", [])):
        return "network"
    return "other"


def normalize(raw, types):
    ident = str(raw.get("hostid", ""))
    if not re.fullmatch(r"[0-9]{1,32}", ident):
        raise SyncError("Host ID 格式无效")
    groups = [
        {"groupid": str(g["groupid"]), "name": str(g["name"])}
        for g in raw.get("hostgroups", raw.get("groups", []))
    ]
    asset_type = classify(raw)
    address, issue = "", ""
    # An agent/SNMP port (10050/161) must never become the SSH port.
    interfaces = sorted(
        raw.get("interfaces", []),
        key=lambda r: (str(r.get("type")) != "1", str(r.get("main")) != "1"),
    )
    if interfaces:
        interface = interfaces[0]
        if str(interface.get("useip", "1")) != "1":
            issue = "Zabbix 使用 DNS 接口，请先登记并核对内网 IP"
        else:
            try:
                address = store.private_ip(str(interface.get("ip", "")))
            except ValueError:
                issue = "没有有效的内网 IP，请在 Zabbix 补充接口或手工登记"
    else:
        issue = "没有主机接口（可能仅主动 Agent），请在 Zabbix 补充 IP 或手工登记"
    if asset_type not in types:
        issue = (
            "不在本次选择的资产类型中"
            if asset_type != "other"
            else "无法确认操作系统，请补充 Linux 主机组、模板、标签或资产清单"
        )
    if (
        not groups
        or len(groups) > 50
        or any(
            not re.fullmatch(r"[0-9]{1,32}", g["groupid"])
            or not g["name"].strip()
            or len(g["name"]) > 80
            for g in groups
        )
    ):
        issue = "主机组数据缺失或超出本地限制，请检查 Zabbix 权限与分组"
    return {
        "hostid": ident,
        "name": str(raw.get("name") or raw.get("host") or ident)[:160],
        "address": address,
        "asset_type": asset_type,
        "monitored": str(raw.get("status", "0")) == "0",
        "groups": groups,
        "issue": issue,
    }


def check_actor(actor):
    if actor not in admins():
        raise SyncError("操作员已失去管理员权限")


def run_discovery(ident, cfg, options, actor):
    async def run():
        with store.db() as c:
            c.execute(
                "UPDATE zabbix_sync_runs SET status='running' WHERE id=?", (ident,)
            )
        async with gateway(cfg) as client:
            known = {str(g["groupid"]) for g in await fetch_groups(client)}
            if set(options["group_ids"]) - known:
                raise SyncError("部分主机组已删除或无权读取，请重新获取分组")
            ids = set()
            for group in options["group_ids"]:
                check_actor(actor)
                ids.update(
                    await client.index(
                        "host_get",
                        {
                            "groupids": [group],
                            **(
                                {"filter": {"status": "0"}}
                                if options["monitored_only"]
                                else {}
                            ),
                        },
                        "hostid",
                    )
                )
                if len(ids) > MAX_HOSTS:
                    raise SyncError("本次发现超过 10000 台，请按主机组拆分任务")
            ids = sorted(ids, key=int)
            with store.db() as c:
                c.execute(
                    "UPDATE zabbix_sync_runs SET total=? WHERE id=?", (len(ids), ident)
                )
            for start in range(0, len(ids), cfg["batch_size"]):
                check_actor(actor)
                rows = await client.details(
                    ids[start : start + cfg["batch_size"]],
                    selections={
                        "selectInterfaces": ["type", "main", "useip", "ip"],
                        "selectHostGroups": ["groupid", "name"],
                        "selectParentTemplates": ["name"],
                        "selectInventory": ["os"],
                        "selectTags": ["tag", "value"],
                    },
                )
                with store.db() as c:
                    for row in rows:
                        item = normalize(row, options["asset_types"])
                        match, _ = existing(c, item)
                        item["local_id"] = match["id"] if match else None
                        item["local_revision"] = match["revision"] if match else None
                        c.execute(
                            "INSERT INTO zabbix_sync_items(run_id,hostid,data) VALUES (?,?,?)",
                            (
                                ident,
                                item["hostid"],
                                store.seal(json.dumps(item, ensure_ascii=False)),
                            ),
                        )
                    c.execute(
                        "UPDATE zabbix_sync_runs SET completed=completed+? WHERE id=?",
                        (len(rows), ident),
                    )
        with store.db() as c:
            c.execute(
                "UPDATE zabbix_sync_runs SET status='preview',completed_at=CURRENT_TIMESTAMP WHERE id=?",
                (ident,),
            )

    try:
        asyncio.run(run())
        store.audit(actor, "zabbix_discover", ident, "success")
    except Exception as exc:
        # Never serialize arbitrary upstream exceptions (URLs/tokens can be embedded).
        error = (
            str(exc)[:240]
            if isinstance(exc, SyncError)
            else "连接或协议异常，请使用连接测试检查 MCP 地址、令牌和网络（"
            + type(exc).__name__
            + "）"
        )
        with store.db() as c:
            c.execute(
                "UPDATE zabbix_sync_runs SET status='failed',error=?,completed_at=CURRENT_TIMESTAMP WHERE id=?",
                (error, ident),
            )
        store.audit(actor, "zabbix_discover", ident, "failed", type(exc).__name__)


@router.get("/config")
def get_config(actor=Depends(admin)):
    return {"config": public_config(config())}


@router.put("/config")
def save_config(body: ConfigIn, actor=Depends(admin)):
    try:
        cfg = validate_config(body)
        with store.db() as c:
            c.execute("BEGIN IMMEDIATE")
            if c.execute(
                "SELECT 1 FROM zabbix_sync_runs WHERE status IN ('queued','running')"
            ).fetchone():
                raise HTTPException(409, "资产发现正在运行，完成后再修改连接")
            c.execute(
                "INSERT INTO settings(key,value,encrypted) VALUES ('zabbix_mcp_config',?,1) ON CONFLICT(key) DO UPDATE SET value=excluded.value,encrypted=1",
                (store.seal(json.dumps(cfg)),),
            )
        store.audit(actor, "zabbix_config", "mcp", "success")
        return {"config": public_config(cfg)}
    except SyncError as exc:
        raise HTTPException(422, str(exc)) from None


@router.post("/test")
async def test_config(actor=Depends(admin)):
    cfg = config()
    if not cfg:
        raise HTTPException(422, "请先保存 Zabbix MCP 连接")
    try:
        async with gateway(cfg) as client:
            groups = await fetch_groups(client)
            # Exercise host_get too, so tool presence alone cannot pass validation.
            count = await client.get("host_get", {"countOutput": True})
            if not str(count).isdigit():
                raise SyncError("主机数量响应无效")
        return {
            "ok": True,
            "groups": groups,
            "host_count": int(count),
            "note": "MCP 握手、主机组读取和主机计数均已通过",
        }
    except Exception as exc:
        message = (
            str(exc)
            if isinstance(exc, SyncError)
            else "连接测试失败，请检查 MCP 地址、令牌、证书和工具权限"
        )
        raise HTTPException(422, message) from None


@router.post("/groups")
async def get_groups(actor=Depends(admin)):
    cfg = config()
    if not cfg:
        raise HTTPException(422, "请先保存 Zabbix MCP 连接")
    try:
        async with gateway(cfg) as client:
            return {"items": await fetch_groups(client)}
    except Exception as exc:
        raise HTTPException(
            422,
            str(exc) if isinstance(exc, SyncError) else "获取主机组失败，请先测试连接",
        ) from None


@router.post("/runs", status_code=202)
def discover(body: DiscoverIn, actor=Depends(admin)):
    cfg = config()
    if not cfg:
        raise HTTPException(422, "请先保存 Zabbix MCP 连接")
    if any(not re.fullmatch(r"[0-9]{1,32}", g) for g in body.group_ids) or set(
        body.asset_types
    ) - {"linux", "windows", "network", "other"}:
        raise HTTPException(422, "分组 ID 或资产类型无效")
    ident = uuid.uuid4().hex
    with store.db() as c:
        c.execute("BEGIN IMMEDIATE")
        if c.execute(
            "SELECT 1 FROM zabbix_sync_runs WHERE status IN ('queued','running')"
        ).fetchone():
            raise HTTPException(409, "已有资产发现任务运行中，请等待完成")
        c.execute(
            "INSERT INTO zabbix_sync_runs(id,actor,status,source,options) VALUES (?,?,'queued',?,?)",
            (ident, actor, source_key(cfg), json.dumps(body.model_dump())),
        )
    try:
        POOL.submit(run_discovery, ident, cfg, body.model_dump(), actor)
    except RuntimeError:
        with store.db() as c:
            c.execute(
                "UPDATE zabbix_sync_runs SET status='failed',error='服务正在停止，请稍后重试',completed_at=CURRENT_TIMESTAMP WHERE id=?",
                (ident,),
            )
        raise HTTPException(503, "服务正在停止，请稍后重试") from None
    return {"id": ident}


@router.get("/runs")
def list_runs(actor=Depends(admin)):
    with store.db() as c:
        return {
            "items": [
                dict(r)
                for r in c.execute(
                    "SELECT id,status,total,completed,error,created_at,completed_at FROM zabbix_sync_runs ORDER BY created_at DESC,rowid DESC LIMIT 20"
                )
            ]
        }


def run_row(c, ident):
    row = c.execute("SELECT * FROM zabbix_sync_runs WHERE id=?", (ident,)).fetchone()
    if not row:
        raise HTTPException(404, "资产发现任务不存在")
    return dict(row)


def existing(c, item):
    rows = c.execute(
        "SELECT * FROM hosts WHERE zabbix_hostid=? OR address=?",
        (item["hostid"], item["address"]),
    ).fetchall()
    if len(rows) > 1:
        return None, "Host ID 与 IP 分别关联了不同资产，请先处理冲突"
    row = dict(rows[0]) if rows else None
    if row and row["zabbix_hostid"] and row["zabbix_hostid"] != item["hostid"]:
        return None, "IP 已关联其他 Zabbix Host ID，请核对资产"
    return row, ""


@router.get("/runs/{ident}")
def preview(ident: str, page: int = Query(1, ge=1), actor=Depends(admin)):
    with store.db() as c:
        run = run_row(c, ident)
        total = c.execute(
            "SELECT COUNT(*) FROM zabbix_sync_items WHERE run_id=?", (ident,)
        ).fetchone()[0]
        rows = c.execute(
            "SELECT * FROM zabbix_sync_items WHERE run_id=? ORDER BY length(hostid),hostid LIMIT 25 OFFSET ?",
            (ident, (page - 1) * 25),
        ).fetchall()
        items = []
        for row in rows:
            item = json.loads(store.unseal(row["data"]))
            match, conflict = existing(c, item)
            item.update(
                outcome=row["outcome"],
                host_id=row["host_id"],
                plan="skip"
                if item["issue"]
                else "conflict"
                if conflict
                else "adopt"
                if match and not match["zabbix_hostid"]
                else "update"
                if match
                else "create",
                conflict=conflict,
            )
            items.append(item)
    return {"run": run, "items": items, "total": total, "page": page, "page_size": 25}


def sync_groups(c, host_id, groups):
    wanted = set()
    for group in groups:
        row = c.execute(
            "SELECT group_id FROM zabbix_groups WHERE zabbix_groupid=?",
            (group["groupid"],),
        ).fetchone()
        gid = row[0] if row else None
        name = group["name"]
        for attempt in range(1000):
            collision = c.execute(
                "SELECT id FROM groups WHERE name=?", (name,)
            ).fetchone()
            if not collision or collision[0] == gid:
                break
            suffix = (
                " · Zabbix " + group["groupid"] + (f"-{attempt}" if attempt else "")
            )
            name = group["name"][: 80 - len(suffix)] + suffix
        else:
            raise SyncError("无法分配唯一的 Zabbix 主机组名称，请先处理重名组")
        if gid:
            c.execute("UPDATE groups SET name=? WHERE id=?", (name, gid))
        else:
            gid = c.execute("INSERT INTO groups(name) VALUES (?)", (name,)).lastrowid
            c.execute("INSERT INTO zabbix_groups VALUES (?,?)", (group["groupid"], gid))
        wanted.add(gid)
    previous = {
        r[0]
        for r in c.execute(
            "SELECT group_id FROM zabbix_memberships WHERE host_id=?", (host_id,)
        )
    }
    for gid in previous - wanted:
        c.execute(
            "DELETE FROM host_groups WHERE host_id=? AND group_id=?", (host_id, gid)
        )
        c.execute(
            "DELETE FROM zabbix_memberships WHERE host_id=? AND group_id=?",
            (host_id, gid),
        )
    for gid in wanted:
        c.execute("INSERT OR IGNORE INTO host_groups VALUES (?,?)", (host_id, gid))
        c.execute(
            "INSERT OR IGNORE INTO zabbix_memberships VALUES (?,?)", (host_id, gid)
        )


@router.post("/runs/{ident}/register")
def register(ident: str, body: RegisterIn, actor=Depends(admin)):
    try:
        username = store.username(body.username)
        with store.db() as c:
            c.execute("BEGIN IMMEDIATE")
            run = run_row(c, ident)
            if c.execute(
                "SELECT 1 FROM zabbix_sync_runs WHERE id=? AND created_at<datetime('now','-30 minutes')",
                (ident,),
            ).fetchone():
                raise SyncError("预览已超过 30 分钟，请重新拉取当前资产后登记")
            if run["status"] not in {"preview", "registered"}:
                raise SyncError("只能登记完整发现成功的预览，请重新拉取失败任务")
            if run["source"] != source_key(config() or {"url": "", "server": ""}):
                raise SyncError("Zabbix 连接已变更，请重新发现资产")
            if (
                body.credential_id
                and not c.execute(
                    "SELECT 1 FROM credentials WHERE id=?", (body.credential_id,)
                ).fetchone()
            ):
                raise SyncError("SSH 凭据不存在")
            if (
                body.proxy_id
                and not c.execute(
                    "SELECT 1 FROM proxies WHERE id=?", (body.proxy_id,)
                ).fetchone()
            ):
                raise SyncError("SSH 跳板不存在")
            rows = c.execute(
                "SELECT * FROM zabbix_sync_items WHERE run_id=?", (ident,)
            ).fetchall()
            wanted = (
                set(body.hostids)
                if body.hostids is not None
                else {r["hostid"] for r in rows}
            )
            if wanted - {r["hostid"] for r in rows}:
                raise SyncError("所选 Host ID 不属于此预览")
            changed, skipped, issues = [], 0, []
            for row in rows:
                if row["hostid"] not in wanted:
                    continue
                if row["outcome"] == "registered":
                    skipped += 1
                    continue
                item = json.loads(store.unseal(row["data"]))
                match, conflict = existing(c, item)
                if match and (
                    match["id"] != item.get("local_id")
                    or match["revision"] != item.get("local_revision")
                ):
                    conflict = "资产在预览后已被修改，请重新拉取后登记"
                if (
                    item["issue"]
                    or conflict
                    or (
                        match and not match["zabbix_hostid"] and not body.adopt_existing
                    )
                ):
                    issues.append(
                        {
                            "hostid": item["hostid"],
                            "reason": item["issue"]
                            or conflict
                            or "同 IP 的手工资产需要勾选关联已有资产",
                        }
                    )
                    continue
                if match:
                    host_id = match["id"]
                    # Security settings/credentials are never overwritten on re-import.
                    moved = match["address"] != item["address"]
                    c.execute(
                        "UPDATE hosts SET name=?,address=?,zabbix_hostid=?,asset_type=?,enabled=CASE WHEN ?='linux' THEN enabled ELSE 0 END,host_key=CASE WHEN ? THEN '' ELSE host_key END,last_status=CASE WHEN ? THEN 'untested' ELSE last_status END,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                        (
                            item["name"],
                            item["address"],
                            item["hostid"],
                            item["asset_type"],
                            item["asset_type"],
                            moved,
                            moved,
                            host_id,
                        ),
                    )
                    if moved:
                        c.execute(
                            "DELETE FROM host_key_candidates WHERE host_id=?",
                            (host_id,),
                        )
                else:
                    host_id = c.execute(
                        "INSERT INTO hosts(name,address,port,username,credential_id,proxy_id,zabbix_hostid,asset_type,enabled) VALUES (?,?,?,?,?,?,?,?,?)",
                        (
                            item["name"],
                            item["address"],
                            body.port,
                            username,
                            body.credential_id,
                            body.proxy_id,
                            item["hostid"],
                            item["asset_type"],
                            int(
                                item["asset_type"] == "linux"
                                and item.get("monitored", True)
                            ),
                        ),
                    ).lastrowid
                sync_groups(c, host_id, item["groups"])
                c.execute(
                    "UPDATE zabbix_sync_items SET outcome='registered',host_id=? WHERE run_id=? AND hostid=?",
                    (host_id, ident, item["hostid"]),
                )
                changed.append(host_id)
                if len(changed) >= 1000:
                    break
            remaining = c.execute(
                "SELECT COUNT(*) FROM zabbix_sync_items WHERE run_id=? AND outcome='pending'",
                (ident,),
            ).fetchone()[0]
            c.execute(
                "UPDATE zabbix_sync_runs SET status='registered' WHERE id=?", (ident,)
            )
        store.audit(
            actor,
            "zabbix_register",
            ident,
            "success",
            f"registered={len(changed)};skipped={skipped};issues={len(issues)}",
        )
        return {
            "host_ids": changed,
            "registered": len(changed),
            "skipped": skipped,
            "issues": issues,
            "remaining": remaining,
        }
    except (ValueError, SyncError) as exc:
        raise HTTPException(422, str(exc)) from None

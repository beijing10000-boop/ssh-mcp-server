"""中文管理 API：资产、凭据、跳板、分组、批量公钥、只读诊断和审计。"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import re
import secrets

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field

from . import store, diagnostics

router = APIRouter(prefix="/api/v1")
SCAN_WORKERS = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ssh-key-batches")


def admin(authorization: str | None = Header(default=None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "请先输入管理员访问令牌")
    if not secrets.compare_digest(authorization[7:], store.token("admin.token")):
        raise HTTPException(401, "管理员令牌无效")
    return "admin"


def fail(exc: Exception):
    if isinstance(exc, ValueError):
        raise HTTPException(422, str(exc)[:240]) from None
    raise HTTPException(500, "服务器处理失败：" + type(exc).__name__) from None


class CredentialIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    private_key: str = Field(min_length=64, max_length=16000)
    passphrase: str = Field(default="", max_length=200)


class HostIn(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    address: str
    port: int = Field(default=22, ge=1, le=65535)
    username: str = "ai-diagnostic"
    host_key: str = ""
    credential_id: int | None = None
    proxy_id: int | None = None
    zabbix_hostid: str | None = None
    enabled: bool = True
    mode: str = "standard"
    gateway_approved: bool = False
    group_ids: list[int] = Field(default_factory=list, max_length=50)


class ProxyIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    address: str
    port: int = Field(default=22, ge=1, le=65535)
    username: str
    host_key: str
    credential_id: int = Field(ge=1)


class GroupIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)


class ScanIn(BaseModel):
    host_ids: list[int] = Field(min_length=1, max_length=1000)


class ConfirmIn(BaseModel):
    host_id: int
    independently_verified_sha256: str
    confirmed: bool


class RunIn(BaseModel):
    action: str
    service: str | None = None
    minutes: int = Field(default=30, ge=1, le=120)


def safe_host_input(item: HostIn) -> dict:
    x = item.model_dump()
    x["address"] = store.private_ip(x["address"])
    x["username"] = store.username(x["username"])
    x["host_key"] = store.validate_hostkey(x["host_key"], optional=True)
    if x["zabbix_hostid"] and not re.fullmatch(r"[0-9]{1,32}", x["zabbix_hostid"]):
        raise ValueError("Zabbix Host ID 必须是数字字符串")
    if x["mode"] not in {"standard", "gateway"}:
        raise ValueError("未知诊断模式")
    if x["mode"] == "gateway" and not x["gateway_approved"]:
        raise ValueError("受限网关模式必须经管理员审核目标强制命令配置")
    return x


def _host_view(row) -> dict:
    v = dict(row)
    v["has_host_key"] = bool(v.pop("host_key"))
    if v["has_host_key"]:
        with store.db() as c:
            r = c.execute("SELECT host_key FROM hosts WHERE id=?", (v["id"],)).fetchone()
        v["host_fingerprint"] = diagnostics.host_fingerprint(r["host_key"])
    else:
        v["host_fingerprint"] = None
    v["group_ids"] = store.groups_for(v["id"])
    return v


@router.get("/auth/check")
def check_auth(actor=Depends(admin)):
    return {"ok": True, "role": actor}


@router.get("/overview")
def overview(actor=Depends(admin)):
    with store.db() as c:
        hosts = c.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
        ready = c.execute("SELECT COUNT(*) FROM hosts WHERE host_key!='' AND enabled=1").fetchone()[0]
        groups = c.execute("SELECT COUNT(*) FROM groups").fetchone()[0]
        failed = c.execute("SELECT COUNT(*) FROM audit WHERE outcome='failed'").fetchone()[0]
    return {"hosts": hosts, "ready": ready, "groups": groups, "failed_actions": failed, "version": "0.1.0"}


@router.get("/hosts")
def hosts(actor=Depends(admin)):
    with store.db() as c:
        rows = c.execute("SELECT * FROM hosts ORDER BY id DESC LIMIT 2000").fetchall()
    return [_host_view(x) for x in rows]


@router.post("/hosts", status_code=201)
def host_create(body: HostIn, actor=Depends(admin)):
    try:
        item = safe_host_input(body)
        gids = item.pop("group_ids")
        with store.db() as c:
            cols = ",".join(item)
            ids = ",".join("?" for _ in item)
            cur = c.execute("INSERT INTO hosts(" + cols + ") VALUES (" + ids + ")", list(item.values()))
            hid = cur.lastrowid
            for gid in set(gids):
                c.execute("INSERT INTO host_groups(host_id,group_id) VALUES (?,?)", (hid, gid))
        store.audit(actor, "host_create", str(hid), "success")
        return {"id": hid}
    except Exception as exc:
        fail(exc)


@router.put("/hosts/{host_id}")
def host_update(host_id: int, body: HostIn, actor=Depends(admin)):
    try:
        item = safe_host_input(body)
        gids = item.pop("group_ids")
        with store.db() as c:
            columns = ",".join(k + "=?" for k in item)
            cur = c.execute(
                "UPDATE hosts SET " + columns + ",last_status='untested',updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (*item.values(), host_id),
            )
            if cur.rowcount != 1:
                raise ValueError("主机不存在")
            c.execute("DELETE FROM host_groups WHERE host_id=?", (host_id,))
            for gid in set(gids):
                c.execute("INSERT INTO host_groups(host_id,group_id) VALUES (?,?)", (host_id, gid))
            c.execute("DELETE FROM host_key_candidates WHERE host_id=?", (host_id,))
        store.audit(actor, "host_update", str(host_id), "success")
        return {"id": host_id}
    except Exception as exc:
        fail(exc)


@router.post("/hosts/{host_id}/disable")
def disable_host(host_id: int, actor=Depends(admin)):
    with store.db() as c:
        updated = c.execute("UPDATE hosts SET enabled=0,last_status='untested' WHERE id=?", (host_id,))
        if not updated.rowcount:
            raise HTTPException(404, "未找到主机")
    store.audit(actor, "host_disable", str(host_id), "success")
    return {"ok": True}


@router.get("/groups")
def groups(actor=Depends(admin)):
    with store.db() as c:
        return [dict(r) for r in c.execute("SELECT * FROM groups ORDER BY name")]


@router.post("/groups", status_code=201)
def group_create(body: GroupIn, actor=Depends(admin)):
    try:
        with store.db() as c:
            id = c.execute("INSERT INTO groups(name) VALUES (?)", (body.name.strip(),)).lastrowid
        store.audit(actor, "group_create", str(id), "success")
        return {"id": id}
    except Exception as exc:
        fail(exc)


@router.get("/credentials")
def credential_list(actor=Depends(admin)):
    with store.db() as c:
        return [dict(r) for r in c.execute("SELECT id,name,created_at FROM credentials ORDER BY name")]


@router.post("/credentials", status_code=201)
def credential_add(body: CredentialIn, actor=Depends(admin)):
    try:
        blob = json.dumps({"private_key": body.private_key, "passphrase": body.passphrase})
        # Validate the key before persistence; never return the submitted private material.
        parsed = None
        import io
        import paramiko
        for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
            try:
                parsed = cls.from_private_key(io.StringIO(body.private_key), password=body.passphrase or None)
                break
            except (paramiko.SSHException, ValueError, TypeError):
                continue
        if parsed is None:
            raise ValueError("私钥无法解析或口令错误")
        with store.db() as c:
            id = c.execute(
                "INSERT INTO credentials(name,secret) VALUES (?,?)",
                (body.name.strip(), store.seal(blob)),
            ).lastrowid
        store.audit(actor, "credential_add", str(id), "success")
        return {"id": id}
    except Exception as exc:
        fail(exc)


@router.put("/credentials/{credential_id}")
def credential_rotate(credential_id: int, body: CredentialIn, actor=Depends(admin)):
    # The new key must be valid before any old credential is replaced.
    import io
    import paramiko
    ok = False
    for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            cls.from_private_key(io.StringIO(body.private_key), password=body.passphrase or None)
            ok = True
            break
        except (paramiko.SSHException, ValueError, TypeError):
            pass
    if not ok:
        raise HTTPException(422, "SSH 私钥无效")
    with store.db() as c:
        changed = c.execute(
            "UPDATE credentials SET name=?,secret=? WHERE id=?",
            (body.name.strip(), store.seal(json.dumps(body.model_dump())), credential_id),
        )
        if not changed.rowcount:
            raise HTTPException(404, "未找到凭据")
        c.execute("UPDATE hosts SET last_status='untested' WHERE credential_id=?", (credential_id,))
    store.audit(actor, "credential_rotate", str(credential_id), "success")
    return {"ok": True}


@router.get("/proxies")
def proxies(actor=Depends(admin)):
    with store.db() as c:
        return [dict(r) for r in c.execute("SELECT * FROM proxies ORDER BY name")]


@router.post("/proxies", status_code=201)
def proxy_add(body: ProxyIn, actor=Depends(admin)):
    try:
        item = body.model_dump()
        item["address"] = store.private_ip(item["address"])
        item["username"] = store.username(item["username"])
        item["host_key"] = store.validate_hostkey(item["host_key"])
        with store.db() as c:
            id = c.execute(
                "INSERT INTO proxies(name,address,port,username,host_key,credential_id) "
                "VALUES (?,?,?,?,?,?)", tuple(item.values())
            ).lastrowid
        store.audit(actor, "proxy_add", str(id), "success")
        return {"id": id}
    except Exception as exc:
        fail(exc)


@router.post("/hosts/{host_id}/test")
def host_test(host_id: int, actor=Depends(admin)):
    return _execute(host_id, "connection", None, 30, actor)


@router.post("/hosts/{host_id}/diagnose")
def host_diagnose(host_id: int, body: RunIn, actor=Depends(admin)):
    return _execute(host_id, body.action, body.service, body.minutes, actor)


def _execute(host_id, action, service, minutes, actor):
    try:
        result = diagnostics.execute(host_id, action, service, minutes)
        with store.db() as c:
            if action == "connection":
                c.execute("UPDATE hosts SET last_status=? WHERE id=?", (result["status"], host_id))
        store.audit(actor, action, str(host_id), result["status"], "exit=" + str(result["exit_code"]))
        return result
    except Exception as exc:
        error = str(exc) if isinstance(exc, (ValueError, diagnostics.SSHDiagnosticError)) else type(exc).__name__
        with store.db() as c:
            if action == "connection":
                c.execute("UPDATE hosts SET last_status='failed' WHERE id=?", (host_id,))
        store.audit(actor, action, str(host_id), "failed", type(exc).__name__)
        raise HTTPException(422, error[:240]) from None


def _scan_batch(batch_id: str, ids: list[int]):
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="host-key") as pool:
        futures = {pool.submit(diagnostics.scan_host_key, hid): hid for hid in ids}
        for future in as_completed(futures):
            hid = futures[future]
            try:
                value = future.result()
            except Exception as exc:
                value = {"state": "failed", "error": type(exc).__name__}
            with store.db() as c:
                c.execute(
                    "INSERT OR REPLACE INTO scan_results(batch_id,host_id,status,fingerprint,error) VALUES (?,?,?,?,?)",
                    (batch_id, hid, value.get("state", "failed"), value.get("fingerprint"), value.get("error")),
                )
                c.execute("UPDATE scan_batches SET completed=completed+1 WHERE id=?", (batch_id,))
    with store.db() as c:
        c.execute("UPDATE scan_batches SET status='finished' WHERE id=?", (batch_id,))


@router.post("/host-keys/scan", status_code=202)
def scan_keys(body: ScanIn, actor=Depends(admin)):
    ids = list(dict.fromkeys(body.host_ids))
    with store.db() as c:
        actual = c.execute(
            "SELECT COUNT(*) FROM hosts WHERE id IN (" + ",".join("?" for _ in ids) + ") AND enabled=1", ids
        ).fetchone()[0]
    if actual != len(ids):
        raise HTTPException(422, "批次包含不存在或已禁用的主机")
    batch_id = secrets.token_hex(12)
    with store.db() as c:
        c.execute("INSERT INTO scan_batches(id,status,total) VALUES (?,?,?)", (batch_id, "running", len(ids)))
    SCAN_WORKERS.submit(_scan_batch, batch_id, ids)
    store.audit(actor, "host_keys_scan", batch_id, "started", "count=" + str(len(ids)))
    return {"batch_id": batch_id, "total": len(ids)}


@router.get("/host-keys/batches")
def batches(actor=Depends(admin)):
    with store.db() as c:
        return [dict(r) for r in c.execute("SELECT * FROM scan_batches ORDER BY created_at DESC LIMIT 30")]


@router.get("/host-keys/batches/{batch_id}")
def batch_detail(batch_id: str, actor=Depends(admin)):
    with store.db() as c:
        batch = c.execute("SELECT * FROM scan_batches WHERE id=?", (batch_id,)).fetchone()
        if not batch:
            raise HTTPException(404, "批次不存在")
        rows = c.execute(
            "SELECT r.*, h.name,h.address FROM scan_results r "
            "LEFT JOIN hosts h ON h.id=r.host_id WHERE batch_id=? ORDER BY host_id", (batch_id,)
        ).fetchall()
    return {"batch": dict(batch), "items": [dict(r) for r in rows]}


@router.post("/host-keys/confirm")
def confirm_key(body: ConfirmIn, actor=Depends(admin)):
    if not body.confirmed:
        raise HTTPException(422, "必须由管理员在可信渠道核验后确认")
    with store.db() as c:
        row = c.execute(
            "SELECT key,fingerprint FROM host_key_candidates WHERE host_id=?", (body.host_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "没有待确认主机公钥")
        if not secrets.compare_digest(row["fingerprint"], body.independently_verified_sha256.strip()):
            raise HTTPException(422, "核验指纹与候选公钥不一致，禁止保存")
        changed = c.execute(
            "UPDATE hosts SET host_key=?,last_status='untested',updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (row["key"], body.host_id),
        )
        if not changed.rowcount:
            raise HTTPException(404, "资产不存在")
        c.execute("DELETE FROM host_key_candidates WHERE host_id=?", (body.host_id,))
    store.audit(actor, "host_key_confirm", str(body.host_id), "success", row["fingerprint"])
    return {"ok": True}


@router.get("/audit")
def audit_log(actor=Depends(admin)):
    with store.db() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM audit ORDER BY id DESC LIMIT 200"
        )]

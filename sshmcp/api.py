"""中文管理 API：资产、凭据、跳板、分组、批量公钥、只读诊断和审计。"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import re
import secrets
import sqlite3

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt

from . import store, diagnostics, jobs
from .auth import admin

router = APIRouter(prefix="/api/v1")
SCAN_WORKERS = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ssh-key-batches")


def fail(exc: Exception):
    if isinstance(exc, HTTPException):
        raise exc
    if isinstance(exc, sqlite3.IntegrityError):
        raise HTTPException(409, "名称或地址重复，或关联的凭据/主机组不存在") from None
    if isinstance(exc, ValueError):
        raise HTTPException(422, str(exc)[:240]) from None
    raise HTTPException(500, "服务器处理失败：" + type(exc).__name__) from None


class CredentialIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    private_key: str = Field(min_length=64, max_length=16000)
    passphrase: str = Field(default="", max_length=200)


class HostIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=160)
    address: str = Field(max_length=64)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = "ai-diagnostic"
    host_key: str = Field(default="", max_length=4096)
    credential_id: int | None = Field(default=None, ge=1)
    proxy_id: int | None = Field(default=None, ge=1)
    zabbix_hostid: str | None = None
    enabled: bool = True
    mode: str = "standard"
    gateway_approved: bool = False
    group_ids: list[int] = Field(default_factory=list, max_length=50)
    asset_type: str = "linux"


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
    host_ids: list[int] = Field(default_factory=list, max_length=1000)
    query: str = Field(default="", max_length=160)
    retry_failed_batch: str | None = Field(default=None, max_length=64)
    unverified_only: bool = False


class ConfirmIn(BaseModel):
    host_id: StrictInt = Field(ge=1)
    independently_verified_sha256: str
    confirmed: StrictBool


class BatchConfirmedKey(BaseModel):
    host_id: StrictInt = Field(ge=1)
    independently_verified_sha256: str = Field(min_length=1, max_length=120)


class ConfirmBatchIn(BaseModel):
    items: list[BatchConfirmedKey] = Field(min_length=1, max_length=1000)
    confirmed: StrictBool = False


class RunIn(BaseModel):
    action: str
    service: str | None = None
    minutes: int = Field(default=30, ge=1, le=120)
    directory_root: str | None = None


def safe_host_input(item: HostIn) -> dict:
    x = item.model_dump()
    x["name"] = x["name"].strip()
    if not x["name"]:
        raise ValueError("资产名称不能为空")
    x["address"] = store.private_ip(x["address"])
    x["username"] = store.username(x["username"])
    x["host_key"] = store.validate_hostkey(x["host_key"], optional=True)
    if x["zabbix_hostid"] and not re.fullmatch(r"[0-9]{1,32}", x["zabbix_hostid"]):
        raise ValueError("Zabbix Host ID 必须是数字字符串")
    if x["mode"] not in {"standard", "gateway"}:
        raise ValueError("未知诊断模式")
    if x["asset_type"] not in {"linux", "windows", "network", "other"}:
        raise ValueError("资产类型无效")
    if x["asset_type"] != "linux":
        x["enabled"] = False
    if x["mode"] == "gateway" and not x["gateway_approved"]:
        raise ValueError("受限网关模式必须经管理员审核目标强制命令配置")
    return x


def _host_view(row) -> dict:
    v = dict(row)
    key = v.pop("host_key")
    v["has_host_key"] = bool(key)
    if v["has_host_key"]:
        try:
            v["host_fingerprint"] = diagnostics.host_fingerprint(key)
        except ValueError:
            v["has_host_key"] = False
            v["host_fingerprint"] = None
            v["key_error"] = "旧公钥无效，请重新核验"
    else:
        v["host_fingerprint"] = None
    v["group_ids"] = store.groups_for(v["id"])
    v["readiness"] = (
        "unsupported"
        if v["asset_type"] != "linux"
        else "disabled"
        if not v["enabled"]
        else "missing_credential"
        if not v["credential_id"]
        else "unverified"
        if not v["has_host_key"]
        else "failed"
        if v["last_status"] in {"failed", "partial"}
        else "verified"
        if v["last_status"] == "success"
        else "untested"
    )
    return v


@router.get("/auth/check")
def check_auth(actor=Depends(admin)):
    return {"ok": True, "role": actor}


@router.get("/overview")
def overview(actor=Depends(admin)):
    with store.db() as c:
        hosts = c.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
        ready = c.execute(
            "SELECT COUNT(*) FROM hosts WHERE host_key!='' AND credential_id IS NOT NULL AND enabled=1"
        ).fetchone()[0]
        verified = c.execute(
            "SELECT COUNT(*) FROM hosts WHERE asset_type='linux' AND enabled=1 AND host_key!='' AND credential_id IS NOT NULL AND last_status='success'"
        ).fetchone()[0]
        groups = c.execute("SELECT COUNT(*) FROM groups").fetchone()[0]
        failed = c.execute(
            "SELECT COUNT(*) FROM audit WHERE outcome='failed' AND created_at>=datetime('now','-1 day')"
        ).fetchone()[0]
    return {
        "hosts": hosts,
        "ready": ready,
        "verified": verified,
        "groups": groups,
        "failed_actions": failed,
        "version": "0.3.0",
    }


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
            c.execute("BEGIN IMMEDIATE")
            if (
                item["zabbix_hostid"]
                and c.execute(
                    "SELECT 1 FROM hosts WHERE zabbix_hostid=?",
                    (item["zabbix_hostid"],),
                ).fetchone()
            ):
                raise ValueError("Zabbix Host ID 已关联其他主机")
            cols = ",".join(item)
            ids = ",".join("?" for _ in item)
            cur = c.execute(
                "INSERT INTO hosts(" + cols + ") VALUES (" + ids + ")",
                list(item.values()),
            )
            hid = cur.lastrowid
            for gid in set(gids):
                c.execute(
                    "INSERT INTO host_groups(host_id,group_id) VALUES (?,?)", (hid, gid)
                )
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
            c.execute("BEGIN IMMEDIATE")
            if (
                item["zabbix_hostid"]
                and c.execute(
                    "SELECT 1 FROM hosts WHERE zabbix_hostid=? AND id!=?",
                    (item["zabbix_hostid"], host_id),
                ).fetchone()
            ):
                raise ValueError("Zabbix Host ID 已关联其他主机")
            previous = c.execute(
                "SELECT address,port,proxy_id,host_key FROM hosts WHERE id=?",
                (host_id,),
            ).fetchone()
            if previous is None:
                raise ValueError("主机不存在")
            # A pinned host key belongs to a specific endpoint, not to an arbitrary
            # asset row. Moving an IP, SSH port, or proxy requires re-verification.
            endpoint_changed = (
                item["address"] != previous["address"]
                or item["port"] != previous["port"]
                or item["proxy_id"] != previous["proxy_id"]
            )
            if endpoint_changed:
                if item["host_key"]:
                    raise ValueError(
                        "SSH 目标已变更；请清空主机公钥，并重新执行独立核验"
                    )
                item["host_key"] = ""
            elif not item["host_key"]:
                item["host_key"] = previous["host_key"]
            columns = ",".join(k + "=?" for k in item)
            cur = c.execute(
                "UPDATE hosts SET "
                + columns
                + ",revision=revision+1,last_status='untested',updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (*item.values(), host_id),
            )
            if cur.rowcount != 1:
                raise ValueError("主机不存在")
            c.execute("DELETE FROM host_groups WHERE host_id=?", (host_id,))
            for gid in set(gids):
                c.execute(
                    "INSERT INTO host_groups(host_id,group_id) VALUES (?,?)",
                    (host_id, gid),
                )
            if endpoint_changed or item["host_key"] != previous["host_key"]:
                c.execute("DELETE FROM host_key_candidates WHERE host_id=?", (host_id,))
        store.audit(actor, "host_update", str(host_id), "success")
        return {"id": host_id}
    except Exception as exc:
        fail(exc)


@router.post("/hosts/{host_id}/disable")
def disable_host(host_id: int, actor=Depends(admin)):
    with store.db() as c:
        updated = c.execute(
            "UPDATE hosts SET enabled=0,revision=revision+1,last_status='untested' WHERE id=?",
            (host_id,),
        )
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
        if not body.name.strip():
            raise ValueError("主机组名称不能为空")
        with store.db() as c:
            id = c.execute(
                "INSERT INTO groups(name) VALUES (?)", (body.name.strip(),)
            ).lastrowid
        store.audit(actor, "group_create", str(id), "success")
        return {"id": id}
    except Exception as exc:
        fail(exc)


@router.get("/credentials")
def credential_list(actor=Depends(admin)):
    with store.db() as c:
        return [
            dict(r)
            for r in c.execute(
                "SELECT id,name,created_at FROM credentials ORDER BY name"
            )
        ]


@router.post("/credentials", status_code=201)
def credential_add(body: CredentialIn, actor=Depends(admin)):
    try:
        blob = json.dumps(
            {"private_key": body.private_key, "passphrase": body.passphrase}
        )
        # Validate the key before persistence; never return the submitted private material.
        parsed = None
        import io
        import paramiko

        for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
            try:
                parsed = cls.from_private_key(
                    io.StringIO(body.private_key), password=body.passphrase or None
                )
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
            cls.from_private_key(
                io.StringIO(body.private_key), password=body.passphrase or None
            )
            ok = True
            break
        except (paramiko.SSHException, ValueError, TypeError):
            pass
    if not ok:
        raise HTTPException(422, "SSH 私钥无效")
    with store.db() as c:
        changed = c.execute(
            "UPDATE credentials SET name=?,secret=? WHERE id=?",
            (
                body.name.strip(),
                store.seal(json.dumps(body.model_dump())),
                credential_id,
            ),
        )
        if not changed.rowcount:
            raise HTTPException(404, "未找到凭据")
        c.execute(
            "UPDATE hosts SET last_status='untested',revision=revision+1 WHERE credential_id=? OR proxy_id IN (SELECT id FROM proxies WHERE credential_id=?)",
            (credential_id, credential_id),
        )
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
                "VALUES (?,?,?,?,?,?)",
                tuple(item.values()),
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
    return _execute(
        host_id, body.action, body.service, body.minutes, actor, body.directory_root
    )


def _execute(host_id, action, service, minutes, actor, directory_root=None):
    try:
        result = jobs.run_inline(
            host_id, action, actor, service, minutes, directory_root, source="web"
        )
    except Exception as exc:
        error = (
            str(exc)
            if isinstance(exc, (ValueError, diagnostics.SSHDiagnosticError))
            else type(exc).__name__
        )
        store.audit(actor, action, str(host_id), "failed", type(exc).__name__)
        raise HTTPException(422, diagnostics.redact_output(error)[:240]) from None
    # jobs.work owns audit and revision-guarded status updates for all entry points.
    if result["status"] == "failed":
        raise HTTPException(422, result.get("error", "诊断失败"))
    return result


def _scan_batch(batch_id: str, ids: list[int], actor=None):
    def scan(hid):
        from .auth import admins

        if actor and actor not in admins():
            return {"state": "failed", "error": "提交者已失去管理员权限"}
        return diagnostics.scan_host_key(hid)

    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="host-key") as pool:
        futures = {pool.submit(scan, hid): hid for hid in ids}
        for future in as_completed(futures):
            hid = futures[future]
            try:
                value = future.result()
            except Exception as exc:
                value = {"state": "failed", "error": type(exc).__name__}
            with store.db() as c:
                c.execute(
                    "INSERT OR REPLACE INTO scan_results("
                    "batch_id,host_id,status,fingerprint,algorithm,previous_fingerprint,error"
                    ") VALUES (?,?,?,?,?,?,?)",
                    (
                        batch_id,
                        hid,
                        value.get("state", "failed"),
                        value.get("fingerprint"),
                        value.get("algorithm"),
                        value.get("previous_fingerprint"),
                        value.get("error"),
                    ),
                )
                c.execute(
                    "UPDATE scan_batches SET completed=completed+1 WHERE id=?",
                    (batch_id,),
                )
    with store.db() as c:
        c.execute("UPDATE scan_batches SET status='finished' WHERE id=?", (batch_id,))


@router.post("/host-keys/scan", status_code=202)
def scan_keys(body: ScanIn, actor=Depends(admin)):
    ids = list(dict.fromkeys(body.host_ids))
    if body.retry_failed_batch:
        if ids or body.query.strip():
            raise HTTPException(422, "失败重试与指定主机/搜索条件不能同时使用")
        with store.db() as c:
            batch = c.execute(
                "SELECT 1 FROM scan_batches WHERE id=?", (body.retry_failed_batch,)
            ).fetchone()
            if not batch:
                raise HTTPException(404, "待重试批次不存在")
            ids = [
                r[0]
                for r in c.execute(
                    "SELECT r.host_id FROM scan_results r JOIN hosts h ON h.id=r.host_id "
                    "WHERE r.batch_id=? AND h.enabled=1 AND r.status IN ('failed','stale','interrupted')",
                    (body.retry_failed_batch,),
                )
            ]
    elif not ids:
        search = body.query.strip().lower()
        with store.db() as c:
            all_rows = c.execute(
                "SELECT id,name,address,zabbix_hostid,host_key FROM hosts WHERE enabled=1 ORDER BY id"
            ).fetchall()
        ids = [
            row["id"]
            for row in all_rows
            if (
                not search
                or any(
                    search in str(row[k] or "").lower()
                    for k in ("name", "address", "zabbix_hostid")
                )
            )
            and (not body.unverified_only or not row["host_key"])
        ]
    ids = list(dict.fromkeys(ids))
    if not ids:
        raise HTTPException(422, "没有符合条件的可扫描主机")
    if len(ids) > 1000:
        raise HTTPException(422, "每批最多扫描 1000 台主机；请缩小筛选范围")
    with store.db() as c:
        actual = c.execute(
            "SELECT COUNT(*) FROM hosts WHERE id IN ("
            + ",".join("?" for _ in ids)
            + ") AND enabled=1",
            ids,
        ).fetchone()[0]
    if actual != len(ids):
        raise HTTPException(422, "批次包含不存在或已禁用的主机")
    batch_id = secrets.token_hex(12)
    with store.db() as c:
        c.execute("BEGIN IMMEDIATE")
        if (
            c.execute(
                "SELECT COUNT(*) FROM scan_batches WHERE status='running'"
            ).fetchone()[0]
            >= 3
        ):
            raise HTTPException(429, "已有三批扫描排队或执行中，请等待当前批次完成")
        c.execute(
            "INSERT INTO scan_batches(id,status,total) VALUES (?,?,?)",
            (batch_id, "running", len(ids)),
        )
        c.executemany(
            "INSERT INTO scan_results(batch_id,host_id,status) VALUES (?,?,?)",
            [(batch_id, hid, "queued") for hid in ids],
        )
    try:
        SCAN_WORKERS.submit(_scan_batch, batch_id, ids, actor)
    except RuntimeError:
        with store.db() as c:
            c.execute(
                "UPDATE scan_batches SET status='interrupted' WHERE id=?", (batch_id,)
            )
            c.execute(
                "UPDATE scan_results SET status='interrupted',error='服务正在停止，请稍后重试' WHERE batch_id=?",
                (batch_id,),
            )
    store.audit(actor, "host_keys_scan", batch_id, "started", "count=" + str(len(ids)))
    return {"batch_id": batch_id, "total": len(ids)}


@router.get("/host-keys/batches")
def batches(actor=Depends(admin)):
    with store.db() as c:
        return [
            dict(r)
            for r in c.execute(
                "SELECT * FROM scan_batches ORDER BY created_at DESC LIMIT 30"
            )
        ]


@router.get("/host-keys/batches/{batch_id}")
def batch_detail(batch_id: str, actor=Depends(admin)):
    with store.db() as c:
        batch = c.execute(
            "SELECT * FROM scan_batches WHERE id=?", (batch_id,)
        ).fetchone()
        if not batch:
            raise HTTPException(404, "批次不存在")
        rows = c.execute(
            "SELECT r.*, h.name,h.address FROM scan_results r "
            "LEFT JOIN hosts h ON h.id=r.host_id WHERE batch_id=? ORDER BY host_id",
            (batch_id,),
        ).fetchall()
    return {"batch": dict(batch), "items": [dict(r) for r in rows]}


def _save_confirmed_key(c, item: BatchConfirmedKey):
    row = c.execute(
        "SELECT key,fingerprint,source_signature FROM host_key_candidates WHERE host_id=?",
        (item.host_id,),
    ).fetchone()
    host = c.execute(
        "SELECT * FROM hosts WHERE id=? AND enabled=1", (item.host_id,)
    ).fetchone()
    if not row or not host:
        raise HTTPException(422, f"主机 {item.host_id} 没有有效的待核验公钥")
    if not row["source_signature"] or row["source_signature"] != store.scan_signature(
        dict(host)
    ):
        raise HTTPException(409, f"主机 {item.host_id} SSH 目标已发生变化，请重新扫描")
    provided = item.independently_verified_sha256.strip()
    if not provided.isascii() or not secrets.compare_digest(
        row["fingerprint"], provided
    ):
        raise HTTPException(422, f"主机 {item.host_id} 可信指纹与扫描结果不一致")
    c.execute(
        "UPDATE hosts SET host_key=?,revision=revision+1,last_status='untested',updated_at=CURRENT_TIMESTAMP WHERE id=?",
        (row["key"], item.host_id),
    )
    c.execute(
        "UPDATE scan_results SET status='confirmed' "
        "WHERE host_id=? AND fingerprint=? AND status IN ('candidate','changed')",
        (item.host_id, row["fingerprint"]),
    )
    c.execute("DELETE FROM host_key_candidates WHERE host_id=?", (item.host_id,))
    return row["fingerprint"]


@router.post("/host-keys/confirm")
def confirm_key(body: ConfirmIn, actor=Depends(admin)):
    result = confirm_batch(
        ConfirmBatchIn(
            items=[
                BatchConfirmedKey(
                    host_id=body.host_id,
                    independently_verified_sha256=body.independently_verified_sha256,
                )
            ],
            confirmed=body.confirmed,
        ),
        actor,
    )
    return {"ok": True, "count": result["count"]}


@router.post("/host-keys/confirm-batch")
def confirm_batch(body: ConfirmBatchIn, actor=Depends(admin)):
    if not body.confirmed:
        raise HTTPException(422, "必须在可信渠道独立核验所有主机公钥后确认")
    ids = [item.host_id for item in body.items]
    if len(ids) != len(set(ids)):
        raise HTTPException(422, "批量核验包含重复的主机 ID")
    with store.db() as c:
        c.execute("BEGIN IMMEDIATE")
        # Transactional batch: any mismatch means zero keys are confirmed.
        verified = [(item.host_id, _save_confirmed_key(c, item)) for item in body.items]
    for hid, fingerprint in verified:
        store.audit(actor, "host_key_confirm", str(hid), "success", fingerprint)
    return {"ok": True, "count": len(verified)}


@router.get("/audit")
def audit_log(actor=Depends(admin)):
    with store.db() as c:
        return [
            dict(r) for r in c.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 200")
        ]

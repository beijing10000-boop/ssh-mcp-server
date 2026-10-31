"""Paged inventory, atomic imports and safe maintenance for the desktop console."""

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt

from . import store
from .api import (
    HOST_SELECT,
    GroupIn,
    HostIn,
    ProxyIn,
    fail,
    host_with_groups,
    safe_host_input,
    safe_proxy_input,
)
from .auth import admin

router = APIRouter(prefix="/api/v1")


def where_hosts(q="", group_id=None, status="all"):
    clauses, args = [], []
    if q:
        clauses.append(
            "(instr(lower(name),lower(?))>0 OR instr(address,?)>0 OR zabbix_hostid=? OR id IN (SELECT hg.host_id FROM host_groups hg JOIN groups g ON g.id=hg.group_id WHERE instr(lower(g.name),lower(?))>0))"
        )
        args.extend((q, q, q, q))
    if group_id:
        clauses.append("id IN (SELECT host_id FROM host_groups WHERE group_id=?)")
        args.append(group_id)
    rules = {
        "disabled": "enabled=0",
        "unverified": "enabled=1 AND host_key=''",
        "credential_bound": "asset_type='linux' AND enabled=1 AND credential_id IS NOT NULL",
        "ready": "asset_type='linux' AND enabled=1 AND host_key!='' AND credential_id IS NOT NULL",
        "failed": "last_status='failed'",
        "enabled": "enabled=1",
        "missing_credential": "asset_type='linux' AND credential_id IS NULL",
        "untested": "enabled=1 AND host_key!='' AND credential_id IS NOT NULL AND last_status='untested'",
        "verified": "enabled=1 AND asset_type='linux' AND last_status='success' AND host_key!='' AND credential_id IS NOT NULL",
        "unsupported": "asset_type!='linux'",
    }
    if status in rules:
        clauses.append(rules[status])
    elif status != "all":
        raise HTTPException(422, "主机筛选状态无效")
    return (" WHERE " + " AND ".join(clauses) if clauses else ""), args


@router.get("/inventory/hosts")
def listing(
    q: str = Query("", max_length=160),
    group_id: int | None = Query(None, ge=1),
    status: str = "all",
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    sort: str = "id",
    direction: str = "desc",
    actor=Depends(admin),
):
    if sort not in {
        "id",
        "name",
        "address",
        "last_test_at",
        "last_diagnostic_at",
    } or direction not in {"asc", "desc"}:
        raise HTTPException(422, "排序字段或方向无效")
    where, args = where_hosts(q, group_id, status)
    with store.db() as c:
        total = c.execute("SELECT COUNT(*) FROM hosts" + where, args).fetchone()[0]
        rows = c.execute(
            HOST_SELECT
            + where
            + " ORDER BY "
            + sort
            + " "
            + direction
            + ",id DESC LIMIT ? OFFSET ?",
            (*args, page_size, (page - 1) * page_size),
        ).fetchall()
    return {
        "items": [host_with_groups(row) for row in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/inventory/ids")
def selected(
    q: str = Query("", max_length=160),
    group_id: int | None = Query(None, ge=1),
    status: str = "all",
    actor=Depends(admin),
):
    where, args = where_hosts(q, group_id, status)
    with store.db() as c:
        rows = c.execute(
            "SELECT id FROM hosts" + where + " ORDER BY id LIMIT 1001", args
        ).fetchall()
    if len(rows) > 1000:
        raise HTTPException(422, "筛选超过 1000 台，请按主机组分批操作")
    return {"host_ids": [r[0] for r in rows]}


class ImportIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hosts: list[HostIn] = Field(min_length=1, max_length=1000)


@router.post("/hosts/import", status_code=201)
def import_hosts(body: ImportIn, actor=Depends(admin)):
    try:
        values = [safe_host_input(x) for x in body.hosts]
        created = []
        with store.db() as c:
            c.execute("BEGIN IMMEDIATE")
            for item in values:
                gids = item.pop("group_ids")
                if (
                    item["zabbix_hostid"]
                    and c.execute(
                        "SELECT 1 FROM hosts WHERE zabbix_hostid=?",
                        (item["zabbix_hostid"],),
                    ).fetchone()
                ):
                    raise ValueError("Zabbix Host ID 已存在，未导入任何主机")
                ident = c.execute(
                    "INSERT INTO hosts("
                    + ",".join(item)
                    + ") VALUES ("
                    + ",".join("?" for _ in item)
                    + ")",
                    tuple(item.values()),
                ).lastrowid
                c.executemany(
                    "INSERT INTO host_groups VALUES (?,?)",
                    [(ident, gid) for gid in set(gids)],
                )
                created.append(ident)
        store.audit(actor, "hosts_import", str(len(created)), "success")
        return {"count": len(created), "host_ids": created}
    except Exception as exc:
        fail(exc)


class EnableIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host_ids: list[StrictInt] = Field(min_length=1, max_length=1000)
    enabled: StrictBool


class AccessIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host_ids: list[StrictInt] = Field(min_length=1, max_length=1000)
    credential_id: StrictInt = Field(ge=1)
    username: str = Field(min_length=1, max_length=32)
    port: StrictInt = Field(default=22, ge=1, le=65535)
    proxy_id: StrictInt | None = Field(default=None, ge=1)


@router.post("/hosts/bulk-access")
def bind_access(body: AccessIn, actor=Depends(admin)):
    try:
        username = store.username(body.username)
        ids = sorted(set(body.host_ids))
        with store.db() as c:
            c.execute("BEGIN IMMEDIATE")
            if not c.execute(
                "SELECT 1 FROM credentials WHERE id=?", (body.credential_id,)
            ).fetchone():
                raise ValueError("SSH 凭据不存在")
            if (
                body.proxy_id
                and not c.execute(
                    "SELECT 1 FROM proxies WHERE id=?", (body.proxy_id,)
                ).fetchone()
            ):
                raise ValueError("跳板不存在")
            for ident in ids:
                row = c.execute("SELECT * FROM hosts WHERE id=?", (ident,)).fetchone()
                if not row or row["asset_type"] != "linux":
                    raise ValueError("所选资产包含不存在或非 Linux 的主机")
                moved = row["port"] != body.port or row["proxy_id"] != body.proxy_id
                c.execute(
                    "UPDATE hosts SET credential_id=?,username=?,port=?,proxy_id=?,host_key=CASE WHEN ? THEN '' ELSE host_key END,last_status='untested',revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                    (
                        body.credential_id,
                        username,
                        body.port,
                        body.proxy_id,
                        moved,
                        ident,
                    ),
                )
                if moved:
                    c.execute(
                        "DELETE FROM host_key_candidates WHERE host_id=?", (ident,)
                    )
        store.audit(actor, "hosts_bind_access", str(len(ids)), "success")
        return {"count": len(ids)}
    except Exception as exc:
        fail(exc)


@router.post("/hosts/bulk-enabled")
def enable_hosts(body: EnableIn, actor=Depends(admin)):
    ids = list(dict.fromkeys(body.host_ids))
    slots = ",".join("?" for _ in ids)
    with store.db() as c:
        c.execute("BEGIN IMMEDIATE")
        if c.execute(
            "SELECT COUNT(*) FROM hosts WHERE id IN (" + slots + ")", ids
        ).fetchone()[0] != len(ids):
            raise HTTPException(404, "所选主机中包含不存在的资产")
        if (
            body.enabled
            and c.execute(
                "SELECT 1 FROM hosts WHERE id IN ("
                + slots
                + ") AND asset_type!='linux'",
                ids,
            ).fetchone()
        ):
            raise HTTPException(422, "非 Linux 资产暂不支持启用 SSH 诊断")
        c.execute(
            "UPDATE hosts SET enabled=?,revision=revision+1,last_status='untested' WHERE id IN ("
            + slots
            + ")",
            (int(body.enabled), *ids),
        )
    store.audit(
        actor,
        "hosts_enable" if body.enabled else "hosts_disable",
        str(len(ids)),
        "success",
    )
    return {"count": len(ids)}


@router.put("/groups/{group_id}")
def update_group(group_id: int, body: GroupIn, actor=Depends(admin)):
    try:
        if not body.name.strip():
            raise ValueError("主机组名称不能为空")
        with store.db() as c:
            if not c.execute(
                "UPDATE groups SET name=? WHERE id=?", (body.name.strip(), group_id)
            ).rowcount:
                raise HTTPException(404, "主机组不存在")
        store.audit(actor, "group_update", str(group_id), "success")
        return {"ok": True}
    except Exception as exc:
        fail(exc)


@router.delete("/groups/{group_id}")
def delete_group(group_id: int, actor=Depends(admin)):
    with store.db() as c:
        if not c.execute("DELETE FROM groups WHERE id=?", (group_id,)).rowcount:
            raise HTTPException(404, "主机组不存在")
    store.audit(actor, "group_delete", str(group_id), "success")
    return {"ok": True}


@router.put("/proxies/{proxy_id}")
def update_proxy(proxy_id: int, body: ProxyIn, actor=Depends(admin)):
    try:
        value = safe_proxy_input(body)
        with store.db() as c:
            c.execute("BEGIN IMMEDIATE")
            if not c.execute(
                "UPDATE proxies SET "
                + ",".join(k + "=?" for k in value)
                + " WHERE id=?",
                (*value.values(), proxy_id),
            ).rowcount:
                raise HTTPException(404, "跳板不存在")
            c.execute(
                "UPDATE hosts SET revision=revision+1,last_status='untested' WHERE proxy_id=?",
                (proxy_id,),
            )
        store.audit(actor, "proxy_update", str(proxy_id), "success")
        return {"ok": True}
    except Exception as exc:
        fail(exc)


@router.get("/audit/page")
def audit_page(
    q: str = Query("", max_length=160),
    outcome: str = "all",
    page: int = Query(1, ge=1),
    actor=Depends(admin),
):
    clauses, args = [], []
    if q:
        clauses.append("(instr(action,?)>0 OR instr(actor,?)>0 OR target=?)")
        args.extend((q, q, q))
    if outcome != "all":
        clauses.append("outcome=?")
        args.append(outcome)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with store.db() as c:
        total = c.execute("SELECT COUNT(*) FROM audit" + where, args).fetchone()[0]
        rows = c.execute(
            "SELECT * FROM audit" + where + " ORDER BY id DESC LIMIT 50 OFFSET ?",
            (*args, (page - 1) * 50),
        ).fetchall()
    return {
        "items": [dict(r) for r in rows],
        "total": total,
        "page": page,
        "page_size": 50,
    }


class TargetsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host_ids: list[StrictInt] = Field(min_length=1, max_length=1000)


@router.post("/inventory/targets")
def targets(body: TargetsIn, actor=Depends(admin)):
    ids = sorted(set(body.host_ids))
    with store.db() as c:
        rows = c.execute(
            HOST_SELECT + " WHERE h.id IN (" + ",".join("?" for _ in ids) + ")", ids
        ).fetchall()
    return [host_with_groups(row) for row in rows]

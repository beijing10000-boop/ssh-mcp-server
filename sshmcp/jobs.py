"""Bounded diagnostic jobs with encrypted results and restart-visible failure."""

from concurrent.futures import ThreadPoolExecutor
import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, StrictInt

from . import diagnostics, store, observations
from .auth import admin

router = APIRouter(prefix="/api/v1/jobs")
POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ssh-diagnostics")


class RunIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host_ids: list[StrictInt] = Field(min_length=1, max_length=100)
    action: str
    service: str | None = Field(default=None, max_length=64)
    minutes: StrictInt = Field(default=30, ge=1, le=120)
    directory_root: str | None = Field(default=None, max_length=200)
    symptom: str | None = None
    strict: bool = False


def _request(action, service=None, minutes=30, directory_root=None, symptom=None):
    diagnostics.command_for(action, service, minutes, directory_root, symptom=symptom)
    return {
        "action": action,
        "service": service,
        "minutes": minutes,
        "directory_root": directory_root,
        **({"symptom": symptom} if symptom is not None else {}),
    }


def create(
    host_ids,
    request,
    actor,
    source="web",
    *,
    background=True,
    expected_revisions=None,
    strict=False,
):
    ids = list(dict.fromkeys(host_ids))
    if not ids or len(ids) > 100 or any(type(i) is not int or i < 1 for i in ids):
        raise ValueError("请选择 1–100 台主机")
    request = _request(**request)
    batch_id, jobs, accepted, skipped = uuid.uuid4().hex, [], [], []
    with store.db() as c:
        c.execute("BEGIN IMMEDIATE")
        pending = c.execute(
            "SELECT COUNT(*) FROM diagnostic_jobs WHERE status IN ('queued','running')"
        ).fetchone()[0]
        for host_id in ids:
            row = c.execute(
                "SELECT * FROM hosts WHERE id=? AND enabled=1", (host_id,)
            ).fetchone()
            reason = None
            if not row or not row["host_key"] or not row["credential_id"]:
                reason = "主机未启用、未核验公钥或未绑定凭据"
            elif row["asset_type"] != "linux":
                reason = "资产不是 Linux，不能执行 SSH 诊断"
            elif (
                row["mode"] == "gateway"
                and request["action"] in diagnostics.STANDARD_ONLY
            ):
                reason = "此动作需要标准 SSH 模式；受限网关尚不支持"
            elif expected_revisions is not None and row[
                "revision"
            ] != expected_revisions.get(host_id):
                reason = "主机配置已变更，请重新解析映射并确认诊断目标"
            elif pending + len(jobs) >= 200:
                reason = "待执行任务已达上限，请等待现有任务完成"
            if reason:
                if strict:
                    raise ValueError(f"主机 {host_id}: {reason}")
                skipped.append({"host_id": host_id, "reason": reason})
                continue
            ident = uuid.uuid4().hex
            c.execute(
                "INSERT INTO diagnostic_jobs(id,batch_id,host_id,host_name,host_revision,actor,source,action,request) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    ident,
                    batch_id,
                    host_id,
                    row["name"],
                    row["revision"],
                    actor,
                    source,
                    request["action"],
                    store.seal(json.dumps(request, ensure_ascii=False)),
                ),
            )
            jobs.append(ident)
            accepted.append({"host_id": host_id, "job_id": ident})
        c.execute(
            "INSERT INTO diagnostic_batches(id,actor,source,skipped) VALUES (?,?,?,?)",
            (
                batch_id,
                actor,
                source,
                store.seal(json.dumps(skipped, ensure_ascii=False)),
            ),
        )
    for ident in jobs:
        if background:
            try:
                POOL.submit(work, ident, True)
            except RuntimeError:
                with store.db() as c:
                    c.execute(
                        "UPDATE diagnostic_jobs SET status='failed',error='服务正在停止，请稍后重试',completed_at=CURRENT_TIMESTAMP WHERE id=?",
                        (ident,),
                    )
        else:
            work(ident)
    store.audit(
        actor,
        "diagnostic_submit",
        batch_id,
        "success",
        f"count={len(jobs)};action={request['action']}",
    )
    return {
        "batch_id": batch_id,
        "job_ids": jobs,
        "total": len(jobs),
        "accepted": accepted,
        "skipped": skipped,
    }


def cancelled(ident):
    with store.db() as c:
        row = c.execute(
            "SELECT cancel_requested FROM diagnostic_jobs WHERE id=?", (ident,)
        ).fetchone()
    return row is None or bool(row[0])


def authorize(job):
    if job["source"] == "web":
        from .auth import admins

        if job["actor"] not in admins():
            raise PermissionError("提交者已失去管理权限")
    else:
        # Background MCP tasks must re-check live scope, expiry and revoke
        # state; a credential may change while its task waits in the queue.
        from . import access
        import time

        client_id = job["actor"].removeprefix("mcp:")
        if client_id == "legacy":
            if not access.legacy_enabled():
                raise PermissionError("原始 MCP 令牌已停用")
        else:
            with store.db() as c:
                current = c.execute(
                    "SELECT * FROM mcp_clients WHERE id=? AND enabled=1 AND expires_at>?",
                    (client_id, int(time.time())),
                ).fetchone()
                if not current or job["action"] not in json.loads(current["actions"]):
                    raise PermissionError("MCP 客户端已撤销、到期或动作不再授权")
                if not current["all_hosts"] and not set(
                    store.groups_for(job["host_id"])
                ) & set(json.loads(current["group_ids"])):
                    raise PermissionError("主机已不在 MCP 客户端授权范围内")


def work(ident, background=False):
    with store.db() as c:
        c.execute("BEGIN IMMEDIATE")
        if not c.execute(
            "UPDATE diagnostic_jobs SET status='running',started_at=CURRENT_TIMESTAMP WHERE id=? AND status='queued' AND cancel_requested=0",
            (ident,),
        ).rowcount:
            return
        job = dict(
            c.execute("SELECT * FROM diagnostic_jobs WHERE id=?", (ident,)).fetchone()
        )
    request = json.loads(store.unseal(job["request"]))
    error = ""
    try:
        authorize(job)
        result = diagnostics.execute(
            job["host_id"],
            **request,
            cancelled=lambda: cancelled(ident),
            expected_revision=job["host_revision"],
            background=background,
            preflight=lambda: authorize(job),
        )
        if "summary" not in result and job["action"] in observations.PARSERS:
            result.update(
                observations.analyze(
                    job["action"],
                    result.get("output", ""),
                    data=result.get("data"),
                    status=result["status"],
                    truncated=result.get("truncated", False),
                )
            )
        status = result["status"]
    except Exception as exc:
        error = (
            diagnostics.redact_output(str(exc))[:240]
            if isinstance(
                exc, (ValueError, diagnostics.SSHDiagnosticError, PermissionError)
            )
            else type(exc).__name__
        )
        status = "failed"
        result = {
            "host_id": job["host_id"],
            "action": job["action"],
            "status": status,
            "error": error,
        }
    with store.db() as c:
        c.execute("BEGIN IMMEDIATE")
        if c.execute(
            "SELECT cancel_requested FROM diagnostic_jobs WHERE id=?", (ident,)
        ).fetchone()[0]:
            status = "cancelled"
            result["status"] = status
            result["note"] = "任务已取消；已有采集结果保留"
        result["job_id"] = ident
        c.execute(
            "UPDATE diagnostic_jobs SET status=?,error=?,result=?,completed_at=CURRENT_TIMESTAMP WHERE id=?",
            (status, error, store.seal(json.dumps(result, ensure_ascii=False)), ident),
        )
        if job["action"] == "connection":
            c.execute(
                "UPDATE hosts SET last_status=? WHERE id=? AND revision=?",
                (status, job["host_id"], job["host_revision"]),
            )
        c.execute(
            "INSERT INTO audit(actor,action,target,outcome,detail) VALUES (?,?,?,?,?)",
            (job["actor"], job["action"], str(job["host_id"]), status, "job=" + ident),
        )


def run_inline(
    host_id,
    action,
    actor,
    service=None,
    minutes=30,
    directory_root=None,
    source="mcp",
    expected_revision=None,
    symptom=None,
):
    batch = create(
        [host_id],
        _request(action, service, minutes, directory_root, symptom),
        actor,
        source,
        background=False,
        strict=True,
        expected_revisions={host_id: expected_revision}
        if expected_revision is not None
        else None,
    )
    job = detail(batch["job_ids"][0])
    return job["result"] or {
        "host_id": host_id,
        "action": action,
        "status": job["status"],
        "job_id": job["id"],
    }


def detail(ident):
    with store.db() as c:
        row = c.execute("SELECT * FROM diagnostic_jobs WHERE id=?", (ident,)).fetchone()
    if not row:
        raise HTTPException(404, "诊断任务不存在")
    data = dict(row)
    data["request"] = json.loads(store.unseal(data["request"]))
    data["result"] = (
        json.loads(store.unseal(data["result"])) if data["result"] else None
    )
    return data


def batch_detail(batch_id, page=1, page_size=25, *, actor=None):
    import re

    if not re.fullmatch(r"[a-f0-9]{32}", batch_id):
        raise ValueError("批次 ID 格式无效")
    if (
        type(page) is not int
        or page < 1
        or type(page_size) is not int
        or not 1 <= page_size <= 100
    ):
        raise ValueError("批次分页参数无效")
    with store.db() as c:
        batch = c.execute(
            "SELECT * FROM diagnostic_batches WHERE id=?", (batch_id,)
        ).fetchone()
        if batch is None:
            # Existing v0.3.1 batches have no parent row.
            batch = c.execute(
                "SELECT actor,source FROM diagnostic_jobs WHERE batch_id=? LIMIT 1",
                (batch_id,),
            ).fetchone()
        if batch is None or actor is not None and batch["actor"] != actor:
            raise PermissionError("批次不存在或不属于当前客户端")
        rows = c.execute(
            "SELECT id,status,actor FROM diagnostic_jobs WHERE batch_id=? ORDER BY rowid",
            (batch_id,),
        ).fetchall()
        if actor is not None and any(r["actor"] != actor for r in rows):
            raise PermissionError("批次不属于当前客户端")
        counts = {
            key: sum(r["status"] == key for r in rows)
            for key in (
                "queued",
                "running",
                "success",
                "partial",
                "failed",
                "cancelled",
            )
        }
    skipped = (
        json.loads(store.unseal(batch["skipped"])) if "skipped" in batch.keys() else []
    )
    items = []
    for row in rows[(page - 1) * page_size : page * page_size]:
        job = detail(row["id"])
        items.append(
            {
                k: job[k]
                for k in (
                    "id",
                    "host_id",
                    "host_name",
                    "action",
                    "status",
                    "error",
                    "created_at",
                    "completed_at",
                    "result",
                )
            }
        )
    for item in items:
        item["findings"] = (item["result"] or {}).get("findings", [])
    return {
        "batch_id": batch_id,
        "total": len(rows),
        "skipped": skipped,
        "counts": counts,
        "completed": sum(
            counts[k] for k in ("success", "partial", "failed", "cancelled")
        ),
        "page": page,
        "page_size": page_size,
        "items": items,
    }


@router.get("/batches/{batch_id}")
def get_batch(
    batch_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    actor=Depends(admin),
):
    try:
        return batch_detail(batch_id, page, page_size)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(
            422 if isinstance(exc, ValueError) else 404, str(exc)
        ) from None


@router.post("", status_code=202)
def submit(body: RunIn, actor=Depends(admin)):
    try:
        return create(
            body.host_ids,
            body.model_dump(exclude={"host_ids", "strict"}),
            actor,
            strict=body.strict,
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None


@router.get("")
def listing(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    status: str = "all",
    host_id: int | None = None,
    batch_id: str | None = None,
    actor=Depends(admin),
):
    clauses, values = [], []
    if status != "all":
        clauses.append("status=?")
        values.append(status)
    if host_id:
        clauses.append("host_id=?")
        values.append(host_id)
    if batch_id:
        clauses.append("batch_id=?")
        values.append(batch_id)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with store.db() as c:
        total = c.execute(
            "SELECT COUNT(*) FROM diagnostic_jobs" + where, values
        ).fetchone()[0]
        rows = c.execute(
            "SELECT id,batch_id,host_id,host_name,actor,source,action,status,error,created_at,started_at,completed_at "
            "FROM diagnostic_jobs"
            + where
            + " ORDER BY created_at DESC,rowid DESC LIMIT ? OFFSET ?",
            (*values, page_size, (page - 1) * page_size),
        ).fetchall()
    return {
        "items": [dict(r) for r in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/{job_id}")
def get(job_id: str, actor=Depends(admin)):
    return detail(job_id)


@router.post("/{job_id}/cancel")
def cancel(job_id: str, actor=Depends(admin)):
    with store.db() as c:
        result = c.execute(
            "UPDATE diagnostic_jobs SET cancel_requested=1,status=CASE WHEN status='queued' THEN 'cancelled' ELSE status END,"
            "completed_at=CASE WHEN status='queued' THEN CURRENT_TIMESTAMP ELSE completed_at END "
            "WHERE id=? AND status IN ('queued','running')",
            (job_id,),
        )
        if not result.rowcount:
            raise HTTPException(409, "任务不存在或已经结束")
    store.audit(actor, "diagnostic_cancel", job_id, "success")
    return {"ok": True}


@router.post("/{job_id}/retry", status_code=202)
def retry(job_id: str, actor=Depends(admin)):
    job = detail(job_id)
    if job["status"] in {"queued", "running"}:
        raise HTTPException(409, "任务尚未结束")
    try:
        return create([job["host_id"]], job["request"], actor)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None

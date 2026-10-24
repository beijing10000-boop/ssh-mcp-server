"""Bounded diagnostic jobs with encrypted results and restart-visible failure."""

from concurrent.futures import ThreadPoolExecutor
import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, StrictInt

from . import diagnostics, store
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


def _request(action, service=None, minutes=30, directory_root=None):
    diagnostics.command_for(action, service, minutes, directory_root)
    return {
        "action": action,
        "service": service,
        "minutes": minutes,
        "directory_root": directory_root,
    }


def create(
    host_ids, request, actor, source="web", *, background=True, expected_revisions=None
):
    ids = list(dict.fromkeys(host_ids))
    if not ids or len(ids) > 100 or any(type(i) is not int or i < 1 for i in ids):
        raise ValueError("请选择 1–100 台主机")
    request = _request(**request)
    batch_id, jobs = uuid.uuid4().hex, []
    with store.db() as c:
        c.execute("BEGIN IMMEDIATE")
        pending = c.execute(
            "SELECT COUNT(*) FROM diagnostic_jobs WHERE status IN ('queued','running')"
        ).fetchone()[0]
        if pending + len(ids) > 200:
            raise ValueError("待执行任务已达上限，请等待现有任务完成")
        for host_id in ids:
            row = c.execute(
                "SELECT * FROM hosts WHERE id=? AND enabled=1", (host_id,)
            ).fetchone()
            if not row or not row["host_key"] or not row["credential_id"]:
                raise ValueError(f"主机 {host_id} 未启用、未核验公钥或未绑定凭据")
            if expected_revisions is not None and row[
                "revision"
            ] != expected_revisions.get(host_id):
                raise ValueError("主机配置已变更，请重新解析映射并确认诊断目标")
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
    for ident in jobs:
        if background:
            try:
                POOL.submit(work, ident)
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
    return {"batch_id": batch_id, "job_ids": jobs, "total": len(jobs)}


def cancelled(ident):
    with store.db() as c:
        row = c.execute(
            "SELECT cancel_requested FROM diagnostic_jobs WHERE id=?", (ident,)
        ).fetchone()
    return row is None or bool(row[0])


def work(ident):
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
        if job["source"] == "web":
            from .auth import admins

            if job["actor"] not in admins():
                raise PermissionError("提交者已失去管理权限")
        result = diagnostics.execute(
            job["host_id"],
            **request,
            cancelled=lambda: cancelled(ident),
            expected_revision=job["host_revision"],
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
):
    batch = create(
        [host_id],
        _request(action, service, minutes, directory_root),
        actor,
        source,
        background=False,
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


@router.post("", status_code=202)
def submit(body: RunIn, actor=Depends(admin)):
    try:
        return create(body.host_ids, body.model_dump(exclude={"host_ids"}), actor)
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

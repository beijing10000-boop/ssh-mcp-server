"""可由任何 MCP 客户端独立调用的安全 SSH 工具集。"""

from __future__ import annotations

import asyncio
import inspect
from typing import Literal
from functools import wraps

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from . import store, diagnostics, access, jobs, observations

mcp = FastMCP(
    "Linux SSH 智能诊断",
    instructions=(
        "本服务仅对预先登记和核验的内网 Linux 主机执行固定只读诊断。"
        "禁止臆测主机 ID，先通过 ssh_list_hosts 获取。"
        "不能传入任意网络地址、Shell 命令或执行修复。"
    ),
    stateless_http=True,
    json_response=True,
    host="0.0.0.0",
)


READ_ONLY = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False
)


def offload(fn):
    """FastMCP must await tools; to_thread preserves the MCP ContextVar."""

    summarized = fn.__name__.startswith("ssh_diagnose_") or fn.__name__ in {
        "ssh_test_connection",
        "ssh_triage",
        "ssh_get_diagnostic_job",
        "ssh_get_diagnostic_batch",
    }

    @wraps(fn)
    async def run(*args, **kwargs):
        detail = kwargs.pop("detail", "summary") if summarized else None
        if summarized and detail not in {"summary", "full"}:
            raise ValueError("detail 必须为 summary 或 full")
        result = await asyncio.to_thread(fn, *args, **kwargs)
        return observations.present(result, detail) if summarized else result

    if summarized:
        signature = inspect.signature(fn, eval_str=True)
        run.__signature__ = signature.replace(
            parameters=[
                *signature.parameters.values(),
                inspect.Parameter(
                    "detail",
                    inspect.Parameter.KEYWORD_ONLY,
                    default="summary",
                    annotation=Literal["summary", "full"],
                ),
            ]
        )
        run.__doc__ = (
            fn.__doc__ or ""
        ) + " detail 默认 summary 返回结构化摘要/findings；full 另带可用的脱敏原文。"
    return run


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_list_hosts(
    query: str = "", offset: int = 0, limit: int = 100, group_id: int | None = None
) -> list[dict]:
    """列出当前启用且已经审核的 Linux SSH 主机，返回 ID、名称、Host ID 与连接状态，不暴露密钥。"""
    if (
        len(query) > 160
        or type(offset) is not int
        or offset < 0
        or type(limit) is not int
        or not 1 <= limit <= 1000
    ):
        raise ValueError("主机搜索或分页参数无效")
    if group_id is not None and (type(group_id) is not int or group_id < 1):
        raise ValueError("主机组 ID 无效")
    who = access.identity()
    clauses = [
        "enabled=1",
        "asset_type='linux'",
        "host_key!=''",
        "credential_id IS NOT NULL",
    ]
    values = []
    if query:
        clauses.append(
            "(instr(lower(name),lower(?))>0 OR instr(address,?)>0 OR zabbix_hostid=?)"
        )
        values.extend((query, query, query))
    if group_id is not None:
        if not who["all_hosts"] and group_id not in who["group_ids"]:
            raise PermissionError("当前客户端无权访问此主机组")
        clauses.append("id IN (SELECT host_id FROM host_groups WHERE group_id=?)")
        values.append(group_id)
    if not who["all_hosts"]:
        clauses.append(
            "id IN (SELECT host_id FROM host_groups WHERE group_id IN ("
            + ",".join("?" for _ in who["group_ids"])
            + "))"
        )
        values.extend(who["group_ids"])
    with store.db() as c:
        rows = c.execute(
            "SELECT id,name,zabbix_hostid,last_status,revision FROM hosts WHERE "
            + " AND ".join(clauses)
            + " ORDER BY id LIMIT ? OFFSET ?",
            (*values, limit, offset),
        ).fetchall()
        group_rows = (
            c.execute(
                "SELECT hg.host_id,g.id,g.name FROM host_groups hg JOIN groups g ON g.id=hg.group_id WHERE hg.host_id IN ("
                + ",".join("?" for _ in rows)
                + ")",
                [r["id"] for r in rows],
            ).fetchall()
            if rows
            else []
        )
    return [
        {
            **dict(r),
            "groups": [
                {"id": g["id"], "name": g["name"]}
                for g in group_rows
                if g["host_id"] == r["id"]
                and (who["all_hosts"] or g["id"] in who["group_ids"])
            ],
        }
        for r in rows
    ]


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_resolve_host(zabbix_hostid: str) -> dict:
    """按数字 Zabbix Host ID 精确查找授权主机；禁止使用名称或 IP 推测关联，重复映射会拒绝。"""
    return _resolve_host(zabbix_hostid)


def _resolve_host(zabbix_hostid):
    import re

    if not re.fullmatch(r"[0-9]{1,32}", zabbix_hostid):
        raise ValueError("Zabbix Host ID 格式无效")
    with store.db() as c:
        rows = c.execute(
            "SELECT id,name,zabbix_hostid,revision,enabled,host_key,credential_id FROM hosts WHERE zabbix_hostid=?",
            (zabbix_hostid,),
        ).fetchall()
    if len(rows) != 1:
        return {"status": "failed", "error": "映射不存在或存在重复关联，请由管理员修正"}
    host = dict(rows[0])
    if (
        not access.host_allowed(host["id"])
        or not host["enabled"]
        or not host["host_key"]
        or not host["credential_id"]
    ):
        return {"status": "failed", "error": "关联主机未就绪或当前客户端无权访问"}
    return {
        "status": "success",
        "host_id": host["id"],
        "name": host["name"],
        "zabbix_hostid": host["zabbix_hostid"],
        "revision": host["revision"],
    }


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_test_connection(host_id: int, expected_revision: int | None = None) -> dict:
    """通过固定命令对已登记主机验证身份、SSH 登录和远程命令执行。"""
    return _run(host_id, "connection", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_cpu(host_id: int, expected_revision: int | None = None) -> dict:
    """只读查询 Linux CPU 负载、CPU 计数器及 vmstat。"""
    return _run(host_id, "cpu", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_memory(host_id: int, expected_revision: int | None = None) -> dict:
    """只读查询 Linux 物理内存与 Swap 信息。"""
    return _run(host_id, "memory", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_disk(host_id: int, expected_revision: int | None = None) -> dict:
    """只读查询文件系统容量、inode 使用率和挂载信息。"""
    return _run(host_id, "disk", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_processes(host_id: int, expected_revision: int | None = None) -> dict:
    """只读查询占 CPU 较高的 25 个进程信息。"""
    return _run(host_id, "processes", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_io(host_id: int, expected_revision: int | None = None) -> dict:
    """只读查询磁盘 I/O 与累计 /proc/diskstats。"""
    return _run(host_id, "io", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_network(host_id: int, expected_revision: int | None = None) -> dict:
    """只读查询网络接口、路由和协议统计。"""
    return _run(host_id, "network", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_system(host_id: int, expected_revision: int | None = None) -> dict:
    """只读查询内核版本、系统运行时长及负载。"""
    return _run(host_id, "system", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_sockets(host_id: int, expected_revision: int | None = None) -> dict:
    """只读查询系统监听端口概况与 TCP 统计。"""
    return _run(host_id, "sockets", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_service(
    host_id: int, service: str, expected_revision: int | None = None
) -> dict:
    """只读查询指定 systemd 服务状态；服务名需满足严格白名单字符校验。"""
    return _run(
        host_id, "service", service=service, expected_revision=expected_revision
    )


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_logs(
    host_id: int, service: str, minutes: int = 30, expected_revision: int | None = None
) -> dict:
    """只读读取指定 systemd 服务最近 1–120 分钟内的最多 120 行日志。"""
    return _run(
        host_id,
        "logs",
        service=service,
        minutes=minutes,
        expected_revision=expected_revision,
    )


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_directory_usage(
    host_id: int, root: str = "/data", expected_revision: int | None = None
) -> dict:
    """只读扫描指定白名单根目录下一层子目录的磁盘占用排行，支持 /、/data、/var、/var/log、/var/lib、/opt、/home、/tmp、/usr；8 秒超时，结果可能不完整。"""
    return _run(
        host_id, "directory", directory_root=root, expected_revision=expected_revision
    )


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_peer_connections(
    host_id: int, expected_revision: int | None = None
) -> dict:
    """统计当前 Linux TCP 连接按远端 IP 排名，以及其中已建立连接的数量；不表示流量。"""
    return _run(host_id, "peer_connections", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_peer_traffic(
    host_id: int, expected_revision: int | None = None
) -> dict:
    """近 3 秒持续 TCP 会话按远端 IP 的发送/接收字节增量排行。仅在 ss -ti 计数可用时有效；不包含 UDP、短连接及转发流量，也不是历史流量。"""
    return _run(host_id, "peer_traffic", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_health(host_id: int, expected_revision: int | None = None) -> dict:
    """采集负载、内存、Swap、磁盘、inode 与高 CPU 进程的当前快照；不能证明历史故障原因。"""
    return _run(host_id, "health", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_capabilities(
    host_id: int, expected_revision: int | None = None
) -> dict:
    """查看登录 UID 与诊断命令是否安装；命令存在并不代表该账号拥有读取权限，不自动安装软件。"""
    return _run(host_id, "capabilities", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_memory_processes(
    host_id: int, expected_revision: int | None = None
) -> dict:
    """按 RSS 排序查询前 24 个进程，不读取进程环境变量或完整命令行。"""
    return _run(host_id, "memory_processes", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_failed_services(
    host_id: int, expected_revision: int | None = None
) -> dict:
    """列出当前失败的 systemd 服务，最多 60 项，不重启服务。"""
    return _run(host_id, "failed_services", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_containers(host_id: int, expected_revision: int | None = None) -> dict:
    """限时读取 Docker 或 Podman 容器名称、镜像与运行状态，不读取环境变量、不修改或进入容器。"""
    return _run(host_id, "containers", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_kernel(
    host_id: int, minutes: int = 30, expected_revision: int | None = None
) -> dict:
    """只读采集最近 1–120 分钟内最多 100 行内核告警，需要该客户端获授 kernel 权限。"""
    return _run(host_id, "kernel", minutes=minutes, expected_revision=expected_revision)


def _run(
    host_id: int,
    action: str,
    service: str | None = None,
    minutes: int = 30,
    directory_root: str | None = None,
    expected_revision: int | None = None,
    symptom: str | None = None,
) -> dict:
    try:
        if type(host_id) is not int or host_id < 1:
            raise ValueError("主机 ID 必须是正整数")
        if expected_revision is not None and (
            type(expected_revision) is not int or expected_revision < 1
        ):
            raise ValueError("主机版本必须是正整数")
        actor = access.enforce(host_id, action)
        result = jobs.run_inline(
            host_id,
            action,
            actor,
            service,
            minutes,
            directory_root,
            expected_revision=expected_revision,
            symptom=symptom,
        )
        return result
    except Exception as exc:
        # Return bounded, typed error to the model, not a Python traceback or private key.
        error = (
            str(exc)
            if isinstance(
                exc, (ValueError, diagnostics.SSHDiagnosticError, PermissionError)
            )
            else type(exc).__name__
        )
        who = access.principal.get()
        store.audit(
            "mcp:" + (who["id"] if who else "unauthenticated"),
            action,
            str(host_id),
            "failed",
            type(exc).__name__,
        )
        return {
            "host_id": host_id,
            "action": action,
            "status": "failed",
            "error": diagnostics.redact_output(error)[:250],
        }


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_pressure(host_id: int, expected_revision: int | None = None) -> dict:
    """读取内核 PSI CPU/内存/I/O 压力；旧内核不支持时返回能力缺失。"""
    return _run(host_id, "pressure", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_resource_limits(
    host_id: int, expected_revision: int | None = None
) -> dict:
    """读取系统文件句柄、PID 上限及当前 SSH shell 限制，不代表业务进程限制。"""
    return _run(host_id, "resource_limits", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_mounts(host_id: int, expected_revision: int | None = None) -> dict:
    """读取文件系统类型与只读挂载，不返回可能含凭据的挂载选项。"""
    return _run(host_id, "mount_health", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_block_devices(
    host_id: int, expected_revision: int | None = None
) -> dict:
    """读取块设备类型、容量、只读状态与挂载位置，不更改磁盘。"""
    return _run(host_id, "block_devices", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_time_sync(host_id: int, expected_revision: int | None = None) -> dict:
    """读取系统时间、NTP 同步状态及可用的 chrony 跟踪信息。"""
    return _run(host_id, "time_sync", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_tcp_states(host_id: int, expected_revision: int | None = None) -> dict:
    """统计 TCP 各状态连接数量，定位 TIME-WAIT/CLOSE-WAIT 等积压线索。"""
    return _run(host_id, "tcp_states", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_service_inventory(
    host_id: int, expected_revision: int | None = None
) -> dict:
    """读取最多 100 行 systemd 服务清单，包含当前状态，不启动或重启服务。"""
    return _run(host_id, "service_inventory", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_timers(host_id: int, expected_revision: int | None = None) -> dict:
    """读取最多 80 行 systemd timer 的上次/下次运行，不读取用户 cron 脚本。"""
    return _run(host_id, "timers", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_system_errors(
    host_id: int, minutes: int = 30, expected_revision: int | None = None
) -> dict:
    """读取最近 1–120 分钟内最多 100 行 warning 及以上系统日志，输出会脱敏。"""
    return _run(
        host_id, "log_errors", minutes=minutes, expected_revision=expected_revision
    )


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_oom(
    host_id: int, minutes: int = 30, expected_revision: int | None = None
) -> dict:
    """从最近 1–120 分钟最多 300 行内核日志筛选 OOM 线索；没有匹配不代表没有发生 OOM。"""
    return _run(host_id, "oom", minutes=minutes, expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_container_stats(
    host_id: int, expected_revision: int | None = None
) -> dict:
    """限时采集 Docker/Podman 容器 CPU、内存、网络与块 I/O 当前数据，不读取环境变量。"""
    return _run(host_id, "container_stats", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_security_status(
    host_id: int, expected_revision: int | None = None
) -> dict:
    """读取 SELinux、AppArmor 及防火墙服务状态；不是完整安全合规检查。"""
    return _run(host_id, "security_status", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_list_tool_catalog() -> list[dict]:
    """按分类列出当前客户端获准使用的诊断动作及参数要求。"""
    from .catalog import entries

    who = access.identity()
    return [e for e in entries() if e["id"] in who["actions"]]


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_list_groups() -> list[dict]:
    """列出当前客户端授权主机组的 ID 与名称，不返回其他组。"""
    who = access.identity()
    with store.db() as c:
        return [
            dict(r)
            for r in c.execute("SELECT id,name FROM groups ORDER BY name")
            if who["all_hosts"] or r["id"] in who["group_ids"]
        ]


JOB_CONTROL = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False
)


@mcp.tool(annotations=JOB_CONTROL)
@offload
def ssh_submit_diagnostics(
    host_ids: list[int],
    action: str = "health",
    service: str | None = None,
    minutes: int = 30,
    directory_root: str | None = None,
    strict: bool = False,
    symptom: str | None = None,
) -> dict:
    """对 1–100 台授权主机提交后台只读诊断，返回任务 ID；使用 ssh_get_diagnostic_job 逐项查看结果。"""
    if (
        not host_ids
        or len(host_ids) > 100
        or any(type(h) is not int or h < 1 for h in host_ids)
    ):
        raise ValueError("请选择 1–100 台主机")
    who = access.identity()
    if action not in who["actions"]:
        raise PermissionError("该诊断动作未授权")
    actor = "mcp:" + who["id"]
    skipped = [
        {"host_id": h, "reason": "当前客户端无权访问"}
        for h in host_ids
        if not access.host_allowed(h)
    ]
    if strict and skipped:
        raise PermissionError("所选主机包含未授权目标")
    allowed = [h for h in host_ids if access.host_allowed(h)]
    if not allowed:
        return {
            "batch_id": None,
            "job_ids": [],
            "accepted": [],
            "skipped": skipped,
            "total": 0,
        }
    result = jobs.create(
        allowed,
        jobs._request(action, service, minutes, directory_root, symptom),
        actor,
        source="mcp",
        strict=strict,
    )
    result["skipped"].extend(skipped)
    return result


def _owned_job(job_id):
    import re

    if not re.fullmatch(r"[a-f0-9]{32}", job_id):
        raise ValueError("任务 ID 格式无效")
    job = jobs.detail(job_id)
    who = access.identity()
    if job["actor"] != "mcp:" + who["id"]:
        raise PermissionError("只能访问当前客户端提交的诊断任务")
    access.enforce(job["host_id"], job["action"])
    return job


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_get_diagnostic_job(job_id: str) -> dict:
    """查询当前客户端提交且仍在授权范围内的任务状态和采集结果。"""
    job = _owned_job(job_id)
    return {
        k: job[k]
        for k in (
            "id",
            "host_id",
            "action",
            "status",
            "created_at",
            "completed_at",
            "error",
            "result",
        )
    }


@mcp.tool(annotations=JOB_CONTROL)
@offload
def ssh_cancel_diagnostic_job(job_id: str) -> dict:
    """取消当前客户端自己的排队/运行诊断；已采集数据保留，不修改目标主机。"""
    job = _owned_job(job_id)
    return jobs.cancel(job_id, actor=job["actor"])


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_triage(
    host_id: int,
    symptom: str,
    service: str | None = None,
    minutes: int = 30,
    expected_revision: int | None = None,
) -> dict:
    """同一 SSH 会话顺序执行固定组合。symptom: cpu_high/mem_high/disk_full/io_slow/service_down/network。需独立 triage 授权；service_down 必须指定服务。"""
    return _run(
        host_id,
        "triage",
        service=service,
        minutes=minutes,
        expected_revision=expected_revision,
        symptom=symptom,
    )


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_resolve_hosts(zabbix_hostids: list[str]) -> dict:
    """批量按精确 Zabbix Host ID 解析，最多 100 个；逐项返回映射或不可用原因。"""
    if not zabbix_hostids or len(zabbix_hostids) > 100:
        raise ValueError("请选择 1–100 个 Host ID")
    access.identity()
    return {
        "items": [
            {"zabbix_hostid": ident, **_resolve_host(ident)}
            for ident in dict.fromkeys(zabbix_hostids)
        ]
    }


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_get_diagnostic_batch(batch_id: str, page: int = 1, page_size: int = 25) -> dict:
    """分页查看本客户端提交的批次计数、逐主机状态与 findings；再次检查当前授权，默认不带原文。"""
    who = access.identity()
    batch = jobs.batch_detail(batch_id, page, page_size, actor="mcp:" + who["id"])
    with store.db() as c:
        targets = c.execute(
            "SELECT host_id,action FROM diagnostic_jobs WHERE batch_id=?", (batch_id,)
        ).fetchall()
    for host in targets:
        access.enforce(host["host_id"], host["action"])
    return batch

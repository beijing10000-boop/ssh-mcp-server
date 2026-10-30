"""可由任何 MCP 客户端独立调用的安全 SSH 工具集。"""

from __future__ import annotations

import asyncio
import inspect
from typing import Annotated, Literal
from functools import wraps

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field
from . import store, diagnostics, access, jobs, observations
from .extensions import collect as collect_spec

mcp = FastMCP(
    "Linux SSH 智能诊断",
    instructions=(
        "本服务仅对预先登记和核验的内网 Linux 主机执行固定只读诊断。"
        "禁止臆测主机 ID，先通过 ssh_resolve_target、ssh_resolve_host 或 ssh_list_hosts 精确核验。"
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
        "ssh_collect",
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
    """列出当前启用且已经审核的 Linux SSH 主机，返回 ID、名称、登记 IP、Host ID、版本与连接状态，不暴露密钥。"""
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
            "SELECT id,name,address,zabbix_hostid,last_status,revision FROM hosts WHERE "
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
def ssh_resolve_target(address: str) -> dict:
    """按已登记内网 IP 精确定位授权 Linux 主机；只读资产库，不连接任意地址，不依赖 Zabbix。"""
    address = store.private_ip(address)
    with store.db() as c:
        row = c.execute(
            "SELECT id,name,address,zabbix_hostid,revision,enabled,host_key,credential_id,asset_type,mode FROM hosts WHERE address=?",
            (address,),
        ).fetchone()
    if not row or not access.host_allowed(row["id"]):
        return {
            "status": "failed",
            "error": "主机不存在、未就绪或不在当前客户端授权范围内",
            "error_code": "unavailable",
        }
    host = dict(row)
    return _not_ready(host) or {
        "status": "success",
        "host_id": host["id"],
        "name": host["name"],
        "address": host["address"],
        "zabbix_hostid": host["zabbix_hostid"],
        "revision": host["revision"],
        "device_type": "linux",
        "asset_type": host["asset_type"],
        "mode": host.get("mode") or "standard",
    }


def _not_ready(host):
    """Structured refusal for an authorized but unusable asset.

    `not_linux` lets an AI platform pick the Zabbix-only path for Windows or
    network devices; `not_ready` marks a Linux host that is registered but not
    yet verified or bound. Unknown or unauthorized hosts stay `unavailable`.
    """
    if host["asset_type"] != "linux":
        return {
            "status": "failed",
            "error": f"该资产类型为 {host['asset_type']}，不支持 Linux SSH 诊断",
            "error_code": "not_linux",
            "asset_type": host["asset_type"],
            "name": host["name"],
        }
    if not host["enabled"] or not host["host_key"] or not host["credential_id"]:
        reason = (
            "主机已停用"
            if not host["enabled"]
            else "主机公钥尚未核验"
            if not host["host_key"]
            else "主机尚未绑定 SSH 凭据"
        )
        return {
            "status": "failed",
            "error": "Linux 主机已登记但尚未就绪：" + reason,
            "error_code": "not_ready",
            "asset_type": "linux",
            "name": host["name"],
        }
    return None


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
            "SELECT id,name,address,zabbix_hostid,revision,enabled,host_key,credential_id,asset_type,mode FROM hosts WHERE zabbix_hostid=?",
            (zabbix_hostid,),
        ).fetchall()
    if len(rows) != 1:
        return {
            "status": "failed",
            "error": "映射不存在或存在重复关联，请由管理员修正",
            "error_code": "mapping_unresolved",
        }
    host = dict(rows[0])
    if not access.host_allowed(host["id"]):
        return {
            "status": "failed",
            "error": "关联主机未就绪或当前客户端无权访问",
            "error_code": "unavailable",
        }
    return _not_ready(host) or {
        "status": "success",
        "host_id": host["id"],
        "name": host["name"],
        "address": host["address"],
        "device_type": "linux",
        "asset_type": host["asset_type"],
        "mode": host.get("mode") or "standard",
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
    """按 RSS 排序查询前 24 个进程，可识别的 Java JAR/服务单元给出安全应用名称，不返回完整命令行或进程环境变量。"""
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
    options: dict | None = None,
    enforce: tuple[str, ...] | None = None,
) -> dict:
    try:
        if type(host_id) is not int or host_id < 1:
            raise ValueError("主机 ID 必须是正整数")
        if expected_revision is not None and (
            type(expected_revision) is not int or expected_revision < 1
        ):
            raise ValueError("主机版本必须是正整数")
        # A multi-step collection is authorized per step, never as a whole.
        for step in enforce or (action,):
            actor = access.enforce(host_id, step)
        result = jobs.run_inline(
            host_id,
            action,
            actor,
            service,
            minutes,
            directory_root,
            expected_revision=expected_revision,
            symptom=symptom,
            options=options,
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
        code = error_code(exc, error)
        # The same parameter summary as a successful job (actions=, minutes=…);
        # values that failed validation are not echoed into the audit trail.
        detail = (
            jobs.audit_detail(
                {
                    "service": service,
                    "minutes": minutes,
                    "directory_root": directory_root,
                    "options": options,
                }
            )
            if code != "invalid_argument"
            else ""
        )
        store.audit(
            "mcp:" + (who["id"] if who else "unauthenticated"),
            action,
            str(host_id),
            "failed",
            (type(exc).__name__ + ";" + code + ";" + detail)[:240],
        )
        return {
            "host_id": host_id,
            "action": action,
            "status": "failed",
            "error": diagnostics.redact_output(error)[:250],
            "error_code": code,
        }


ERROR_CODES = (
    ("繁忙", "busy"),
    ("超时", "timeout"),
    ("已变更", "revision_changed"),
    ("取消", "cancelled"),
    ("公钥", "host_unverified"),
    ("网关", "unsupported"),
    ("尚未就绪", "not_ready"),
    ("不支持 Linux", "not_linux"),
)


def error_code(exc, message):
    """Stable machine-readable failure class; `error` stays human readable.

    Messages are matched before the generic ValueError class so that a stale
    revision or an unverified host key raised while creating the job keeps
    its specific code instead of `invalid_argument`.
    """
    if isinstance(exc, PermissionError):
        return "forbidden"
    matched = next((code for word, code in ERROR_CODES if word in message), None)
    if matched:
        return matched
    if isinstance(exc, ValueError):
        return "invalid_argument"
    return "failed"


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


def _options(**values) -> dict:
    """Only explicitly given parameters; the registry fills documented defaults."""
    return {key: value for key, value in values.items() if value is not None}


Minutes = Annotated[
    int, Field(ge=1, le=1440, description="回溯窗口（分钟）；给出 since/until 时忽略")
]
Since = Annotated[
    int | None,
    Field(ge=0, description="窗口开始（Unix 秒）；告警诊断取告警时间前 15 分钟"),
]
Until = Annotated[
    int | None,
    Field(
        ge=0,
        description="窗口结束（Unix 秒）；缺省为当前时间，与 since 相距最多 24 小时",
    ),
]
Revision = Annotated[
    int | None, Field(ge=1, description="解析主机时取得的 revision；不一致则拒绝执行")
]


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_nginx(
    host_id: int, minutes: Minutes = 30, expected_revision: Revision = None
) -> dict:
    """发现 Nginx 二进制、配置、access/error 日志路径与轮转文件，读取 nginx 进程、监听端口、systemd 状态和 upstream/超时配置摘要，并统计最近 minutes 分钟 error.log 的级别分布、上游超时/连接失败/无可用上游、worker_connections 不足等线索及代表性日志行；不修改配置、不重载服务。"""
    return _run(
        host_id,
        "nginx",
        expected_revision=expected_revision,
        options=_options(minutes=minutes),
    )


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_nginx_access(
    host_id: int,
    minutes: Minutes = 30,
    since: Since = None,
    until: Until = None,
    path: Annotated[
        str | None,
        Field(
            max_length=200,
            description="访问日志路径；只接受 Nginx 配置中声明的 access_log 或标准日志目录下的文件，缺省自动选择",
        ),
    ] = None,
    status: Annotated[
        str | None,
        Field(
            pattern=r"^(all|[2-5]xx|[1-5][0-9]{2})$",
            description="只统计该状态的请求 TOP：all、4xx、5xx 或具体状态码（如 502）",
        ),
    ] = None,
    keyword: Annotated[
        str | None,
        Field(max_length=64, description="按原文子串过滤请求行（URL、IP、UA 等）"),
    ] = None,
    top: Annotated[int, Field(ge=5, le=30, description="TOP 条数")] = 10,
    expected_revision: Revision = None,
) -> dict:
    """在远端用 awk 聚合 Nginx 访问日志：时间窗口（minutes，或 since/until Unix 秒，最长 24 小时）内的请求总数、状态码分布（2xx/3xx/4xx/5xx 与具体码）、错误请求 TOP URL / 客户端 IP / User-Agent、每分钟请求与 5xx 趋势、request_time 与 upstream_response_time 统计（日志格式含这些字段时）。只读取文件尾部有限字节，不返回整份日志；窗口被轮转文件切断时说明覆盖范围。"""
    return _run(
        host_id,
        "nginx_access",
        expected_revision=expected_revision,
        options=_options(
            minutes=minutes,
            since=since,
            until=until,
            path=path,
            status=status,
            keyword=keyword,
            top=top,
        ),
    )


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_syslog(
    host_id: int,
    minutes: Minutes = 30,
    since: Since = None,
    until: Until = None,
    unit: Annotated[
        str | None,
        Field(
            pattern=r"^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}$",
            description="只看该 systemd 单元（如 nginx.service）",
        ),
    ] = None,
    priority: Annotated[
        Literal["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"],
        Field(description="最低级别（journalctl -p）；回退到文件日志时按关键字近似"),
    ] = "warning",
    keyword: Annotated[
        str | None, Field(max_length=64, description="按子串过滤（不区分大小写）")
    ] = None,
    pid: Annotated[
        int | None, Field(ge=1, le=4194304, description="只看该进程的日志")
    ] = None,
    lines: Annotated[
        int, Field(ge=20, le=300, description="返回的代表性日志上限")
    ] = 120,
    expected_revision: Revision = None,
) -> dict:
    """按时间窗口读取系统日志：优先 journalctl（unit、priority、keyword、pid 过滤），journald 不可用、无权限或未覆盖该窗口时回退 /var/log/messages、syslog、secure、auth.log 并说明来源。返回按级别/单元的计数，OOM、磁盘 I/O 错误、网络链路、服务启动失败、内核异常与登录失败等分类线索，以及代表性日志行；输出脱敏；空结果会区分“无日志”与“无权限”。"""
    return _run(
        host_id,
        "syslog",
        expected_revision=expected_revision,
        options=_options(
            minutes=minutes,
            since=since,
            until=until,
            unit=unit,
            priority=priority,
            keyword=keyword,
            pid=pid,
            lines=lines,
        ),
    )


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_java(host_id: int, expected_revision: Revision = None) -> dict:
    """盘点 Java 进程（最多 20 个）：PID、用户、运行时长、RSS、CPU/内存占比、线程数、打开文件数、对应 systemd 单元、JAR 或主类、应用名（spring.application.name / -Dapp 等）、-Xms/-Xmx/-Xss 与 GC/元空间参数、GC 日志与应用日志位置、JDK 路径与版本；启动命令中的密码、Token、密钥等敏感参数自动脱敏，完整启动命令仅在 detail=full 时附带。只读 /proc、cgroup 内存上限与 JDK release 文件，不附加到 JVM。"""
    return _run(host_id, "java", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_jvm(
    host_id: int,
    pid: Annotated[int, Field(ge=1, le=4194304, description="Java 进程 PID")],
    probes: Annotated[
        list[Literal["heap_info", "vm_flags", "gc_stat", "gc_log"]] | None,
        Field(description="探针列表，缺省 heap_info、vm_flags、gc_stat"),
    ] = None,
    expected_revision: Revision = None,
) -> dict:
    """对指定 Java 进程执行有界 JVM 探针：heap_info（jcmd GC.heap_info，各代用量）、vm_flags（jcmd VM.flags，生效的堆与 GC 参数）、gc_stat（jstat -gc，GC 次数与累计耗时）、gc_log（GC 日志尾部 40 行）。jcmd 会短暂进入安全点，属中等开销，生产高峰期谨慎使用；缺少 jcmd/jstat 或无法以 JVM 所属用户附加时返回能力缺失。不捕获 SIGQUIT（-Xrs、jsvc 父进程）或禁用 attach 的进程跳过 jcmd，以免终止进程；GC 日志只在文件属主与 JVM 用户一致时读取。"""
    return _run(
        host_id,
        "jvm",
        expected_revision=expected_revision,
        options=_options(pid=pid, probes=probes),
    )


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_service_detail(
    host_id: int,
    service: Annotated[
        str,
        Field(
            pattern=r"^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}$",
            description="systemd 单元名，如 nginx.service、app@1.service",
        ),
    ],
    minutes: Minutes = 30,
    expected_revision: Revision = None,
) -> dict:
    """指定 systemd 服务的深度诊断：状态、Result、退出码、重启次数与重启策略、启动时间、MainPID、内存/任务数、启动命令（ExecStart）、运行用户与工作目录、单元文件与 drop-in、cgroup 内进程、监听端口、最近 minutes 分钟日志，以及近 24 小时的异常退出/重启记录；单元不存在时明确返回 unit_not_found，不会把不存在的单元说成“已停止”。不启动、不重启、不修改服务。"""
    return _run(
        host_id,
        "service_detail",
        expected_revision=expected_revision,
        options=_options(service=service, minutes=minutes),
    )


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_diagnose_service_map(host_id: int, expected_revision: Revision = None) -> dict:
    """服务发现：监听端口 → 进程（PID、程序名、用户）→ systemd 单元 / 容器的映射（最多 80 行），附进程 RSS 与运行时长；用于定位“哪个服务占用哪个端口”和“端口是否在监听”。"""
    return _run(host_id, "service_map", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_collect(
    host_id: int,
    actions: Annotated[
        list[Literal[collect_spec.COLLECTABLE]],
        Field(min_length=1, max_length=6, description="按顺序执行的固定诊断动作"),
    ],
    service: Annotated[
        str | None,
        Field(
            pattern=r"^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}$",
            description="service / logs 步骤的 systemd 单元名",
        ),
    ] = None,
    minutes: Annotated[
        int, Field(ge=1, le=120, description="日志类步骤的回溯窗口（分钟）")
    ] = 30,
    expected_revision: Revision = None,
) -> dict:
    """在一次 SSH 会话内顺序执行 1–6 个固定诊断（如 cpu、processes、pressure），每个步骤单独返回 exit_code、summary 与 findings，并合并为带 source_action 的总 findings；比逐个调用更快，且不会因同主机互斥而排队。每个步骤都需要本客户端已获得该动作的授权。"""
    steps = list(dict.fromkeys(actions or []))
    return _run(
        host_id,
        "collect",
        expected_revision=expected_revision,
        options=_options(actions=steps, service=service, minutes=minutes),
        enforce=tuple(steps) or ("collect",),
    )


@mcp.tool(annotations=READ_ONLY)
@offload
def ssh_list_tool_catalog() -> list[dict]:
    """按分类列出当前客户端获准使用的诊断动作、参数结构（params）与风险等级。"""
    from .catalog import entries

    who = access.identity()
    granted = set(who["actions"])
    return [
        e
        for e in entries()
        if e["id"] in granted
        # The multi-step collector is usable whenever any step is granted.
        or (e["id"] == "collect" and granted & set(collect_spec.COLLECTABLE))
    ]


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

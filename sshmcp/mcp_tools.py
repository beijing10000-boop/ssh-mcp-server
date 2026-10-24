"""可由任何 MCP 客户端独立调用的安全 SSH 工具集。"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from . import store, diagnostics, access, jobs

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


@mcp.tool(annotations=READ_ONLY)
def ssh_list_hosts(query: str = "", offset: int = 0, limit: int = 100) -> list[dict]:
    """列出当前启用且已经审核的 Linux SSH 主机，返回 ID、名称、Host ID 与连接状态，不暴露密钥。"""
    if (
        len(query) > 160
        or type(offset) is not int
        or offset < 0
        or type(limit) is not int
        or not 1 <= limit <= 1000
    ):
        raise ValueError("主机搜索或分页参数无效")
    who = access.identity()
    clauses = ["enabled=1", "host_key!=''", "credential_id IS NOT NULL"]
    values = []
    if query:
        clauses.append("(instr(lower(name),lower(?))>0 OR zabbix_hostid=?)")
        values.extend((query, query))
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
    return [dict(r) for r in rows]


@mcp.tool(annotations=READ_ONLY)
def ssh_resolve_host(zabbix_hostid: str) -> dict:
    """按数字 Zabbix Host ID 精确查找授权主机；禁止使用名称或 IP 推测关联，重复映射会拒绝。"""
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
def ssh_test_connection(host_id: int, expected_revision: int | None = None) -> dict:
    """通过固定命令对已登记主机验证身份、SSH 登录和远程命令执行。"""
    return _run(host_id, "connection", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
def ssh_diagnose_cpu(host_id: int, expected_revision: int | None = None) -> dict:
    """只读查询 Linux CPU 负载、CPU 计数器及 vmstat。"""
    return _run(host_id, "cpu", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
def ssh_diagnose_memory(host_id: int, expected_revision: int | None = None) -> dict:
    """只读查询 Linux 物理内存与 Swap 信息。"""
    return _run(host_id, "memory", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
def ssh_diagnose_disk(host_id: int, expected_revision: int | None = None) -> dict:
    """只读查询文件系统容量、inode 使用率和挂载信息。"""
    return _run(host_id, "disk", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
def ssh_diagnose_processes(host_id: int, expected_revision: int | None = None) -> dict:
    """只读查询占 CPU 较高的 25 个进程信息。"""
    return _run(host_id, "processes", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
def ssh_diagnose_io(host_id: int, expected_revision: int | None = None) -> dict:
    """只读查询磁盘 I/O 与累计 /proc/diskstats。"""
    return _run(host_id, "io", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
def ssh_diagnose_network(host_id: int, expected_revision: int | None = None) -> dict:
    """只读查询网络接口、路由和协议统计。"""
    return _run(host_id, "network", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
def ssh_diagnose_system(host_id: int, expected_revision: int | None = None) -> dict:
    """只读查询内核版本、系统运行时长及负载。"""
    return _run(host_id, "system", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
def ssh_diagnose_sockets(host_id: int, expected_revision: int | None = None) -> dict:
    """只读查询系统监听端口概况与 TCP 统计。"""
    return _run(host_id, "sockets", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
def ssh_diagnose_service(
    host_id: int, service: str, expected_revision: int | None = None
) -> dict:
    """只读查询指定 systemd 服务状态；服务名需满足严格白名单字符校验。"""
    return _run(
        host_id, "service", service=service, expected_revision=expected_revision
    )


@mcp.tool(annotations=READ_ONLY)
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
def ssh_diagnose_directory_usage(
    host_id: int, root: str = "/data", expected_revision: int | None = None
) -> dict:
    """只读扫描指定白名单根目录下一层子目录的磁盘占用排行，支持 /、/data、/var、/var/log、/var/lib、/opt、/home、/tmp、/usr；8 秒超时，结果可能不完整。"""
    return _run(
        host_id, "directory", directory_root=root, expected_revision=expected_revision
    )


@mcp.tool(annotations=READ_ONLY)
def ssh_diagnose_peer_connections(
    host_id: int, expected_revision: int | None = None
) -> dict:
    """统计当前 Linux TCP 连接按远端 IP 排名，以及其中已建立连接的数量；不表示流量。"""
    return _run(host_id, "peer_connections", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
def ssh_diagnose_peer_traffic(
    host_id: int, expected_revision: int | None = None
) -> dict:
    """近 3 秒持续 TCP 会话按远端 IP 的发送/接收字节增量排行。仅在 ss -ti 计数可用时有效；不包含 UDP、短连接及转发流量，也不是历史流量。"""
    return _run(host_id, "peer_traffic", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
def ssh_diagnose_health(host_id: int, expected_revision: int | None = None) -> dict:
    """采集负载、内存、Swap、磁盘、inode 与高 CPU 进程的当前快照；不能证明历史故障原因。"""
    return _run(host_id, "health", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
def ssh_diagnose_capabilities(
    host_id: int, expected_revision: int | None = None
) -> dict:
    """查看登录 UID 与诊断命令是否安装；命令存在并不代表该账号拥有读取权限，不自动安装软件。"""
    return _run(host_id, "capabilities", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
def ssh_diagnose_memory_processes(
    host_id: int, expected_revision: int | None = None
) -> dict:
    """按 RSS 排序查询前 24 个进程，不读取进程环境变量或完整命令行。"""
    return _run(host_id, "memory_processes", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
def ssh_diagnose_failed_services(
    host_id: int, expected_revision: int | None = None
) -> dict:
    """列出当前失败的 systemd 服务，最多 60 项，不重启服务。"""
    return _run(host_id, "failed_services", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
def ssh_diagnose_containers(host_id: int, expected_revision: int | None = None) -> dict:
    """限时读取 Docker 或 Podman 容器名称、镜像与运行状态，不读取环境变量、不修改或进入容器。"""
    return _run(host_id, "containers", expected_revision=expected_revision)


@mcp.tool(annotations=READ_ONLY)
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

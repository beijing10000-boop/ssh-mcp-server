"""可由任何 MCP 客户端独立调用的安全 SSH 工具集。"""
from __future__ import annotations

from mcp.server.fastmcp import FastMCP
from . import store, diagnostics

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


@mcp.tool()
def ssh_list_hosts() -> list[dict]:
    """列出当前启用且已经审核的 Linux SSH 主机，返回 ID、名称、Host ID 与连接状态，不暴露密钥。"""
    with store.db() as c:
        rows = c.execute(
            "SELECT id,name,address,zabbix_hostid,last_status FROM hosts "
            "WHERE enabled=1 AND host_key!='' ORDER BY name LIMIT 1000"
        ).fetchall()
    return [dict(r) for r in rows]


@mcp.tool()
def ssh_test_connection(host_id: int) -> dict:
    """通过固定命令对已登记主机验证身份、SSH 登录和远程命令执行。"""
    return _run(host_id, "connection")


@mcp.tool()
def ssh_diagnose_cpu(host_id: int) -> dict:
    """只读查询 Linux CPU 负载、CPU 计数器及 vmstat。"""
    return _run(host_id, "cpu")


@mcp.tool()
def ssh_diagnose_memory(host_id: int) -> dict:
    """只读查询 Linux 物理内存与 Swap 信息。"""
    return _run(host_id, "memory")


@mcp.tool()
def ssh_diagnose_disk(host_id: int) -> dict:
    """只读查询文件系统容量、inode 使用率和挂载信息。"""
    return _run(host_id, "disk")


@mcp.tool()
def ssh_diagnose_processes(host_id: int) -> dict:
    """只读查询占 CPU 较高的 25 个进程信息。"""
    return _run(host_id, "processes")


@mcp.tool()
def ssh_diagnose_io(host_id: int) -> dict:
    """只读查询磁盘 I/O 与累计 /proc/diskstats。"""
    return _run(host_id, "io")


@mcp.tool()
def ssh_diagnose_network(host_id: int) -> dict:
    """只读查询网络接口、路由和协议统计。"""
    return _run(host_id, "network")


@mcp.tool()
def ssh_diagnose_system(host_id: int) -> dict:
    """只读查询内核版本、系统运行时长及负载。"""
    return _run(host_id, "system")


@mcp.tool()
def ssh_diagnose_sockets(host_id: int) -> dict:
    """只读查询系统监听端口概况与 TCP 统计。"""
    return _run(host_id, "sockets")


@mcp.tool()
def ssh_diagnose_service(host_id: int, service: str) -> dict:
    """只读查询指定 systemd 服务状态；服务名需满足严格白名单字符校验。"""
    return _run(host_id, "service", service=service)


@mcp.tool()
def ssh_diagnose_logs(host_id: int, service: str, minutes: int = 30) -> dict:
    """只读读取指定 systemd 服务最近 1–120 分钟内的最多 120 行日志。"""
    return _run(host_id, "logs", service=service, minutes=minutes)


@mcp.tool()
def ssh_diagnose_directory_usage(host_id: int, root: str = "/data") -> dict:
    """只读扫描指定白名单根目录下一层子目录的磁盘占用排行，支持 /、/data、/var、/var/log、/var/lib、/opt、/home、/tmp、/usr；8 秒超时，结果可能不完整。"""
    return _run(host_id, "directory", directory_root=root)


@mcp.tool()
def ssh_diagnose_peer_connections(host_id: int) -> dict:
    """统计当前 Linux TCP 连接按远端 IP 排名，以及其中已建立连接的数量；不表示流量。"""
    return _run(host_id, "peer_connections")


@mcp.tool()
def ssh_diagnose_peer_traffic(host_id: int) -> dict:
    """近 3 秒持续 TCP 会话按远端 IP 的发送/接收字节增量排行。仅在 ss -ti 计数可用时有效；不包含 UDP、短连接及转发流量，也不是历史流量。"""
    return _run(host_id, "peer_traffic")


def _run(host_id: int, action: str, service: str | None = None, minutes: int = 30, directory_root: str | None = None) -> dict:
    try:
        result = diagnostics.execute(host_id, action, service, minutes, directory_root=directory_root)
        store.audit("mcp", action, str(host_id), result["status"], "exit=" + str(result["exit_code"]))
        return result
    except Exception as exc:
        # Return bounded, typed error to the model, not a Python traceback or private key.
        error = exc.args[0] if isinstance(exc, (ValueError, diagnostics.SSHDiagnosticError)) else type(exc).__name__
        store.audit("mcp", action, str(host_id), "failed", type(exc).__name__)
        return {"host_id": host_id, "action": action, "status": "failed", "error": str(error)[:250]}

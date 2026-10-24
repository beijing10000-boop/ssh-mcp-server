"""Shared, explicit tool catalogue for Web, scoped clients and MCP adapters."""

TITLES = {
    "connection": "SSH 连接测试",
    "health": "主机健康概览",
    "capabilities": "采集能力检查",
    "cpu": "CPU 负载",
    "memory": "内存与 Swap",
    "processes": "CPU 进程排行",
    "memory_processes": "内存进程排行",
    "disk": "磁盘与 inode",
    "directory": "目录空间排行",
    "io": "磁盘 I/O",
    "network": "网络接口",
    "sockets": "监听端口",
    "peer_connections": "远端 IP 连接数",
    "peer_traffic": "远端 IP 流量采样",
    "system": "系统信息",
    "service": "指定服务状态",
    "failed_services": "异常服务",
    "logs": "服务日志",
    "kernel": "内核告警",
    "containers": "容器运行状态",
}
SENSITIVE = {"logs", "kernel", "directory", "peer_traffic"}


def entries():
    return [
        {
            "id": action,
            "name": name,
            "sensitive": action in SENSITIVE,
            "service_required": action in {"service", "logs"},
            "directory_required": action == "directory",
            "window_required": action in {"logs", "kernel"},
        }
        for action, name in TITLES.items()
    ]

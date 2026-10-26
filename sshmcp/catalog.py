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
    "pressure": "CPU / 内存 / I/O 压力",
    "resource_limits": "文件句柄与资源限制",
    "mount_health": "挂载与只读文件系统",
    "block_devices": "块设备与磁盘结构",
    "time_sync": "时间与 NTP 同步",
    "tcp_states": "TCP 连接状态分布",
    "service_inventory": "系统服务清单",
    "timers": "定时任务与下次运行",
    "log_errors": "系统告警日志",
    "oom": "内存不足与 OOM 记录",
    "container_stats": "容器资源使用",
    "security_status": "安全组件状态",
}
SENSITIVE = {"logs", "kernel", "directory", "peer_traffic", "log_errors", "oom"}
CATEGORIES = {
    "连接与概览": {"connection", "health", "capabilities", "system"},
    "性能与进程": {
        "cpu",
        "memory",
        "processes",
        "memory_processes",
        "pressure",
        "resource_limits",
    },
    "存储": {"disk", "directory", "io", "mount_health", "block_devices"},
    "网络": {"network", "sockets", "peer_connections", "peer_traffic", "tcp_states"},
    "服务与日志": {
        "service",
        "failed_services",
        "logs",
        "kernel",
        "service_inventory",
        "timers",
        "log_errors",
        "oom",
    },
    "系统与容器": {"containers", "container_stats", "time_sync", "security_status"},
}


def entries():
    from .diagnostics import STANDARD_ONLY

    return [
        {
            "id": action,
            "name": name,
            "sensitive": action in SENSITIVE,
            "service_required": action in {"service", "logs"},
            "directory_required": action == "directory",
            "window_required": action in {"logs", "kernel", "log_errors", "oom"},
            "category": next(k for k, v in CATEGORIES.items() if action in v),
            "standard_only": action in STANDARD_ONLY,
        }
        for action, name in TITLES.items()
    ]

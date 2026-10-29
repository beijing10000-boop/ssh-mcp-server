"""Shared, explicit tool catalogue for Web, scoped clients and MCP adapters."""

TITLES = {
    "triage": "组合场景诊断",
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
SENSITIVE = {
    "triage",
    "logs",
    "kernel",
    "directory",
    "peer_traffic",
    "log_errors",
    "oom",
}
CATEGORIES = {
    "连接与概览": {"connection", "health", "capabilities", "system", "triage"},
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


QUESTIONS = {
    "triage": "按故障场景一次收集多项固定证据，并汇总排查线索",
    "connection": "是否能严格校验主机身份、登录并执行 Linux 命令？",
    "health": "负载、可用内存和磁盘当前是否触发基础阈值？",
    "capabilities": "诊断依赖的命令是否存在，当前登录 UID 是什么？",
    "cpu": "负载相对核数是否偏高，vmstat 是否显示任务等待？",
    "memory": "可用内存是否不足，是否存在 Swap 占用？",
    "processes": "哪些进程占用 CPU 较多？",
    "memory_processes": "哪些进程 RSS 内存占用较高？",
    "disk": "哪些本地文件系统容量或 inode 接近耗尽？",
    "directory": "白名单目录下一层的空间主要被谁占用？",
    "io": "设备忙碌度和等待情况如何；缺少 iostat 时返回累计计数",
    "network": "接口、路由和累计错误/丢包计数如何？",
    "sockets": "当前监听端口和 TCP 套接字概况如何？",
    "peer_connections": "当前哪些远端 IP 的 TCP 连接数量最多？",
    "peer_traffic": "持续 TCP 会话的 3 秒字节增量主要来自哪些远端？",
    "system": "内核、运行时长和当前负载如何？",
    "service": "指定 systemd 服务是否运行、上次退出原因是什么？",
    "failed_services": "当前有哪些 systemd 服务处于失败状态？",
    "logs": "指定服务在时间窗口内最近有哪些日志？",
    "kernel": "近期内核有哪些 warning 及以上消息？",
    "containers": "容器的名称、镜像与当前运行/退出状态如何？",
    "pressure": "CPU、内存或 I/O 是否导致任务阻塞（PSI）？",
    "resource_limits": "系统文件句柄是否接近上限，本 SSH shell 的限制是什么？",
    "mount_health": "挂载类型与只读文件系统有哪些？",
    "block_devices": "块设备容量、类型与只读属性如何？",
    "time_sync": "系统是否报告 NTP 已同步，chrony 状态如何？",
    "tcp_states": "TCP 各状态数量如何，是否有 CLOSE-WAIT 积压线索？",
    "service_inventory": "系统服务当前状态清单是什么？",
    "timers": "systemd timer 上次和下次运行时间是什么？",
    "log_errors": "时间窗口内有哪些系统 warning 及以上消息？",
    "oom": "时间窗口内是否返回 OOM 或 Killed process 线索？",
    "container_stats": "容器当前 CPU、内存和 I/O 用量如何？",
    "security_status": "SELinux、AppArmor 与各防火墙服务状态如何？",
}


# MCP tool per action; all others are named ssh_diagnose_<action>. Clients filter
# their tool list by `tool` so they never offer an action this token cannot run.
TOOLS = {
    "connection": "ssh_test_connection",
    "triage": "ssh_triage",
    "directory": "ssh_diagnose_directory_usage",
    "mount_health": "ssh_diagnose_mounts",
    "log_errors": "ssh_diagnose_system_errors",
}


def tool_name(action):
    return TOOLS.get(action, "ssh_diagnose_" + action)


def entries():
    from .diagnostics import STANDARD_ONLY

    return [
        {
            "id": action,
            "tool": tool_name(action),
            "name": name,
            "question": QUESTIONS[action],
            "estimated_seconds": 60 if action == "triage" else 20,
            "duration_hint": "组合最多 60 秒"
            if action == "triage"
            else "通常 1–8 秒，最多 20 秒",
            "parameters": (
                ["故障场景", "服务异常场景需服务名", "时间窗口"]
                if action == "triage"
                else (["服务名"] if action in {"service", "logs"} else [])
                + (
                    ["时间窗口 1–120 分钟"]
                    if action in {"logs", "kernel", "log_errors", "oom"}
                    else []
                )
                + (["白名单目录"] if action == "directory" else [])
            ),
            "sensitive": action in SENSITIVE,
            "service_required": action in {"service", "logs"},
            "directory_required": action == "directory",
            "window_required": action in {"logs", "kernel", "log_errors", "oom"},
            "category": next(k for k, v in CATEGORIES.items() if action in v),
            "standard_only": action in STANDARD_ONLY,
        }
        for action, name in TITLES.items()
    ]

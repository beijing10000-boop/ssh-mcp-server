"""只读空间与连接分析：只解析内核现有统计，不修改目标主机。"""

from __future__ import annotations

from collections import defaultdict
import ipaddress
import re

# 固定扫描根路径，不能通过工具输入任意磁盘路径。
DIRECTORY_ROOTS = (
    "/",
    "/data",
    "/var",
    "/var/log",
    "/var/lib",
    "/opt",
    "/home",
    "/root",
    "/tmp",
    "/usr",
)


def validate_directory_root(root: str | None) -> str:
    """Accept bounded absolute paths under whitelisted roots; reject path traversal."""
    if not isinstance(root, str) or len(root) > 120:
        raise ValueError("目录路径长度不正确")
    if root == "/":
        return root
    if not re.fullmatch(
        r"/(?:data|var|opt|home|root|tmp|usr)(?:/[A-Za-z0-9._-]+){0,6}", root
    ):
        raise ValueError("目录须位于 /data、/var、/opt、/home、/root、/tmp 或 /usr 下")
    if any(segment in (".", "..") for segment in root.split("/")):
        raise ValueError("目录路径禁止 . 或 .. 等跳转")
    return root


_SS_COUNTER = re.compile(r"^(bytes_sent|bytes_received):([0-9]+)$")
_SAMPLE_MARKER = re.compile(r"^__SAMPLE_([AB])__$")


def parse_directory(text: str, root: str) -> dict:
    """Parse du -B1 -x -d1. Data is disk allocated bytes, not logical file sizes."""
    rows = []
    for line in text.splitlines():
        if "\t" not in line:
            continue
        size, path = line.split("\t", 1)
        if not size.isdecimal() or not path.startswith("/"):
            continue
        rows.append({"directory": path, "bytes": int(size)})
    root_total = next(
        (item["bytes"] for item in rows if item["directory"] == root), None
    )
    children = [r for r in rows if r["directory"] != root]
    children.sort(key=lambda item: item["bytes"], reverse=True)
    return {
        "root": root,
        "scanned_root_bytes": root_total,
        "top_directories": children[:30],
        "ranking_scope": "根目录的直接子目录（-x：只统计同一文件系统）",
        "notes": [
            "du 统计已分配磁盘空间，不等同于文件逻辑大小。",
            "扫描仅一层、设有 8 秒上限；超时、权限不足或目录不存在会造成结果不完整。",
            "未跨越其他挂载文件系统；请单独选择 /data、/var 等路径核查。",
        ],
    }


def parse_peer_connections(text: str) -> dict:
    rows = []
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) != 3:
            continue
        ip, total, established = fields
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        if total.isdecimal() and established.isdecimal():
            rows.append(
                {
                    "peer_ip": ip,
                    "tcp_connections": int(total),
                    "established_connections": int(established),
                }
            )
    rows.sort(key=lambda x: x["tcp_connections"], reverse=True)
    return {
        "ranking": rows[:50],
        "metric": "当前 TCP socket 数量",
        "notes": [
            "包含 ss -tan 能观察到的 TCP 连接状态；不代表每个 IP 的流量大小。",
            "不包含 UDP；默认无 DNS 解析，避免反查造成延时。",
            "仅显示本机可见的套接字；转发流量不一定包含在内。",
        ],
    }


def _ip_from_endpoint(endpoint: str) -> str | None:
    if ":" not in endpoint:
        return None
    address, port = endpoint.rsplit(":", 1)
    address = address.strip("[]")
    if "%" in address:
        address = address.rsplit("%", 1)[0]
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    if parsed.is_unspecified:
        return None
    return str(parsed)


def parse_tcp_samples(text: str, sample_seconds: int = 3) -> dict:
    """Per-socket *delta*, not sum of all counters since connection start.

    Inputs are remote awk records: local<TAB>peer<TAB>bytes_sent<TAB>bytes_received.
    Same 4-tuples are matched across snapshots; new/closed sockets are excluded.
    """
    snapshots: dict[str, dict[tuple[str, str], tuple[int, int]]] = {"A": {}, "B": {}}
    selected = None
    seen = {"A": False, "B": False}
    total_records = 0
    for line in text.splitlines():
        match = _SAMPLE_MARKER.fullmatch(line.strip())
        if match:
            selected = match.group(1)
            seen[selected] = True
            continue
        if selected is None:
            continue
        f = line.split("\t")
        if len(f) != 4:
            continue
        local, peer, sent, received = f
        if not (sent.isdecimal() and received.isdecimal()):
            continue
        if _ip_from_endpoint(peer) is None:
            continue
        total_records += 1
        snapshots[selected][(local, peer)] = (int(sent), int(received))
    rows = defaultdict(
        lambda: {"sent_bytes": 0, "received_bytes": 0, "matched_tcp_connections": 0}
    )
    common = snapshots["A"].keys() & snapshots["B"].keys()
    for socket_id in common:
        first, second = snapshots["A"][socket_id], snapshots["B"][socket_id]
        # Counter resets or socket identity reuse must not produce made-up deltas.
        if second[0] < first[0] or second[1] < first[1]:
            continue
        ip = _ip_from_endpoint(socket_id[1])
        row = rows[ip]
        row["sent_bytes"] += second[0] - first[0]
        row["received_bytes"] += second[1] - first[1]
        row["matched_tcp_connections"] += 1
    ranking = [
        {
            "peer_ip": ip,
            **stats,
            "total_bytes": stats["sent_bytes"] + stats["received_bytes"],
            "avg_bytes_per_second": round(
                (stats["sent_bytes"] + stats["received_bytes"]) / sample_seconds, 2
            ),
        }
        for ip, stats in rows.items()
    ]
    ranking.sort(key=lambda r: r["total_bytes"], reverse=True)
    return {
        "sample_seconds": sample_seconds,
        "metric": "采样期间持续存在的 TCP socket 已发送/已接收字节增量",
        "supported": bool(seen["A"] and seen["B"]),
        "sample_a_sockets": len(snapshots["A"]),
        "sample_b_sockets": len(snapshots["B"]),
        "matched_sockets": len(common),
        "ranking": ranking[:30],
        "notes": [
            "这是短时 TCP 采样，不是历史流量、网卡全流量或计费数据。",
            "仅统计两次采样持续存在且内核导出 bytes_sent/bytes_received 的 TCP 连接；短连接、UDP、转发流量不会完整体现。",
            "需要目标主机支持 ss -ti / TCP_INFO 字节计数，否则会明确标记无法采样。",
            "bytes_sent/received 是 TCP 内核计数；可能含重传等差异，不应视为准确的应用层传输量。",
        ],
    }

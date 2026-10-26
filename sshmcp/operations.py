"""Fixed Linux observation scripts. No user script, URL or path interpolation."""

SCRIPTS = {
    "pressure": (
        "found=0; for resource in cpu memory io; do path=/proc/pressure/$resource; "
        'if [ -r "$path" ]; then printf "[%s PSI]\\n" "$resource"; cat "$path"; found=1; fi; done; '
        '[ "$found" = 1 ] || { printf "CAPABILITY_MISSING:kernel-psi\\n"; exit 69; }'
    ),
    "resource_limits": (
        "printf '[系统文件句柄]\\n'; cat /proc/sys/fs/file-nr /proc/sys/fs/file-max; "
        "printf '[PID 上限]\\n'; cat /proc/sys/kernel/pid_max /proc/sys/kernel/threads-max; "
        "printf '[当前 SSH shell 的资源限制，非业务进程]\\n'; ulimit -a"
    ),
    "mount_health": (
        "if ! command -v findmnt >/dev/null 2>&1; then printf 'CAPABILITY_MISSING:findmnt\\n'; exit 69; fi; "
        "findmnt --list --noheadings --output TARGET,FSTYPE; "
        "printf '[只读文件系统]\\n'; findmnt --list --noheadings --options ro --output TARGET,FSTYPE; "
        'code=$?; [ "$code" -eq 1 ] && exit 0; exit "$code"'
    ),
    "block_devices": (
        "if ! command -v lsblk >/dev/null 2>&1; then printf 'CAPABILITY_MISSING:lsblk\\n'; exit 69; fi; "
        "lsblk --bytes --output NAME,TYPE,SIZE,RO,ROTA,MOUNTPOINT"
    ),
    "time_sync": (
        "if ! command -v timedatectl >/dev/null 2>&1; then printf 'CAPABILITY_MISSING:timedatectl\\n'; exit 69; fi; "
        "date -u '+%Y-%m-%dT%H:%M:%SZ'; timedatectl show --property=Timezone,LocalRTC,NTP,NTPSynchronized; "
        'code=$?; [ "$code" = 0 ] || exit "$code"; '
        "if command -v chronyc >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then timeout -k 1 5 chronyc tracking; fi"
    ),
    "tcp_states": (
        "if ! command -v ss >/dev/null 2>&1; then printf 'CAPABILITY_MISSING:ss\\n'; exit 69; fi; "
        'rows=$(ss -H -tan); code=$?; [ "$code" = 0 ] || exit "$code"; '
        "printf '%s\\n' \"$rows\" | awk 'NF>=5 {states[$1]++} END {for (s in states) print s,states[s]}' | sort"
    ),
    "service_inventory": (
        "if ! command -v systemctl >/dev/null 2>&1; then printf 'CAPABILITY_MISSING:systemctl\\n'; exit 69; fi; "
        "rows=$(systemctl list-units --type=service --all --no-pager --plain --no-legend); code=$?; "
        'printf \'%s\\n\' "$rows" | head -n 100; exit "$code"'
    ),
    "timers": (
        "if ! command -v systemctl >/dev/null 2>&1; then printf 'CAPABILITY_MISSING:systemctl\\n'; exit 69; fi; "
        "rows=$(systemctl list-timers --all --no-pager --plain); code=$?; "
        'printf \'%s\\n\' "$rows" | head -n 80; exit "$code"'
    ),
    "container_stats": (
        "if ! command -v timeout >/dev/null 2>&1; then printf 'CAPABILITY_MISSING:timeout\\n'; exit 69; fi; "
        "if command -v docker >/dev/null 2>&1; then engine=docker; "
        "elif command -v podman >/dev/null 2>&1; then engine=podman; "
        "else printf 'CAPABILITY_MISSING:docker-or-podman\\n'; exit 69; fi; "
        'timeout -k 1 8 "$engine" stats --no-stream '
        "--format '{{.ID}}\\t{{.Name}}\\t{{.CPUPerc}}\\t{{.MemUsage}}\\t{{.NetIO}}\\t{{.BlockIO}}'"
    ),
    "security_status": (
        "printf '[SELinux]\\n'; if command -v getenforce >/dev/null 2>&1; then getenforce; "
        "else printf 'CAPABILITY_MISSING:getenforce\\n'; fi; "
        "printf '[AppArmor]\\n'; if [ -r /sys/module/apparmor/parameters/enabled ]; then "
        "cat /sys/module/apparmor/parameters/enabled; else printf 'unavailable\\n'; fi; "
        "printf '[防火墙服务状态，非规则审计]\\n'; if command -v systemctl >/dev/null 2>&1; then "
        'for unit in firewalld nftables ufw; do systemctl is-active "$unit" || true; done; '
        "else printf 'CAPABILITY_MISSING:systemctl\\n'; fi"
    ),
}

WINDOW_ACTIONS = {"log_errors", "oom"}
NEW_ACTIONS = set(SCRIPTS) | WINDOW_ACTIONS


def window_script(action, minutes):
    guard = (
        "if ! command -v journalctl >/dev/null 2>&1; then "
        "printf 'CAPABILITY_MISSING:journalctl\\n'; exit 69; fi; "
    )
    if action == "log_errors":
        return (
            guard
            + f"journalctl --no-pager -q --since '-{minutes} min' -p warning -n 100 -o short-iso"
        )
    return guard + (
        f"rows=$(journalctl --no-pager -q -k --since '-{minutes} min' -n 300 -o short-iso); code=$?; "
        '[ "$code" = 0 ] || exit "$code"; '
        "printf '%s\\n' \"$rows\" | awk 'tolower($0) ~ /out of memory|oom-kill|killed process|memory cgroup out of memory/ {print}'"
    )

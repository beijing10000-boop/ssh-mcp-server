"""``collect``: several classic diagnostics in one verified SSH session.

An AI client that needs cpu + processes + pressure for one host used to open
three SSH sessions that also queued behind the per-host slot. ``ssh_collect``
runs the chosen fixed actions sequentially in one channel (the triage wrapper),
keeps every step's exit code and parses each step as its own action, so the
caller gets the same summary/findings per step plus merged findings.

Authorization is per step: the MCP tool enforces every requested action for
the client before anything runs, and background re-checks do the same.
"""

from __future__ import annotations

from . import ActionSpec, Param, SERVICE_RE, register

# Fixed, parameterless (or service-scoped) classic actions only: no directory
# or peer tools (own output formats and limits), no triage nesting.
COLLECTABLE = (
    "cpu",
    "memory",
    "processes",
    "memory_processes",
    "pressure",
    "resource_limits",
    "disk",
    "io",
    "mount_health",
    "block_devices",
    "network",
    "sockets",
    "tcp_states",
    "system",
    "health",
    "capabilities",
    "failed_services",
    "service_inventory",
    "timers",
    "time_sync",
    "containers",
    "container_stats",
    "security_status",
    "kernel",
    "log_errors",
    "oom",
    "service",
    "logs",
)
SERVICE_ACTIONS = {"service", "logs"}
MAX_ACTIONS = 6
STEP_SECONDS = 20
STEP_OUTPUT = 32768


def actions_of(options: dict) -> list[str]:
    return list(options.get("actions") or [])


def script(options: dict) -> str:
    from .. import diagnostics, triage

    actions = actions_of(options)
    service = options.get("service")
    if any(action in SERVICE_ACTIONS for action in actions) and not service:
        raise ValueError("service / logs 步骤需要 service 参数")
    if service and not any(action in SERVICE_ACTIONS for action in actions):
        raise ValueError("只有 service / logs 步骤接受 service 参数")
    return triage.command_many(
        actions,
        service,
        int(options.get("minutes") or 30),
        diagnostics.command_for,
    )


def parse(text: str, summary: dict, findings: list, options: dict) -> None:
    from .. import triage

    actions = actions_of(options)
    result = triage.parse_many(text, actions)
    summary.update(
        {
            "steps": result["steps"],
            "completed": result["summary"]["completed"],
            "total": result["summary"]["total"],
            "coverage": "同一 SSH 会话顺序执行所选固定动作；单次快照，各步骤分别解析",
        }
    )
    findings.extend(result["findings"])


register(
    ActionSpec(
        id="collect",
        tool="ssh_collect",
        title="多项采集（单会话）",
        question="在一次 SSH 会话内按顺序执行所选的多个固定诊断，各步骤分别解析",
        category="连接与概览",
        params=(
            Param(
                "actions",
                "list",
                "要执行的固定诊断动作，按顺序 1–6 个",
                required=True,
                choices=COLLECTABLE,
                max_items=MAX_ACTIONS,
            ),
            Param(
                "service",
                "str",
                "service / logs 步骤的 systemd 单元名",
                pattern=SERVICE_RE,
                max_length=64,
            ),
            Param(
                "minutes",
                "int",
                "日志类步骤的回溯窗口（分钟，1–120）",
                default=30,
                minimum=1,
                maximum=120,
            ),
        ),
        script=script,
        parse=parse,
        sensitive=False,
        risk="low",
        timeout=STEP_SECONDS * MAX_ACTIONS,
        output_limit=STEP_OUTPUT * MAX_ACTIONS,
        estimated_seconds=60,
        notes=("每个步骤单独授权；步骤数越多总耗时越长，上限 120 秒。",),
    )
)

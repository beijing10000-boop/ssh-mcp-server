"""Scenario templates and ad-hoc action lists executed sequentially in one SSH channel."""

import re
import shlex
from . import observations

SCENARIOS = {
    "cpu_high": ("cpu", "processes", "pressure"),
    "mem_high": ("memory", "memory_processes", "pressure", "oom"),
    "disk_full": ("disk", "mount_health", "block_devices"),
    "io_slow": ("io", "pressure", "mount_health", "block_devices"),
    "service_down": ("service", "failed_services", "logs"),
    "network": ("network", "sockets", "tcp_states", "time_sync"),
}
STEP_LIMIT = 32768


def actions(symptom):
    if symptom not in SCENARIOS:
        raise ValueError("symptom 必须是 " + ", ".join(SCENARIOS))
    return SCENARIOS[symptom]


def command_many(steps, service, minutes, command_for, step_seconds=None):
    """Wrap each fixed action so its output and exit code stay separable.

    With ``step_seconds`` each step runs in its own ``sh`` under ``timeout``
    (when the host has it): a stuck step ends with 124 and the next one runs.
    """
    if not steps or len(set(steps)) != len(steps):
        raise ValueError("采集步骤不能为空或重复")
    parts = []
    if step_seconds:
        parts.append(
            "aiops_step() { if command -v timeout >/dev/null 2>&1; then "
            'timeout -k 1 "$1" sh -c "$2"; else sh -c "$2"; fi; }'
        )
    for action in steps:
        # command_for remains the sole validator and fixed-command source.
        script = command_for(
            action, service if action in {"service", "logs"} else None, minutes
        )
        body = (
            f"aiops_step {int(step_seconds)} {shlex.quote(script)}"
            if step_seconds
            else f"( {script} )"
        )
        parts.append(
            f"printf '\\n__SSHMCP_BEGIN_{action}__\\n'; {body}; code=$?; printf '\\n__SSHMCP_END_{action}__:%s\\n' \"$code\""
        )
    return "; ".join(parts)


def command(symptom, service, minutes, command_for):
    if service and symptom != "service_down":
        raise ValueError("此组合诊断不接收服务参数")
    return command_many(actions(symptom), service, minutes, command_for)


def parse_many(text, steps, truncated=False, step_seconds=None):
    results = []
    findings = []
    for action in steps:
        m = re.search(
            rf"(?:^|\n)__SSHMCP_BEGIN_{action}__\n(.*?)\n__SSHMCP_END_{action}__:(\d+)(?:\n|$)",
            text,
            re.S,
        )
        if not m:
            result = {
                "action": action,
                "status": "partial",
                "error": "该动作未完整返回（超限、中断或超时）",
                "findings": [],
                "summary": {"action": action, "metrics": []},
            }
        else:
            output, code = m[1], int(m[2])
            status = "partial" if code or "CAPABILITY_MISSING:" in output else "success"
            result = {
                "action": action,
                "status": status,
                "exit_code": code,
                "output": output[:STEP_LIMIT],
                "truncated": len(output) > STEP_LIMIT,
            }
            if step_seconds and code in (124, 137):
                # Ended by the per-step timeout (TERM, or KILL a second later).
                result["timed_out"] = True
                result["error"] = f"该步骤超过 {step_seconds} 秒被终止，输出可能不完整"
            result.update(
                observations.analyze(
                    action,
                    result["output"],
                    status=status,
                    truncated=result["truncated"],
                )
            )
        results.append(result)
        findings.extend({**f, "source_action": action} for f in result["findings"])
    if truncated or any(r["status"] != "success" for r in results):
        findings.append(
            {
                "level": "info",
                "metric": "triage_coverage",
                "value": "partial",
                "threshold": "complete",
                "hint": "组合诊断包含未完成动作，不能排除未采集部分的问题",
            }
        )
    findings.sort(key=lambda f: observations.LEVELS[f["level"]])
    return {
        "summary": {
            "action": "triage",
            "metrics": [],
            "completed": sum(r["status"] == "success" for r in results),
            "total": len(results),
            "coverage": "同一 SSH 会话顺序采集固定动作；单次快照",
        },
        "findings": findings,
        "steps": results,
    }


def parse(text, symptom, truncated=False):
    result = parse_many(text, actions(symptom), truncated)
    result["summary"]["symptom"] = symptom
    return result

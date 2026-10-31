"""Registry of parameterised read-only diagnostics (v0.6.0).

Every extension action declares its parameters (validated here, never by the
shell), builds a fixed script from the validated options, and parses the
bounded stdout into the same summary/findings shape as the classic actions.
diagnostics.command_for, observations.analyze, catalog.entries and the MCP
tool functions all consult this registry, so adding a diagnostic means one
module here plus one explicitly typed MCP tool function in mcp_tools.py.

Rules for action modules:
- Scripts are fixed templates. Integers are inserted with str(int(...)),
  strings only after ``Param`` validation and ``shlex.quote``.
- No writes on the target: no redirections to files, no tee, no touch.
- Every command that may stall wraps itself in ``timeout -k 1 N``.
- Output stays bounded (head/tail/awk aggregation); the executor caps it.
- Section markers ``[AIOPS_<NAME>]`` separate blocks; parsers use
  ``observations.section``.
- ``ps`` takes one column per ``-o`` (``ps -o pid= -o comm=``): procps-ng up to
  3.3.11 (EL7, Ubuntu 16.04) reads ``-o pid=,comm=`` on a command line of
  POSIX options only as the single column ``pid`` headed ",comm=".
"""

from __future__ import annotations

from dataclasses import dataclass
import re
import shlex
import time
from typing import Callable

RISKS = ("low", "medium", "high")
# Sane bounds for every time-window parameter shared by log-style actions.
MAX_WINDOW_SECONDS = 86400
MAX_LOOKBACK_SECONDS = 30 * 86400
SERVICE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}$")
# Log keywords are matched literally (grep -F / awk index()) after shlex.quote;
# anything printable is fine except backslash (awk -v unescapes it), backtick
# and dollar (kept out as defence in depth) and control characters.
KEYWORD_RE = re.compile(r"^[^\x00-\x1f\x7f\\`$]{1,64}$")
PATH_RE = re.compile(r"^/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+$")


@dataclass(frozen=True)
class Param:
    name: str
    kind: str  # int | str | enum | list
    description: str
    required: bool = False
    default: object = None
    minimum: int | None = None
    maximum: int | None = None
    pattern: re.Pattern | None = None
    max_length: int = 64
    choices: tuple = ()
    max_items: int = 8


@dataclass(frozen=True)
class ActionSpec:
    id: str
    title: str
    question: str
    category: str
    params: tuple[Param, ...]
    script: Callable[[dict], str]
    parse: Callable[..., None]
    tool: str = ""
    sensitive: bool = True
    risk: str = "low"
    timeout: int = 20
    output_limit: int = 32768
    estimated_seconds: int = 20
    notes: tuple[str, ...] = ()

    def __post_init__(self):
        if self.risk not in RISKS:
            raise ValueError("risk must be low, medium or high")
        if not self.tool:
            object.__setattr__(self, "tool", "ssh_diagnose_" + self.id)


REGISTRY: dict[str, ActionSpec] = {}


def register(spec: ActionSpec) -> ActionSpec:
    if spec.id in REGISTRY:
        raise ValueError("duplicate action " + spec.id)
    REGISTRY[spec.id] = spec
    return spec


def spec_for(action: str) -> ActionSpec | None:
    return REGISTRY.get(action)


def validate_options(spec: ActionSpec, options) -> dict:
    """Return the normalised options (defaults filled) or raise ValueError.

    Unknown keys, wrong types, out-of-range numbers and strings outside the
    parameter's pattern are refused before any script is built.
    """
    options = {} if options is None else options
    if not isinstance(options, dict):
        raise ValueError("诊断参数必须是对象")
    known = {param.name for param in spec.params}
    unknown = sorted(set(options) - known)
    if unknown:
        raise ValueError("不支持的诊断参数：" + ", ".join(unknown)[:120])
    result = {}
    for param in spec.params:
        value = options.get(param.name)
        if value is None:
            if param.required:
                raise ValueError(f"缺少必需参数 {param.name}")
            result[param.name] = param.default
            continue
        result[param.name] = _check(param, value)
    return result


def _check(param: Param, value):
    label = param.name
    if param.kind == "int":
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"参数 {label} 必须是整数")
        if param.minimum is not None and value < param.minimum:
            raise ValueError(f"参数 {label} 不能小于 {param.minimum}")
        if param.maximum is not None and value > param.maximum:
            raise ValueError(f"参数 {label} 不能大于 {param.maximum}")
        return value
    if param.kind == "str":
        if not isinstance(value, str) or not value or len(value) > param.max_length:
            raise ValueError(f"参数 {label} 必须是 1–{param.max_length} 字符的文本")
        if param.pattern is not None and not param.pattern.fullmatch(value):
            raise ValueError(f"参数 {label} 含有不允许的字符")
        if "\x00" in value or ".." in value.split("/"):
            raise ValueError(f"参数 {label} 含有不允许的字符")
        return value
    if param.kind == "enum":
        if not isinstance(value, str) or value not in param.choices:
            raise ValueError(
                f"参数 {label} 只能是 " + "、".join(str(c) for c in param.choices)
            )
        return value
    if param.kind == "list":
        if not isinstance(value, list) or not value or len(value) > param.max_items:
            raise ValueError(f"参数 {label} 必须是 1–{param.max_items} 项的列表")
        if any(
            not isinstance(item, str) or item not in param.choices for item in value
        ):
            raise ValueError(
                f"参数 {label} 只能包含 " + "、".join(str(c) for c in param.choices)
            )
        return list(dict.fromkeys(value))
    raise ValueError("unknown parameter kind " + param.kind)


def quote(value: str) -> str:
    """Shell-quote a value that already passed ``Param`` validation."""
    return shlex.quote(value)


WINDOW_PARAMS = (
    Param(
        "minutes",
        "int",
        "回溯窗口（分钟，1–1440）；给出 since/until 时忽略",
        default=30,
        minimum=1,
        maximum=1440,
    ),
    Param(
        "since",
        "int",
        "窗口开始，Unix 秒；通常取告警时间减 15 分钟",
        minimum=0,
        maximum=4102444800,
    ),
    Param(
        "until",
        "int",
        "窗口结束，Unix 秒；缺省为当前时间，与 since 相距最多 24 小时",
        minimum=0,
        maximum=4102444800,
    ),
)


def resolve_window(options: dict, now: int | None = None) -> tuple[int, int]:
    """(since, until) Unix seconds from minutes or explicit since/until."""
    now = int(time.time()) if now is None else int(now)
    since, until = options.get("since"), options.get("until")
    if since is None and until is None:
        minutes = int(options.get("minutes") or 30)
        return now - minutes * 60, now
    until = now if until is None else int(until)
    if since is None:
        since = until - int(options.get("minutes") or 30) * 60
    since = int(since)
    if until > now + 300:
        raise ValueError("until 不能晚于当前时间")
    if not 0 < until - since <= MAX_WINDOW_SECONDS:
        raise ValueError("since/until 窗口必须在 1 秒到 24 小时之间")
    if since < now - MAX_LOOKBACK_SECONDS:
        raise ValueError("日志窗口最多回溯 30 天")
    return since, until


def guard(*commands: str) -> str:
    """Shell fragment that refuses to run when a required command is missing."""
    return "".join(
        "if ! command -v "
        + command
        + " >/dev/null 2>&1; then printf 'CAPABILITY_MISSING:"
        + command
        + "\\n'; exit 69; fi; "
        for command in commands
    )


def timed(seconds: int, command: str) -> str:
    """Wrap a command in ``timeout`` when available (never leave it unbounded)."""
    return (
        "if command -v timeout >/dev/null 2>&1; then timeout -k 1 "
        + str(int(seconds))
        + " "
        + command
        + "; else "
        + command
        + "; fi"
    )


def journal_permission_probe(limited: str = "") -> str:
    """Shell fragment that flags an account outside the journal-reading groups.

    Unlike ``operations.JOURNAL_GUARD`` it never exits: the caller still has
    useful work without the journal. ``limited`` runs first when flagged.
    """
    return (
        "if [ \"$(id -u)\" != 0 ] && ! id -nG 2>/dev/null | tr ' ' '\\n' | "
        "grep -qxE 'systemd-journal|adm|wheel|root'; then "
        + limited
        + "printf 'CAPABILITY_MISSING:journal-permission\\n'; fi"
    )


UNIT_SUFFIXES = (
    ".service",
    ".socket",
    ".target",
    ".timer",
    ".path",
    ".mount",
    ".automount",
    ".swap",
    ".slice",
    ".scope",
    ".device",
)


def unit_name(unit: str) -> str:
    """Full unit name: a bare name means NAME.service, as systemctl assumes."""
    return unit if unit.endswith(UNIT_SUFFIXES) else unit + ".service"


def has_section(text: str, name: str) -> bool:
    """True when the ``[AIOPS_<name>]`` marker stands on a line of its own."""
    return re.search(r"(?m)^\[AIOPS_" + name + r"\]$", text) is not None


def param_views(spec: ActionSpec) -> list[dict]:
    """Serialisable parameter descriptions for the Web console and clients."""
    rows = []
    for param in spec.params:
        row = {
            "name": param.name,
            "type": {"int": "integer", "list": "array"}.get(param.kind, "string"),
            "required": param.required,
            "description": param.description,
        }
        if param.default is not None:
            row["default"] = param.default
        if param.minimum is not None:
            row["minimum"] = param.minimum
        if param.maximum is not None:
            row["maximum"] = param.maximum
        if param.choices:
            row["choices"] = list(param.choices)
        if param.pattern is not None:
            row["pattern"] = param.pattern.pattern
        rows.append(row)
    return rows


from . import collect, nginx, syslog, java, services  # noqa: E402,F401

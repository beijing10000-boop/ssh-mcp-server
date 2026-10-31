"""ps column lists must parse the same on every procps, EL7's 3.3.10 included.

procps-ng up to 3.3.11 applies a Unix98 rule when a ps command line holds
POSIX options only: in ``ps -o pid=,comm= -p 1`` everything after the first
"=" is the header of ``pid`` and a single column comes back. That is how
ssh_diagnose_java lost RSS, CPU, memory and elapsed time on EL7 hosts, so
every ``-o`` names one column. The static check runs everywhere; the
container tests run the real ps calls on procps-ng 3.3.10 when
SSHMCP_OLD_PROCPS_IMAGE names such an image (CI uses centos:7.9.2009).
"""

import os
import re
import subprocess
from pathlib import Path

import pytest

from sshmcp import diagnostics, extensions, observations, operations

GATEWAY = (
    Path(__file__).resolve().parent.parent / "gateway" / "aiops-diagnostic-gateway"
)
IMAGE = os.environ.get("SSHMCP_OLD_PROCPS_IMAGE", "")
# Set means required: a missing docker then fails instead of skipping.
needs_image = pytest.mark.skipif(
    not IMAGE, reason="set SSHMCP_OLD_PROCPS_IMAGE to an image with procps-ng <= 3.3.11"
)
# A ps call up to the end of its simple command, and the -o lists inside it.
PS_CALL = re.compile(r"(?<![\w./-])ps((?:[ \t]+[^\s|;&)]+)+)")
FORMAT = re.compile(r"(?<!\S)-[A-Za-z]*o[ \t]+(\S+)")
REDIRECT = re.compile(r"^[0-9]*[<>]")
# The calls v0.7.2 rewrote, so the checks below cannot pass vacuously.
FIXED = {
    "java": "ps -o user= -o etimes= -o rss= -o pcpu= -o pmem= -o nlwp= -p",
    "service_detail": "ps -o pid= -o ppid= -o user:32= -o etimes= -o rss=",
    "service_map": "ps -o pid= -o user:32= -o etimes= -o rss= -p",
    "nginx": "ps -e -o pid= -o ppid= -o user= -o etimes= -o rss= -o pcpu=",
    "processes": "ps -e -o pid= -o state= -o wchan:32= -o comm=",
}


def samples(spec):
    """Option sets that between them switch on every list choice of a spec."""
    base = {}
    for param in spec.params:
        if param.required and param.kind != "list":
            if param.kind == "str":
                base[param.name] = "nginx.service"
            elif param.kind == "enum":
                base[param.name] = param.choices[0]
            else:
                base[param.name] = max(param.minimum or 1, 1)
    sets = [
        {**base, param.name: list(param.choices[start : start + param.max_items])}
        for param in spec.params
        if param.kind == "list"
        for start in range(0, len(param.choices), param.max_items)
    ]
    return sets or [base]


def scripts():
    """(action, script) for every fixed script the server can send."""
    classic = set(diagnostics.ACTIONS) | operations.NEW_ACTIONS
    for action in sorted(classic | {"kernel", "peer_connections", "peer_traffic"}):
        yield action, diagnostics.command_for(action)
    for action in ("service", "logs"):
        yield action, diagnostics.command_for(action, "nginx.service")
    for spec in extensions.REGISTRY.values():
        if spec.id == "collect":  # its steps are the classic scripts above
            continue
        for options in samples(spec):
            yield spec.id, diagnostics.command_for(spec.id, options=options)
    yield "gateway", GATEWAY.read_text(encoding="utf-8")


def ps_calls(script):
    """(command, -o lists) of every ps call that picks its columns."""
    calls = []
    for match in PS_CALL.finditer(script):
        words = [word for word in match[1].split() if not REDIRECT.match(word)]
        formats = FORMAT.findall(" ".join(words))
        if formats:
            calls.append(("ps " + " ".join(words), formats))
    return calls


def all_calls():
    """{command: (actions using it, -o lists)} over every script."""
    calls = {}
    for action, script in scripts():
        for command, formats in ps_calls(script):
            calls.setdefault(command, (set(), formats))[0].add(action)
    return calls


def test_every_ps_column_list_with_a_header_holds_one_column():
    calls = all_calls()
    for command, (actions, formats) in calls.items():
        for fmt in formats:
            # `pid`, `pid,comm`, `pid=` and `user:32=` parse alike everywhere;
            # `pid=,comm=` is one column on procps-ng <= 3.3.11.
            assert "=" not in fmt or "," not in fmt, (sorted(actions), command)
    for action, prefix in FIXED.items():
        assert any(
            action in actions and command.startswith(prefix)
            for command, (actions, _) in calls.items()
        ), (action, prefix)


def in_container(script):
    return subprocess.run(
        ["docker", "run", "--rm", "-i", IMAGE, "sh", "-s"],
        input=script,
        capture_output=True,
        text=True,
        timeout=180,
    )


@needs_image
def test_old_procps_reads_a_comma_list_after_equals_as_one_column():
    # The premise of the rule, on the real ps of the image.
    result = in_container(
        "ps --version; ps -o user=,etimes=,rss= -p 1; echo @@\n"
        "ps -o user= -o etimes= -o rss= -p 1\n"
    )
    version, _, rest = result.stdout.partition("\n")
    old, _, new = rest.partition("@@\n")
    assert ",etimes=,rss=" in old and old.split()[-1] == "root", (version, old)
    assert len(old.splitlines()[-1].split()) == 1, (version, old)
    assert len(new.split()) == 3 and new.split()[0] == "root", (version, new)


@needs_image
def test_every_ps_call_returns_all_its_columns_on_old_procps():
    calls = sorted(all_calls().items())
    body = "".join(
        f"printf '@@ {index}\\n'; "
        + command.replace('"$pid"', "1").replace('"$pl"', "1")
        + " 2>/dev/null || printf 'FAILED %s\\n' \"$?\"\n"
        for index, (command, _) in enumerate(calls)
    )
    result = in_container(body)
    parts = re.split(r"(?m)^@@ ([0-9]+)\n", result.stdout)[1:]
    outputs = dict(zip(map(int, parts[0::2]), parts[1::2]))
    for index, (command, (actions, formats)) in enumerate(calls):
        columns = sum(len(fmt.split(",")) for fmt in formats)
        lines = [line for line in outputs.get(index, "").splitlines() if line.strip()]
        assert lines and not lines[-1].startswith("FAILED"), (command, lines)
        # comm/args may hold spaces, so at least one field per column.
        short = [line for line in lines if len(line.split()) < columns]
        assert not short, (sorted(actions), command, short[:3])


@needs_image
def test_java_inventory_fills_ps_columns_on_old_procps():
    # A sleeping process named java; the script runs as root in the container.
    result = in_container(
        "cp /bin/sleep /tmp/java && /tmp/java 300 &\nsleep 1\n"
        + diagnostics.command_for("java")
        + "\n"
    )
    assert result.returncode == 0, result.stderr
    assert re.search(r"(?m)^PS root [0-9]+ [0-9]+ ", result.stdout), result.stdout
    report = observations.analyze("java", diagnostics.redact_output(result.stdout))
    (row,) = [r for r in report["summary"]["processes"] if r["exe"] == "/tmp/java"]
    assert row["user"] == "root" and row["rss_KiB"] > 0 and row["threads"] == 1
    assert row["elapsed_seconds"] is not None and row["elapsed_seconds"] >= 0
    assert row["cpu_percent"] is not None and row["mem_percent"] is not None

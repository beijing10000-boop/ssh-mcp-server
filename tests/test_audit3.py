"""2026-11 third audit: TCP states with digits (SC-02) and a service inventory
that says when it lists only part of the units (SC-03). Script cases need
/bin/sh (CI)."""

import os
import subprocess

import pytest

from sshmcp import observations
from sshmcp.operations import SCRIPTS

needs_sh = pytest.mark.skipif(not os.path.exists("/bin/sh"), reason="needs /bin/sh")


def analyze(action, text):
    return observations.analyze(action, text)


def test_tcp_states_keep_fin_wait_1_and_2():
    text = "\n".join(
        f"{state} {n}"
        for n, state in enumerate(
            (
                "CLOSE-WAIT",
                "CLOSING",
                "ESTAB",
                "FIN-WAIT-1",
                "FIN-WAIT-2",
                "LAST-ACK",
                "LISTEN",
                "SYN-RECV",
                "SYN-SENT",
                "TIME-WAIT",
            ),
            start=1,
        )
    )
    states = analyze("tcp_states", text)["summary"]["states"]
    assert states["FIN-WAIT-1"] == 4 and states["FIN-WAIT-2"] == 5
    assert len(states) == 10


def unit(name, active="active", sub="running"):
    return f"{name}.service loaded {active} {sub} {name} unit"


def test_a_cut_service_inventory_says_so():
    text = "UNITS_TOTAL 260\n" + "\n".join(
        [unit("crond"), unit("sshd"), "● broken.service loaded failed failed Broken"]
        + [unit(f"idle{i}", "inactive", "dead") for i in range(50)]
    )
    summary = analyze("service_inventory", text)["summary"]
    assert summary["units_total"] == 260 and summary["units_truncated"] is True
    assert "260" in summary["coverage"] and "只统计列出的单元" in summary["coverage"]
    assert {u["unit"] for u in summary["units"]} >= {"crond.service", "broken.service"}
    assert summary["failed_services"] == ["broken.service"]
    # All of them listed: nothing said.
    whole = analyze(
        "service_inventory", "UNITS_TOTAL 2\n" + unit("crond") + "\n" + unit("sshd")
    )
    assert whole["summary"]["units_truncated"] is False


@needs_sh
def test_the_inventory_lists_units_that_are_not_inactive_first(tmp_path):
    rows = [unit(f"idle{i:03d}", "inactive", "dead") for i in range(240)]
    rows += [unit("zabbix-agent"), "● zz-broken.service loaded failed failed Broken"]
    stub = tmp_path / "systemctl"
    stub.write_text("#!/bin/sh\ncat <<'EOF'\n" + "\n".join(sorted(rows)) + "\nEOF\n")
    stub.chmod(0o755)
    done = subprocess.run(
        ["/bin/sh", "-c", SCRIPTS["service_inventory"]],
        capture_output=True,
        text=True,
        env={"PATH": f"{tmp_path}:/usr/bin:/bin", "LC_ALL": "C"},
        timeout=30,
    )
    assert done.returncode == 0, done.stderr
    summary = analyze("service_inventory", done.stdout)["summary"]
    names = [u["unit"] for u in summary["units"]]
    assert names[:2] == ["zabbix-agent.service", "zz-broken.service"]
    assert summary["units_total"] == 242 and len(names) == 52
    assert summary["failed_services"] == ["zz-broken.service"]

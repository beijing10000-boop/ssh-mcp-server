"""Extension registry: validated options, fixed scripts, catalog and authorization."""

import json
import re

import pytest

from sshmcp import access, catalog, diagnostics, extensions, jobs, observations, store
from sshmcp.extensions import ActionSpec, Param
from test_console import auth, mcp_call, ready_host


def spec_fixture():
    return ActionSpec(
        id="fixture_probe",
        title="测试探针",
        question="测试用",
        category="连接与概览",
        params=(
            Param("minutes", "int", "窗口", default=30, minimum=1, maximum=120),
            Param(
                "keyword",
                "str",
                "关键字",
                pattern=extensions.KEYWORD_RE,
                max_length=64,
            ),
            Param("mode", "enum", "模式", default="fast", choices=("fast", "full")),
            Param("probes", "list", "探针", choices=("a", "b", "c"), max_items=2),
        ),
        script=lambda opts: (
            "printf '%s' "
            + extensions.quote(opts.get("keyword") or "none")
            + " # "
            + str(opts["minutes"])
        ),
        parse=lambda text, summary, findings, options: summary.update(
            {"echo": text.strip(), "options": options}
        ),
        sensitive=True,
        risk="medium",
    )


def test_validate_options_fills_defaults_and_rejects_bad_values():
    spec = spec_fixture()
    assert extensions.validate_options(spec, None) == {
        "minutes": 30,
        "keyword": None,
        "mode": "fast",
        "probes": None,
    }
    good = extensions.validate_options(
        spec, {"minutes": 5, "keyword": "upstream timed out", "probes": ["a", "a"]}
    )
    assert good["probes"] == ["a"] and good["keyword"] == "upstream timed out"
    for bad in (
        {"minutes": 0},
        {"minutes": 121},
        {"minutes": "5"},
        {"minutes": True},
        # Shell punctuation is matched literally after quoting (see below);
        # substitution characters, backslashes and line breaks are refused.
        {"keyword": "$(rm -rf /)"},
        {"keyword": "a\\b"},
        {"keyword": "line\nbreak"},
        {"keyword": "a" * 65},
        {"keyword": "../etc"},
        {"mode": "shell"},
        {"probes": ["z"]},
        {"probes": ["a", "b", "c"]},
        {"probes": []},
        {"unknown": 1},
        "not-a-dict",
    ):
        with pytest.raises(ValueError):
            extensions.validate_options(spec, bad)


def test_resolve_window_bounds():
    now = 1_800_000_000
    assert extensions.resolve_window({"minutes": 15}, now) == (now - 900, now)
    assert extensions.resolve_window({"since": now - 100}, now) == (now - 100, now)
    assert extensions.resolve_window(
        {"since": now - 3600, "until": now - 60, "minutes": 5}, now
    ) == (now - 3600, now - 60)
    for bad in (
        {"since": now - 90000, "until": now},
        {"since": now, "until": now - 1},
        {"since": now - 40 * 86400},
        {"until": now + 3600},
    ):
        with pytest.raises(ValueError):
            extensions.resolve_window(bad, now)


def test_registered_spec_flows_through_command_analyze_and_catalog(monkeypatch):
    spec = spec_fixture()
    monkeypatch.setitem(extensions.REGISTRY, spec.id, spec)
    command = diagnostics.command_for(
        "fixture_probe", options={"keyword": "it's quoted", "minutes": 7}
    )
    assert command.startswith(diagnostics.PREFIX)
    assert "'it'\"'\"'s quoted'" in command and "# 7" in command
    literal = diagnostics.command_for(
        "fixture_probe", options={"keyword": "x; rm -rf /"}
    )
    assert "'x; rm -rf /'" in literal
    with pytest.raises(ValueError):
        diagnostics.command_for("fixture_probe", service="nginx")
    with pytest.raises(ValueError):
        diagnostics.command_for("fixture_probe", options={"keyword": "`id`"})
    with pytest.raises(ValueError):
        diagnostics.command_for("cpu", options={"minutes": 5})
    assert diagnostics.standard_only("fixture_probe")
    report = observations.analyze(
        "fixture_probe", "hello", options={"keyword": "x", "minutes": 7}
    )
    assert report["summary"]["echo"] == "hello"
    assert report["summary"]["request"] == {"keyword": "x", "minutes": 7}
    assert report["summary"]["title"] == "测试探针"
    assert observations.parseable("fixture_probe")
    entry = next(e for e in catalog.entries() if e["id"] == "fixture_probe")
    assert entry["extension"] and entry["risk"] == "medium" and entry["sensitive"]
    assert [p["name"] for p in entry["params"]] == [
        "minutes",
        "keyword",
        "mode",
        "probes",
    ]
    assert entry["params"][2]["choices"] == ["fast", "full"]
    assert entry["window_required"] and not entry["service_required"]


def test_classic_entries_publish_structured_params():
    by_id = {e["id"]: e for e in catalog.entries()}
    assert [p["name"] for p in by_id["logs"]["params"]] == ["service", "minutes"]
    assert by_id["logs"]["params"][0]["required"] and by_id["logs"]["service_required"]
    assert by_id["directory"]["params"][0]["name"] == "root"
    assert by_id["cpu"]["params"] == [] and by_id["cpu"]["risk"] == "low"
    assert by_id["triage"]["params"][0]["choices"] == list(
        __import__("sshmcp.triage", fromlist=["SCENARIOS"]).SCENARIOS
    )
    assert all("risk" in e and "params" in e for e in catalog.entries())


def test_collect_runs_steps_in_one_session_and_parses_each(monkeypatch):
    command = diagnostics.command_for(
        "collect", options={"actions": ["cpu", "memory", "logs"], "service": "nginx"}
    )
    assert command.count("__SSHMCP_BEGIN_") == 3
    assert "journalctl" in command and "loadavg" in command
    # Repeated steps collapse into one; the order of first use is kept.
    twice = diagnostics.command_for("collect", options={"actions": ["cpu", "cpu"]})
    assert twice.count("__SSHMCP_BEGIN_") == 1
    for bad in (
        {"actions": ["logs"]},  # service missing
        {"actions": ["cpu"], "service": "nginx"},  # service without a step
        {"actions": ["directory"]},
        {"actions": ["triage"]},
        {"actions": []},
        {"actions": ["cpu"] * 7},
        {"actions": ["cpu"], "minutes": 121},
    ):
        with pytest.raises(ValueError):
            diagnostics.command_for("collect", options=bad)
    text = (
        "__SSHMCP_BEGIN_cpu__\nCPU_COUNT=2\n5.00 1.00 0.00 1/100 99\n__SSHMCP_END_cpu__:0\n"
        "__SSHMCP_BEGIN_memory__\nMemTotal: 1000 kB\nMemAvailable: 40 kB\n__SSHMCP_END_memory__:0\n"
    )
    report = observations.analyze(
        "collect", text, options={"actions": ["cpu", "memory", "disk"]}
    )
    steps = {step["action"]: step for step in report["summary"]["steps"]}
    assert steps["cpu"]["status"] == "success" and steps["disk"]["status"] == "partial"
    assert report["summary"]["completed"] == 2 and report["summary"]["total"] == 3
    assert {f["source_action"] for f in report["findings"] if "source_action" in f} >= {
        "cpu",
        "memory",
    }
    assert any(f["metric"] == "triage_coverage" for f in report["findings"])


def test_collect_is_authorized_per_step(client, key_pair, monkeypatch):
    hid = ready_host(client, key_pair)
    token = client.post(
        "/api/v1/mcp/clients",
        headers=auth(),
        json={"name": "steps", "all_hosts": True, "actions": ["cpu", "memory"]},
    ).json()["token"]
    seen = []

    def execute(host_id, action, *args, **kwargs):
        seen.append((action, kwargs.get("options")))
        return {
            "host_id": host_id,
            "action": action,
            "status": "success",
            "output": "__SSHMCP_BEGIN_cpu__\nCPU_COUNT=1\n__SSHMCP_END_cpu__:0\n",
            "exit_code": 0,
        }

    monkeypatch.setattr(diagnostics, "execute", execute)
    denied = mcp_call(
        client, token, "ssh_collect", {"host_id": hid, "actions": ["cpu", "pressure"]}
    )[1]
    assert denied["status"] == "failed" and denied["error_code"] == "forbidden"
    assert seen == []
    allowed = mcp_call(
        client, token, "ssh_collect", {"host_id": hid, "actions": ["cpu", "memory"]}
    )[1]
    assert allowed["status"] == "success"
    assert seen[0][0] == "collect" and seen[0][1]["actions"] == ["cpu", "memory"]
    assert allowed["summary"]["steps"][0]["action"] == "cpu"
    # Summary detail keeps per-step findings but not the raw step output.
    assert "output" not in allowed and "output" not in allowed["summary"]["steps"][0]
    # The catalog offers the collector to any client holding at least one step.
    listed = mcp_call(client, token, "ssh_list_tool_catalog")[1]
    listed = listed.get("result", listed) if isinstance(listed, dict) else listed
    assert {e["id"] for e in listed} == {"cpu", "memory", "collect"}
    with store.db() as c:
        row = c.execute(
            "SELECT detail FROM audit WHERE action='collect' ORDER BY id DESC LIMIT 1"
        ).fetchone()
    assert "actions=cpu,memory" in row["detail"]


def test_extension_tools_are_registered_with_descriptive_schemas():
    import asyncio

    from sshmcp.mcp_tools import mcp

    tools = {tool.name: tool for tool in asyncio.run(mcp.list_tools())}
    for name in (
        "ssh_diagnose_nginx",
        "ssh_diagnose_nginx_access",
        "ssh_diagnose_syslog",
        "ssh_diagnose_java",
        "ssh_diagnose_jvm",
        "ssh_diagnose_service_detail",
        "ssh_diagnose_service_map",
        "ssh_collect",
    ):
        assert name in tools, name
        assert tools[name].annotations.readOnlyHint is True
        props = tools[name].inputSchema["properties"]
        assert not {"command", "script", "shell", "url", "address"} & set(props)
    access_props = tools["ssh_diagnose_nginx_access"].inputSchema["properties"]
    assert access_props["top"]["minimum"] == 5 and access_props["top"]["maximum"] == 30
    assert "description" in access_props["minutes"]
    assert tools["ssh_diagnose_syslog"].inputSchema["properties"]["priority"]["enum"]
    assert tools["ssh_collect"].inputSchema["properties"]["actions"]["items"]["enum"]
    assert (
        "cpu"
        in tools["ssh_collect"].inputSchema["properties"]["actions"]["items"]["enum"]
    )


def test_resolve_distinguishes_non_linux_and_not_ready(client, key_pair):
    hid = ready_host(client, key_pair)
    token = store.token("mcp.token")
    with store.db() as c:
        c.execute("UPDATE hosts SET credential_id=NULL WHERE id=?", (hid,))
    result = mcp_call(client, token, "ssh_resolve_host", {"zabbix_hostid": "101"})[1]
    assert result["error_code"] == "not_ready" and result["asset_type"] == "linux"
    windows = client.post(
        "/api/v1/hosts",
        headers=auth(),
        json={
            "name": "win",
            "address": "10.20.0.50",
            "username": "Administrator",
            "zabbix_hostid": "777",
            "asset_type": "windows",
        },
    )
    assert windows.status_code == 201, windows.text
    result = mcp_call(client, token, "ssh_resolve_host", {"zabbix_hostid": "777"})[1]
    assert result["error_code"] == "not_linux" and result["asset_type"] == "windows"
    missing = mcp_call(client, token, "ssh_resolve_host", {"zabbix_hostid": "999"})[1]
    assert missing["error_code"] == "mapping_unresolved"
    by_ip = mcp_call(client, token, "ssh_resolve_target", {"address": "10.20.0.50"})[1]
    assert by_ip["error_code"] == "not_linux"


def test_execution_failures_carry_error_codes(client, key_pair, monkeypatch):
    hid = ready_host(client, key_pair)

    def busy(*args, **kwargs):
        raise diagnostics.SSHDiagnosticError(
            "SSH 诊断繁忙：等待名额或同主机任务超时，请稍后重试"
        )

    monkeypatch.setattr(diagnostics, "execute", busy)
    result = mcp_call(
        client, store.token("mcp.token"), "ssh_diagnose_cpu", {"host_id": hid}
    )[1]
    assert result["status"] == "failed" and result["error_code"] == "busy"
    from sshmcp.mcp_tools import error_code

    assert error_code(ValueError("主机 7: 主机配置已变更"), "主机配置已变更") == (
        "revision_changed"
    )
    assert error_code(ValueError("x"), "服务名无效") == "invalid_argument"
    assert error_code(RuntimeError(), "Linux 主机已登记但尚未就绪") == "not_ready"


def test_client_actions_can_be_edited_and_are_extended_on_upgrade(client, key_pair):
    group = client.post("/api/v1/groups", headers=auth(), json={"name": "web"}).json()[
        "id"
    ]
    created = client.post(
        "/api/v1/mcp/clients",
        headers=auth(),
        json={"name": "platform", "group_ids": [group], "actions": ["cpu", "logs"]},
    ).json()
    ident = created["id"]
    assert (
        client.put(
            f"/api/v1/mcp/clients/{ident}",
            headers=auth(),
            json={"actions": ["cpu", "logs", "bogus"]},
        ).status_code
        == 422
    )
    assert (
        client.put(
            f"/api/v1/mcp/clients/{ident}",
            headers=auth(),
            json={"actions": ["cpu"], "group_ids": []},
        ).status_code
        == 422
    )
    assert (
        client.put(
            f"/api/v1/mcp/clients/{ident}",
            headers=auth(),
            json={"actions": ["cpu", "logs", "syslog"], "all_hosts": True},
        ).status_code
        == 200
    )
    row = next(
        c for c in client.get("/api/v1/mcp/clients").json()["items"] if c["id"] == ident
    )
    assert row["actions"] == ["cpu", "logs", "syslog"] and row["all_hosts"] == 1
    # A client created on this release already has the full action list.
    assert access.extend_client_actions() == []
    # Startup extension: a client from before v0.6.0 holding `logs` gains the
    # implied log tools once.
    _created_before_v060(ident)
    changed = access.extend_client_actions()
    assert changed and changed[0][0] == ident
    row = next(
        c for c in client.get("/api/v1/mcp/clients").json()["items"] if c["id"] == ident
    )
    assert {"nginx", "nginx_access", "java", "service_detail"} <= set(row["actions"])
    assert "jvm" not in row["actions"] and "service_map" not in row["actions"]
    assert access.extend_client_actions() == []
    with store.db() as c:
        audit = c.execute(
            "SELECT detail FROM audit WHERE action='mcp_client_actions_extended'"
        ).fetchone()
    assert audit and audit["detail"].startswith("v0.6.0:")
    # The token keeps working with the new scope.
    assert mcp_call(client, created["token"], "ssh_list_groups")[0] == 200


def _client_actions(client, ident):
    return next(
        c["actions"]
        for c in client.get("/api/v1/mcp/clients").json()["items"]
        if c["id"] == ident
    )


def _created_before_v060(*idents):
    """Make clients look like ones that existed before the extension marker."""
    with store.db() as c:
        c.executemany(
            "UPDATE mcp_clients SET actions_extended='' WHERE id=?",
            [(ident,) for ident in idents],
        )


def _extension_audits():
    with store.db() as c:
        return c.execute(
            "SELECT COUNT(*) FROM audit WHERE action='mcp_client_actions_extended'"
        ).fetchone()[0]


def test_removed_extension_actions_are_not_granted_again_on_restart(client):
    ident = client.post(
        "/api/v1/mcp/clients",
        headers=auth(),
        json={"name": "platform", "all_hosts": True, "actions": ["cpu", "logs"]},
    ).json()["id"]
    _created_before_v060(ident)
    assert [i for i, _ in access.extend_client_actions()] == [ident]
    assert "nginx" in _client_actions(client, ident)
    # The administrator removes an implied action with 编辑权限 ...
    kept = [a for a in _client_actions(client, ident) if a != "nginx"]
    assert (
        client.put(
            f"/api/v1/mcp/clients/{ident}", headers=auth(), json={"actions": kept}
        ).status_code
        == 200
    )
    # ... and it stays removed across restarts, without new audit rows.
    for _ in range(2):
        assert access.extend_client_actions() == []
    assert _client_actions(client, ident) == kept
    assert _extension_audits() == 1
    # Granting `logs` to a client that was already considered is the
    # administrator's explicit choice too: nothing implied is added later.
    other = client.post(
        "/api/v1/mcp/clients",
        headers=auth(),
        json={"name": "cpu-only", "all_hosts": True, "actions": ["cpu"]},
    ).json()["id"]
    _created_before_v060(other)
    assert access.extend_client_actions() == []
    assert (
        client.put(
            f"/api/v1/mcp/clients/{other}", headers=auth(), json={"actions": ["logs"]}
        ).status_code
        == 200
    )
    assert access.extend_client_actions() == []
    assert _client_actions(client, other) == ["logs"]


def test_clients_extended_before_the_marker_existed_are_not_extended_again(client):
    """Upgrade from a release that extended on every start without a marker."""
    old, fresh = (
        client.post(
            "/api/v1/mcp/clients",
            headers=auth(),
            json={"name": name, "all_hosts": True, "actions": ["cpu", "logs"]},
        ).json()["id"]
        for name in ("extended-by-v0.6.0", "never-extended")
    )
    # v0.6.0 extended `old` and wrote its audit row; the administrator then
    # removed nginx. Neither client carries the new marker yet.
    _created_before_v060(old, fresh)
    with store.db() as c:
        c.execute(
            "UPDATE mcp_clients SET actions=? WHERE id=?",
            (json.dumps(["cpu", "java", "logs", "service_detail"]), old),
        )
    store.audit(
        "platform",
        "mcp_client_actions_extended",
        old,
        "success",
        "v0.6.0:java,nginx,nginx_access,service_detail,syslog",
    )
    changed = access.extend_client_actions()
    assert [i for i, _ in changed] == [fresh]
    assert "nginx" in _client_actions(client, fresh)
    assert _client_actions(client, old) == ["cpu", "java", "logs", "service_detail"]
    assert access.extend_client_actions() == []
    assert _extension_audits() == 2


def test_deleted_group_neither_blocks_nor_widens_client_edits(client, key_pair):
    def group(name):
        return client.post(
            "/api/v1/groups", headers=auth(), json={"name": name}
        ).json()["id"]

    def edit(ident, **body):
        return client.put(f"/api/v1/mcp/clients/{ident}", headers=auth(), json=body)

    def row(ident):
        return next(
            c
            for c in client.get("/api/v1/mcp/clients").json()["items"]
            if c["id"] == ident
        )

    kept, gone, only = group("kept"), group("gone"), group("only")
    inside = ready_host(client, key_pair, group=kept)
    ready_host(client, key_pair, address="10.20.0.11", group=gone, zabbix="102")
    created = client.post(
        "/api/v1/mcp/clients",
        headers=auth(),
        json={"name": "scoped", "group_ids": [kept, gone], "actions": ["cpu"]},
    ).json()
    lone = client.post(
        "/api/v1/mcp/clients",
        headers=auth(),
        json={"name": "lone", "group_ids": [only], "actions": ["cpu"]},
    ).json()["id"]
    for ident in (gone, only):
        assert (
            client.delete(f"/api/v1/groups/{ident}", headers=auth()).status_code == 200
        )
    # Omitting group_ids keeps the scope that still exists.
    response = edit(created["id"], actions=["cpu", "memory"])
    assert response.status_code == 200, response.text
    assert row(created["id"])["group_ids"] == [kept]
    assert row(created["id"])["all_hosts"] == 0
    assert row(created["id"])["actions"] == ["cpu", "memory"]
    hosts = mcp_call(client, created["token"], "ssh_list_hosts")[1]["result"]
    assert [h["id"] for h in hosts] == [inside]
    # A deleted group given explicitly is still rejected.
    assert edit(created["id"], actions=["cpu"], group_ids=[gone]).status_code == 422
    # A client left without any group must choose a scope; never all hosts.
    response = edit(lone, actions=["cpu", "memory"])
    assert (
        response.status_code == 422 and "请选择授权主机组" in response.json()["detail"]
    )
    assert row(lone)["all_hosts"] == 0 and row(lone)["actions"] == ["cpu"]


def test_redaction_covers_startup_commands_and_connection_strings():
    cases = {
        "java -Dspring.datasource.password=Hunter2 -jar app.jar": "Hunter2",
        "-Djavax.net.ssl.keyStorePassword=Hunter3": "Hunter3",
        "MYSQL_ROOT_PASSWORD=Hunter4 CLIENT_SECRET=Hunter6": "Hunter4",
        "ACCESS_TOKEN=Hunter7": "Hunter7",
        "jdbc:mysql://appuser:Hunter9@10.0.0.5:3306/db": "Hunter9",
        "redis://:Hunter10@10.0.0.6:6379/0": "Hunter10",
        "aws_access_key_id=AKIAIOSFODNN7EXAMPLE": "AKIAIOSFODNN7EXAMPLE",
        "accessKeyId=LTAI5tFakeKeyId1234": "LTAI5tFakeKeyId1234",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop": "eyJhbGciOiJIUzI1NiJ9",
        "--spring.datasource.url=jdbc:mysql://h/db?user=u&password=Hunter11&x=1": "Hunter11",
        'password: "my secret value"': "my secret value",
        # The secret in the next argument, and *_pwd keys.
        "app --password Hunter12 --port 1": "Hunter12",
        "mysql -u root --password 'Hunter13 x'": "Hunter13",
        "-Ddb.pwd=Hunter14": "Hunter14",
        "ExecStart=/opt/app --api-key Hunter15": "Hunter15",
    }
    for source, secret in cases.items():
        result = diagnostics.redact_output(source)
        assert secret not in result, (source, result)
        assert "REDACTED" in result
    kept = diagnostics.redact_output("-Xmx2g -XX:+UseG1GC -jar billing.jar --port=8080")
    assert "Xmx2g" in kept and "UseG1GC" in kept and "8080" in kept
    # Directory variables stay; an empty value never swallows the next line.
    assert diagnostics.redact_output("PWD=/opt/app OLDPWD=/root") == (
        "PWD=/opt/app OLDPWD=/root"
    )
    assert diagnostics.redact_output("ARG -Dapp.password=\nARG -Xmx2g") == (
        "ARG -Dapp.password=\nARG -Xmx2g"
    )
    assert "--port 1" in diagnostics.redact_output("--token x --port 1")


def test_timeout_keeps_partial_output_and_benign_stderr_stays_success(monkeypatch):
    class Chan:
        def __init__(self, out, err, slow=False):
            self.out, self.err, self.slow = out, err, slow
            self.sent = False

        def settimeout(self, value):
            pass

        def exec_command(self, command):
            self.command = command

        def recv_ready(self):
            return bool(self.out)

        def recv(self, size):
            data, self.out = self.out[:size], self.out[size:]
            return data

        def recv_stderr_ready(self):
            return bool(self.err)

        def recv_stderr(self, size):
            data, self.err = self.err[:size], self.err[size:]
            return data

        def exit_status_ready(self):
            return not self.slow

        def recv_exit_status(self):
            return 0

        def close(self):
            pass

    class Transport:
        def __init__(self, chan):
            self.chan = chan

        def open_session(self, timeout):
            return self.chan

    class Client:
        def __init__(self, chan):
            self.chan = chan

        def get_transport(self):
            return Transport(self.chan)

        def close(self):
            pass

    host = {
        "id": 1,
        "name": "h",
        "address": "10.0.0.1",
        "port": 22,
        "username": "root",
        "host_key": "k",
        "credential_id": 1,
        "proxy_id": None,
        "revision": 1,
        "mode": "standard",
    }
    monkeypatch.setattr(store, "get_host", lambda hid: host)
    monkeypatch.setattr(diagnostics, "private_key", lambda cid: object())
    monkeypatch.setattr(diagnostics, "_route", lambda host: (None, None))
    chan = Chan(b"", b"df: /run/user/1000/gvfs: Permission denied\n")
    chan.out = b"Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda 100 50 50 50% /\n"
    monkeypatch.setattr(diagnostics, "client_connect", lambda *a, **k: Client(chan))
    result = diagnostics._execute_inner(1, "disk")
    # `Permission denied` on an unrelated autofs mount is a warning, not a failure.
    assert result["status"] == "success" and result["warnings"]
    slow = Chan(b"CPU_COUNT=2\n1.00 1.00 1.00 1/10 1\n", b"", slow=True)
    monkeypatch.setattr(diagnostics, "client_connect", lambda *a, **k: Client(slow))
    monkeypatch.setattr(diagnostics.time, "monotonic", _clock([0, 0, 0, 100, 100, 100]))
    result = diagnostics._execute_inner(1, "cpu")
    assert result["status"] == "partial" and result["timed_out"]
    assert result["incomplete_reason"] == "timeout" and result["exit_code"] is None
    assert any(m["metric"] == "load_1m" for m in result["summary"]["metrics"])


def _clock(values):
    values = list(values)

    def monotonic():
        return values.pop(0) if len(values) > 1 else values[0]

    return monotonic


def test_logs_summary_keeps_bounded_entries_and_flags_journal_access():
    text = (
        "CAPABILITY_MISSING:journal-permission\n"
        "2026-10-29T10:00:01+0800 host kernel: Out of memory: Killed process 4242 (java)\n"
        "2026-10-29T10:00:02+0800 host kernel: EXT4-fs error (device sda1): ext4_find_entry\n"
        "2026-10-29T10:00:03+0800 host systemd[1]: nginx.service: Failed with result 'exit-code'.\n"
        "2026-10-29T10:00:04+0800 host sshd[1]: Failed password for root from 10.0.0.9 port 1 ssh2\n"
    )
    report = observations.analyze("log_errors", text)
    summary = report["summary"]
    assert summary["entries_total"] == 4 and len(summary["entries"]) == 4
    assert set(summary["matched"]) == {"oom", "io_error", "service", "auth"}
    assert summary["first_at"].startswith("2026-10-29T10:00:01")
    assert summary["journal_access"] == "limited"
    metrics = {f["metric"] for f in report["findings"]}
    assert {"oom_matches", "log_io_error", "log_service", "journal_access"} <= metrics
    long = "\n".join(
        f"2026-10-29T10:00:{i:02d}+0800 host app: line {i}" for i in range(60)
    )
    assert len(observations.analyze("logs", long)["summary"]["entries"]) == 40


def test_service_parser_knows_missing_units_and_restarts():
    missing = observations.analyze(
        "service",
        "Id=ghost.service\nLoadState=not-found\nActiveState=inactive\nSubState=dead\nResult=success\n",
    )
    metrics = {f["metric"] for f in missing["findings"]}
    assert "unit_not_found" in metrics and "service_active_state" not in metrics
    looping = observations.analyze(
        "service",
        "Id=app.service\nLoadState=loaded\nActiveState=activating\nSubState=auto-restart\n"
        "Result=exit-code\nNRestarts=7\nExecMainStatus=1\n",
    )
    metrics = {f["metric"]: f for f in looping["findings"]}
    assert metrics["service_restarts"]["value"] == 7
    assert metrics["service_result"]["value"] == "exit-code"
    inventory = observations.analyze(
        "service_inventory",
        "nginx.service loaded active running Nginx\n"
        "crond.service loaded failed failed Cron\n",
    )
    assert [u["unit"] for u in inventory["summary"]["units"]] == [
        "nginx.service",
        "crond.service",
    ]
    assert inventory["summary"]["active_counts"] == {"active": 1, "failed": 1}
    assert "SERVICE_PROPERTIES" not in diagnostics.command_for("service", "nginx")
    assert "NRestarts" in diagnostics.command_for("service", "nginx")


def test_sockets_and_health_summaries_carry_rows():
    sockets = observations.analyze(
        "sockets",
        "Total: 120\nTCP:   30 (estab 12, closed 3, orphaned 0, timewait 2)\n\n"
        "State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
        "LISTEN 0      511    0.0.0.0:80         0.0.0.0:*\n"
        "LISTEN 0      128    [::]:22            [::]:*\n",
    )
    assert [row["port"] for row in sockets["summary"]["listening"]] == [80, 22]
    assert sockets["summary"]["socket_stats"]["tcp_established"] == 12
    health = observations.analyze(
        "health",
        "CPU_COUNT=2\n\n[负载与运行时长]\n0.10 0.20 0.30 1/100 99\n100.0 50.0\n\n"
        "[高 CPU 进程]\n  PID COMMAND %CPU %MEM\n 4242 java 85.0 20.0\n 1 systemd 0.1 0.2\n",
    )
    assert health["summary"]["top_processes"][0] == {
        "pid": 4242,
        "name": "java",
        "cpu_percent": 85.0,
        "memory_percent": 20.0,
    }


def test_journal_scripts_flag_permission_without_breaking_root():
    for action in ("kernel", "log_errors", "oom"):
        command = diagnostics.command_for(action)
        assert "journal-permission" in command and "exit 69" in command
    assert "journal-permission" in diagnostics.command_for("logs", "nginx")


def test_job_request_keeps_options_and_rejects_oversized(client, key_pair, monkeypatch):
    hid = ready_host(client, key_pair)
    monkeypatch.setattr(jobs.POOL, "submit", lambda *_: None)
    created = client.post(
        "/api/v1/jobs",
        headers=auth(),
        json={"host_ids": [hid], "action": "collect", "options": {"actions": ["cpu"]}},
    )
    assert created.status_code == 202, created.text
    job = jobs.detail(created.json()["job_ids"][0])
    assert job["request"]["options"] == {"actions": ["cpu"]}
    huge = client.post(
        "/api/v1/jobs",
        headers=auth(),
        json={
            "host_ids": [hid],
            "action": "collect",
            "options": {"actions": ["cpu"], "pad": "x" * 5000},
        },
    )
    assert huge.status_code == 422
    assert re.search(r"actions=cpu", jobs.audit_detail(job["request"]))
    assert json.dumps(jobs.audit_detail({"options": {"k": "v" * 500}})).count("v") <= 60

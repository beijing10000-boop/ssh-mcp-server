"""java_apps: Java applications with the ports they can be reached on."""

import asyncio
import json
import os
import re
import subprocess
import sys
import time
import zipfile

import pytest

from sshmcp import catalog, diagnostics, extensions, observations
from sshmcp.extensions import apps as apps_ext

needs_sh = pytest.mark.skipif(not os.path.exists("/bin/sh"), reason="needs sh")
needs_linux = pytest.mark.skipif(
    not (os.path.exists("/bin/sh") and os.path.exists("/proc/self/stat")),
    reason="needs /bin/sh and Linux /proc",
)
CONTAINER = "3f2a9c1b7d4e" + "0" * 52

HEADER = """[AIOPS_APPS]
SCAN_UID 0
ADDR 10.20.0.15
ADDR 10.20.8.15
ADDR not-an-address
JAVA_TOTAL 4
"""
# Spring Boot under systemd: one port for everyone, one on loopback only.
ORDERS = """[AIOPS_APP_PID]
PID 4242
PS appuser 86400 2300000
USER appuser
UNIT orders.service
ARG java
ARG -Xmx2g
ARG -Dspring.datasource.password=Hunter2
ARG -jar
ARG /srv/orders/orders-service-2.3.1.jar
ARG --spring.application.name=orders
ARG --spring.profiles.active=prod,cn
ARG --server.port=6066
ARG --token
ARG Hunter4
ARGS_END 10
"""
TOMCAT = """[AIOPS_APP_PID]
PID 5151
PS tomcat 864000 1048576
USER tomcat
UNIT tomcat.service
ARG /usr/lib/jvm/jre/bin/java
ARG -Dcatalina.base=/opt/tomcat
ARG -classpath
ARG /opt/tomcat/bin/bootstrap.jar:/opt/tomcat/bin/tomcat-juli.jar
ARG org.apache.catalina.startup.Bootstrap
ARG start
ARGS_END 6
"""
# In a bridge-network container: its sockets are not the host's.
BILLING = """[AIOPS_APP_PID]
PID 6363
PS 1000 3600 800000
USER UNKNOWN
CONTAINER 3f2a9c1b7d4e
ARG java
ARG -jar
ARG /app/billing.jar
ARG --server.port=8080
ARGS_END 4
"""
# A batch job: no socket at all.
NIGHTLY = """[AIOPS_APP_PID]
PID 7474
PS batch 120 400000
USER batch
ARG java
ARG -cp
ARG /opt/jobs/lib/*
ARG com.example.jobs.Nightly
ARGS_END 4
"""
LISTEN = """[AIOPS_LISTEN]
L 4242 *:6066
L 4242 [::ffff:127.0.0.1]:6067
L 5151 0.0.0.0:8080
L 5151 127.0.0.1:8005
L 5151 [::]:8080
L 5151 *:notaport
LISTEN_TOTAL 9
LISTEN_USERS 9
"""
DOCKER = (
    "[AIOPS_DOCKER]\n"
    f"D {CONTAINER} 0.0.0.0:18080->8080/tcp, :::18080->8080/tcp, 9000/tcp, "
    "127.0.0.1:18443->8443/tcp, 0.0.0.0:5353->53/udp\n"
    "D " + "a" * 64 + " 0.0.0.0:3306->3306/tcp\n"
)
OUTPUT = HEADER + ORDERS + TOMCAT + BILLING + NIGHTLY + LISTEN + DOCKER


def report_of(text):
    """The executor redacts stdout before parsing; do the same here."""
    return observations.analyze("java_apps", diagnostics.redact_output(text))


def test_inventory_joins_processes_ports_containers_and_addresses():
    report = report_of(OUTPUT)
    summary = report["summary"]
    assert summary["addresses"] == ["10.20.0.15", "10.20.8.15"]
    assert summary["java_processes"] == 4 and "apps_shown" not in summary
    assert summary["port_owner_visible"] is True and summary["docker_ports"] == "ok"
    rows = {row["pid"]: row for row in summary["apps"]}
    orders = rows[4242]
    assert orders["application"] == "orders" and orders["profiles"] == ["prod", "cn"]
    assert orders["main"] == "orders-service-2.3.1.jar"
    assert orders["jar_path"] == "/srv/orders/orders-service-2.3.1.jar"
    assert orders["user"] == "appuser" and orders["unit"] == "orders.service"
    assert orders["elapsed_seconds"] == 86400 and orders["rss_KiB"] == 2300000
    assert orders["ports"] == [6066, 6067] and orders["local_ports"] == [6067]
    assert orders["ports_source"] == "listen" and orders["declared_port"] == 6066
    tomcat = rows[5151]
    assert tomcat["application"] == "tomcat" and tomcat["jar_path"] is None
    assert tomcat["main"] == "org.apache.catalina.startup.Bootstrap"
    assert tomcat["ports"] == [8005, 8080] and tomcat["local_ports"] == [8005]
    billing = rows[6363]
    assert billing["container"] == "3f2a9c1b7d4e" and billing["user"] == "1000"
    # The host ports Docker publishes, not the container's own 8080.
    assert billing["ports"] == [18080, 18443] and billing["local_ports"] == [18443]
    assert billing["ports_source"] == "docker" and billing["declared_port"] == 8080
    nightly = rows[7474]
    assert nightly["application"] == "未识别" and nightly["ports"] == []
    assert nightly["ports_source"] is None
    unknown = next(f for f in report["findings"] if f["metric"] == "ports_unknown")
    assert unknown["value"] == {"count": 1, "pids": [7474]}
    assert unknown["level"] == "info" and "root" not in unknown["hint"]


def test_inventory_never_returns_the_command_line():
    dumped = json.dumps(report_of(OUTPUT), ensure_ascii=False)
    for secret in ("Hunter2", "Hunter4", "-Xmx2g", "spring.datasource"):
        assert secret not in dumped
    # The parser stays safe on output the executor did not redact.
    raw = json.dumps(observations.analyze("java_apps", OUTPUT), ensure_ascii=False)
    assert "Hunter2" not in raw and "Hunter4" not in raw


def test_without_root_a_declared_port_stands_in_and_says_so():
    text = (
        HEADER.replace("SCAN_UID 0", "SCAN_UID 1001")
        + ORDERS
        + BILLING
        + "[AIOPS_LISTEN]\nLISTEN_TOTAL 5\nLISTEN_USERS 0\n"
        + "[AIOPS_DOCKER]\nDOCKER_UNAVAILABLE\n"
    )
    report = report_of(text)
    summary = report["summary"]
    assert summary["scan_uid"] == 1001 and summary["port_owner_visible"] is False
    assert summary["docker_ports"] == "unavailable"
    rows = {row["pid"]: row for row in summary["apps"]}
    assert rows[4242]["ports"] == [6066] and rows[4242]["ports_source"] == "argument"
    # A container's own port says nothing about the host port.
    assert rows[6363]["ports"] == [] and rows[6363]["ports_source"] is None
    unknown = next(f for f in report["findings"] if f["metric"] == "ports_unknown")
    assert unknown["value"]["pids"] == [6363]
    assert "不是 root" in unknown["hint"] and "读不到 Docker" in unknown["hint"]


def test_no_java_no_listing_and_a_cut_off_inventory():
    none = report_of("[AIOPS_APPS]\nSCAN_UID 0\nADDR 10.20.0.15\nNO_JAVA\n")
    assert none["summary"]["java_processes"] == 0 and none["summary"]["apps"] == []
    assert none["summary"]["addresses"] == ["10.20.0.15"]
    assert [f["metric"] for f in none["findings"]] == ["java_not_found"]
    # ss missing: the inventory stands, the ports are unknown, not absent.
    no_ss = report_of(HEADER + ORDERS + "[AIOPS_LISTEN]\nCAPABILITY_MISSING:ss\n")
    assert no_ss["summary"]["port_owner_visible"] is None
    assert no_ss["summary"]["apps"][0]["ports_source"] == "argument"
    assert any(f["metric"] == "collection_coverage" for f in no_ss["findings"])
    # More processes than listed, and the time budget ran out.
    cut = report_of(
        HEADER.replace("JAVA_TOTAL 4", "JAVA_TOTAL 75")
        + ORDERS
        + "APPS_TIME_BUDGET 5151\n"
        + LISTEN
    )
    assert cut["summary"]["java_processes"] == 75 and cut["summary"]["apps_shown"] == 1
    assert cut["summary"]["time_budget_reached"] is True
    assert any(f["metric"] == "apps_not_all_listed" for f in cut["findings"])
    # Whatever arrives, the parser answers.
    for text in ("", "garbage", OUTPUT[:300], OUTPUT[: len(OUTPUT) // 2]):
        json.dumps(observations.analyze("java_apps", text, status="partial"))


def test_a_process_manager_unit_does_not_name_the_application():
    block = NIGHTLY.replace("USER batch\n", "USER batch\nUNIT supervisord.service\n")
    report = report_of(HEADER + block + LISTEN)
    (row,) = report["summary"]["apps"]
    assert row["unit"] == "supervisord.service" and row["application"] == "未识别"
    assert row["main"] == "com.example.jobs.Nightly"
    # A jar still names it, and the application's own unit does.
    jar = block.replace(
        "ARG -cp\nARG /opt/jobs/lib/*\nARG com.example.jobs.Nightly\n",
        "ARG -jar\nARG /opt/jobs/nightly-1.0.jar\n",
    )
    assert report_of(HEADER + jar)["summary"]["apps"][0]["application"] == "nightly-1.0"
    own = NIGHTLY.replace("USER batch\n", "USER batch\nUNIT nightly.service\n")
    assert report_of(HEADER + own)["summary"]["apps"][0]["application"] == "nightly"


def test_published_ports_and_loopback_addresses():
    published = apps_ext.published_of(
        "D " + "b" * 64 + " 10.0.0.5:7000-7002->7000-7002/tcp, [::1]:9443->443/tcp\n"
        "D " + "c" * 64 + " 0.0.0.0:1000-9000->1000-9000/tcp\n"
        "D " + "d" * 64 + "\n"
    )
    assert published["b" * 12] == {7000: True, 7001: True, 7002: True, 9443: False}
    # A range wider than a row can hold is left out, an idle container is known.
    assert published["c" * 12] == {} and published["d" * 12] == {}
    listeners = apps_ext.listeners_of(
        "L 1 127.0.0.1:8080\nL 1 10.0.0.5:8080\nL 2 ::1:9000\nL 2 127.0.0.53%lo:53\n"
        "L 3 :::7001\nL 3 *:70000\n"
    )
    assert listeners == {1: {8080: True}, 2: {9000: False, 53: False}, 3: {7001: True}}


def with_libs(block, lines):
    """The block with what the script prints about its jars (before the argv)."""
    head, mark, rest = block.partition("ARG ")
    return head + lines + mark + rest


def test_dubbo_version_comes_from_jar_file_names():
    text = (
        HEADER
        # The JAR on disk is gone, the one the JVM holds open was read whole.
        + with_libs(ORDERS, "JARFD 4 1\nLIB dubbo-2.7.23.jar\nLIBS dir\n")
        # Started with a class path: Dubbo modules among the open files.
        + with_libs(
            TOMCAT,
            "LIB dubbo-cluster-3.2.5.jar\nLIB dubbo-common-3.2.5.jar\nLIBS open\n",
        )
        # The whole directory of the JAR lists no Dubbo.
        + with_libs(BILLING, "JARFD 7 0\nLIBS dir\n")
        # No JAR to read and nothing among the open files: not known.
        + with_libs(NIGHTLY, "LIBS open\n")
        + LISTEN
        + DOCKER
    )
    report = report_of(text)
    rows = {row["pid"]: row for row in report["summary"]["apps"]}
    assert (rows[4242]["dubbo_version"], rows[4242]["dubbo_status"]) == (
        "2.7.23",
        "found",
    )
    assert (rows[5151]["dubbo_version"], rows[5151]["dubbo_status"]) == (
        "3.2.5",
        "found",
    )
    assert (rows[6363]["dubbo_version"], rows[6363]["dubbo_status"]) == (None, "absent")
    assert (rows[7474]["dubbo_version"], rows[7474]["dubbo_status"]) == (
        None,
        "unknown",
    )
    assert not any("dubbo_versions" in row for row in rows.values())
    assert not any(f["metric"].startswith("dubbo") for f in report["findings"])
    # The other fields are what they were without these lines.
    plain = {row["pid"]: row for row in report_of(OUTPUT)["summary"]["apps"]}
    for pid, row in rows.items():
        same = {key: value for key, value in row.items() if "dubbo" not in key}
        assert same == {k: v for k, v in plain[pid].items() if "dubbo" not in k}
    # Output of a server that does not look for Dubbo yet: not known, not absent.
    assert {row["dubbo_status"] for row in plain.values()} == {"unknown"}
    assert {row["dubbo_version"] for row in plain.values()} == {None}
    assert "dubbo_status=unknown" in report["summary"]["coverage"]


def test_dubbo_status_tells_absent_from_not_checked():
    of = apps_ext.dubbo_of
    assert of("LIB dubbo-2.7.9.jar\nLIBS dir\n") == (["2.7.9"], "found")
    assert of("LIB dubbo-3.3.0-beta.1.jar\nLIBS dir\n") == (["3.3.0-beta.1"], "found")
    # The all-in-one artifact tells the release before a module does.
    assert of("LIB dubbo-common-2.7.5.jar\nLIB dubbo-2.7.8.jar\nLIBS dir\n") == (
        ["2.7.8"],
        "found",
    )
    assert of("LIB dubbo-rpc-api-3.1.11.jar\nLIBS open\n") == (["3.1.11"], "found")
    # A hit in a JAR that was only partly read still counts, a miss does not.
    assert of("LIB dubbo-2.6.12.jar\nLIBS tail\n") == (["2.6.12"], "found")
    for state in ("tail", "cut", "nofd", "open", "unreadable", "anything"):
        assert of(f"JARFD 5 0\nLIBS {state}\n") == ([], "unknown"), state
    assert of("") == ([], "unknown") and of("LIBS\n") == ([], "unknown")
    assert of("LIBS dir\n") == ([], "absent")
    # Dubbo without a version in any file name.
    assert of("LIBX\nLIBS dir\n") == ([], "present")
    assert of("LIBX\nLIBS open\n") == ([], "present")
    assert of("LIBX\nLIB dubbo-2.7.23.jar\nLIBS tail\n") == (["2.7.23"], "found")
    # Names that do not tell the release of Dubbo are not taken for one.
    for name in (
        "dubbo-spring-boot-starter-2.7.23.jar",
        "dubbo-admin-ui-0.7.0-SNAPSHOT.jar",
        "base-dubbo-api-1.0.0-SNAPSHOT.jar",
        "dubbo-.jar",
        "dubbo-2.7.23.jar.bak",
        "x" * 90,
    ):
        assert of(f"LIB {name}\nLIBS dir\n") == ([], "absent"), name
    # An argument cannot pass for one of these lines: argv lines start with ARG.
    assert of("ARG LIB dubbo-9.9.9.jar\nARG LIBX\nLIBS dir\n") == ([], "absent")


def test_two_dubbo_versions_in_one_application_are_reported():
    block = with_libs(
        ORDERS, "JARFD 4 0\nLIB dubbo-2.6.12.jar\nLIB dubbo-2.7.23.jar\nLIBS dir\n"
    )
    report = report_of(HEADER + block + BILLING + LISTEN)
    rows = {row["pid"]: row for row in report["summary"]["apps"]}
    assert rows[4242]["dubbo_version"] == "2.6.12"
    assert rows[4242]["dubbo_versions"] == ["2.6.12", "2.7.23"]
    assert rows[4242]["dubbo_status"] == "found" and "dubbo_versions" not in rows[6363]
    mixed = next(f for f in report["findings"] if f["metric"] == "dubbo_versions_mixed")
    assert mixed["level"] == "info" and mixed["value"] == {"count": 1, "pids": [4242]}
    # The same version from two modules is one version.
    same = with_libs(
        ORDERS, "LIB dubbo-common-3.2.5.jar\nLIB dubbo-cluster-3.2.5.jar\nLIBS open\n"
    )
    (row,) = report_of(HEADER + same)["summary"]["apps"]
    assert row["dubbo_version"] == "3.2.5" and "dubbo_versions" not in row


def test_script_reads_jar_names_through_the_descriptor_the_jvm_holds():
    script = diagnostics.command_for("java_apps")
    # Only the file the process itself has open, never a path from its argv.
    assert 'jf="/proc/$pid/fd/$jfd"' in script
    assert 'tail -c 22 "$jf"' in script and 'tail -c "$need" "$jf"' in script
    assert script.count('"$jf"') == 2 and "/root" not in script
    # A pipe or a device under that name is not read (it would block).
    assert '[ ! -f "/proc/$pid/fd/$jfd" ]' in script
    assert str(apps_ext.MAX_DIRECTORY) in script
    for tool in ("unzip", "jar tf", "jar -tf", "zipinfo"):
        assert tool not in script, tool
    # Every option java.main_of skips together with its value is skipped here.
    from sshmcp.extensions import java as java_ext

    for option in java_ext.VALUE_OPTIONS:
        assert option + "|" in script or option + '"' in script, option
    assert "__LIB_GREP__" not in script and apps_ext.LIB_GREP in script
    # The file names that are printed come out of fixed patterns only.
    assert "'" not in apps_ext.LIB_GREP
    for program in (apps_ext.JAR_AWK, apps_ext.FD_AWK, apps_ext.LIB_AWK):
        assert "'" not in program


def awk(program, text, *options):
    result = subprocess.run(
        ["awk", *options, program], input=text, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.splitlines()


@needs_sh
def test_awk_names_the_jar_like_main_of_does():
    from sshmcp.extensions import java as java_ext

    cases = [
        ["java", "-jar", "/srv/orders/orders_12.jar"],
        ["java", "-jar", "-Xms128m", "-Xmx1g", "/srv/orders/orders_12.jar", "--x=1"],
        ["/usr/bin/java", "-Xmx1g", "-Dapp=a", "-jar", "orders.war"],
        ["java", "-cp", "/opt/lib/dubbo-2.7.8.jar:/opt/app.jar", "com.example.Main"],
        ["java", "-classpath", "a.jar", "-jar", "b.jar"],
        ["java", "@/etc/app/java.args", "-jar", "/srv/a+b.jar"],
        ["java", "--add-opens", "java.base/java.lang=ALL-UNNAMED", "-jar", "c.jar"],
        ["java", "-m", "com.example/com.example.Main", "-jar", "x.jar"],
        ["java", "--module=com.example", "x.jar"],
        ["java", "com.example.Main", "-jar", "x.jar"],
        ["jsvc", "-cwd", "/opt/app", "-pidfile", "/run/a.pid", "-jar", "d.jar"],
        ["java", "-jar", "/srv/we ird.jar"],
        ["java", "-jar", "/srv/$(id).jar"],
        ["java", "-jar", "/srv/not-a-jar.txt"],
        ["java", "-jar"],
        ["java"],
    ]
    for argv in cases:
        main, _ = java_ext.main_of(argv)
        want = []
        if main["kind"] == "jar":
            base = main["name"].rsplit("/", 1)[-1]
            if re.fullmatch(r"[A-Za-z0-9._+-]+\.[jw]ar", base):
                want = [base]
        assert awk(apps_ext.JAR_AWK, "\n".join(argv) + "\n") == want, argv


@needs_sh
def test_awk_picks_the_jar_descriptor_and_dubbo_names():
    listing = (
        "total 0\n"
        "lrwx------ 1 app app 64 Nov 13 10:00 0 -> /dev/null\n"
        "lr-x------ 1 app app 64 Nov 13 10:00 3 -> /usr/lib/jvm/jre/lib/rt.jar\n"
        "lr-x------ 1 app app 64 Nov 13 10:00 4 -> /srv/orders/orders_12.jar (deleted)\n"
        "lr-x------ 1 app app 64 Nov 13 10:00 5 -> /srv/orders/orders_12.jar (deleted)\n"
        "lr-x------ 1 app app 64 Nov 13 10:00 6 -> /srv/lib/dubbo-2.7.8.jar\n"
        "lr-x------ 1 app app 64 Nov 13 10:00 7 -> /srv/lib/dubbo-2.7.8.jar\n"
        "lr-x------ 1 app app 64 Nov 13 10:00 8 -> /srv/lib/base-dubbo-api-1.0.jar\n"
        "lr-x------ 1 app app 64 Nov 13 10:00 9 -> /srv/lib/dubbo-common-3.2.5.jar\n"
        "lr-x------ 1 app app 64 Nov 13 10:00 10 -> /srv/lib/dubbo.jar\n"
        "lr-x------ 1 app app 64 Nov 13 10:00 11 -> /srv/lib/dubbo-2.7.8.jar.log\n"
        "lrwx------ 1 app app 64 Nov 13 10:00 12 -> socket:[12345]\n"
    )
    assert awk(apps_ext.FD_AWK, listing, "-v", "base=orders_12.jar") == [
        "LIB dubbo-2.7.8.jar",
        "LIB dubbo-common-3.2.5.jar",
        "LIBX",
        "JARFD 4 1",
    ]
    # Not started from a JAR: nothing to read, the open jars are still named.
    assert awk(apps_ext.FD_AWK, listing, "-v", "base=") == [
        "LIB dubbo-2.7.8.jar",
        "LIB dubbo-common-3.2.5.jar",
        "LIBX",
    ]
    # The application's own JAR is not a Dubbo jar, whatever it is called.
    own = "lr-x------ 1 a a 64 Nov 13 10:00 4 -> /srv/dubbo-2.7.8.jar\n"
    assert awk(apps_ext.FD_AWK, own, "-v", "base=dubbo-2.7.8.jar") == ["JARFD 4 0"]
    names = (
        "/dubbo-2.7.23.jar\n/dubbo-spring-boot-starter-2.7.23.jar\n/dubbo-2.7.23.jar\n"
        "/dubbo-registry-api-2.7.23.jar\n/dubbo-admin-ui-0.7.0.jar\n"
        "META-INF/maven/org.apache.dubbo/dubbo/pom.properties\n"
    )
    assert awk(apps_ext.LIB_AWK, names) == [
        "LIB dubbo-2.7.23.jar",
        "LIB dubbo-registry-api-2.7.23.jar",
        "LIBX",
    ]
    many = "".join(f"/dubbo-2.7.{n}.jar\n" for n in range(30))
    assert len(awk(apps_ext.LIB_AWK, many)) == 8


def test_script_is_a_fixed_read_only_bounded_template():
    script = diagnostics.command_for("java_apps")
    assert script.startswith(diagnostics.PREFIX) and "timeout -k 1" in script
    assert "head -n " + str(apps_ext.MAX_APPS) in script
    assert "ss -ltnp" in script and "docker ps --no-trunc" in script
    assert "jcmd" not in script and "jstat" not in script
    assert not re.search(r"(?<![\w/.$-])java\s+-", script)
    forbidden = re.compile(
        r"(?<![\w./-])(?:tee|touch|mkdir|rm|mv|cp|dd|truncate|chmod|chown|kill|pkill"
        r"|killall|docker (?!ps )\w+)(?![\w.-])"
    )
    assert not forbidden.search(script), forbidden.search(script)
    for text in ("sed -i", ">>", "system(", "getline"):
        assert text not in script, text
    unquoted = re.sub(r"'[^']*'", "''", script)
    assert set(re.findall(r"[0-9]*>&?[^\s;)\"'|&]*", unquoted)) <= {
        ">/dev/null",
        "2>/dev/null",
        "2>&1",
    }
    for program in re.findall(r"'([^']*)'", script):
        assert not re.search(r"\bprintf?\b[^;{}\n]*>", program), program
    with pytest.raises(ValueError):
        diagnostics.command_for("java_apps", options={"pid": 1})
    with pytest.raises(ValueError):
        diagnostics.command_for("java_apps", service="nginx.service")


@needs_sh
def test_script_parses_under_sh():
    script = diagnostics.command_for("java_apps")
    subprocess.run(["/bin/sh", "-n"], input=script, text=True, check=True)


def test_catalog_and_mcp_tool():
    entry = {row["id"]: row for row in catalog.entries()}["java_apps"]
    assert entry["tool"] == "ssh_diagnose_java_apps" and entry["params"] == []
    assert entry["category"] == "应用与中间件" and entry["risk"] == "low"
    assert entry["sensitive"] and entry["extension"] and entry["standard_only"]
    # Granted by an administrator only: neither implied nor recommended.
    assert "java_apps" not in catalog.RECOMMENDED
    from sshmcp import access
    from sshmcp.mcp_tools import mcp

    assert "java_apps" not in access.EXTENDS
    tools = {tool.name: tool for tool in asyncio.run(mcp.list_tools())}
    tool = tools["ssh_diagnose_java_apps"]
    assert tool.annotations.readOnlyHint is True
    assert set(tool.inputSchema["properties"]) <= {
        "host_id",
        "expected_revision",
        "detail",
    }
    spec = extensions.spec_for("java_apps")
    assert (spec.timeout, spec.output_limit) == (20, 65536)


@pytest.fixture
def listening_java(tmp_path):
    """A Python process named java (exec'd through a symlink) that listens on
    a loopback port and prints it."""
    link = tmp_path / "java"
    try:
        link.symlink_to(sys.executable)
    except OSError:
        pytest.skip("symlinks are not available")
    code = (
        "import socket, time\n"
        "s = socket.socket()\n"
        "s.bind(('127.0.0.1', 0))\n"
        "s.listen(1)\n"
        "print(s.getsockname()[1], flush=True)\n"
        "time.sleep(60)\n"
    )
    proc = subprocess.Popen(
        [
            str(link),
            "-c",
            code,
            "--spring.application.name=fake-orders",
            "--spring.datasource.password=Hunter2",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        port = int(proc.stdout.readline())
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            with open(f"/proc/{proc.pid}/comm") as handle:
                if handle.read().strip() == "java":
                    break
            time.sleep(0.05)
        yield proc, port
    finally:
        proc.kill()
        proc.wait()


@needs_linux
def test_script_runs_under_sh_and_finds_a_listening_process_named_java(
    listening_java,
):
    proc, port = listening_java
    result = subprocess.run(
        ["/bin/sh", "-c", diagnostics.command_for("java_apps")],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert "[AIOPS_APPS]" in result.stdout and "[AIOPS_LISTEN]" in result.stdout
    report = report_of(result.stdout)
    summary = report["summary"]
    rows = {row["pid"]: row for row in summary["apps"]}
    if proc.pid not in rows:
        assert summary["java_processes"] > apps_ext.MAX_APPS
        pytest.skip("more than 60 larger Java processes on this host")
    row = rows[proc.pid]
    assert row["application"] == "fake-orders" and row["rss_KiB"] > 0
    assert row["elapsed_seconds"] >= 0 and row["user"]
    assert "Hunter2" not in json.dumps(report, ensure_ascii=False)
    if "CAPABILITY_MISSING:ss" in result.stdout:
        pytest.skip("no ss on this host")
    # The process is this account's own, so ss names it even without root.
    assert row["ports"] == [port] and row["local_ports"] == [port]
    assert row["ports_source"] == "listen" and summary["port_owner_visible"] is True
    # Not started from a JAR and no Dubbo jar open: not known, not absent.
    assert (row["dubbo_version"], row["dubbo_status"]) == (None, "unknown")


def make_jar(path, names, comment=b""):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as jar:
        jar.comment = comment
        for name in names:
            jar.writestr(name, b"\xca\xfe\xba\xbe" + name.encode() * 3)


@pytest.fixture
def java_from_jar(tmp_path):
    """Starts Python processes named java as ``java @holder.py -jar <jar>``.

    The java launcher (and main_of) take ``@file`` for an argument file, so
    the JAR is the first non-option argument, and the process keeps the JAR
    open the way a JVM does.
    """
    link = tmp_path / "java"
    try:
        link.symlink_to(sys.executable)
    except OSError:
        pytest.skip("symlinks are not available")
    (tmp_path / "@holder.py").write_text(
        "import sys, time\n"
        "handle = open(sys.argv[2], 'rb')\n"
        "print('ready', flush=True)\n"
        "time.sleep(60)\n"
    )
    started = []

    def start(jar):
        proc = subprocess.Popen(
            [str(link), "@holder.py", "-jar", str(jar)],
            cwd=tmp_path,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        started.append(proc)
        assert proc.stdout.readline().strip() == "ready"
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            with open(f"/proc/{proc.pid}/comm") as handle:
                if handle.read().strip() == "java":
                    break
            time.sleep(0.05)
        return proc

    try:
        yield start
    finally:
        for proc in started:
            proc.kill()
            proc.wait()


@needs_linux
def test_script_reads_dubbo_from_the_jar_a_process_holds_open(java_from_jar, tmp_path):
    boot = [
        "META-INF/MANIFEST.MF",
        "BOOT-INF/classes/application.properties",
        "BOOT-INF/lib/spring-core-5.3.31.jar",
    ]
    jars = {
        # A Spring Boot JAR carrying Dubbo; deleted from disk after the start.
        "orders_12.jar": boot
        + [
            "BOOT-INF/lib/base-dubbo-api-1.0.0-SNAPSHOT.jar",
            "BOOT-INF/lib/dubbo-2.7.23.jar",
            "BOOT-INF/lib/dubbo-spring-boot-starter-2.7.23.jar",
        ],
        "report_3.jar": boot,
        # Dubbo used module by module, in a WAR.
        "portal.war": ["WEB-INF/lib/dubbo-common-3.2.5.jar", "WEB-INF/web.xml"],
        # Dubbo's classes merged into the JAR: there, but no name has a version.
        "shaded.jar": [
            "META-INF/maven/org.apache.dubbo/dubbo/pom.properties",
            "org/apache/dubbo/common/URL.class",
        ],
    }
    for name, names in jars.items():
        make_jar(tmp_path / name, names)
    # An archive comment: the end of the file is not the 22-byte record, so
    # only the tail is searched. A hit counts, a miss proves nothing.
    make_jar(tmp_path / "legacy.jar", ["lib/dubbo-2.6.12.jar"], comment=b"by hand")
    make_jar(tmp_path / "tool.jar", ["lib/guava-33.0.jar"], comment=b"by hand")
    # Thousands of entries before the one that matters: the directory is
    # still read whole.
    make_jar(
        tmp_path / "big.jar",
        [f"BOOT-INF/classes/com/example/C{n}.class" for n in range(3000)]
        + ["BOOT-INF/lib/dubbo-3.2.5.jar"],
    )
    procs = {
        name: java_from_jar(tmp_path / name)
        for name in (*jars, "legacy.jar", "tool.jar", "big.jar")
    }
    (tmp_path / "orders_12.jar").unlink()
    result = subprocess.run(
        ["/bin/sh", "-c", diagnostics.command_for("java_apps")],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    report = report_of(result.stdout)
    rows = {row["pid"]: row for row in report["summary"]["apps"]}
    if any(proc.pid not in rows for proc in procs.values()):
        assert report["summary"]["java_processes"] > apps_ext.MAX_APPS
        pytest.skip("more than 60 larger Java processes on this host")
    got = {
        name: (rows[proc.pid]["dubbo_version"], rows[proc.pid]["dubbo_status"])
        for name, proc in procs.items()
    }
    assert got == {
        "orders_12.jar": ("2.7.23", "found"),
        "report_3.jar": (None, "absent"),
        "portal.war": ("3.2.5", "found"),
        "shaded.jar": (None, "present"),
        "legacy.jar": ("2.6.12", "found"),
        "tool.jar": (None, "unknown"),
        "big.jar": ("3.2.5", "found"),
    }
    assert rows[procs["orders_12.jar"].pid]["main"] == "orders_12.jar"
    # Only names that tell the release are printed, and no file content.
    assert "base-dubbo-api" not in result.stdout
    assert "spring-boot-starter" not in result.stdout
    assert "spring-core" not in result.stdout and "\xca\xfe" not in result.stdout
    assert not any(f["metric"].startswith("dubbo") for f in report["findings"])

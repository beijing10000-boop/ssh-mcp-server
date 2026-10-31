"""Java / JVM extensions: fixed scripts, conservative parsers, two-layer redaction."""

import json
import os
import re
import subprocess
import sys
import time

import pytest

from sshmcp import catalog, diagnostics, extensions, observations
from sshmcp.extensions import java as java_ext

needs_sh = pytest.mark.skipif(not os.path.exists("/bin/sh"), reason="needs sh")
needs_linux = pytest.mark.skipif(
    not (os.path.exists("/bin/sh") and os.path.exists("/proc/self/stat")),
    reason="needs /bin/sh and Linux /proc",
)
SECRETS = ("Hunter2", "SecretKey1", "Pwd123", "Hunter3", "Hunter4")

JAVA_HEADER = """[AIOPS_JAVA]
SCAN_UID 0
JAVA_TOTAL 3
JAVA_PIDS 4242 5151 6363
"""
# Spring Boot fat jar in a container (cgroup v2 limit 2 GiB), secrets in argv.
SPRING_BOOT = """[AIOPS_JAVA_PID]
PID 4242
PS appuser 300 3300000 35.5 9.6 2300
USER appuser
THREADS 2300
FDLIMIT 4096
CONTAINER 3f2a9c1b7d4e
CWD /app
EXE /opt/java/openjdk/bin/java
RELEASE JAVA_VERSION="17.0.9"
RELEASE IMPLEMENTOR="Eclipse Adoptium"
CGMEM 2147483648
CGMEM max
LOGFD /data/logs/billing/app.log
LOGFD /data/logs/billing/gc.log
FDS 3500
ARG java
ARG -Xms1g
ARG -Xmx2g
ARG -XX:+UseG1GC
ARG -XX:MaxMetaspaceSize=256m
ARG -Xlog:gc*:file=/data/logs/billing/gc.log:time,uptime:filecount=5,filesize=20M
ARG -Dspring.datasource.password=Hunter2
ARG -Dapp.key=SecretKey1
ARG -Ddb.pwd=Pwd123
ARG -jar
ARG /app/billing-service-1.4.2.jar
ARG --spring.profiles.active=prod,cn
ARG --spring.application.name=billing
ARG --token
ARG Hunter4
ARG --jasypt.encryptor.password=Hunter3
ARG --logging.file.name=/data/logs/billing/app.log
ARG --server.port=8080
ARGS_END 18
"""
# Tomcat on a JDK 8 JRE under systemd, cgroup v1 without a memory limit.
TOMCAT = """[AIOPS_JAVA_PID]
PID 5151
PS tomcat 864000 1048576 5.0 3.2 180
USER tomcat
THREADS 180
FDLIMIT 65536
UNIT tomcat.service
CWD /opt/tomcat
EXE /usr/lib/jvm/java-1.8.0-openjdk-1.8.0.392.b08-2.el7_9.x86_64/jre/bin/java
RELEASE JAVA_VERSION="1.8.0_392"
CGMEM 9223372036854771712
CGMEM 9223372036854771712
LOGFD /opt/tomcat/logs/catalina.out
LOGFD /opt/tomcat/logs/localhost_access_log.2026-10-30.txt
LOGFD /opt/tomcat/logs/catalina.2026-10-29.log (deleted)
FDS 220
ARG /usr/lib/jvm/jre/bin/java
ARG -Djava.util.logging.config.file=/opt/tomcat/conf/logging.properties
ARG -Djava.util.logging.manager=org.apache.juli.ClassLoaderLogManager
ARG -Xms512m
ARG -Xmx1024m
ARG -XX:+UseParallelGC
ARG -Xloggc:/opt/tomcat/logs/gc-%t.log
ARG -Djdk.tls.ephemeralDHKeySize=2048
ARG -Dorg.apache.catalina.security.SecurityListener.UMASK=0027
ARG -Dignore.endorsed.dirs=
ARG -classpath
ARG /opt/tomcat/bin/bootstrap.jar:/opt/tomcat/bin/tomcat-juli.jar
ARG -Dcatalina.base=/opt/tomcat
ARG -Dcatalina.home=/opt/tomcat
ARG -Djava.io.tmpdir=/opt/tomcat/temp
ARG org.apache.catalina.startup.Bootstrap
ARG start
ARGS_END 17
"""
# Elasticsearch 8 in Docker (uid without a passwd entry), module main class,
# part of its -D properties dropped by the per-PID byte budget.
ELASTICSEARCH = """[AIOPS_JAVA_PID]
PID 6363
PS 1000 1209600 8800000 120.0 52.0 95
USER UNKNOWN
THREADS 95
FDLIMIT 1048576
CONTAINER 9b8f6a2c1d3e
CWD /usr/share/elasticsearch
EXE /usr/share/elasticsearch/jdk/bin/java
RELEASE JAVA_VERSION="21.0.2"
RELEASE IMPLEMENTOR="Oracle Corporation"
CGMEM 8589934592
CGMEM max
FDS 1650
ARG /usr/share/elasticsearch/jdk/bin/java
ARG -Des.networkaddress.cache.ttl=60
ARG -XX:+AlwaysPreTouch
ARG -Xss1m
ARG -Djava.awt.headless=true
ARG -XX:+UseG1GC
ARG -Xlog:gc*,gc+age=trace,safepoint:file=/usr/share/elasticsearch/logs/gc.log:utctime,level,pid,tags:filecount=32,filesize=64m
ARG -Xms4g
ARG -Xmx4g
ARG -XX:MaxDirectMemorySize=2147483648
ARG -Des.path.home=/usr/share/elasticsearch
ARG -Des.distribution.type=docker
ARG --module-path
ARG /usr/share/elasticsearch/lib
ARG --add-modules=jdk.net
ARG -m
ARG org.elasticsearch.server/org.elasticsearch.bootstrap.Elasticsearch
ARGS_SKIPPED 12
ARGS_END 40
"""
JAVA_OUTPUT = JAVA_HEADER + SPRING_BOOT + TOMCAT + ELASTICSEARCH


def java_report(text):
    """The executor redacts stdout before parsing; do the same here."""
    return observations.analyze("java", diagnostics.redact_output(text))


def by_metric(findings):
    result = {}
    for finding in findings:
        result.setdefault(finding["metric"], []).append(finding)
    return result


def test_java_inventory_parses_spring_boot_tomcat_and_elasticsearch():
    report = java_report(JAVA_OUTPUT)
    summary = report["summary"]
    assert summary["java_processes"] == 3 and "processes_shown" not in summary
    rows = {row["pid"]: row for row in summary["processes"]}
    boot, tomcat, es = rows[4242], rows[5151], rows[6363]
    assert boot["main"] == "billing-service-1.4.2.jar"
    assert boot["jar_path"] == "/app/billing-service-1.4.2.jar"
    assert boot["application"] == "billing" and boot["profiles"] == ["prod", "cn"]
    assert boot["heap"]["xmx"] == "2g" and "xmx_MiB" not in boot["heap"]
    assert boot["heap"]["xms"] == "1g" and boot["heap"]["max_metaspace"] == "256m"
    assert boot["gc"]["collector"] == "G1"
    assert boot["gc"]["gc_log"] == "/data/logs/billing/gc.log"
    assert boot["gc"]["xx_flags"] == ["-XX:+UseG1GC", "-XX:MaxMetaspaceSize=256m"]
    assert boot["logs"]["configured"] == [
        "logging.file.name=/data/logs/billing/app.log"
    ]
    assert boot["logs"]["open_files"][0] == "/data/logs/billing/app.log"
    assert boot["container"] == "3f2a9c1b7d4e" and boot["unit"] is None
    assert boot["cgroup_memory_limit_bytes"] == 2147483648
    assert (
        boot["java_version"] == "17.0.9" and boot["implementor"] == "Eclipse Adoptium"
    )
    assert (boot["threads"], boot["fds"], boot["fd_limit"]) == (2300, 3500, 4096)
    assert boot["system_properties_count"] == 3 and not boot["args_truncated"]
    assert tomcat["main"] == "org.apache.catalina.startup.Bootstrap"
    assert tomcat["jar_path"] is None
    assert tomcat["application"] == "tomcat" and tomcat["unit"] == "tomcat.service"
    assert tomcat["gc"] == {
        "collector": "Parallel",
        "gc_log": "/opt/tomcat/logs/gc-%t.log",
        "xx_flags": ["-XX:+UseParallelGC"],
    }
    assert tomcat["cgroup_memory_limit_bytes"] is None
    assert tomcat["system_properties_count"] == 8
    assert "catalina.base=/opt/tomcat" in tomcat["logs"]["configured"]
    assert any(path.endswith("(deleted)") for path in tomcat["logs"]["open_files"])
    assert tomcat["java_version"] == "1.8.0_392" and tomcat["implementor"] is None
    assert es["user"] == "1000" and es["container"] == "9b8f6a2c1d3e"
    # A module main keeps its module: "module/class".
    assert es["main"] == (
        "org.elasticsearch.server/org.elasticsearch.bootstrap.Elasticsearch"
    )
    assert es["jar_path"] is None
    assert es["application"] == "未识别"
    assert es["heap"]["xss"] == "1m" and es["heap"]["max_direct"] == "2147483648"
    assert es["gc"]["gc_log"] == "/usr/share/elasticsearch/logs/gc.log"
    assert es["system_properties_count"] == 4 + 12 and not es["args_truncated"]
    assert es["cgroup_memory_limit_bytes"] == 8589934592 and es["cpu_percent"] == 120.0
    json.dumps(report, allow_nan=False)


def test_java_findings_follow_documented_thresholds():
    findings = by_metric(java_report(JAVA_OUTPUT)["findings"])
    assert {f["value"]["pid"] for f in findings["heap_exceeds_cgroup"]} == {4242}
    # Rows carry -Xmx as written ("2g"); findings still compare in MiB.
    assert findings["heap_exceeds_cgroup"][0]["value"]["xmx_MiB"] == 2048.0
    threads = findings["threads_high"][0]
    assert threads["level"] == "warning" and threads["value"]["threads"] == 2300
    assert findings["fds_near_limit"][0]["value"]["fd_limit"] == 4096
    assert findings["rss_far_above_heap"][0]["level"] == "info"
    assert findings["rss_far_above_heap"][0]["value"]["xmx_MiB"] == 2048.0
    assert findings["recent_start"][0]["value"]["elapsed_seconds"] == 300
    assert "heap_max_unset" not in findings and "many_java_processes" not in findings
    for finding in java_report(JAVA_OUTPUT)["findings"]:
        assert set(finding) >= {"level", "metric", "value", "threshold", "hint"}
        assert finding["level"] in {"critical", "warning", "info"}
    crowded = SPRING_BOOT.replace("THREADS 2300", "THREADS 6000").replace(
        "2300\n", "6000\n", 1
    )
    critical = by_metric(java_report(JAVA_HEADER + crowded)["findings"])
    assert critical["threads_high"][0]["level"] == "critical"


def test_java_command_lines_are_redacted_twice_and_previewed_only():
    for text in (JAVA_OUTPUT, diagnostics.redact_output(JAVA_OUTPUT)):
        report = observations.analyze("java", text)
        dumped = json.dumps(report, ensure_ascii=False)
        for secret in SECRETS:
            assert secret not in dumped, secret
        boot = report["summary"]["processes"][0]
        preview = boot["command_preview"]
        assert len(preview) <= 400 and "-Xmx2g" in preview and "-XX:+UseG1GC" in preview
        assert "--token [REDACTED]" in preview and "-Ddb.pwd=[REDACTED]" in preview
        assert "ARG " not in dumped
    assert java_ext.redact_args(
        [
            "java",
            "-XX:+UseG1GC",
            "-Xlog:gc:file=/var/log/key-store/gc.log",
            "-Dkey",
            "-Dmonkey.mode=on",
            "--keystore",
            "/etc/app/ks.p12",
            "SECRET_TOKEN=abc",
            "-javaagent:/opt/agent.jar",
            "com.example.Main",
            "--spring.datasource.url=jdbc:mysql://app:Hunter9@db:3306/x",
        ]
    ) == [
        "java",
        "-XX:+UseG1GC",
        "-Xlog:gc:file=/var/log/key-store/gc.log",
        "-Dkey",
        "-Dmonkey.mode=[REDACTED]",
        "--keystore",
        "[REDACTED]",
        "SECRET_TOKEN=[REDACTED]",
        "-javaagent:/opt/agent.jar",
        "com.example.Main",
        "--spring.datasource.url=jdbc:mysql://[REDACTED]@db:3306/x",
    ]


def test_java_no_process_truncation_and_heap_defaults():
    none = observations.analyze("java", "NO_JAVA\n")
    assert none["summary"]["java_processes"] == 0 and none["summary"]["processes"] == []
    assert [f["metric"] for f in none["findings"]] == ["java_not_found"]
    assert none["findings"][0]["level"] == "info"
    truncated = observations.analyze(
        "java",
        "[AIOPS_JAVA]\nSCAN_UID 0\nJAVA_TOTAL 25\nJAVA_PIDS 7001 7002\n"
        "[AIOPS_JAVA_PID]\nPID 7001\nPS app 7200 512000 1.0 1.0 40\nUSER app\n"
        "ARG java\nARG -XX:MaxRAMPercentage=75.0\nARG -jar\nARG /srv/orders.jar\n"
        "ARGS_END 4\n"
        "[AIOPS_JAVA_PID]\nPID 7002\nPS app 7200 512000 1.0 1.0 40\nUSER app\n"
        "ARG java\nARG -Dfoo=bar\n",
        status="partial",
        truncated=True,
    )
    summary = truncated["summary"]
    assert summary["java_processes"] == 25 and summary["processes_shown"] == 2
    orders, cut = summary["processes"]
    assert orders["application"] == "orders"
    assert (
        orders["heap"]["max_ram_percentage"] == 75.0 and orders["heap"]["xmx"] is None
    )
    assert cut["args_truncated"] and cut["main"] is None and cut["jar_path"] is None
    metrics = by_metric(truncated["findings"])
    # Neither MaxRAMPercentage nor a cut-off argv may be reported as "no -Xmx".
    assert "heap_max_unset" not in metrics
    assert metrics["many_java_processes"][0]["value"] == 25
    assert "collection_coverage" in metrics
    unset = observations.analyze(
        "java",
        "[AIOPS_JAVA]\nJAVA_TOTAL 1\n[AIOPS_JAVA_PID]\nPID 8001\n"
        "PS app 9000 900000 1.0 1.0 60\nUNIT orders.service\n"
        "ARG java\nARG -cp\nARG /srv/lib/*\nARG com.example.Orders\nARGS_END 4\n",
    )
    finding = by_metric(unset["findings"])["heap_max_unset"][0]
    assert finding["level"] == "warning" and finding["value"]["application"] == "orders"
    argfile = observations.analyze(
        "java",
        "[AIOPS_JAVA]\nJAVA_TOTAL 1\n[AIOPS_JAVA_PID]\nPID 8002\n"
        "ARG java\nARG @/etc/orders/jvm.options\nARG -jar\nARG orders.jar\nARGS_END 4\n",
    )
    assert "heap_max_unset" not in by_metric(argfile["findings"])


# supervisord-launched services: `-jar` only selects jar mode in the java
# launcher, so JVM options may still follow it before the jar itself.
JAR_FIRST = """[AIOPS_JAVA]
JAVA_TOTAL 1
[AIOPS_JAVA_PID]
PID 7301
PS app 86400 1200000 3.0 7.5 120
USER app
UNIT supervisord.service
ARG java
ARG -jar
ARG -Xms256m
ARG -Xmx1024m
ARG -XX:+HeapDumpOnOutOfMemoryError
ARG -XX:HeapDumpPath=/data/dump
ARG -Dspring.profiles.active=prod
ARG -Dfile.encoding=UTF-8
ARG /data/jar/dsp-api/dsp-api_445.jar
ARG --server.port=8080
ARGS_END 10
"""


def test_java_options_after_dash_jar_belong_to_the_jvm():
    report = java_report(JAR_FIRST)
    (row,) = report["summary"]["processes"]
    assert row["main"] == "dsp-api_445.jar"
    assert row["jar_path"] == "/data/jar/dsp-api/dsp-api_445.jar"
    assert row["application"] == "dsp-api_445"
    assert (row["heap"]["xms"], row["heap"]["xmx"]) == ("256m", "1024m")
    assert row["profiles"] == ["prod"]
    assert row["gc"]["xx_flags"] == [
        "-XX:+HeapDumpOnOutOfMemoryError",
        "-XX:HeapDumpPath=/data/dump",
    ]
    assert row["system_properties_count"] == 2
    assert "heap_max_unset" not in by_metric(report["findings"])
    # An application name among the options after -jar still wins over the jar.
    named = JAR_FIRST.replace(
        "ARG -Dfile.encoding=UTF-8\n", "ARG -Dspring.application.name=dsp-api\n"
    )
    (row,) = java_report(named)["summary"]["processes"]
    assert row["application"] == "dsp-api" and row["heap"]["xmx"] == "1024m"


@pytest.mark.parametrize(
    ("args", "main", "index"),
    [
        (["java", "-Xmx1g", "-jar", "app.jar", "--x"], ("jar", "app.jar"), 3),
        (
            ["java", "-jar", "-Xmx1g", "-cp", "lib.jar", "app.jar"],
            ("jar", "app.jar"),
            5,
        ),
        (["java", "-jar", "@opts", "[REDACTED]", "", "app.jar"], ("jar", "app.jar"), 5),
        (["java", "-jar"], ("unknown", None), 2),
        (["java", "-jar", "-Xmx1g", "-Dk=v"], ("unknown", None), 4),
        (["java", "-cp", "a.jar", "com.x.Main", "-jar"], ("class", "com.x.Main"), 3),
        (["java", "-m", "mod/com.x.Main", "y.jar"], ("class", "mod/com.x.Main"), 2),
        (["java", "--module=mod/com.x.Main"], ("class", "mod/com.x.Main"), 1),
        (["java", "-m"], ("unknown", None), 2),
    ],
)
def test_main_of_skips_jvm_options_between_dash_jar_and_the_jar(args, main, index):
    found, at = java_ext.main_of(args)
    assert (found["kind"], found["name"], at) == (*main, index)


@pytest.mark.parametrize(
    ("main", "name"),
    [
        (
            {"kind": "jar", "name": "/data/jar/dsp-api/dsp-api_445.jar"},
            "dsp-api_445.jar",
        ),
        ({"kind": "jar", "name": "app.war"}, "app.war"),
        ({"kind": "class", "name": "com.x.Main"}, "com.x.Main"),
        ({"kind": "class", "name": "mod/com.x.Main"}, "mod/com.x.Main"),
        ({"kind": "unknown", "name": None}, None),
    ],
)
def test_main_is_one_string_whose_kind_stays_readable(main, name):
    assert java_ext.main_name(main) == name


@pytest.mark.parametrize(
    "text",
    [
        "",
        '{"error": "unexpected", "trace": ["java.lang.NullPointerException"]}\n',
        'Exception in thread "main" java.lang.IllegalStateException: boom\n\tat x.y(Z.java:1)\n',
        "[AIOPS_JAVA_PID]\nPID notanumber\nARG -Xmx\n[AIOPS_JAVA_PID]\nPID 99999999999999999999999\n",
        "[AIOPS_JAVA]\nJAVA_TOTAL many\n[AIOPS_JAVA_PID]\nPID 12\n"
        "PS u 1e400 nan inf -5 9999999999999999999999\nCGMEM 99999999999999999999999\n"
        "FDLIMIT unlimited\nFDS -1\nRELEASE garbage\nARG -Xmx99999999999999999999g\n"
        "ARG -jar\nARGS_END x\n",
    ],
)
def test_java_parser_survives_garbage(text):
    report = observations.analyze("java", text, status="partial", truncated=True)
    json.dumps(report, allow_nan=False)
    assert isinstance(report["summary"]["processes"], list)


JVM_G1 = """[AIOPS_PROC]
PID 4242
COMM java
USER appuser
ETIMES 3600
EXE /usr/lib/jvm/java-17-openjdk-amd64/bin/java
GCLOG /data/logs/billing/gc.log
[AIOPS_ATTACH]
UID 0
MODE runuser
JCMD ok
[AIOPS_HEAP_INFO]
4242:
 garbage-first heap   total 2097152K, used 1950000K [0x0000000080000000, 0x0000000100000000)
  region size 1024K, 120 young (122880K), 8 survivors (8192K)
 Metaspace       used 120000K, committed 122880K, reserved 1179648K
  class space    used 14000K, committed 15360K, reserved 1048576K
RC 0
[AIOPS_VM_FLAGS]
4242:
-XX:CICompilerCount=4
-XX:ConcGCThreads=2
-XX:G1HeapRegionSize=1048576
-XX:InitialHeapSize=1073741824
-XX:MaxHeapSize=2147483648
-XX:MaxMetaspaceSize=134217728
-XX:MaxNewSize=1287651328
-XX:+UseCompressedOops
-XX:+UseG1GC
RC 0
[AIOPS_GC_STAT]
 S0C    S1C    S0U    S1U      EC       EU        OC         OU       MC     MU    CCSC   CCSU   YGC     YGCT    FGC    FGCT    CGC    CGCT     GCT
   0.0 8192.0    0.0 8192.0 114688.0  98304.0 1974272.0 1830000.0 122880.0 120000.0 15360.0 14000.0   5000   300.000    12   120.000   200    3.000   423.000
RC 0
[AIOPS_GC_LOG]
FILE /data/logs/billing/gc.log
[2026-10-30T10:00:01.123+0800][info][gc] GC(120) Pause Young (Normal) (G1 Evacuation Pause) 1800M->1700M(2048M) 25.123ms
[2026-10-30T10:00:05.456+0800][info][gc] GC(121) Pause Full (G1 Compaction Pause) 2040M->1900M(2048M) 1520.789ms
[2026-10-30T10:00:09.001+0800][info][gc] GC(122) Pause Full (G1 Compaction Pause) 2040M->1950M(2048M) 1610.000ms
[2026-10-30T10:00:12.002+0800][info][gc] GC(123) Pause Full (Allocation Failure) 2047M->2000M(2048M) 1702.500ms
"""
ALL_PROBES = ["heap_info", "vm_flags", "gc_stat", "gc_log"]
JDK8_JSTAT = """ S0C    S1C    S0U    S1U      EC       EU        OC         OU       MC     MU    CCSC   CCSU   YGC     YGCT    FGC    FGCT     GCT
10752.0 10752.0  0.0   5120.0 65536.0  3932.2   175104.0   60000.0  4480.0 4200.9  384.0  360.6    320    4.210   3      1.020    5.230
"""
JVM_JDK8 = (
    """[AIOPS_PROC]
PID 5151
COMM java
USER tomcat
ETIMES 864000
EXE /usr/lib/jvm/java-1.8.0-openjdk/jre/bin/java
GCLOG /opt/tomcat/logs/gc-%t.log
[AIOPS_ATTACH]
UID 0
MODE runuser
JCMD ok
[AIOPS_HEAP_INFO]
5151:
java.lang.IllegalArgumentException: Unknown diagnostic command
RC 0
[AIOPS_VM_FLAGS]
5151:
-XX:CICompilerCount=3
-XX:InitialHeapSize=536870912
-XX:MaxHeapSize=1073741824
-XX:MaxNewSize=357564416
-XX:+UseCompressedOops
-XX:+UseParallelGC
RC 0
[AIOPS_GC_STAT]
"""
    + JDK8_JSTAT
    + "RC 0\n"
)


def jvm_report(text, probes=None, pid=4242):
    return observations.analyze(
        "jvm", diagnostics.redact_output(text), options={"pid": pid, "probes": probes}
    )


def test_jvm_g1_heap_flags_jstat_and_gc_log():
    report = jvm_report(JVM_G1, ALL_PROBES)
    summary = report["summary"]
    assert summary["process"] == {
        "pid": 4242,
        "user": "appuser",
        "elapsed_seconds": 3600,
        "exe": "/usr/lib/jvm/java-17-openjdk-amd64/bin/java",
        "gc_log_path": "/data/logs/billing/gc.log",
        "attach": "ok",
    }
    assert set(summary["probes"].values()) == {"ok"}
    heap = summary["heap"]
    assert heap["collector"] == "G1" and heap["total_KiB"] == 2097152
    assert heap["used_KiB"] == 1950000 and heap["used_percent_basis"] == "max_heap"
    assert heap["young"] == {"used_KiB": 122880, "regions": 120, "survivor_KiB": 8192}
    assert heap["old"]["used_KiB"] == 1950000 - 122880
    assert heap["metaspace"] == {
        "used_KiB": 120000,
        "committed_KiB": 122880,
        "reserved_KiB": 1179648,
    }
    flags = summary["flags"]
    assert flags["MaxHeapSize"] == 2147483648 and flags["collector"] == "G1"
    assert flags["ConcGCThreads"] == 2 and flags["ParallelGCThreads"] is None
    assert flags["MaxMetaspaceSize"] == 134217728 and flags["UseCompressedOops"] is True
    gc = summary["gc"]
    assert (gc["young_count"], gc["full_count"], gc["concurrent_count"]) == (
        5000,
        12,
        200,
    )
    assert gc["total_time_s"] == 423.0 and gc["gc_time_ratio"] == 0.1175
    assert gc["old_used_percent"] == 92.69
    assert summary["gc_log"]["full_pauses"] == 3
    assert summary["gc_log"]["last_pause_ms"] == 1702.5
    assert len(summary["gc_log"]["lines"]) == 4
    levels = {f["metric"]: f["level"] for f in report["findings"]}
    assert levels == {
        "heap_used_percent": "warning",
        "old_gen_used_percent": "warning",
        "gc_time_ratio": "critical",
        "full_gc_count": "warning",
        "metaspace_limit_percent": "warning",
        "gc_log_full_pauses": "warning",
    }
    hints = {f["metric"]: f["hint"] for f in report["findings"]}
    assert "累计" in hints["full_gc_count"]
    json.dumps(report, allow_nan=False)


def test_jvm_jdk8_without_heap_info_falls_back_to_jstat_columns():
    report = jvm_report(JVM_JDK8, pid=5151)
    summary = report["summary"]
    assert summary["probes"] == {
        "heap_info": "unsupported",
        "vm_flags": "ok",
        "gc_stat": "ok",
    }
    assert summary["process"]["attach"] == "ok"
    heap = summary["heap"]
    assert heap["source"] == "jstat -gc" and heap["total_KiB"] == 262144.0
    assert heap["used_KiB"] == 69052.2 and heap["used_percent"] == 6.59
    gc = summary["gc"]
    assert "concurrent_count" not in gc and gc["full_count"] == 3
    assert gc["old_used_percent"] == 34.27
    assert summary["flags"]["collector"] == "Parallel"
    assert not [f for f in report["findings"] if f["level"] != "info"]
    # jstat columns are matched by name: a reordered header gives the same values.
    names, values = (line.split() for line in JDK8_JSTAT.splitlines())
    order = sorted(range(len(names)), key=lambda i: names[i])
    shuffled = JVM_JDK8.replace(
        JDK8_JSTAT,
        " ".join(names[i] for i in order)
        + "\n"
        + " ".join(values[i] for i in order)
        + "\n",
    )
    assert jvm_report(shuffled, pid=5151)["summary"]["gc"] == gc


@pytest.mark.parametrize(
    ("body", "collector", "used_percent", "level"),
    [
        (
            """ PSYoungGen      total 76288K, used 3932K [0x000000076ab00000, 0x0000000770000000, 0x00000007c0000000)
  eden space 65536K, 6% used [0x000000076ab00000,0x000000076aed7240,0x000000076eb00000)
  from space 10752K, 0% used [0x000000076f580000,0x000000076f580000,0x0000000770000000)
  to   space 10752K, 0% used [0x000000076eb00000,0x000000076eb00000,0x000000076f580000)
 ParOldGen       total 175104K, used 170000K [0x00000006c0000000, 0x00000006cab00000, 0x000000076ab00000)
  object space 175104K, 97% used [0x00000006c0000000,0x00000006c0000000,0x00000006cab00000)
 Metaspace       used 2617K, capacity 4486K, committed 4864K, reserved 1056768K
  class space    used 284K, capacity 386K, committed 512K, reserved 1048576K
""",
            "Parallel",
            69.19,
            None,
        ),
        (
            """ ZHeap           used 3900M, capacity 4096M, max capacity 4096M
 Metaspace       used 6420K, committed 6592K, reserved 1056768K
  class space    used 556K, committed 640K, reserved 1048576K
""",
            "ZGC",
            95.21,
            "critical",
        ),
        (
            """Shenandoah Heap
 4096M max, 4096M soft max, 1024M committed, 800M used
 2048 x 2048K regions
Status: not cancelled
Reserved region:
 - [0x0000000700000000, 0x0000000800000000)
 Metaspace       used 6420K, committed 6592K, reserved 1056768K
""",
            "Shenandoah",
            19.53,
            None,
        ),
        (
            """ def new generation   total 9216K, used 4058K [0x00000000f9a00000, 0x00000000fa400000, 0x00000000fa400000)
  eden space 8192K,  49% used [0x00000000f9a00000, 0x00000000f9df6a40, 0x00000000fa200000)
 tenured generation   total 20480K, used 19000K [0x00000000fa400000, 0x00000000fb800000, 0x0000000100000000)
 Metaspace       used 6234K, capacity 6371K, committed 6528K, reserved 1056768K
""",
            "Serial",
            77.65,
            None,
        ),
    ],
)
def test_jvm_heap_info_layouts(body, collector, used_percent, level):
    text = (
        "[AIOPS_PROC]\nPID 6000\nCOMM java\nUSER app\nETIMES 100\nEXE /x/bin/java\nGCLOG \n"
        "[AIOPS_ATTACH]\nUID 0\nMODE direct\nJCMD ok\n"
        "[AIOPS_HEAP_INFO]\n6000:\n" + body + "RC 0\n"
    )
    report = jvm_report(text, ["heap_info"], pid=6000)
    heap = report["summary"]["heap"]
    assert heap["collector"] == collector and heap["used_percent"] == used_percent
    assert heap["metaspace"]["committed_KiB"] > 0
    found = {f["metric"]: f["level"] for f in report["findings"]}
    assert found.get("heap_used_percent") == level
    if collector == "Parallel":
        assert heap["old"] == {
            "name": "ParOldGen",
            "total_KiB": 175104,
            "used_KiB": 170000,
            "used_percent": 97.09,
        }
        assert found["old_gen_used_percent"] == "warning"
        assert heap["used_percent_basis"] == "committed"
    json.dumps(report, allow_nan=False)


ATTACH_HEAD = """[AIOPS_PROC]
PID 7000
COMM java
USER es
ETIMES 500
EXE /usr/share/elasticsearch/jdk/bin/java
GCLOG
"""


@pytest.mark.parametrize(
    ("attach", "probes", "state", "reason"),
    [
        (
            "[AIOPS_ATTACH]\nUID 0\nMODE runuser\nJCMD ok\n"
            "[AIOPS_HEAP_INFO]\n7000:\nRC 1\n[AIOPS_VM_FLAGS]\n7000:\nRC 1\n"
            "[AIOPS_GC_STAT]\n7000 not found\nRC 1\n",
            {"heap_info": "failed", "vm_flags": "failed", "gc_stat": "failed"},
            "unavailable",
            "附加失败",
        ),
        (
            "[AIOPS_ATTACH]\nATTACH_UNAVAILABLE\nUID 1001\nMODE direct\nJCMD ok\n"
            "[AIOPS_HEAP_INFO]\nSKIPPED uid\n[AIOPS_VM_FLAGS]\nSKIPPED uid\n"
            "[AIOPS_GC_STAT]\nSKIPPED uid\n",
            {
                "heap_info": "skipped:uid",
                "vm_flags": "skipped:uid",
                "gc_stat": "skipped:uid",
            },
            "unavailable",
            "既不是 root",
        ),
        (
            "[AIOPS_ATTACH]\nUID 0\nMODE direct\nJCMD ok\n"
            "[AIOPS_HEAP_INFO]\nCAPABILITY_MISSING:jcmd\n[AIOPS_VM_FLAGS]\n"
            "CAPABILITY_MISSING:jcmd\n[AIOPS_GC_STAT]\nCAPABILITY_MISSING:jstat\n",
            {
                "heap_info": "missing_tool",
                "vm_flags": "missing_tool",
                "gc_stat": "missing_tool",
            },
            "missing_tool",
            "JRE",
        ),
        (
            "[AIOPS_ATTACH]\nUID 0\nMODE direct\nJCMD sigquit\n"
            "[AIOPS_HEAP_INFO]\nSKIPPED sigquit\n[AIOPS_VM_FLAGS]\nSKIPPED sigquit\n"
            "[AIOPS_GC_STAT]\n" + JDK8_JSTAT + "RC 0\n",
            {"heap_info": "skipped:sigquit", "vm_flags": "skipped:sigquit"},
            "ok",
            "SIGQUIT",
        ),
        (
            "[AIOPS_ATTACH]\nUID 0\nMODE runuser\nJCMD ok\n"
            "[AIOPS_HEAP_INFO]\n7000:\nRC 124\n[AIOPS_VM_FLAGS]\nSKIPPED timeout\n"
            "[AIOPS_GC_STAT]\n" + JDK8_JSTAT + "RC 0\n",
            {"heap_info": "timeout", "vm_flags": "skipped:timeout"},
            "ok",
            "8 秒",
        ),
    ],
)
def test_jvm_attach_failures_are_explained(attach, probes, state, reason):
    report = jvm_report(ATTACH_HEAD + attach, pid=7000)
    summary = report["summary"]
    assert summary["process"]["attach"] == state
    assert summary["process"]["gc_log_path"] is None
    failed = [f for f in report["findings"] if f["metric"] == "attach_failed"]
    assert len(failed) == 1 and failed[0]["level"] == "warning"
    assert failed[0]["value"] == probes and reason in failed[0]["hint"]
    assert "JVM 属主" in failed[0]["hint"]
    json.dumps(report, allow_nan=False)


def test_jvm_refused_pid_and_gc_log_only_probe():
    refused = observations.analyze(
        "jvm",
        "[AIOPS_PROC]\nCOMM nginx\nAIOPS_REFUSED:pid\n",
        status="partial",
        options={"pid": 1234, "probes": None},
    )
    process = refused["summary"]["process"]
    assert process["attach"] == "refused" and process["pid"] == 1234
    assert process["comm"] == "nginx"
    finding = next(f for f in refused["findings"] if f["metric"] == "pid_not_java")
    assert finding["level"] == "warning" and finding["value"] == 1234
    legacy = jvm_report(
        ATTACH_HEAD.replace("GCLOG", "GCLOG /opt/tomcat/logs/gc-%t.log")
        + "[AIOPS_GC_LOG]\nFILE /opt/tomcat/logs/gc-2026-10-30_10-00-00.log.0.current\n"
        "2026-10-30T10:00:00.000+0800: 1234.567: [GC (Allocation Failure) [PSYoungGen: "
        "524800K->20000K(611840K)] 524800K->20008K(2010112K), 0.0234567 secs] "
        "[Times: user=0.05 sys=0.01, real=0.02 secs]\n"
        "2026-10-30T10:01:00.000+0800: 1294.567: [Full GC (Ergonomics) [PSYoungGen: "
        "20000K->0K(611840K)] [ParOldGen: 1398000K->1200000K(1398272K)] "
        "1418000K->1200000K(2010112K), [Metaspace: 80000K->80000K(1120256K)], "
        "1.2345678 secs] [Times: user=4.00 sys=0.02, real=1.23 secs]\n",
        ["gc_log"],
        pid=7000,
    )
    summary = legacy["summary"]
    assert summary["process"]["attach"] == "not_requested"
    assert summary["probes"] == {"gc_log": "ok"}
    assert summary["gc_log"]["full_pauses"] == 1
    assert summary["gc_log"]["last_pause_ms"] == 1234.568
    assert "heap" not in summary and "gc" not in summary
    assert not [f for f in legacy["findings"] if f["level"] != "info"]
    missing = jvm_report(
        ATTACH_HEAD + "[AIOPS_GC_LOG]\nGC_LOG_NOT_CONFIGURED\n", ["gc_log"]
    )
    assert missing["summary"]["probes"] == {"gc_log": "not_configured"}
    assert missing["summary"]["gc_log"]["lines"] == []
    foreign = jvm_report(
        ATTACH_HEAD + "[AIOPS_GC_LOG]\nGC_LOG_FOREIGN_OWNER\n", ["gc_log"]
    )
    assert foreign["summary"]["probes"] == {"gc_log": "foreign_owner"}


@pytest.mark.parametrize(
    "text",
    [
        "",
        "[AIOPS_HEAP_INFO]\nZHeap used nanM, capacity 0M\n",
        "[AIOPS_PROC]\nPID 1\nETIMES 0\n[AIOPS_GC_STAT]\nYGC FGC GCT\n1e400 nan -\nRC x\n",
        '{"vmFlags": ["-XX:+UseG1GC"], "error": null}\n[AIOPS_VM_FLAGS]\n-XX:MaxHeapSize=99999999999999999999999\n',
        "[AIOPS_PROC]\nPID 2\n[AIOPS_ATTACH]\n[AIOPS_GC_LOG]\nFILE /x\n"
        + "Pause Full 1e999ms\n" * 50,
    ],
)
def test_jvm_parser_survives_garbage(text):
    for probes in (None, ALL_PROBES):
        report = observations.analyze(
            "jvm", text, status="partial", truncated=True, options={"probes": probes}
        )
        json.dumps(report, allow_nan=False)
        assert report["summary"]["process"]["attach"] in {
            "ok",
            "unavailable",
            "missing_tool",
            "refused",
            "unknown",
        }


def test_jvm_options_are_validated_before_any_script_is_built():
    for bad in (
        None,
        {},
        {"pid": 0},
        {"pid": -1},
        {"pid": 4194305},
        {"pid": "4242"},
        {"pid": "1; reboot"},
        {"pid": True},
        {"pid": 4.5},
        {"pid": 1, "probes": ["heap_dump"]},
        {"pid": 1, "probes": ["heap_info; id"]},
        {"pid": 1, "probes": ["GC.run"]},
        {"pid": 1, "probes": []},
        {"pid": 1, "probes": ["heap_info"] * 5},
        {"pid": 1, "probes": "heap_info"},
        {"pid": 1, "command": "id"},
    ):
        with pytest.raises(ValueError):
            diagnostics.command_for("jvm", options=bad)
    with pytest.raises(ValueError):
        diagnostics.command_for("java", options={"pid": 1})
    with pytest.raises(ValueError):
        diagnostics.command_for("jvm", service="java", options={"pid": 1})
    spec = extensions.spec_for("jvm")
    assert extensions.validate_options(
        spec, {"pid": 1, "probes": ["gc_log", "gc_log"]}
    ) == {
        "pid": 1,
        "probes": ["gc_log"],
    }
    assert extensions.validate_options(spec, {"pid": 4194304})["probes"] is None


def scripts():
    yield "java", diagnostics.command_for("java")
    for probes in (
        None,
        ["heap_info"],
        ["vm_flags"],
        ["gc_stat"],
        ["gc_log"],
        ALL_PROBES,
    ):
        yield (
            "jvm " + ",".join(probes or ["default"]),
            diagnostics.command_for("jvm", options={"pid": 4242, "probes": probes}),
        )


FORBIDDEN_WORDS = re.compile(
    r"(?<![\w./-])(?:tee|touch|mkdir|rm|mv|cp|dd|truncate|chmod|chown|kill|pkill"
    r"|killall|jmap|jstack|gcore)(?![\w.-])"
)
FORBIDDEN_TEXT = (
    "GC.run",
    "Thread.print",
    "GC.heap_dump",
    "GC.class_histogram",
    "JFR.",
    "VM.native_memory",
    "sed -i",
    ">>",
    "-gcutil",
    "system(",
    "getline",
)


@pytest.mark.parametrize(("name", "script"), list(scripts()))
def test_scripts_are_read_only_bounded_templates(name, script):
    assert script.startswith(diagnostics.PREFIX)
    assert "timeout -k 1" in script, name
    assert not FORBIDDEN_WORDS.search(script), FORBIDDEN_WORDS.search(script)
    # Never start a JVM of our own (`java -version` and friends).
    assert not re.search(r"(?<![\w/.$-])java\s+-", script)
    for text in FORBIDDEN_TEXT:
        assert text not in script, (name, text)
    # Outside single-quoted strings (printf formats, awk programs) only
    # /dev/null redirections exist; awk programs never print into a file.
    unquoted = re.sub(r"'[^']*'", "''", script)
    assert set(re.findall(r"[0-9]*>&?[^\s;)\"'|&]*", unquoted)) <= {
        ">/dev/null",
        "2>/dev/null",
        "2>&1",
    }
    for program in re.findall(r"'([^']*)'", script):
        assert not re.search(r"\bprintf?\b[^;{}\n]*>", program), program
    commands = set(
        re.findall(
            r"\b(?:GC|VM|Thread|JFR|Compiler|ManagementAgent|System)\.\w+", script
        )
    )
    assert commands <= {"GC.heap_info", "VM.flags"}, commands


def test_jvm_script_interpolates_only_the_pid_and_requested_probes():
    default = diagnostics.command_for("jvm", options={"pid": 4242})
    assert "pid=4242\n" in default and default.count("4242") == 1
    assert "GC.heap_info" in default and "VM.flags" in default and " -gc " in default
    assert "tail -n 40" not in default and "runuser -u" in default
    assert "SigCgt" in default and "DisableAttachMechanism" in default
    assert "jskip=timeout" in default and default.count("timeout -k 1 8 ") == 2
    log_only = diagnostics.command_for("jvm", options={"pid": 99, "probes": ["gc_log"]})
    assert "tail -n 40" in log_only and "GC_LOG_FOREIGN_OWNER" in log_only
    assert "/proc/$pid/root" in log_only and 'stat -c %u "$rt$gl"' in log_only
    assert (
        "jcmd" not in log_only and "jstat" not in log_only and "runuser" not in log_only
    )
    java = diagnostics.command_for("java")
    assert "NO_JAVA" in java and "[AIOPS_JAVA_PID]" in java and "jcmd" not in java
    assert "head -n " + str(java_ext.MAX_PIDS) in java


@needs_sh
@pytest.mark.parametrize(("name", "script"), list(scripts()))
def test_scripts_parse_under_sh(name, script):
    subprocess.run(["/bin/sh", "-n"], input=script, text=True, check=True)


def test_catalog_lists_java_tools_with_their_risk():
    entries = {entry["id"]: entry for entry in catalog.entries()}
    java, jvm = entries["java"], entries["jvm"]
    assert java["tool"] == "ssh_diagnose_java" and jvm["tool"] == "ssh_diagnose_jvm"
    assert java["category"] == jvm["category"] == "应用与中间件"
    assert java["risk"] == "low" and jvm["risk"] == "medium"
    assert java["sensitive"] and jvm["sensitive"] and java["params"] == []
    assert [p["name"] for p in jvm["params"]] == ["pid", "probes"]
    assert jvm["params"][0]["required"] and jvm["params"][0]["maximum"] == 4194304
    assert jvm["params"][1]["choices"] == ["heap_info", "vm_flags", "gc_stat", "gc_log"]
    assert jvm["notes"] == [
        "jcmd 会让 JVM 短暂进入安全点，生产高峰期谨慎使用；GC 计数是进程启动以来的累计值。"
    ]
    spec = extensions.spec_for("jvm")
    assert (spec.timeout, spec.output_limit) == (30, 32768)
    spec = extensions.spec_for("java")
    assert (spec.timeout, spec.output_limit) == (20, 49152)


def spawn_java(tmp_path, *args):
    """A sleeping Python process whose comm is "java" (exec'd through a symlink);
    ``args`` follow ``-c`` and so show up in /proc/<pid>/cmdline untouched."""
    link = tmp_path / "java"
    if not link.exists():
        try:
            link.symlink_to(sys.executable)
        except OSError:
            pytest.skip("symlinks are not available")
    proc = subprocess.Popen(
        [str(link), "-c", "import time; time.sleep(60)", *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            with open(f"/proc/{proc.pid}/comm") as handle:
                if handle.read().strip() == "java":
                    break
        except OSError:
            pass
        time.sleep(0.05)
    return proc


@pytest.fixture
def fake_jvm(tmp_path):
    proc = spawn_java(
        tmp_path,
        "-Xlog:gc*:file=" + str(tmp_path / "gc-%p.log") + ":time,uptime",
        "--spring.application.name=fake-billing",
        "--spring.datasource.password=Hunter2",
        "--db-token",
        "Hunter4",
    )
    try:
        yield proc, tmp_path
    finally:
        proc.kill()
        proc.wait()


def run_sh(command):
    return subprocess.run(
        ["/bin/sh", "-c", command], capture_output=True, text=True, timeout=60
    )


@needs_linux
def test_java_script_runs_under_sh_and_finds_a_process_named_java(fake_jvm):
    proc, _ = fake_jvm
    result = run_sh(diagnostics.command_for("java"))
    assert result.returncode == 0, result.stderr
    assert "[AIOPS_JAVA]" in result.stdout, result.stdout[-2000:]
    report = java_report(result.stdout)
    rows = {row["pid"]: row for row in report["summary"]["processes"]}
    if proc.pid not in rows:
        assert report["summary"]["java_processes"] > java_ext.MAX_PIDS
        pytest.skip("more than 20 larger Java processes on this host")
    row = rows[proc.pid]
    assert row["threads"] >= 1 and row["rss_KiB"] > 0 and row["fds"] >= 3
    assert row["elapsed_seconds"] >= 0 and row["fd_limit"]
    assert row["application"] == "fake-billing" and row["exe"]
    assert "fake-billing" in row["command_preview"]
    for report in (report, observations.analyze("java", result.stdout)):
        dumped = json.dumps(report["summary"], ensure_ascii=False)
        assert "Hunter2" not in dumped and "Hunter4" not in dumped


@needs_linux
def test_jvm_script_refuses_non_java_and_never_signals_without_handler(fake_jvm):
    proc, tmp_path = fake_jvm
    (tmp_path / f"gc-{proc.pid}.log").write_text(
        "[0.100s][info][gc] GC(0) Pause Young (Normal) (G1 Evacuation Pause) "
        "24M->4M(256M) 3.456ms\n"
        "[5.000s][info][gc] GC(1) Pause Full (System.gc()) 10M->2M(256M) 15.000ms\n"
    )
    refused = run_sh(diagnostics.command_for("jvm", options={"pid": os.getpid()}))
    assert refused.returncode == 69 and "AIOPS_REFUSED:pid" in refused.stdout
    options = {"pid": proc.pid, "probes": ["heap_info", "gc_log"]}
    result = run_sh(diagnostics.command_for("jvm", options=options))
    assert result.returncode == 0, result.stdout + result.stderr
    summary = observations.analyze("jvm", result.stdout, options=options)["summary"]
    # Python does not handle SIGQUIT, so jcmd (which would kill it) is skipped.
    assert summary["probes"] == {"heap_info": "skipped:sigquit", "gc_log": "ok"}
    assert summary["process"]["gc_log_path"].endswith("/gc-%p.log")
    assert summary["gc_log"]["file"].endswith(f"/gc-{proc.pid}.log")
    assert summary["gc_log"]["full_pauses"] == 1
    assert summary["gc_log"]["last_pause_ms"] == 15.0
    assert proc.poll() is None


@needs_linux
@pytest.mark.skipif(
    hasattr(os, "getuid") and os.getuid() == 0, reason="root also owns /etc/passwd"
)
def test_jvm_gc_log_probe_only_reads_files_owned_by_the_jvm(tmp_path):
    # The GC log path comes from the target's own argv: a fake "java" pointing
    # it at a file it does not own must not get that file tailed by the probe.
    proc = spawn_java(tmp_path, "-Xloggc:/etc/passwd")
    options = {"pid": proc.pid, "probes": ["gc_log"]}
    try:
        result = run_sh(diagnostics.command_for("jvm", options=options))
    finally:
        proc.kill()
        proc.wait()
    assert "GC_LOG_FOREIGN_OWNER" in result.stdout and "root:" not in result.stdout
    summary = observations.analyze("jvm", result.stdout, options=options)["summary"]
    assert summary["probes"] == {"gc_log": "foreign_owner"}
    assert summary["process"]["gc_log_path"] == "/etc/passwd"

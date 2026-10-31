"""Exercise the built image with an isolated Docker volume; prints no secrets."""

import json
import subprocess
import time
import uuid
import urllib.error
import urllib.request

name = "sshmcp-ci-" + uuid.uuid4().hex[:10]
volume = name + "-data"


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


try:
    docker("volume", "create", volume)
    docker(
        "run",
        "-d",
        "--name",
        name,
        "-p",
        "127.0.0.1::9099",
        "-v",
        volume + ":/app/data",
        "ssh-mcp-server:ci",
    )
    port = docker("port", name, "9099/tcp").split(":")[-1]
    base = "http://127.0.0.1:" + port
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def healthy():
        for _ in range(100):
            try:
                with opener.open(base + "/healthz", timeout=2) as response:
                    assert json.load(response)["version"] == "0.7.1"
                return
            except (OSError, urllib.error.URLError):
                time.sleep(0.2)
        raise RuntimeError("Container did not become healthy")

    healthy()
    assert docker("exec", name, "id", "-u") == "10001"
    code = "from sshmcp import store; import hashlib; print(hashlib.sha256(store.token('mcp.token').encode()).hexdigest())"
    before = docker("exec", name, "python", "-c", code)
    verify = (
        "from sshmcp import store; "
        "assert all(p.stat().st_mode & 0o077 == 0 for p in "
        "[store.DATA_DIR,store.DATA_DIR/'master.key',store.DATA_DIR/'ssh-mcp.sqlite3']); "
        "store.save_settings({'ci_probe':'persistent'})"
    )
    docker("exec", name, "python", "-c", verify)
    for path, status in (("/api/v1/jobs", 503), ("/mcp", 401)):
        try:
            opener.open(base + path, timeout=3)
            raise AssertionError("Unauthenticated access must fail")
        except urllib.error.HTTPError as exc:
            assert exc.code == status
    docker("restart", name)
    # Docker may reassign an ephemeral published port when restarting a container.
    port = docker("port", name, "9099/tcp").split(":")[-1]
    base = "http://127.0.0.1:" + port
    healthy()
    assert before == docker("exec", name, "python", "-c", code)
    docker(
        "exec",
        name,
        "python",
        "-c",
        "from sshmcp import store; assert store.setting('ci_probe') == 'persistent'",
    )
    print(
        "Container healthy; UID 10001; private files; auth enforced; volume and identity preserved after restart"
    )
except BaseException:
    subprocess.run(["docker", "logs", "--tail", "80", name], check=False)
    raise
finally:
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    subprocess.run(["docker", "volume", "rm", volume], capture_output=True)

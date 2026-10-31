# v0.8.0 · Java 进程行精简（MCP 输出字段变化）

`ssh_diagnose_java` 返回的进程行字段有变化，读取下表旧字段的 MCP 客户端需要调整。工具名与参数不变，无数据库变化。本版包含 v0.7.2 的 ps 列修复。

## 字段变化

`ssh_diagnose_java` 的 `summary.processes[]`：

| 字段 | v0.7.x | v0.8.0 |
| --- | --- | --- |
| `main` | 对象 `{"kind": "jar" \| "class" \| "unknown", "name": …}` | 字符串：jar 模式为 jar 文件名（如 `dsp-api_445.jar`），主类为类名（如 `org.apache.catalina.startup.Bootstrap`），模块启动为 `模块/主类`；未识别为 `null` |
| `jar_path` | 无 | **新增**：jar 模式下命令行中的 jar 路径（即原 `main.name`，相对路径不展开）；主类、模块启动或未识别时为 `null` |
| `heap.xmx_MiB` | `-Xmx` 换算的 MiB | **删除**；`heap.xmx` 保留启动命令中的原写法（如 `1024m`），需要数值时按 JVM 大小写法换算 |

原 `main.kind` 的判断方式：`jar_path` 非空即 jar 模式；否则 `main` 含 `/` 为模块启动，其余为主类；`main` 为 `null` 即未识别。

发现项不变：`heap_exceeds_cgroup` 与 `rss_far_above_heap` 的 `value` 仍带 `xmx_MiB`，阈值判断照旧按 MiB 计算。`ssh_diagnose_jvm` 不受影响。

## 原因

AI Ops Platform 把每次 SSH 结果放进 4000 字符的模型视图：先去掉空值字段，再按总量从大到小删除非核心字段，`pid`、`application`、`unit`、`main`、`heap` 始终保留。同一主机有 13 个 Java 进程时，单是这些字段就超过 4000，只能放下 11 行；其中每行 `main` 对象约 85 字符、`heap` 中的 `xmx_MiB` 与 `xmx` 重复。

以一台 13 个 Java 进程的 CentOS 7 主机的存储证据实测（用本版解析器重新解析原始输出，ps 列取自同次采集，平台 v1.3.2 的 `ssh_view` 按 4000 字符生成视图）：

| 情形 | 视图字符数 | 进程行 |
| --- | --- | --- |
| v0.7.1（ps 列为空） | 3789 | 11/13 |
| v0.7.2（ps 列有值，行结构不变） | 3837 | 11/13 |
| v0.8.0 | 3817 | **13/13** |

平台当前在空间不足时会先删掉 `rss_KiB`、`cpu_percent`、`mem_percent`、`elapsed_seconds`，然后才轮到 `user`、`threads` 等更小的字段。若平台把 `rss_KiB` 列入常驻字段，v0.8.0 的 13 行连同 RSS 为 3868 字符，仍可全部放下；再加 `cpu_percent` 与 `mem_percent` 为 12/13 行。

## 升级

先备份数据目录（至少 `ssh-mcp.sqlite3` 与密钥文件），确认接入的 MCP 客户端不再读取 `main.kind`、`main.name` 与 `heap.xmx_MiB`，然后在原部署目录执行：

```bash
cd /data/ssh-mcp-server
git fetch origin
git switch main
git pull --ff-only origin main
docker compose up -d --build --wait --wait-timeout 180
curl -fsS http://127.0.0.1:9099/healthz
```

`/healthz` 应返回 `0.8.0`（`.env` 的 `WEB_BIND_IP` 设成服务器地址时，curl 改用该地址）。回滚：切回 v0.7.2 的合并提交后按同样命令重建；只回滚输出字段时不影响 v0.7.2 的 ps 列修复。

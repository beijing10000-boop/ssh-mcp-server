# v0.7.1 · Java 启动命令解析与内存进程采集修复

无数据库变化，MCP 工具名、参数与返回字段不变。

## 修复

- **`java -jar <JVM 选项> app.jar` 被解析错**：Java 启动器允许把 JVM 选项写在 `-jar` 之后（`-jar` 只切换为 jar 模式，第一个非选项参数才是 jar）。此前 `ssh_diagnose_java` 把 `-jar` 后紧跟的参数当成 jar，应用名显示成 `-Xms256m` 之类，且 `-jar` 之后的 `-Xmx`、`-D` 与 profiles 都未识别（AI 据此误判“未设 -Xmx”）。现在跳过这些选项取真正的 jar，并把它们计入 JVM 选项。
- **`memory_processes` 退出码**：进程身份探测循环的最后一句在按内存排第 24 的进程识别不出 jar / 服务名时返回 1，使整个采集以退出码 1 结束、被标为部分完成（`ssh_collect` 中的这一步同样受影响）。现在退出码与身份识别无关；同一段探测也改为在 `-jar` 之后跳过 JVM 选项再识别 jar。只输出白名单校验的 jar 基名，安全约束不变。

## 升级

先备份数据目录（至少 `ssh-mcp.sqlite3` 与密钥文件），然后在原部署目录执行：

```bash
cd /data/ssh-mcp-server
git fetch origin
git switch main
git pull --ff-only origin main
docker compose up -d --build --wait --wait-timeout 180
curl -fsS http://127.0.0.1:9099/healthz
```

`/healthz` 应返回 `0.7.1`（`.env` 的 `WEB_BIND_IP` 设成服务器地址时，curl 改用该地址）。回滚：切回 v0.7.0（`239b4aa`）后按同样命令重建。

# v0.11.0 · Java 应用清单（含监听端口）

> 基线为 v0.10.3（`02d074d`）。

新增 1 个只读 MCP 工具，现有工具的名称、参数与返回字段不变，无数据库结构变化。

## 新增

- **`ssh_diagnose_java_apps`（动作 `java_apps`，无参数）**：一次 SSH 会话取回
  - 主机上的 Java 应用（最多 60 个进程）：应用名、JAR/主类、profiles、用户、systemd 单元或容器、运行时长、RSS；
  - 每个应用监听的 TCP 端口：来自 `ss -ltnp`；bridge 网络的容器取 `docker ps` 的发布端口（宿主机端口）；只绑定回环地址的端口单独列在 `local_ports`；
  - 本机 IPv4 地址（不含 docker0、网桥等虚拟接口）。

  用途是回答“这台主机上跑了哪些应用、各在哪个端口”，并让调用方把发往 `地址:端口` 的流量（例如 Nginx 访问日志里的上游地址）对应到应用。此前要分别调用 `ssh_diagnose_java`（没有端口、最多 20 个进程）和 `ssh_diagnose_service_map`（没有应用名、不含容器发布端口）再自行合并。字段说明见 [MCP.md](MCP.md) 的“v0.11.0 新增工具”。

- 它没有参数，可以用 `ssh_submit_diagnostics`（`action="java_apps"`）对多台主机批量采集，用 `ssh_get_diagnostic_batch` 读取结果。后台任务同时最多执行 3 个、等待名额最多 180 秒，建议每批 10–20 台，上一批完成后再提交下一批。

## 行为与限制

- 只读 `/proc`、`ss`、`ip`（没有时用 `hostname -I`）与 `docker ps`；不附加 JVM、不启动进程、不写文件。读取启动命令只为识别应用名，结果里没有启动命令。
- 非 root 账号看不到其他用户进程的端口归属：此时用启动参数里的 `server.port` 代替并标 `ports_source=argument`，都没有则 `ports` 为空、`ports_source=null`，并给出 `ports_unknown` 提示。端口为空不代表应用不对外服务。
- 容器：host 网络的容器由 `ss` 直接看到；bridge 网络的容器需要诊断账号能执行 `docker ps`，否则 `docker_ports=unavailable`。Kubernetes Pod、Podman 的端口映射不识别。
- 只在有容器内的 Java 进程时才执行 `docker ps`。
- 只支持标准 SSH 模式（A 模式），与其他扩展动作相同。

## 授权

新动作**不会自动授予任何已有客户端**，也不在“按 AI Ops Platform 推荐勾选”的范围内。需要它的客户端由管理员在 Web「系统配置 → MCP 接入 → 编辑权限」中勾选「Java 应用清单」；给只做应用清单采集的系统单独建一个只含这一个动作的客户端即可。例外是旧式全局令牌 `mcp.token`：它按定义拥有全部动作，仍启用时也包括本动作。

## 升级

1. 备份数据卷中的 `ssh-mcp.sqlite3`、`master.key`、`admin.token`、`mcp.token`。
2. 拉取新代码后 `docker compose up -d --build --wait`，`/healthz` 返回 0.11.0。

已有客户端的授权与令牌不变。

## 回滚

检出 v0.10.3（`02d074d`）后重建；无数据库变化。回滚后该工具不存在，客户端授权里留下的 `java_apps` 不起作用，其他动作不受影响；只含这一个动作的客户端也就不再可用。

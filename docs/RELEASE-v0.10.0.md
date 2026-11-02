# v0.10.0 · 审计修复（P2）：未知不报 0、EL7 时间同步、调用方离开即释放

> 未发布。基线为 v0.9.0（`22b71d4`）。

本版修复 2026-11 代码审计剩余的 P2 问题（括号内为审计编号）。不新增 MCP 工具（仍为 51 个），工具参数不变，无数据库结构变化。MCP 结果只增加字段，但有几处取值变化，按下列字段做判断的客户端需要核对：

- 经典动作采集不完整时，计数类指标的 0 改为 null（未知）；`ssh_diagnose_service` 的 `failed_service_count` 与 `summary.failed_services` 恒为 null；
- `ssh_diagnose_time_sync` 在 EL7 等没有 `timedatectl show` 的主机上不再是 partial，新增 `summary.sync_source`；
- `ssh_diagnose_nginx_access` 的 request_time 与 upstream_response_time 按该日志的 log_format 定位，新增 `summary.timing.request_time_source` 与 `upstream_time_source`；
- 同步诊断的客户端在结果返回前断开连接时，调用被取消，任务记为 `cancelled`；
- `ssh_collect` 给出 `timeout_seconds` 时，取得主机名额时剩余时间不足即返回 `busy`，不再连接后超时。

经 HTTPS 反向代理部署的实例可以用新的环境变量 `SSHMCP_TRUSTED_PROXIES` 解决 Web 写操作一律 403 的问题。生产中的调用方 AI Ops Platform v1.5.0 可直接使用本版本；先升级本服务，再升级平台。

## 诊断准确性

- **未知的计数不再报 0**：采集不完整（输出 `CAPABILITY_MISSING:*`、非零退出、致命 stderr、超时或截断）时，v0.9.0 仍给出 `failed_service_count=0`、`observed_log_lines=0`、`oom_matches=0` 等，读起来像“没有故障”。现在这些计数为 0 时改为 null，大于 0 的照常给出（看到的就是证据，是下限）；完整采集的 0 仍是 0。涉及 `failed_service_count`、`observed_log_lines`、`oom_matches`、`observed_rows`、`listening_ports`、`reported_firewall_services`、`processes_uninterruptible`、`unavailable_commands` 与日志类的 `summary.entries_total`（SSH-DIAG-12）。
- **`ssh_diagnose_service` 没有失败服务数**：一个单元的属性里没有可数的失败服务，v0.9.0 恒报 `failed_service_count=0`。现在该指标的值与 `summary.failed_services` 都为 null，字段保留（SSH-DIAG-12）。
- **EL7 的时间同步**：systemd 219 没有 `timedatectl show`，v0.9.0 在 EL7 上总是以退出码 1 结束（partial），拿不到 NTP 状态。现在依次尝试 `timedatectl show`、`timedatectl status`（systemd 219、237、239 起的标签都能解析）、`chronyc tracking`、`ntpstat`，`summary.sync_source` 写明同步状态的来源；chronyc 的失败（例如主机用 ntpd）不再让结果变为 partial（SSH-DIAG-16）。
- **不健康的容器**：`docker ps` 状态为 `Up … (unhealthy)` 的容器（在运行但健康检查失败）报 warning 级 `container_state`，v0.9.0 不报（SSH-DIAG-17）。
- **Nginx 访问日志的耗时**：v0.9.0 把“UA 之后的第一个小数”当作 request_time，`"$gzip_ratio"`、`$msec` 会被当成耗时（误报慢请求），`$upstream_response_time $request_time` 的顺序会把上游耗时当成总耗时。现在按该日志在 nginx 配置中的 log_format 计算 `$request_time` 与 `$upstream_response_time` 的位置（引号分段与前后词数，`rt=$request_time` 一类前后缀一并去掉）。`$upstream_addr`、`$upstream_status` 等上游列表（多个上游记为 `a, b : c`）按其 `,` 与 ` : ` 分隔逐词跳过，与它们相邻的耗时照样定位，例如 `$upstream_addr $upstream_response_time $request_time` 与 `$request_time $upstream_response_time $upstream_addr $upstream_status`；`$host`、`$server_name`、`$https`、`$remote_user`、`$uri`、`$document_uri`、`$args`、`$query_string` 可能为空或含空格，不按一个词计数。格式未知、某行与格式不符，或格式所指的位置不是耗时（例如改格式前写入的行）时，该字段才按原方式推测，并在 `summary.timing.request_time_source` / `upstream_time_source` 计入 `heuristic`、在 coverage 中注明，不会丢弃该请求的耗时，也不会把推测值记为 `log_format`（SSH-NGX-06）。
- **jvm 探针的副作用写清楚**：`ssh_diagnose_jvm` 的工具说明、目录 `notes` 与 docs/MCP.md 写明 jcmd 附加时创建的 `.attach_pid<PID>`、发送的 SIGQUIT、常驻的 Attach Listener 线程与 `.java_pid<PID>` 套接字、可能的安全点、runuser 切换身份，以及 jstat 只读 hsperfdata（SSH-DIAG-15）。探针行为不变。

## 并发与连接

- **鉴权不再阻塞事件循环**：每个 MCP 请求的令牌校验移出事件循环线程，只读数据库；客户端的 `last_used_at` 每分钟最多写一次，最多等 1 秒锁，数据库被长事务（VACUUM、Zabbix 登记、整批提交）占用时跳过。v0.9.0 每个请求都在事件循环里做一次写事务，遇到写锁时整个服务（Web、/healthz、所有 MCP 请求）最长停顿 10 秒，随后返回 500。读取本身失败时改为 503 + `Retry-After`（SSH-CORE-02）。
- **诊断有自己的线程池**：同步诊断工具在独立的 32 线程池中等待名额与执行，多出的在池中排队，排队时间计入 30 秒的名额等待（与 `timeout_seconds`），超过即 `busy`，不会在排队之后再等 30 秒；解析、目录、任务查询等轻量工具与鉴权使用默认线程池。v0.9.0 两者共用默认线程池（4 核约 8 个线程），AI 平台对同一主机并发扇出的诊断会把它占满，轻量工具随之排队到超时（SSH-CORE-03）。等名额的调用在池中占一个线程：32 个线程是 4 个名额加 28 个等待者，同时等繁忙主机的调用超过 28 个时，其他主机的调用才需要排队（每个等待者最多等 30 秒）。
- **剩余时间不足不再连接**：`ssh_collect` 给出 `timeout_seconds` 时，取得主机名额后若剩余时间少于 max(5 秒, `timeout_seconds` 的四分之一)（例如在线程池中排队过久），立即释放名额并返回 `busy`（“…未连接主机，请稍后重试”），不打开 SSH。此前仍会连接并启动远程脚本，随即以 `timeout` 失败。
- **调用方离开即释放名额**：MCP 的 JSON 响应模式在读完请求后不再理会连接，v0.9.0 中客户端超时离开后，调用仍在等主机名额（最多 30 秒）或继续执行（最多 120 秒），其间同一主机的重试只能拿到 `busy`。现在客户端在结果返回前关闭连接时：等待名额的调用放弃、不连接 SSH；正在读取输出的调用关闭通道、释放名额；还在线程池排队的调用不再开始；任务记为 `cancelled`（“MCP 客户端已断开连接，诊断已取消”），SSH 握手期间断开的也是如此（此前被归为 `revision_changed`）。只放弃等待而不断开连接的客户端，以及 MCP 的 `notifications/cancelled`（无状态 HTTP 下到不了原调用），服务端仍无法得知，调用照常执行完，排队上限不变（SSH-CORE-04）。

## 安全

- **HTTPS 反向代理下的 Origin 校验**：v0.9.0 只按请求本身的协议与 `Host` 校验浏览器的 `Origin`；TLS 代理在容器外、以 HTTP 转发时（uvicorn 只信任本机地址的 `X-Forwarded-Proto`），所有 Web 写操作返回 403“请求来源不受信任”。新增环境变量 `SSHMCP_TRUSTED_PROXIES`（逗号分隔的 IP 或网段，容器看到的代理地址）：来自这些地址的连接，其 `X-Forwarded-Proto`、`X-Forwarded-Host`（取第一个值）构成的来源也被接受。不设置时与 v0.9.0 相同。`/mcp` 对带 Origin 的浏览器请求使用同一规则（SSH-CORE-10）。

## 控制台

- **批次进度只取计数**：诊断历史按批次查看时，每 3 秒的进度刷新改为 `GET /api/v1/jobs/batches/{id}?counts_only=true`，不再解密并分析 25 条完整结果（SSH-FE-06）。
- **准备状态只是状态**：主机列表的「准备状态」标签不再是按钮；需要处理的主机旁边显示明确的「下一步：启用资产 / 绑定凭据 / 扫描公钥」按钮，悬停说明会做什么。每个按钮只做它写明的那一步：点击时主机状态已经变化（其他管理员或另一个窗口已处理），只提示“状态已变为…，未执行…”并刷新页面，不改做别的步骤。主机详情抽屉的「准备下一步」改为同样写明步骤的按钮（未测试或测试失败的主机为「下一步：测试连接」），没有准备步骤时显示状态说明。v0.9.0 点击标签或「准备下一步」会按当时的状态打开对话框、立即发起公钥扫描或提交连接测试，界面没有任何提示。测试与诊断仍在行内的「测试」「诊断」按钮（SSH-FE-08）。
- **未知的计数显示「未知」**：诊断详情中值为 null 的指标与线索（采集不完整时的计数）显示「未知」，此前显示 “null”；值未知的百分比指标不再画成 0% 的仪表，只在「全部结构化指标」中列出（SSH-DIAG-12）。
- 发布时页面资源地址需改为 `?v=0.10.0`（`web/index.html`，本分支未改），升级后浏览器才会加载新脚本。

## MCP 接口变化

工具名与参数不变（51 个）。`ssh_diagnose_time_sync`、`ssh_diagnose_jvm`、`ssh_diagnose_nginx_access` 的工具说明有更新；`ssh_list_tool_catalog` 中 `jvm` 与 `nginx_access` 的 `notes` 有更新。

### 结果字段

| 工具 | v0.9.0 | v0.10.0 |
| --- | --- | --- |
| 经典诊断（采集不完整时） | 计数类指标为 0 | 为 0 的计数改为 null：`summary.metrics[]` 中 `failed_service_count`、`observed_log_lines`、`oom_matches`、`observed_rows`、`listening_ports`、`reported_firewall_services`、`processes_uninterruptible`、`unavailable_commands` 的 `value`，日志类的 `summary.entries_total`；大于 0 的不变 |
| `ssh_diagnose_service` | `failed_service_count` 恒为 0，`summary.failed_services` 恒为 `[]` | 二者恒为 null（指标仍在 `metrics` 中） |
| `ssh_diagnose_time_sync` | 只解析 `timedatectl show`；EL7 上 partial、`properties` 为空 | 新增 `summary.sync_source`（`timedatectl show`、`timedatectl status`、`chronyc tracking`、`ntpstat` 或 null）；可用时新增 `summary.chrony`（`reference`、`stratum`、`system_time`、`last_offset`、`leap_status`）、`summary.ntpstat`（`exit_code`、`state`）。`properties` 的键不变，`timedatectl status` 的 `NTP service: active/inactive` 记为 `yes/no`。`NTPSynchronized` 的 warning 提示注明来源。chronyc 失败不再使结果 partial；timedatectl 失败且没有其他来源时 partial（stderr 为 timedatectl 的错误） |
| `ssh_diagnose_containers` | `(unhealthy)` 不报 | 报 warning 级 `container_state`，`threshold` 为 `healthy` |
| `ssh_diagnose_nginx_access` | request_time 一律按位置推测 | 新增 `summary.timing.request_time_source` 与 `upstream_time_source`：`log_format`、`field_name`、`heuristic`、`not_in_log_format` 四项请求数（旧结果为 null）；log_format 已知且没有 `$request_time`（`$upstream_response_time`）时不再推测，`timing.request_time`（`upstream_time`）为 null。`timing.request_time`、`upstream_time` 的取值随定位变化。原文的 `[AIOPS_TIMING]` 段多 `REQ_SOURCE`、`UPS_SOURCE` 两行 |
| 同步诊断工具 | 客户端断开后照常执行 | 客户端断开时（含 SSH 握手期间）任务为 `cancelled`、`error_code=cancelled`（结果送不到已断开的客户端，可在 Web 与 `ssh_get_diagnostic_job` 中看到） |
| `ssh_collect`（带 `timeout_seconds`） | 取得名额时预算已用完仍连接，随后 `timeout` | 剩余时间少于 max(5 秒, `timeout_seconds` ÷ 4) 时返回 `failed`、`error_code=busy`，未连接主机 |

### 管理接口（REST，需飞书管理员会话）

- `GET /api/v1/jobs/batches/{batch_id}`：新增可选查询参数 `counts_only`（默认 false）。为 true 时 `items` 为空数组，其余字段（`counts`、`completed`、`total`、`skipped`、分页字段）不变，不解密任何结果。

## 兼容性

- **数据库**：无表结构变化，无迁移。`mcp_clients.last_used_at` 最多滞后约 1 分钟。
- **MCP 客户端**：把计数当作数字读取的客户端需要处理 null（只在采集不完整时出现；`status` 此时不是 `success`）。依赖 `ssh_diagnose_service` 的 `failed_service_count=0` 的客户端改用 `failed_services` 动作。会在等结果时断开连接、稍后用 `job_id` 取结果的客户端，现在拿到的是 `cancelled`；需要后台执行的请改用 `ssh_submit_diagnostics`。
- **AI Ops Platform**：生产中的 v1.5.0 不按名读取上述计数与 `timing` 字段，可直接使用本版本（本地未运行平台联合测试，由 CI 的 platform-contract 任务覆盖）；它把 `busy`、`timeout` 及含“繁忙”的失败当作可重试，剩余时间不足时的新 `busy` 也在其中。平台对 `call_tool` 的单工具超时（`wait_for`）只放弃等待，MCP 会话与 HTTP 连接保持到任务结束，因此服务端在那之前仍按原有上限执行该调用；会话关闭时仍未结束的调用随之取消。v1.5.0 给 `ssh_collect` 传 `timeout_seconds`（单工具超时减 10 秒），服务端会在该期限内结束这类调用。
- **配置**：`SSHMCP_TRUSTED_PROXIES` 不设置时行为不变；`docker-compose.yml` 已透传该变量（默认空）。
- **反向代理**：代理的读超时短于诊断耗时时，代理先断开连接，调用会被取消；建议 ≥180 秒（见 docs/INSTALLATION.md）。

## 升级

以下步骤在 v0.10.0 合并到 main 并发布后适用。先在 Web 确认没有排队或运行中的诊断任务，然后在原部署目录停服，备份整个数据目录（数据库及可能存在的 `-wal`/`-shm`、`master.key`、`bootstrap.token`、`mcp.token` 一起）：

```bash
cd /data/ssh-mcp-server
docker compose stop ssh-mcp
umask 077
backup_dir="./backup/$(date +%Y%m%d-%H%M%S)-v0.9.0"
mkdir -p "$backup_dir"
docker compose cp ssh-mcp:/app/data/. "$backup_dir/"
ls -l "$backup_dir"
```

确认备份中有 `ssh-mcp.sqlite3` 与 `master.key` 后，更新并重建：

```bash
git fetch origin
git switch main
git pull --ff-only origin main
docker compose up -d --build --wait --wait-timeout 180
curl -fsS http://127.0.0.1:9099/healthz
```

`/healthz` 应返回 `0.10.0`。经 HTTPS 反向代理访问控制台的实例，在 `.env` 中加入 `SSHMCP_TRUSTED_PROXIES=<代理地址>`（查法与 nginx 示例见 docs/INSTALLATION.md「HTTPS 反向代理」）后再执行 `docker compose up -d`。本服务验证通过后，再升级 AI Ops Platform。

## 验证

- **服务**：`docker compose ps` 显示 healthy，`docker compose logs --tail=200 ssh-mcp` 中没有异常。
- **控制台**：打开「主机资产」，待处理主机的「准备状态」旁有「下一步：…」按钮，标签本身不可点击；点主机名打开详情，按钮写明步骤（或显示“准备已完成…”），没有「准备下一步」；在「诊断历史」打开一个批次，进度随任务刷新。经 HTTPS 代理访问时，新建并删除一个测试主机组应成功（不再 403）。
- **时间同步**：对一台 EL7 主机执行「时间与 NTP 同步」，结果为成功，结构化摘要中有 `sync_source: timedatectl status` 与 NTPSynchronized。
- **调用方离开**：用 MCP Inspector 对一台正在执行其他诊断的主机发起诊断，在返回前关闭连接；「诊断历史」中该任务为「已取消」，同一主机随即可以再次诊断。

## 回滚

回滚顺序与升级相反：AI Ops Platform 若已升级到下一版本，先回滚平台，再回滚本服务。在原部署目录切回 v0.9.0（`22b71d4`）后按同样命令重建：

```bash
cd /data/ssh-mcp-server
git switch --detach 22b71d4
docker compose up -d --build --wait --wait-timeout 180
curl -fsS http://127.0.0.1:9099/healthz
```

`/healthz` 应返回 `0.9.0`。数据不需要恢复：本版没有改表结构；因客户端断开而记为 `cancelled` 的任务在 v0.9.0 中照常显示。v0.9.0 不认 `SSHMCP_TRUSTED_PROXIES`，经 HTTPS 代理的 Web 写操作会重新返回 403，回滚期间请直连或临时改为 HTTP 访问；`.env` 中的该变量可以保留，v0.9.0 会忽略。

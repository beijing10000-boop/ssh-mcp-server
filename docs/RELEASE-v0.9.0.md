# v0.9.0（未发布）· 审计修复：诊断准确性、安全与任务授权

> **未发布**：本文是 `fix/audit-2026-11` 分支的发布说明草稿，改动尚未合并、发布或部署。分支上的版本号（`sshmcp/__init__.py`）仍是 0.8.0，发布时改为 0.9.0（页面资源已是 `?v=0.9.0`），在此之前 `/healthz` 返回 0.8.0。下文的“v0.9.0”均指这批未发布的改动，基线为 v0.8.0（`a2839ac`）。

本版修复 2026-11 代码审计确认的问题（括号内为审计编号）。不新增 MCP 工具（仍为 51 个），无数据库结构变化。MCP 接口有一个新增的可选参数和几处语义变化，按 `status`、`error_code` 或下文字段做判断的客户端需要核对：

- `ssh_collect` 新增可选参数 `timeout_seconds`（10–120），不传时与 v0.8.0 相同；
- `ssh_collect` 任一步骤未成功时，顶层 `status` 为 `partial`（v0.8.0 可能仍为 `success`）；
- 诊断工具创建任务时的三类拒绝改用 `busy`、`not_ready`、`not_linux`；
- Nginx、syslog 与服务详情在拿不到数据时给出 null 和明确的线索，不再报 0、“无流量”或“未运行”。

此外，`master.key` 缺失而数据库已有加密数据时服务拒绝启动。AI Ops Platform v1.4.5 可直接使用本版本；先升级本服务，再升级平台。

## 诊断准确性

- **`ssh_collect` 的状态**：采集脚本以 printf 结束，整体退出码总是 0，v0.8.0 在某个步骤以非零退出码失败时顶层仍可能为 `success`。现在任一步骤的 `status` 不是 `success` 即为 `partial`（SSH-DIAG-04）。
- **`ssh_collect` 限时**：新增可选参数 `timeout_seconds`，见下文“MCP 接口变化”（SSH-DIAG-05）。
- **`ssh_diagnose_peer_traffic` 在真实主机上没有样本**：`ss … state established` 只选一种状态时不输出 State 列，原解析只认以 `ESTAB` 开头的行，结果总是“没有可比较的 TCP 连接字节计数”。现在两种格式都能解析（SSH-DIAG-02）。
- **进程名含空格时列错位**：`processes`、`memory_processes` 的进程行与 `health` 的 `top_processes` 遇到 `PM2 v5.3.0: God` 这类进程名时，CPU、内存、RSS 取错了列；现在数值列从行尾取（SSH-DIAG-03）。
- **服务详情的重启与失败次数**：诊断账号读不全 journal、主机没有 journalctl，或近 24 小时 PID 1 记录读取超时、失败时，`summary.counts` 的 `restarts_24h`、`failures_24h`、`starts_24h` 为 null（未知），不再是 0。记录读取超时或失败、或 `systemctl show` 没有返回单元属性时，结果为 `partial`；后者另报 warning 级 `unit_state_unknown`（SSH-DIAG-07）。
- **`restart_loop`**：NRestarts 是自上次手动启动以来的累计值，可能跨越数周。现在近 24 小时记录中自动重启 ≥3 次才报 critical；24 小时记录未知时，NRestarts ≥3 且单元正处于 auto-restart、或在本次窗口内启动过，才报 critical；其余 NRestarts ≥3 的情况降为 info（SSH-DIAG-08）。
- **OOM 与内核分类**：服务自身日志中的 “out of memory” 多为应用内存分配失败，不再报 critical 的 `oom_killed`，改报 warning 级 `oom_log_clue`；`oom_killed` 只依据 systemd 的 Result、PID 1 记录与 OOM killer 的记录。日志分类不再把 Python 日志的 `DEBUG:` 当作内核 `BUG:`（SSH-DIAG-09）。
- **很长的 stderr**：非 root 账号运行 du、df 时每个无权限目录写一行错误，v0.8.0 在 stderr 超过 2 KiB 时停止读取并报 `output_limit`，stdout 因此不完整。现在 stderr 只保留前 2 KiB 并标记 `stderr_truncated: true`，stdout 照常读完（SSH-CORE-01、SSH-DIAG-10）。
- **syslog 分类不受 priority 限制**：链路断开、segfault、sshd 登录失败等常以 info/notice 级别记录，默认 `priority=warning` 时被滤掉。journal 可用且 priority 严于 info 时，脚本另以 `-p info` 按相同的 unit、pid、keyword 统计分类（输出段 `[AIOPS_JOURNAL_KINDS]`，限时 3 秒，最坏多用约 3 秒），计入 `matched_counts` 与 `matched`；`entries` 仍按 priority 过滤。分类也不再把 “NIC Link is Up”、开机时的 “NMI watchdog: Enabled” 与 “DEBUG:” 行算作网络或内核异常（SSH-NGX-03）。
- **syslog 级别计数的过滤条件**：crit/err/warning 计数只按 unit、pid 统计，不受 keyword 过滤（计数方式不变）。新增 `summary.counts_filters` 写明各计数的过滤条件；给出 keyword 时，coverage 与相关提示也会注明（SSH-NGX-08）。
- **Nginx 进程看不到不等于未运行**：ps 不接受所需的列（BusyBox、旧版 procps）时脚本输出 `CAPABILITY_MISSING:ps-columns`；看不到 PID 1（/proc 以 hidepid 挂载，只能看到本账号的进程）时输出 `PS_LIMITED`。这两种情况不再报 critical 的 `nginx_inactive`；受限列表中没有 master 时报 info 级 `nginx_process_not_visible`。master 排在进程列表最前，worker 超过 40 个也不会被截掉（SSH-NGX-07）。
- **Nginx 没读到 error.log**：error_log 写到 syslog/stderr、文件不存在或无读权限时，`errors.lines_in_window` 为 null（不是 0），并报 info 级 `error_log_not_read`（SSH-NGX-11）。
- **访问日志不可读不再报“没有流量”**：找不到可读的访问日志时，`ssh_diagnose_nginx_access` 输出 `CAPABILITY_MISSING:nginx-access-log` 并以退出码 69 结束（`partial`），报 warning 级 `access_log_not_found`。v0.8.0 报 0 个请求，并提示“该日志在窗口内可能确实没有流量”（SSH-NGX-02）。
- **访问日志的时区**：日志时间的 UTC 偏移与主机不同（容器内的 nginx 常用 UTC）时，报 warning 级 `log_timezone_mismatch` 并给出 `summary.tz_mismatch`；窗口仍按主机本地时间筛选，不做换算（SSH-NGX-05，部分修复）。
- **访问日志跟随运行中的实例**：`ssh_diagnose_nginx_access` 与 `ssh_diagnose_nginx` 一样，按运行中 master 的 `-p`/`-c` 读取配置、解析相对路径（SSH-NGX-04）。
- **Nginx 配置摘要**：配置输出被截断时，计数与截断标记不再被 200 行上限截掉（SSH-NGX-13）。

## 安全

- **GC 日志与符号链接（P0）**：`ssh_diagnose_jvm` 的 `gc_log` 探针按目标 JVM 自己的启动参数定位 GC 日志。文件检查与读取都会跟随符号链接，容器内的绝对路径链接又按本机根目录解析，被诊断的 JVM 因此可以让探针读出它指定的其他文件，在容器中还能经 `/proc/<pid>/root` 指到宿主机上的文件。现在探针先比较 JVM 的根目录与本机根目录：容器内（根目录不同）的 JVM，GC 日志文件或其任一上级目录是符号链接时不读取，`probes.gc_log` 为 `symlink_refused`；与本机同根的 JVM 可以跟随常见部署链接（如 `/opt/tomcat -> /opt/apache-tomcat-9`、EL7 的 `logs -> /var/log/tomcat`）。读取前在已打开的文件描述符上确认它是 JVM 属主的普通文件，检查与读取之间无法再替换文件；并且只输出符合 GC 日志格式的行，含 JDK8 CMS 的续行与 tenuring 分布（SSH-DIAG-01）。
- **脱敏补充**（作用于所有动作的输出和保存的任务结果）：以 pass 为独立词的键（`DB_PASS`、`RABBITMQ_DEFAULT_PASS`、`-Dredis.pass=`、`?pass=`；bypass、passive 不算）；任意含 pwd 的键（`loginPwd`、`?pwd=`；`PWD`、`OLDPWD` 目录变量除外）；Redis 的 `requirepass`、`masterauth`（含 `--requirepass 值` 写法）；命令行中的 `mysql -p密码` 与 `redis-cli -a 密码`；会话 Cookie（`JSESSIONID`、`PHPSESSID`、`sessionid`、`connect.sid`、`sid`）；`Authorization: Basic/Bearer/Digest …` 的凭据（连同方案名一起替换）；Java 盘点逐行输出的启动参数中，值在下一个参数里的 `--password`、`--db-token` 一类选项。手机号与 18 位身份证号部分遮盖为 `138****8000`、`110101********1234`；手机号只在路径、引号、括号或分隔符之后、紧邻中文、`+86` 之后，或作为 phone、mobile、tel 一类键的值时遮盖，字节计数等数字不受影响（SSH-DIAG-06）。
- **Nginx 与 syslog 证据行二次脱敏**：Nginx 的样本、TOP 值、配置摘要先经上面的通用规则，再经 Nginx 的键规则，并遮盖单独出现的 `Basic`/`Bearer` 凭据（例如 log_format 记录了 `$http_authorization`）；syslog 的 `entries` 与 `matched` 只经通用规则加严格的 `Basic`/`Bearer` 凭据规则，系统日志中的 `host key`、`key_load_public`、auditd 的 `key=` 等诊断内容保持原样（SSH-NGX-01）。
- **服务详情与 journal 权限**：诊断账号没有 journal 权限时，service_detail 仍按主机能力不足（`journal-permission`）上报，退出码为 0，不会被调用方当作采集失败；只有读取超时才把该步骤标为失败。
- **CentOS 7 的 ss**：`peer_traffic`、`peer_connections`、`tcp_states` 不再使用 iproute 4.11 不支持的 `ss -H`，改在解析时跳过表头。注意 EL7 的 `ss -i` 不输出 `bytes_sent`，`peer_traffic` 在 EL7 上仍取不到流量样本（既有限制）。
- **命令行口令**：另遮盖 `sshpass -p`、`curl -u/--user`、`mongo`/`mongosh -p`、`docker`/`podman login -p` 中的口令，以及紧跟命令名的 `mysql -pX`、`redis-cli -a X`。
- **跳板机连接也受时限约束**：给出 `timeout_seconds` 时，经跳板机连接的握手与通道建立也按剩余时间计时。
- **master.key 缺失时拒绝启动**：数据库里已有用 `master.key` 加密的数据（加密的系统配置、SSH 凭据、诊断任务或批次、资产发现记录），而数据目录中没有 `master.key` 时，服务拒绝启动，日志提示从与数据库同一时间的备份恢复。v0.8.0 会生成新的主密钥，已有凭据与诊断记录从此无法解密（SSH-CORE-09）。

## 任务与授权

- **错误码**：诊断工具创建任务时的三类拒绝改用专用错误码，见下文“MCP 接口变化”（SSH-CORE-05）。
- **任务总会结束**：任务请求无法解密（例如换过 master.key）时任务直接失败，不再一直显示“运行中”；数据库被锁时结果写入会重试（共 3 次），仍失败则任务标为失败（“诊断结果保存失败，请重新提交”）；后台线程中的异常写入服务日志（SSH-CORE-06）。
- **隐含动作按动作记录**：`mcp_clients.actions_extended` 记录每个客户端已经考虑过的隐含动作，每个隐含动作对每个客户端最多补一次：管理员去掉的动作，以后的版本也不会再补回；以后新增的隐含动作只单独补一次。旧的 `v0.6.0` 标记照常读取。本版的隐含动作与 v0.6.0 相同，写入的仍是 `v0.6.0`；只有将来新增隐含动作时才会写成动作列表（JSON）。无法识别的标记不会扩大授权（SSH-CORE-07）。
- **采集任务按步骤授权**：`ssh_get_diagnostic_job`、`ssh_cancel_diagnostic_job` 与 `ssh_get_diagnostic_batch` 对 `ssh_collect` 产生的任务逐个检查步骤授权，与 `ssh_collect` 本身一致。v0.8.0 要求客户端持有 `collect` 本身（推荐范围不含它），没有单独勾选 `collect` 的客户端查询自己的采集任务会得到 `forbidden`（SSH-CORE-12）。
- **推荐授权范围由服务端给出**：`GET /api/v1/tools` 每项新增 `recommended`，「按 AI Ops Platform 推荐勾选」改用它。范围覆盖平台托管 Skill 预采集或点名的全部动作，加上诊断测试用的 connection，共 35 个：connection、health、capabilities、cpu、memory、processes、memory_processes、disk、io、network、sockets、system、service、failed_services、logs、kernel、containers、pressure、resource_limits、mount_health、block_devices、time_sync、tcp_states、service_inventory、timers、log_errors、oom、container_stats、security_status、nginx、nginx_access、syslog、java、service_detail、service_map。比原来页面内置的列表多 8 个：containers、resource_limits、mount_health、block_devices、time_sync、timers、container_stats、security_status。仍不含 jvm、triage、directory、peer_connections、peer_traffic；`collect` 按步骤授权，不在其中。已有客户端不会自动获得新增的 8 个动作。

## 控制台

- **批量绑定 SSH 访问**：各项默认「保持不变」，只修改填写了的项。v0.8.0 把对话框中的端口、跳板与用户名（预填 22、直连、root）写到所有选中主机，端口或跳板因此变化的主机被清掉已核验的公钥；现在只有端口或跳板实际变化的主机才清空公钥。保存后列出需要重新核验公钥的主机和被跳过的非 Linux 资产（SSH-FE-01）。
- **缩短保留天数前先确认**：在「数据保留」中把天数改短时，先说明下一次每小时清理将永久删除哪些记录，确认后才保存（SSH-FE-09）。
- **会话过期**：会话过期（8 小时）或管理员权限被移除时，登录页说明原因，并关闭已打开的弹窗（SSH-FE-17）。
- **浏览器禁用本地存储**时控制台照常启动，只是不记住显示密度（SSH-FE-02）。
- **已被清理的记录**：打开已被数据保留清理的公钥扫描批次或资产发现记录（书签、长时间未刷新的页面）时，改为显示最新一条并提示，不再报错（SSH-FE-04）。
- **防止重复提交**：其余按钮（如「只重试失败项」、准备状态标签）在请求进行中禁用，双击不会提交两次（SSH-FE-05）。
- **Zabbix「保存并验证连接与读取权限」失败**时，错误信息替换“正在验证…”（SSH-FE-07）。
- 「重试」时如果主机已不再就绪，提示原因，而不是没有反应。
- 诊断工作台中「多项采集（单会话）」的参数多出可选的 `timeout_seconds`，留空不传，与原来一致。
- 页面资源地址改为 `?v=0.9.0`，升级后浏览器会加载新脚本。

## MCP 接口变化

工具名不变（51 个），`ssh_collect` 的工具说明相应更新。`ssh_list_tool_catalog` 中 `collect` 的 `params` 多了 `timeout_seconds`，`collect` 与 `syslog` 的 `notes` 文字有更新；它不返回 `recommended`。

### ssh_collect

| 项 | v0.8.0 | v0.9.0（未发布） |
| --- | --- | --- |
| 参数 `timeout_seconds` | 无 | **新增**，可选整数 10–120：本次调用的总时长上限，含同主机排队与执行。排队最多等 min(30, timeout_seconds ÷ 2) 秒；SSH 握手各阶段分享剩余时间（每阶段 1–6 秒）；读取输出到上限前 1 秒为止。每个步骤另有单步超时 max(5, min(20, ⌊(timeout_seconds − 5) ÷ 步骤数⌋)) 秒，目标机有 `timeout` 命令时生效。不传时与 v0.8.0 相同：排队最多 30 秒，执行最多 120 秒 |
| 顶层 `status` | 步骤以非零退出码失败时仍可能为 `success`（整段脚本的退出码总是 0） | 任一 `summary.steps[].status` 不是 `success` 即为 `partial`；顶层 `incomplete_reason` 仍只反映整段执行，仅因步骤失败时为 null |
| `summary.steps[]` | — | 被单步超时终止（退出码 124 或 137）的步骤为 `partial`，带 `timed_out: true` 与 `error`（“该步骤超过 N 秒被终止，输出可能不完整”）；后续步骤照常执行 |
| 用完 `timeout_seconds` | — | 返回已完成的步骤，没有返回的步骤为 `partial`；整体 `timed_out: true`、`status=partial`。一点输出都没读到时失败，`error_code=timeout`；排队超过排队上限时为 `busy` |

调用方可从 `tools/list` 中 `ssh_collect` 的 inputSchema 是否含 `timeout_seconds` 判断服务端是否支持；建议取略小于自身单工具超时的值。经跳板访问的主机，跳板的握手与通道建立同样按剩余时间计时。

### 错误码

诊断工具（`ssh_diagnose_*`、`ssh_collect`、`ssh_triage`、`ssh_test_connection`）创建任务时被拒绝，`error` 的文字不变，`error_code` 改为：

| 情形（`error` 中的说明） | v0.8.0 | v0.9.0（未发布） |
| --- | --- | --- |
| 所有诊断任务中排队与运行中的合计已达 200 个（“待执行任务已达上限”） | `invalid_argument` | `busy` |
| 主机已停用、公钥未核验或未绑定凭据（“主机未启用、未核验公钥或未绑定凭据”） | `host_unverified` | `not_ready` |
| 资产不是 Linux（“资产不是 Linux”） | `invalid_argument` | `not_linux` |

非 Linux 资产不能启用，诊断工具对它通常先命中“未启用”而返回 `not_ready`。要区分非 Linux 资产，请用 `ssh_resolve_target`、`ssh_resolve_host` 或 `ssh_resolve_hosts`：它们返回 `not_linux` 并附 `asset_type`（自 v0.6.0 起不变）。`host_unverified` 只用于执行阶段的主机公钥问题（未核验、格式无效或与登记的不一致）。

### 结果字段

| 工具 | 变化 |
| --- | --- |
| 所有诊断 | stderr 超过 2 KiB 时新增 `stderr_truncated: true`（只保留前 2 KiB），不再因此报 `output_limit` |
| `ssh_diagnose_processes`、`ssh_diagnose_memory_processes`、`ssh_diagnose_health` | 进程名 `name` 可以含空格，数值列不再错位 |
| `ssh_diagnose_nginx` | 新增 `summary.process_listing`：`ok`、`limited`（脚本标记 `PS_LIMITED`）、`failed`（`CAPABILITY_MISSING:ps-columns`，结果为 partial）、`missing`（没有 ps），没有进程段时为 null。`summary.worker_count` 只在列表完整或列出了 Nginx 进程时为数值，否则为 null。没有读到任何 error.log 时 `summary.errors.lines_in_window` 为 null，并报 info 级 `error_log_not_read`。`nginx_process_not_visible`（info）也用于受限列表；`nginx_inactive`（critical）只依据完整列表 |
| `ssh_diagnose_nginx_access` | 没有可读的访问日志：退出码 69、`CAPABILITY_MISSING:nginx-access-log`、`status=partial`，报 warning 级 `access_log_not_found`（`value` 含 `missing`、`no_access` 路径）；summary 不含 `totals`、`codes`、`top`、`timeline`、`timing`、`samples`，也不报 `requests_total`、`no_requests`。日志时区与主机不同：`summary.tz_mismatch`（`log_offset`、`host_offset`，形如 `+0000`、`+0800`，以及 `shift_seconds`）与 warning 级 `log_timezone_mismatch`，可把 `since`/`until` 各加上 `shift_seconds` 后重查 |
| `ssh_diagnose_syslog` | 新增 `summary.counts_filters`：`counts.total` 受 priority、unit、pid、keyword 过滤，crit/err/warning 只受 unit、pid 过滤。journal 可用且 priority 严于 info 时多一段 `[AIOPS_JOURNAL_KINDS]`，`matched_counts`/`matched` 包含 info 级的分类命中；这一段超时报 `journal_query_incomplete`。`entries` 与 `matched` 中的日志行经过二次脱敏 |
| `ssh_diagnose_service_detail` | `summary.counts` 的 `restarts_24h`、`failures_24h`、`starts_24h` 在未知时为 null；`systemctl show` 无输出或近 24 小时记录读取失败时 `status=partial`，前者另报 warning 级 `unit_state_unknown`（`value.systemctl_show_exit`）；`restart_loop` 可能是 info；新增 warning 级 `oom_log_clue` |
| `ssh_diagnose_jvm` | 容器内的 JVM 遇到符号链接时 `probes.gc_log` 为新状态 `symlink_refused`（与本机同根的 JVM 跟随链接）；`gc_log.lines` 只含 GC 记录格式的行 |
| `ssh_get_diagnostic_job`、`ssh_cancel_diagnostic_job`、`ssh_get_diagnostic_batch` | `ssh_collect` 任务按步骤授权（见“任务与授权”） |

### 管理接口（REST，需飞书管理员会话）

- `GET /api/v1/tools`：每项新增 `recommended`（布尔值）。
- `POST /api/v1/hosts/bulk-access`：`credential_id`、`username`、`port` 改为可选，省略即保持各主机当前值；`proxy_id` 省略为保持，显式传 `null` 为直连（v0.8.0 省略 `port` 即 22、省略 `proxy_id` 即直连）；至少要给出一项。选中的非 Linux 资产被跳过（v0.8.0 整批拒绝），全部为非 Linux 时返回 422。返回值新增 `updated`（有变化的主机数）、`key_cleared`（因端口或跳板变化被清空已核验公钥的主机）、`skipped`（跳过的非 Linux 资产）；`count` 改为处理的 Linux 主机数。

## 兼容性

- **数据库**：无表结构变化，无迁移。
- **MCP 客户端**：不传 `timeout_seconds` 时，`ssh_collect` 的执行方式与 v0.8.0 相同。以 `status=success` 判断采集完整、按 `error_code` 分支，或把 `worker_count`、`errors.lines_in_window`、`counts.restarts_24h` 等当作数字读取的客户端，需要按上文处理 `partial`、新的错误码与 null。
- **AI Ops Platform**：v1.4.5 可直接使用本版本（平台联调测试 12 项中 11 项通过，未通过的 1 项是平台侧问题，已在平台下一版本修复）。先升级本服务，再升级平台。
- **客户端授权**：升级不改动已有客户端的动作。要让 AI 平台的客户端获得推荐范围新增的 8 个动作，在「系统配置 → MCP 接入」对该客户端点「编辑权限」→「按 AI Ops Platform 推荐勾选」后保存（令牌不变）。
- **master.key**：数据库与 `master.key` 必须成套备份、成套恢复。只恢复了数据库时服务拒绝启动，按日志提示从同一份备份恢复 `master.key`（属主 UID 10001，权限 0600）。

## 升级

以下步骤在 v0.9.0 合并到 main 并发布后适用。先在 Web 确认没有排队或运行中的诊断任务，然后在原部署目录停服，备份整个数据目录（数据库及可能存在的 `-wal`/`-shm`、`master.key`、`bootstrap.token`、`mcp.token` 一起）：

```bash
cd /data/ssh-mcp-server
docker compose stop ssh-mcp
umask 077
backup_dir="./backup/$(date +%Y%m%d-%H%M%S)-v0.8.0"
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

`/healthz` 应返回 `0.9.0`（`.env` 的 `WEB_BIND_IP` 设成服务器地址时，curl 改用该地址）。`backup/` 已在 `.gitignore` 中；备份含主密钥与令牌，只允许管理员读取，不要上传或发到聊天。不要执行 `docker compose down -v`。本服务验证通过后，再升级 AI Ops Platform。

## 验证

- **服务**：`docker compose ps` 显示 healthy，`docker compose logs --tail=200 ssh-mcp` 中没有“拒绝启动”。
- **控制台**：打开控制台（资源地址已是 `?v=0.9.0`，不需要强制刷新），在「诊断工作台」对一台测试主机执行一次诊断（如「CPU 负载」），在「诊断历史」确认状态为成功、结构化摘要正常。在「系统配置 → MCP 接入」的「编辑权限」中点「按 AI Ops Platform 推荐勾选」，应提示已勾选 35 项（不保存可直接关闭）。
- **授权**：「操作审计」搜索 `mcp_client_actions_extended`：本版没有新增隐含动作，已有 `v0.6.0` 标记的客户端不会被补动作。
- **MCP**：`tools/list` 中 `ssh_collect` 应带 `timeout_seconds`。以下命令在容器内用原始令牌调用，令牌不离开容器、也不打印：

```bash
docker compose exec -T ssh-mcp python - <<'EOF'
import json, urllib.request
token = open("/app/data/mcp.token").read().strip()
request = urllib.request.Request(
    "http://127.0.0.1:9099/mcp",
    data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}).encode(),
    headers={
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    },
)
tools = json.load(urllib.request.urlopen(request, timeout=10))["result"]["tools"]
collect = next(t for t in tools if t["name"] == "ssh_collect")
print(len(tools), "timeout_seconds" in collect["inputSchema"]["properties"])
EOF
```

应输出 `51 True`。原始令牌已在 Web 停用时返回 401，可改用 MCP Inspector 等受信客户端，以客户端令牌查看 `tools/list`。

## 回滚

回滚顺序与升级相反：AI Ops Platform 若已升级到下一版本，先回滚平台，再回滚本服务。在原部署目录切回 v0.8.0（`a2839ac`）后按同样命令重建：

```bash
cd /data/ssh-mcp-server
git switch --detach a2839ac
docker compose up -d --build --wait --wait-timeout 180
curl -fsS http://127.0.0.1:9099/healthz
```

`/healthz` 应返回 `0.8.0`。数据不需要恢复：

- 本版没有改表结构。
- `mcp_clients.actions_extended`：本版写入的仍是 `v0.6.0`（隐含动作集合没有变化），v0.8.0 读到它即视为已经扩展，不会给任何客户端补动作，管理员去掉的动作也不会回来。v0.8.0 只认 `v0.6.0` 这一个标记：遇到其他标记时，有 `v0.6.0:` 开头扩展审计记录的客户端直接改标为 `v0.6.0`，其余已启用客户端按 v0.6.0 的规则再补一次（可能补回管理员去掉的动作）。本版不会写出其他标记，只有将来新增隐含动作的版本才会写成动作列表。
- 本版用 `timeout_seconds` 创建的 `ssh_collect` 任务在 v0.8.0 中可以查看，但在 Web「重试」会返回 422（不支持的诊断参数：timeout_seconds），需要重新提交。
- 回滚后，“master.key 缺失时拒绝启动”的保护随之失效（v0.8.0 会生成新密钥），数据库与 `master.key` 仍须成套保管。

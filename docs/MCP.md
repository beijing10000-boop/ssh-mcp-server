# MCP 工具及接入方法

## 接入地址

- 传输：**Streamable HTTP**（MCP 标准协议）
- 地址：`http://可信内网IP:9099/mcp`
- Header：`Authorization: Bearer <Web「系统配置 → MCP 接入」签发的客户端令牌>`
- Web 使用飞书 Cookie 会话，不能用于 MCP；初始化 Token 也不能用于 MCP。
- 带 `Origin` 的浏览器请求只接受本服务自己的来源；经 HTTPS 反向代理接入时，按[安装文档](INSTALLATION.md#https-反向代理)设置 `SSHMCP_TRUSTED_PROXIES`，该代理转发的 `X-Forwarded-Proto`/`X-Forwarded-Host` 才计入（v0.10.0）。不带 Origin 的 MCP 客户端不受影响。
- 鉴权只读数据库：客户端的“最近使用时间”每分钟最多写一次，数据库被长事务占用时跳过，不影响调用（v0.10.0）。

在 Web「系统配置 → MCP 接入」创建客户端，选择允许的主机组（或明确授权全部主机）、诊断动作和 1–365 天有效期。原始令牌只显示一次，关闭弹窗后不能再次读取；数据库仅存哈希。撤销/到期从下一次请求起生效，不承诺终止已经执行中的 SSH。v0.6.0 起可以对有效客户端「编辑权限」（调整动作、全部主机与主机组），令牌保持不变，详见下文[客户端授权自动扩展与编辑](#客户端授权自动扩展与编辑)。

兼容的 `/app/data/mcp.token` 拥有全部主机和动作权限，可在 MCP 接入页面停用。不同团队应使用不同客户端令牌。当前为内部服务 Bearer 认证，不提供完整 OAuth 2.1 动态客户端授权流程。

示例客户端配置（结构依据客户端支持情况调整）：

```json
{
  "mcpServers": {
    "linux-ssh-diagnostics": {
      "type": "streamable-http",
      "url": "http://可信内网IP:9099/mcp",
      "headers": {"Authorization": "Bearer 请通过安全配置渠道注入MCP令牌"}
    }
  }
}
```

## 工具目录

| MCP 工具 | 说明 |
| --- | --- |
| ssh_list_hosts | 只列出已登记、已启用、已审核公钥的主机 |
| ssh_resolve_target | 按已登记内网 IP 精确解析授权 Linux 主机，返回 SSH host_id、address、revision；不依赖 Zabbix |
| ssh_resolve_host | 按 Zabbix Host ID 精确定位唯一授权主机，返回主机 ID 与版本 |
| ssh_test_connection | 验证 SSH 身份、认证和固定命令 |
| ssh_diagnose_health | 负载、内存、Swap、文件系统、inode 与高 CPU 进程综合快照 |
| ssh_diagnose_capabilities | 登录 UID、诊断命令是否可用，不自动安装工具 |
| ssh_diagnose_cpu | CPU 负载（1/5/15 分钟及每核）、vmstat 1 秒采样（运行/阻塞队列与 us/sy/id/wa/st）、procs_running/procs_blocked；负载高但 CPU 空闲时给出 load_cpu_divergence 线索 |
| ssh_diagnose_memory | 内存与 Swap |
| ssh_diagnose_disk | 磁盘容量、inode 与挂载 |
| ssh_diagnose_processes | 进程排行（生命周期平均 CPU）；A 模式另含进程状态计数、D 状态进程及 wchan、最近 1 秒 CPU 增量 cpu_interval |
| ssh_diagnose_memory_processes | 按 RSS 排序的进程概况，不读取环境变量或完整命令行 |
| ssh_diagnose_io | I/O 数据 |
| ssh_diagnose_network | 网卡与路由 |
| ssh_diagnose_sockets | 监听与 TCP 汇总 |
| ssh_diagnose_system | 运行时长/内核 |
| ssh_diagnose_service | 指定合法 systemd 服务状态 |
| ssh_diagnose_failed_services | 最多 60 项失败 systemd 服务，不重启 |
| ssh_diagnose_containers | 限时读取最多 60 项 Docker/Podman 容器状态，不 inspect/exec |
| ssh_diagnose_kernel | 最近 1–120 分钟、最多 100 行内核告警 |
| ssh_diagnose_logs | 指定合法 systemd 服务最近有限时间范围日志 |
| ssh_diagnose_directory_usage | 白名单目录下一级空间排行，8 秒限时，支持逐层深入 |
| ssh_diagnose_peer_connections | 当前远端 IP TCP 连接数 Top 50 |
| ssh_diagnose_peer_traffic | 约 3 秒同一 TCP socket 的发送、接收字节增量 Top 30 |
| ssh_diagnose_pressure | CPU/内存/I/O PSI 压力 |
| ssh_diagnose_resource_limits | 文件句柄、PID 与当前 SSH shell 限制 |
| ssh_diagnose_mounts | 挂载类型与只读文件系统 |
| ssh_diagnose_block_devices | 块设备结构 |
| ssh_diagnose_time_sync | 时间与 NTP/chrony 状态；`timedatectl show` 不可用（systemd 239 以前，如 EL7）时回退 `timedatectl status`，再回退 `chronyc tracking`、`ntpstat`，`summary.sync_source` 写明来源（v0.10.0） |
| ssh_diagnose_tcp_states | TCP 状态分布 |
| ssh_diagnose_service_inventory | 系统服务清单 |
| ssh_diagnose_timers | systemd timer 上次和下次运行 |
| ssh_diagnose_system_errors | 有限时间内的系统告警日志 |
| ssh_diagnose_oom | 有限内核日志中的 OOM 线索 |
| ssh_diagnose_container_stats | Docker/Podman 当前资源数据 |
| ssh_diagnose_security_status | 安全组件状态 |
| ssh_list_tool_catalog | 当前客户端授权的诊断目录；每项 `tool` 为对应的 MCP 工具名，`params` 为结构化参数，另有 `risk`、`extension`、`notes`，客户端可据此只展示获准动作 |
| ssh_list_groups | 当前客户端获授权的主机组 |
| ssh_resolve_hosts | 批量按 Zabbix Host ID 精确解析，最多 100 个，逐项返回映射或原因 |
| ssh_triage | 固定故障场景组合诊断，需单独 `triage` 授权（见下文） |
| ssh_submit_diagnostics | 每批 1–100 台授权主机，后台执行固定只读诊断 |
| ssh_get_diagnostic_job | 查询自己提交且仍有权访问的任务 |
| ssh_get_diagnostic_batch | 分页查看自己提交的批次计数、逐主机状态与 findings |
| ssh_cancel_diagnostic_job | 取消自己提交且仍有权访问的任务 |

### v0.6.0 新增工具

以下 8 个工具都只读、带 `expected_revision` 与 `detail=summary|full`，只支持标准 SSH 模式（A 模式）。参数由服务端注册表校验，未知参数、越界数值或不合格式的文本在生成命令前就被拒绝。风险以 `ssh_list_tool_catalog` 返回的 `risk` 为准。

| MCP 工具（动作 id） | 参数 | 用途 | 风险 |
| --- | --- | --- | --- |
| ssh_diagnose_nginx（nginx） | `minutes`=30（1–1440） | 发现 Nginx 二进制、配置、日志路径与轮转文件；进程、监听端口、systemd 状态与 upstream/超时配置摘要；统计窗口内 error.log 的级别分布、上游超时/连接失败/无可用上游、worker_connections 不足等线索。只读每个 error.log 尾部 20 MB、最多 2 个文件；不 reload、不改配置 | 低 |
| ssh_diagnose_nginx_access（nginx_access） | `minutes`=30（1–1440）、`since`/`until`（Unix 秒，最长 24 小时）、`path`、`status`（all、4xx、5xx 或具体码）、`keyword`（≤64 字符）、`top`=10（5–30） | 远端 awk 聚合访问日志：请求总数、状态码分布、错误请求 TOP URL/IP/UA、每分钟请求与 5xx 趋势、request_time/upstream_response_time 统计。只读每个日志尾部约 30 MB（跨轮转时另读未压缩轮转文件尾部 10 MB），窗口被截断时说明覆盖范围；`path` 只接受 Nginx 配置声明的 access_log 或标准日志目录 | 中 |
| ssh_diagnose_syslog（syslog） | `minutes`=30（1–1440）、`since`/`until`、`unit`、`priority`=warning（emerg…debug）、`keyword`、`pid`、`lines`=120（20–300） | 优先 journalctl，journald 不可用、无权限或未覆盖窗口时回退 /var/log/messages、syslog、secure、auth.log 尾部并说明来源；返回按级别/单元计数、OOM/磁盘 I/O/网络链路/服务失败/内核异常/登录失败分类与代表性日志行；区分“无日志”与“无权限” | 低 |
| ssh_diagnose_java（java） | 无 | 盘点最多 20 个 Java 进程：PID、用户、运行时长、RSS、线程与句柄数、systemd 单元、JAR/主类、应用名、-Xms/-Xmx/-Xss 与 GC 参数、GC 与应用日志位置、JDK 路径与版本。只读 /proc，不附加 JVM；启动命令脱敏，完整命令只在 `detail=full` 附带 | 低 |
| ssh_diagnose_jvm（jvm） | `pid`（必填）、`probes`（heap_info、vm_flags、gc_stat、gc_log，缺省前三项） | 对指定 Java 进程执行有界探针：jcmd GC.heap_info、jcmd VM.flags、jstat -gc、GC 日志尾部 40 行。需以 root（经 runuser 切换到 JVM 所属用户）或与 JVM 相同的用户执行，否则返回能力缺失。对目标的副作用见下文 [jvm 探针的副作用](#jvm-探针的副作用) | 中 |
| ssh_diagnose_service_detail（service_detail） | `service`（必填，systemd 单元名）、`minutes`=30（1–1440） | 单个 systemd 服务深度诊断：状态、Result、退出码、重启次数与策略、启动时间、MainPID、内存/任务数、ExecStart、运行用户与工作目录、单元文件与 drop-in、cgroup 进程、监听端口、窗口内日志与近 24 小时异常退出/重启记录；单元不存在时返回 `unit_not_found`，不会说成“已停止” | 低 |
| ssh_diagnose_service_map（service_map） | 无 | 监听端口 → 进程（PID、程序名、用户）→ systemd 单元/容器映射（最多 80 行），附 RSS 与运行时长；非 root 账号只能看到自己进程的端口归属 | 低 |
| ssh_collect（collect） | `actions`（1–6 个固定动作，按顺序执行）、`service`（含 service/logs 步骤时必填，否则不能传）、`minutes`=30（1–120，日志类步骤的窗口）、`timeout_seconds`（可选，10–120，v0.9.0） | 在一次 SSH 会话内顺序执行多个固定诊断，每个步骤单独返回 exit_code、summary 与 findings，并合并为带 `source_action` 的总 findings；执行上限 120 秒（另可能排队最多 30 秒），给出 `timeout_seconds` 时排队与执行合计不超过该值，见下文 [ssh_collect 使用建议](#ssh_collect-使用建议)。可组合动作为 cpu、memory、processes、memory_processes、pressure、resource_limits、disk、io、mount_health、block_devices、network、sockets、tcp_states、system、health、capabilities、failed_services、service_inventory、timers、time_sync、containers、container_stats、security_status、kernel、log_errors、oom、service、logs（不含 directory、peer_*、triage 及扩展动作） | 低 |

### v0.11.0 新增工具

| MCP 工具（动作 id） | 参数 | 用途 | 风险 |
| --- | --- | --- | --- |
| ssh_diagnose_java_apps（java_apps） | 无 | Java 应用清单：最多 60 个 Java 进程的应用名、JAR/主类、profiles、用户、systemd 单元或容器、运行时长与 RSS，以及各自监听的 TCP 端口；另附本机 IPv4 地址。只读 /proc，不附加 JVM，不返回启动命令 | 低 |

`summary` 的字段：

- `addresses`：本机 IPv4 地址（`ip -4 addr` 的 global 地址，最多 16 个；不含 docker0、网桥、veth 等虚拟接口）。一台主机在资产里只登记一个地址，其他网卡的地址从这里得到。
- `java_processes`：Java 进程总数；多于 60 个或 8 秒时间预算内未读完时另有 `apps_shown`、`time_budget_reached`。
- `apps[]`：`pid`、`application`（依次取 spring.application.name、app.name、app、service.name，再取 JAR 名、自己的 systemd 单元名，都没有为“未识别”；supervisord、docker 这类进程管理器的单元不算应用名）、`main`、`jar_path`、`profiles`、`user`、`unit`、`container`、`elapsed_seconds`、`rss_KiB`、`ports`（最多 16 个）、`local_ports`（只绑定回环地址的端口，是 `ports` 的子集，只有本机上的代理才到得了）、`ports_source`、`declared_port`（启动参数里的 server.port）。
- `ports_source`：`listen` 来自 `ss -ltnp`（该进程自己的监听套接字）；`docker` 来自 `docker ps` 的发布端口（bridge 网络的容器，取的是宿主机端口，同一容器内的多个 Java 进程都记这些端口）；`argument` 表示 ss 没有给出归属，用启动参数里的 server.port 代替（非 root 账号看不到其他用户进程的套接字）；`null` 表示不知道端口，此时 `ports` 为空——可能确实不监听（定时任务、消息消费者），不能据此说应用不对外服务。
- `port_owner_visible`：ss 是否给出了进程归属（`false` 多为非 root 账号，`null` 为 ss 不可用）；`docker_ports`：`ok`、`none`、`unavailable`（读不到 Docker）或 `absent`（没有 docker 命令），只在有容器内的 Java 进程时出现。

这个动作没有参数，可以用 `ssh_submit_diagnostics`（`action="java_apps"`）对多台主机批量采集，再用 `ssh_get_diagnostic_batch` 读取每台的 `result.summary`。它**不随任何已有权限自动扩展，也不在“按 AI Ops Platform 推荐勾选”范围内**：需要的客户端由管理员在「编辑权限」中单独勾选。要看每个 JVM 的堆、GC 与日志位置仍用 `ssh_diagnose_java`，要看所有程序的监听端口用 `ssh_diagnose_service_map`。

共 52 个工具：32 类经典单项诊断（含连接测试）、7 类 v0.6.0 深度诊断、v0.11.0 的 Java 应用清单、单会话多项采集 `ssh_collect`、组合诊断 `ssh_triage`、6 个资产/目录查询工具和 4 个后台任务工具。`ssh_list_hosts` 支持 query、group_id、offset、limit（最多 1000），返回当前授权范围内的所属主机组名称，只返回当前客户端可访问且已就绪的资产。所有执行操作**仅接受登记的数字 host_id**，单项诊断支持可选的 `expected_revision`：建议 AI 平台始终传入解析时取得的版本，拒绝过期映射。即使模型请求任意 IP 或 shell 命令，服务端也没有对应工具。

### jvm 探针的副作用

`ssh_diagnose_jvm` 是唯一会改变目标进程状态的动作，因此只能手动授权（同样写在工具说明与 `ssh_list_tool_catalog` 的 `notes` 中，v0.10.0）：

- **heap_info、vm_flags（jcmd）附加到 JVM**：jcmd 先在 JVM 的工作目录（不可写时为 JVM 的 `/tmp`）创建 `.attach_pid<PID>` 并向 JVM 发送 SIGQUIT，结束后删除该文件（被 8 秒超时终止时可能残留）；JVM 随即启动常驻的 Attach Listener 线程，并在其 `/tmp` 留下 `.java_pid<PID>` 套接字，二者保留到 JVM 退出。不捕获 SIGQUIT（`-Xrs`、jsvc 父进程）或带 `-XX:+DisableAttachMechanism` 的 JVM 跳过 jcmd，以免 SIGQUIT 终止进程。
- **命令在 JVM 内执行**：可能短暂进入安全点或持有堆锁，生产高峰期谨慎使用；不触发 GC、不生成堆转储、不修改参数。
- **身份**：root 账号经 `runuser -u <JVM 属主>` 执行（系统日志可能记录一次 runuser 会话）；其他账号必须就是 JVM 属主。
- **gc_stat（jstat -gc）** 只读 JVM 的性能计数文件 `/tmp/hsperfdata_<用户>/<PID>`，不附加、不发信号；**gc_log** 只读 GC 日志尾部 40 行。
- jcmd、jstat 自身以 `-Xmx64m`、`-XX:-UsePerfData` 启动（不留下自己的计数文件），每个探针限时 8 秒。

`ssh_submit_diagnostics` 不接受扩展参数：扩展动作只能以注册表默认参数批量提交，`jvm`、`service_detail` 这类有必填参数的动作以及 `ssh_collect` 请使用同步工具。Web 控制台与 `POST /api/v1/jobs`、`POST /api/v1/hosts/{id}/diagnose` 通过 `options` 对象传入扩展动作的全部参数（经典动作仍用 service、minutes、directory_root）。

结果包含 `status=success|partial|failed|cancelled`；失败结果另含稳定的 `error_code`（`forbidden` 未授权、`unavailable` 主机不存在/无权访问、`not_linux` 资产不是 Linux（解析工具另附 `asset_type` 与 `name`）、`not_ready` Linux 已登记但停用、公钥未核验或未绑定凭据、`mapping_unresolved` Zabbix 映射缺失或重复、`busy` 同主机或 SSH 名额排队超时，或待执行任务已满、`timeout`、`revision_changed`、`host_unverified` 执行阶段的主机公钥问题（未核验、格式无效或与登记的不一致）、`unsupported`、`invalid_argument`、`cancelled`、`failed`），`error` 仍为中文说明。v0.6.0 起执行阶段（SSH 已开始后）的失败也带 `error_code`，可以区分主机繁忙、版本过期与 SSH 故障。v0.9.0起，诊断工具创建任务时的三类拒绝改用专用代码（`error` 文字不变）：所有诊断任务中排队与运行中的合计已达 200 个返回 `busy`（原 `invalid_argument`）；主机已停用、公钥未核验或未绑定凭据返回 `not_ready`（原 `host_unverified`）；资产不是 Linux 返回 `not_linux`（原 `invalid_argument`）。非 Linux 资产不能启用，诊断工具对它通常先返回 `not_ready`，要区分资产类型请用解析工具。已创建的执行任务包含 `job_id`，可供管理员在 Web 查看。工具层面的 MCP `isError` 和结果里的 `status` 都需要检查。缺命令、读取权限不足、非零退出或输出截断不能解释为诊断成功。单项诊断同步返回；批量任务通过 ssh_submit_diagnostics 后台提交，再查询状态。

**客户端离开（v0.10.0）**：同步诊断（`ssh_diagnose_*`、`ssh_test_connection`、`ssh_collect`、`ssh_triage`）的客户端在收到结果前关闭 HTTP 连接时（会话关闭、进程退出、HTTP 超时后断开），服务端在约 0.2 秒内察觉：仍在等待主机名额的调用放弃等待，不占名额、不连接 SSH；正在建立 SSH 连接的调用在握手结束后关闭连接、不执行命令，正在读取输出的调用停止读取并关闭 SSH 通道，二者都释放名额；尚在服务端排队、未开始的调用不再执行。已创建的任务记为 `cancelled`（`error` 为“MCP 客户端已断开连接，诊断已取消”，`error_code=cancelled`；SSH 握手期间断开的此前被归为 `revision_changed`），已读到的输出不保留。不能取消的情形：客户端只放弃等待而保持连接（例如 MCP Python SDK 中对 `call_tool` 套 `wait_for` 的超时，会话与连接保持到会话关闭），或发送 MCP `notifications/cancelled`（本服务是无状态 HTTP，取消通知作为另一个请求到达，找不到原调用）——此时调用照常执行完（会话关闭时仍未结束的才取消），需要服务端在调用方期限内结束的请给 `ssh_collect` 传 `timeout_seconds`；排队仍受 30 秒（`ssh_collect` 给出 `timeout_seconds` 时为其一半）的上限约束，执行受各动作的时间上限约束。后台任务（`ssh_submit_diagnostics`）与客户端连接无关，只能用 `ssh_cancel_diagnostic_job` 或 Web 取消。经反向代理接入时，代理的读超时应长于调用方自身的超时（建议 ≥180 秒），否则代理先断开连接，调用会被当作客户端离开而取消。

同一主机同一时刻只执行一个诊断。同步诊断调用在服务端独立的 32 线程池中等待名额与执行（v0.10.0；此前与解析、目录、任务查询等轻量工具共用一个线程池，同时排队的诊断多时轻量工具也要等）；超过 32 个的调用在服务端排队，轻量工具不受影响，排队等线程的时间计入下述 30 秒（以及 `timeout_seconds`）。等名额的调用占用一个线程，32 个线程即 4 个名额加 28 个等待者：同时等待繁忙主机的调用不超过 28 个时，其他主机的调用不必排队。v0.6.0 起同步 MCP 调用等待同主机名额的时间从 2 秒延长到 30 秒，超过才返回 `busy`；后台任务最多等待 180 秒；`ssh_collect` 给出 `timeout_seconds` 时最多等待该值的一半，且不超过 30 秒（v0.9.0）。执行超时时保留已经读到的输出，结果标记 `timed_out=true` 与 `incomplete_reason`（`timeout`、`output_limit`、`exit_code`、`stderr`），状态为 partial；完全没有输出才返回 `timeout` 失败。stderr 只有致命错误（命令不存在、权限拒绝、用法错误等）才使结果变为 partial，df 读取 gvfs/FUSE 挂载之类的已知噪声放在 `warnings` 中，不影响状态。stderr 只保留前 2 KiB；v0.9.0起超出时结果带 `stderr_truncated=true`，stdout 照常读完（此前会提前结束读取并报 `output_limit`）。

`ssh_resolve_target` 与 `ssh_resolve_host` 成功时新增 `asset_type`（Linux 主机为 `linux`）和 `mode`（诊断模式：A 模式 `standard`，B 模式强制命令网关 `gateway`；B 模式主机不支持任何 v0.6.0 新动作）。失败时：资产不是 Linux 返回 `not_linux` 并附 `asset_type` 与 `name`，AI 平台可据此改走仅 Zabbix 的分析路径；Linux 主机已登记但停用、公钥未核验或未绑定凭据返回 `not_ready`（`asset_type=linux`）；主机不存在或不在授权范围内仍为 `unavailable`。

## 客户端授权自动扩展与编辑

- **启动时自动扩展**：服务启动时为已启用的客户端补充 v0.6.0 新动作，每个客户端只补一次，并写入审计 `mcp_client_actions_extended`（detail 形如 `v0.6.0:java,nginx,...`）。v0.9.0起按动作记录在 `mcp_clients.actions_extended`：每个隐含动作对每个客户端最多补一次，管理员去掉的动作以后的版本也不会再补回，以后新增的隐含动作只单独补一次；本版的隐含动作与 v0.6.0 相同，标记仍写为 `v0.6.0`。规则：持有 `logs` 的客户端获得 `nginx`、`nginx_access`、`syslog`、`java`、`service_detail`；持有 `log_errors` 的也获得 `syslog`；持有 `sockets` 或 `service` 的获得 `service_map`。
- **`jvm` 只能手动授权**：它会附加到 JVM 并短暂进入安全点，不随任何已有权限自动扩展。
- **`ssh_collect` 按步骤授权**：只要客户端拥有任一可组合步骤，`ssh_list_tool_catalog` 就会列出 `collect`；调用时逐个检查每个步骤，任一步骤未授权即整体拒绝（`forbidden`），不会部分执行。无需单独勾选 `collect`。v0.9.0起 `ssh_get_diagnostic_job`、`ssh_cancel_diagnostic_job` 与 `ssh_get_diagnostic_batch` 对采集任务同样按步骤检查（此前要求客户端持有 `collect` 本身，查询自己的采集任务会得到 `forbidden`）。
- **编辑权限**：Web「系统配置 → MCP 接入」对有效客户端点「编辑权限」，可调整诊断动作、全部主机与主机组；接口为 `PUT /api/v1/mcp/clients/{id}`，body `{"actions": [...], "all_hosts": true|false, "group_ids": [...]}`（`all_hosts`、`group_ids` 可省略表示不变），与其他写接口一样需要飞书管理员会话与 `X-CSRF-Token`。令牌不变，新范围从下一次 MCP 请求起生效，已在执行的 SSH 不受影响；修改记录审计 `mcp_client_update`。
- **推荐范围**：新建或编辑弹窗中的「按 AI Ops Platform 推荐勾选」选中 `GET /api/v1/tools` 中 `recommended=true` 的动作（v0.9.0；此前由页面内置的列表决定）：connection、health、capabilities、cpu、memory、processes、memory_processes、disk、io、network、sockets、system、service、failed_services、logs、kernel、containers、pressure、resource_limits、mount_health、block_devices、time_sync、tcp_states、service_inventory、timers、log_errors、oom、container_stats、security_status、nginx、nginx_access、syslog、java、service_detail、service_map，共 35 个，即平台托管 Skill 预采集或点名的全部动作加上诊断测试用的 connection。其中 containers、resource_limits、mount_health、block_devices、time_sync、timers、container_stats、security_status 是原列表漏掉的 8 个，已有客户端不会自动获得，需要「编辑权限」重新勾选。不含 jvm、triage、directory 与 peer_*；`collect` 按步骤授权，不在其中。`ssh_list_tool_catalog` 不返回 `recommended`。

## ssh_collect 使用建议

AI 平台在告警分析前做预采集时，应把同一主机需要的多个固定诊断合并成**一次** `ssh_collect` 调用（例如 `actions=["cpu","processes","pressure"]`，或 `["service","logs","failed_services"]` 加 `service`），不要并发调用多个单项工具：同一主机的诊断是串行的，多个并发调用会排队等待名额，单次调用等待超过 30 秒即返回 `busy`；`ssh_collect` 只建立一次 SSH 会话，不会自我排队。

- 每次最多 6 个步骤，执行上限 120 秒（另可能排队最多 30 秒）、单步输出上限 32 KiB；步骤越多耗时越长，按需选择。
- 调用方自身有超时（如 AI 平台的单工具超时）时，传 `timeout_seconds`（10–120，略小于自身超时；v0.9.0）：排队与执行合计不超过该值，排队最多等 min(30, timeout_seconds ÷ 2) 秒；取得名额时若剩余不足 max(5, timeout_seconds ÷ 4) 秒（例如在服务端线程池中排队过久），立即返回 `busy`（“…未连接主机，请稍后重试”），不连接 SSH（v0.10.0）；SSH 握手各阶段分享剩余时间，读取输出到上限前 1 秒为止。每个步骤另有单步超时 max(5, min(20, ⌊(timeout_seconds − 5) ÷ 步骤数⌋)) 秒（目标机有 `timeout` 命令时生效），被终止的步骤为 `partial` 并带 `timed_out=true` 与 `error`，后续步骤照常执行。到达上限时返回已完成的步骤，整体 `timed_out=true`、状态为 partial；一点输出都没读到才返回 `timeout` 失败。经跳板访问的主机，跳板的握手与通道建立同样按剩余时间计时。不传时与 v0.8.0 相同。调用方可从 `tools/list` 中 `ssh_collect` 的 inputSchema 是否含 `timeout_seconds` 判断服务端是否支持。
- 结果在 `summary.steps` 中逐步给出 status、exit_code、summary、findings；总 `findings` 带 `source_action`，`summary.completed/total` 说明完成情况，未完成步骤会产生 `triage_coverage` 线索。v0.9.0起任一步骤的 status 不是 success 时，顶层 `status` 为 `partial`（此前整段脚本退出码总是 0，步骤失败时顶层仍可能是 `success`）；顶层 `incomplete_reason` 只反映整段执行，仅因步骤失败时为 null。
- Nginx、syslog、Java、服务详情等扩展动作不能放进 `ssh_collect`，需单独调用对应工具；同一主机上它们同样串行执行。

## 接入 AI Ops Platform

当前整合平台使用内置的 `diagnose_linux_host` 工具和执行器，**不能仅更改 MCP URL 就自动将其切换至本服务**。

详细逐文件说明和可运行适配器见 [AI 平台改造方案](AI-PLATFORM-INTEGRATION.md)。需要在整合平台单独实现：
1. 将本 SSH MCP 作为第二个 MCP 会话加载，与 Zabbix MCP 分开认证；
2. 工具发现与白名单按 `ssh_*` 限制；
3. 使用本平台 Host ID 的精确映射，不要把 Zabbix Host ID 或 IP 直接当作 SSH Host ID；
4. 证据、工具超时、Token 预算、审计和断连错误独立记录；
5. 联调确认无误后禁用旧执行器，避免重复 SSH 任务。

切换前，本 MCP 可以独立使用 MCP Inspector 等受信客户端做测试。


新增诊断数据的覆盖条件请参阅 [目录与 IP 流量分析](INSIGHTS.md)。不要把一次 TCP 采样误写成全协议或历史 IP 流量统计。


v0.3 的 12 类新增诊断需要标准 SSH 模式；受限网关尚不支持。后台任务在执行前重新核对客户端授权。详情见 [v0.3 更新说明](RELEASE-v0.3.md)。


## 结构化结果与组合诊断

诊断工具、任务与批次结果查询支持 `detail=summary|full`，默认 summary：返回 `summary`、`findings` 与执行元数据，省略 stdout/stderr。`full` 才附带可用的脱敏原文；已有目录/连接排行工具保留原来的原文裁剪。历史仍加密保存完整的可用结果，Web 管理员可查看。findings 字段为 level（critical/warning/info）、metric、value、threshold、hint，组合诊断另有 source_action。规则是经验阈值，未触发不代表健康；缺失工具、截断、日志窗口和累计计数均有说明。

`ssh_triage(host_id, symptom, service?, minutes=30, expected_revision?, detail="summary")` 需要单独的 `triage` 授权，现有具名客户端不会自动获得。场景固定为 cpu_high、mem_high、disk_full、io_slow、service_down、network；service_down 必须给合法服务名。每个场景在同一已核验的 SSH 连接和通道中顺序执行预设动作，逐项保留退出码与完整性，最长 60 秒，输出上限 128 KiB；受限网关暂不支持。

`ssh_get_diagnostic_batch(batch_id, page=1, page_size=25, detail="summary")` 一次返回 counts、completed、skipped 和逐主机状态/findings，仅限本客户端提交、且所有目标仍获当前授权的批次。每页最多 100 项，旧版批次可按已有任务聚合。`ssh_resolve_hosts(zabbix_hostids)` 最多 100 个 Host ID，逐项返回精确映射或原因；不接受 IP/名称猜测映射。

v0.6.0 的 summary 补充了可直接引用的证据，模型在默认 summary 模式下也能拿到：

- **日志类**（logs、kernel、log_errors、oom）：`entries` 为窗口内最近 40 行（每行最多 240 字符），`entries_total` 为总行数，`matched` 按 oom、io_error、network、service、kernel、auth（OOM、磁盘 I/O、网络链路、服务启动失败、内核异常、登录失败）分类、每类最多 20 行，`first_at`/`last_at` 为首末时间戳。syslog 与 service_detail 使用同样的分类：syslog 的 `entries` 受 `lines` 与约 16 KB 上限约束，service_detail 的日志在 `journal.entries`/`journal.matched` 中（最多 80 行）。诊断账号既不是 root、也不在 systemd-journal/adm 组时，journalctl 只能看到本账号的日志，结果带 `journal_access=limited` 与同名 warning，空结果不能视为无异常。
- **service**：额外读取 LoadState、UnitFileState、NRestarts、Restart、ExecMainCode、各状态切换时间、MemoryCurrent、TasksCurrent、FragmentPath 等属性；不存在的单元返回 `unit_not_found`，不再误报为“已停止”；自动重启与非 success 的 Result 分别给出 `service_restarts`、`service_result` 线索。
- **service_inventory / sockets / health**：summary 分别带结构化的 `units` 与 `active_counts`、`listening` 与 `socket_stats`、`top_processes`。
- **扩展动作**：summary 带 `request`（已校验并补齐默认值的参数）；结果另带 `request_options` 与 `risk`。

v0.10.1（2026-11 第三轮审计）修正了以下结果（字段只增不改）：

- **nginx / nginx_access 的 master**：只采用 root 或诊断账号本身运行的 `nginx: master process` 行（`ps -e -o pid= -o uid= -o args=`）；其他账号运行的同名进程（任何账号都能这样命名进程）不再决定二进制与 `-c`/`-p`，nginx 动作报 warning 级 `nginx_master_untrusted`，`summary.master_untrusted=true`。
- **nginx_access**：动作在写出统计段前结束（超时或输出被截断）时，`summary.totals_missing=true`、`totals.requests` 为 null，报 warning 级 `access_totals_missing`，不再报 `requests_total=0` 与“可能确实没有流量”的 `no_requests`。
- **tcp_states**：`summary.states` 包含 FIN-WAIT-1 / FIN-WAIT-2（此前正则不接受数字，这两种状态被丢掉）。
- **service_inventory**：先列全部非 inactive 的单元（失败单元不会被截掉），再列最多 50 个 inactive 的；新增 `summary.units_total`（主机上的服务单元总数）与 `units_truncated`，被截短时 `coverage` 写明 `active_counts` 只统计列出的单元。此前只取 `systemctl` 输出的前 100 行且不标截断。
- **连接**：固定的主机公钥为 RSA 时，握手只协商 RSA 的签名算法（rsa-sha2-512/256、ssh-rsa）。此前目标同时有 Ed25519/ECDSA 主机密钥、又不再提供 SHA-1 `ssh-rsa` 签名（OpenSSH 8.8+、RHEL/Rocky 9 默认策略）时，握手拿到的是另一把密钥，被误报为“SSH 主机公钥与已登记公钥不一致”（`host_unverified`）。

v0.9.0修正了以下结果，拿不到数据时给出 null 与说明，调用方应把 null 当作“未知”而不是 0：

- **nginx**：新增 `summary.process_listing`：`ok`；`limited`（看不到 PID 1，多为 /proc 以 hidepid 挂载，脚本标记 `PS_LIMITED`）；`failed`（ps 不接受所需的列，`CAPABILITY_MISSING:ps-columns`，结果为 partial）；`missing`（没有 ps）；没有进程段时为 null。`worker_count` 只在列表完整或列出了 Nginx 进程时为数值，否则为 null。只有完整列表中没有 master、systemd 也不是 active 时才报 critical 的 `nginx_inactive`；受限列表中没有 master 时报 info 级 `nginx_process_not_visible`。master 排在进程列表最前，不会被 40 行上限截掉。没有读到任何 error.log 时 `errors.lines_in_window` 为 null，并报 info 级 `error_log_not_read`。
- **nginx_access**：配置与相对路径按运行中 master 的 `-p`/`-c` 解析。找不到可读的访问日志时，脚本输出 `CAPABILITY_MISSING:nginx-access-log` 并以退出码 69 结束（partial），报 warning 级 `access_log_not_found`（`value` 含 `missing`、`no_access` 路径）；summary 中没有 `totals`、`codes`、`top`、`timeline`、`timing`、`samples`，也不报 `no_requests`。日志时间的 UTC 偏移与主机不同（容器内 nginx 常用 UTC）时，给出 `summary.tz_mismatch`（`log_offset`、`host_offset`，形如 `+0000`、`+0800`，以及 `shift_seconds`）与 warning 级 `log_timezone_mismatch`；窗口仍按主机本地时间筛选、不换算，可把 `since`/`until` 各加上 `shift_seconds` 后重查。
- **syslog**：journal 可用且 `priority` 严于 info（默认 warning）时，另以 `-p info` 按相同的 unit、pid、keyword 统计分类（脚本段 `[AIOPS_JOURNAL_KINDS]`，限时 3 秒），`matched_counts`/`matched` 因此包含以 info/notice 记录的链路断开、segfault、登录失败等，`entries` 仍按 `priority` 过滤；这一段超时报 `journal_query_incomplete`。分类不再把 “NIC Link is Up”、开机时的 “NMI watchdog: Enabled” 与 “DEBUG:” 行算作网络或内核异常。新增 `summary.counts_filters`：`counts.total` 受 priority、unit、pid、keyword 过滤，crit/err/warning 只受 unit、pid 过滤（不受 keyword 影响）。
- **service_detail**：诊断账号读不全 journal、主机没有 journalctl，或近 24 小时 PID 1 记录读取超时、失败时，`counts.restarts_24h`、`failures_24h`、`starts_24h` 为 null；记录读取失败或 `systemctl show` 没有返回属性时结果为 partial，后者另报 warning 级 `unit_state_unknown`（`value.systemctl_show_exit`）。`restart_loop` 只在近 24 小时自动重启 ≥3 次时为 critical；24 小时记录未知时，NRestarts ≥3 且单元处于 auto-restart 或在窗口内启动过也为 critical；其余 NRestarts ≥3 的情况为 info。服务自身日志中的 “out of memory” 报 warning 级 `oom_log_clue`，`oom_killed` 只依据 systemd 的 Result、PID 1 记录与 OOM killer 记录。
- **jvm**：`gc_log` 探针只输出 GC 记录格式的行；容器内（根目录与本机不同）的 JVM，GC 日志文件或其任一上级目录是符号链接时不读取，`probes.gc_log` 为 `symlink_refused`；与本机同根的 JVM 可跟随链接，但最终文件必须是 JVM 属主的普通文件。
- **processes / memory_processes / health**：进程名可以含空格（如 `PM2 v5.3.0: God`），数值列不再错位。
- **日志类的内核分类**（logs、kernel、log_errors、oom）不再把 Python 日志的 `DEBUG:` 当作内核 `BUG:`。

v0.10.0 的结果变化，同样只增不删：

- **未知的计数为 null**：经典动作的采集不完整（输出 `CAPABILITY_MISSING:*`、非零退出、致命 stderr、超时或截断，即 `status` 不是 `success`）时，计数类指标为 0 的改为 null（未知）：`failed_service_count`、`observed_log_lines`、`oom_matches`、`observed_rows`、`listening_ports`、`reported_firewall_services`、`processes_uninterruptible`、`unavailable_commands` 的 `summary.metrics[].value`，以及日志类的 `summary.entries_total`。大于 0 的计数照常给出（已看到的证据，是下限）。完整采集的 0 仍是 0。
- **`ssh_diagnose_service`**：一个单元的属性没有“失败服务数”可数，`failed_service_count` 指标的 value 恒为 null，`summary.failed_services` 为 null（此前恒为 0 和 `[]`）；字段保留，按名读取的客户端不会出错。`failed_services`、`service_inventory` 两个动作不变。
- **`ssh_diagnose_time_sync`**：EL7（systemd 219）等没有 `timedatectl show` 的主机改读 `timedatectl status`（脚本段 `[AIOPS_TIMEDATECTL_STATUS]`，标签映射到原来的 Timezone、LocalRTC、NTP、NTPSynchronized）；timedatectl 不可用或连不上 D-Bus 时，用 `chronyc tracking`（Leap status 为 Not synchronised 即未同步）再用 `ntpstat`（退出码 0 已同步、1 未同步、2 无法判断）。新增 `summary.sync_source`：`timedatectl show`、`timedatectl status`、`chronyc tracking`、`ntpstat`，都取不到为 null；chronyc 可用时新增 `summary.chrony`（`reference`、`stratum`、`system_time`、`last_offset`、`leap_status`），用到 ntpstat 时新增 `summary.ntpstat`（`exit_code`、`state`）。每个外部命令限时 5 秒（有 `timeout` 时）。chronyc 的非零退出不再让整个结果变为 partial；只有 timedatectl 自身失败且没有其他来源时结果才是 partial（stderr 为 timedatectl 的错误），什么都没有时仍是 `CAPABILITY_MISSING:timedatectl`。
- **`ssh_diagnose_containers`**：状态含 `(unhealthy)`（容器在运行但健康检查失败）时报 warning 级 `container_state`（`threshold` 为 `healthy`）；`(healthy)`、`(health: starting)` 不报。
- **`ssh_diagnose_nginx_access`**：request_time 与 upstream_response_time 按该访问日志在 nginx 配置（`nginx -T`，失败时读配置文件）中的 log_format 定位：计算 `$request_time`、`$upstream_response_time` 所在的引号分段与前后的词数，`rt=$request_time` 这类前后缀也去掉；`$upstream_response_time $request_time` 的顺序、`$msec`、`"$gzip_ratio"` 不再被误读。`$upstream_addr`、`$upstream_status`、`$upstream_*_time` 等上游列表（多个上游记为 `a, b : c`，未经上游为 `-`）按 `,` 与 ` : ` 分隔逐词跳过，相邻的耗时照样按格式定位；`$host`、`$server_name`、`$https`、`$remote_user`、`$uri`、`$document_uri`、`$args`、`$query_string` 与请求头变量可能为空或含空格，不按一个词计数，只从另一侧定位。日志格式未知（没有取得配置、`escape=json`/`none` 的非 JSON 行、配置中没有该文件或该格式名）、某一行的引号数与格式不符，或格式所指的位置不是耗时（例如改格式前写入的行）时，该字段按原来的位置推测并计为推测，不丢弃。给出 `path` 时也读取配置（多一次有界的 `nginx -T`）。新增 `summary.timing.request_time_source` 与 `upstream_time_source`：`log_format`、`field_name`（JSON 键或 `rt=`/`urt=`）、`heuristic`（推测）、`not_in_log_format`（格式已知但没有该变量）四项的请求数（`upstream_time_source` 也计入取得 `-` 的请求）；有推测时 coverage、`slow_requests_over_3s`（request_time）与 `upstream_time_max`（upstream_response_time）的提示会注明。脚本输出多 `REQ_SOURCE`、`UPS_SOURCE` 两行。

输出脱敏覆盖 `-Dxxx.password=` 等点分/驼峰形式的密钥参数、任意协议 URL 中的 `user:pass@`、AKIA/LTAI 开头的云访问密钥和 JWT。v0.9.0起另覆盖：以 pass 为独立词的键（`DB_PASS`、`-Dredis.pass=`、`?pass=`）与任意含 pwd 的键（`loginPwd`、`?pwd=`，`PWD`、`OLDPWD` 除外）；Redis 的 `requirepass`、`masterauth`；命令行中的 `mysql -p密码`、`redis-cli -a 密码`；会话 Cookie（`JSESSIONID`、`PHPSESSID`、`sessionid`、`connect.sid`、`sid`）；`Authorization: Basic/Bearer/Digest` 的凭据；Java 启动参数中值在下一个参数里的 `--password` 一类选项；手机号与 18 位身份证号部分遮盖（`138****8000`、`110101********1234`）。Nginx 与 syslog 的日志证据行另遮盖单独出现的 `Basic`/`Bearer` 凭据。审计 detail 记录已校验参数的摘要（例如 `actions=cpu,memory;minutes=60`），不记录模型原始输入。

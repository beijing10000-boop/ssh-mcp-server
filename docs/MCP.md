# MCP 工具及接入方法

## 接入地址

- 传输：**Streamable HTTP**（MCP 标准协议）
- 地址：`http://可信内网IP:9099/mcp`
- Header：`Authorization: Bearer <Web「系统配置 → MCP 接入」签发的客户端令牌>`
- Web 使用飞书 Cookie 会话，不能用于 MCP；初始化 Token 也不能用于 MCP。

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
| ssh_diagnose_time_sync | 时间与 NTP/chrony 状态 |
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
| ssh_diagnose_jvm（jvm） | `pid`（必填）、`probes`（heap_info、vm_flags、gc_stat、gc_log，缺省前三项） | 对指定 Java 进程执行有界探针：jcmd GC.heap_info、jcmd VM.flags、jstat -gc、GC 日志尾部 40 行。jcmd 会让 JVM 短暂进入安全点，生产高峰期谨慎使用；需以 root（经 runuser 切换到 JVM 所属用户）或与 JVM 相同的用户执行，否则返回能力缺失 | 中 |
| ssh_diagnose_service_detail（service_detail） | `service`（必填，systemd 单元名）、`minutes`=30（1–1440） | 单个 systemd 服务深度诊断：状态、Result、退出码、重启次数与策略、启动时间、MainPID、内存/任务数、ExecStart、运行用户与工作目录、单元文件与 drop-in、cgroup 进程、监听端口、窗口内日志与近 24 小时异常退出/重启记录；单元不存在时返回 `unit_not_found`，不会说成“已停止” | 低 |
| ssh_diagnose_service_map（service_map） | 无 | 监听端口 → 进程（PID、程序名、用户）→ systemd 单元/容器映射（最多 80 行），附 RSS 与运行时长；非 root 账号只能看到自己进程的端口归属 | 低 |
| ssh_collect（collect） | `actions`（1–6 个固定动作，按顺序执行）、`service`（含 service/logs 步骤时必填，否则不能传）、`minutes`=30（1–120，日志类步骤的窗口） | 在一次 SSH 会话内顺序执行多个固定诊断，每个步骤单独返回 exit_code、summary 与 findings，并合并为带 `source_action` 的总 findings；总时长上限 120 秒。可组合动作为 cpu、memory、processes、memory_processes、pressure、resource_limits、disk、io、mount_health、block_devices、network、sockets、tcp_states、system、health、capabilities、failed_services、service_inventory、timers、time_sync、containers、container_stats、security_status、kernel、log_errors、oom、service、logs（不含 directory、peer_*、triage 及扩展动作） | 低 |

共 51 个工具：32 类经典单项诊断（含连接测试）、7 类 v0.6.0 深度诊断、单会话多项采集 `ssh_collect`、组合诊断 `ssh_triage`、6 个资产/目录查询工具和 4 个后台任务工具。`ssh_list_hosts` 支持 query、group_id、offset、limit（最多 1000），返回当前授权范围内的所属主机组名称，只返回当前客户端可访问且已就绪的资产。所有执行操作**仅接受登记的数字 host_id**，单项诊断支持可选的 `expected_revision`：建议 AI 平台始终传入解析时取得的版本，拒绝过期映射。即使模型请求任意 IP 或 shell 命令，服务端也没有对应工具。

`ssh_submit_diagnostics` 不接受扩展参数：扩展动作只能以注册表默认参数批量提交，`jvm`、`service_detail` 这类有必填参数的动作以及 `ssh_collect` 请使用同步工具。Web 控制台与 `POST /api/v1/jobs`、`POST /api/v1/hosts/{id}/diagnose` 通过 `options` 对象传入扩展动作的全部参数（经典动作仍用 service、minutes、directory_root）。

结果包含 `status=success|partial|failed|cancelled`；失败结果另含稳定的 `error_code`（`forbidden` 未授权、`unavailable` 主机不存在/无权访问、`not_linux` 资产不是 Linux（附 `asset_type`）、`not_ready` Linux 已登记但停用、公钥未核验或未绑定凭据、`mapping_unresolved` Zabbix 映射缺失或重复、`busy` 同主机或 SSH 名额排队超时、`timeout`、`revision_changed`、`host_unverified`、`unsupported`、`invalid_argument`、`cancelled`、`failed`），`error` 仍为中文说明。v0.6.0 起执行阶段（SSH 已开始后）的失败也带 `error_code`，可以区分主机繁忙、版本过期与 SSH 故障。已创建的执行任务包含 `job_id`，可供管理员在 Web 查看。工具层面的 MCP `isError` 和结果里的 `status` 都需要检查。缺命令、读取权限不足、非零退出或输出截断不能解释为诊断成功。单项诊断同步返回；批量任务通过 ssh_submit_diagnostics 后台提交，再查询状态。客户端断连不保证立即取消远端任务。

同一主机同一时刻只执行一个诊断。v0.6.0 起同步 MCP 调用等待同主机名额的时间从 2 秒延长到 30 秒，超过才返回 `busy`；后台任务最多等待 180 秒。执行超时时保留已经读到的输出，结果标记 `timed_out=true` 与 `incomplete_reason`（`timeout`、`output_limit`、`exit_code`、`stderr`），状态为 partial；完全没有输出才返回 `timeout` 失败。stderr 只有致命错误（命令不存在、权限拒绝、用法错误等）才使结果变为 partial，df 读取 gvfs/FUSE 挂载之类的已知噪声放在 `warnings` 中，不影响状态。

`ssh_resolve_target` 与 `ssh_resolve_host` 成功时新增 `asset_type`（Linux 主机为 `linux`）和 `mode`（诊断模式：A 模式 `standard`，B 模式强制命令网关 `gateway`；B 模式主机不支持任何 v0.6.0 新动作）。失败时：资产不是 Linux 返回 `not_linux` 并附 `asset_type` 与 `name`，AI 平台可据此改走仅 Zabbix 的分析路径；Linux 主机已登记但停用、公钥未核验或未绑定凭据返回 `not_ready`（`asset_type=linux`）；主机不存在或不在授权范围内仍为 `unavailable`。

## 客户端授权自动扩展与编辑

- **启动时自动扩展**：服务启动时为已启用的客户端补充 v0.6.0 新动作，每个客户端只补一次，并写入审计 `mcp_client_actions_extended`（detail 形如 `v0.6.0:java,nginx,...`）。规则：持有 `logs` 的客户端获得 `nginx`、`nginx_access`、`syslog`、`java`、`service_detail`；持有 `log_errors` 的也获得 `syslog`；持有 `sockets` 或 `service` 的获得 `service_map`。
- **`jvm` 只能手动授权**：它会附加到 JVM 并短暂进入安全点，不随任何已有权限自动扩展。
- **`ssh_collect` 按步骤授权**：只要客户端拥有任一可组合步骤，`ssh_list_tool_catalog` 就会列出 `collect`；调用时逐个检查每个步骤，任一步骤未授权即整体拒绝（`forbidden`），不会部分执行。无需单独勾选 `collect`。
- **编辑权限**：Web「系统配置 → MCP 接入」对有效客户端点「编辑权限」，可调整诊断动作、全部主机与主机组；接口为 `PUT /api/v1/mcp/clients/{id}`，body `{"actions": [...], "all_hosts": true|false, "group_ids": [...]}`（`all_hosts`、`group_ids` 可省略表示不变），与其他写接口一样需要飞书管理员会话与 `X-CSRF-Token`。令牌不变，新范围从下一次 MCP 请求起生效，已在执行的 SSH 不受影响；修改记录审计 `mcp_client_update`。
- **推荐范围**：新建或编辑弹窗中的「按 AI Ops Platform 推荐勾选」会选中 connection、health、capabilities、cpu、memory、disk、network、system、processes、memory_processes、pressure、io、sockets、tcp_states、service、logs、log_errors、oom、kernel、failed_services、service_inventory、syslog、nginx、nginx_access、java、service_detail、service_map，不含 jvm、triage、directory 与 peer_*。

## ssh_collect 使用建议

AI 平台在告警分析前做预采集时，应把同一主机需要的多个固定诊断合并成**一次** `ssh_collect` 调用（例如 `actions=["cpu","processes","pressure"]`，或 `["service","logs","failed_services"]` 加 `service`），不要并发调用多个单项工具：同一主机的诊断是串行的，多个并发调用会排队等待名额，单次调用等待超过 30 秒即返回 `busy`；`ssh_collect` 只建立一次 SSH 会话，不会自我排队。

- 每次最多 6 个步骤，总时长上限 120 秒、单步输出上限 32 KiB；步骤越多耗时越长，按需选择。
- 结果在 `summary.steps` 中逐步给出 status、exit_code、summary、findings；总 `findings` 带 `source_action`，`summary.completed/total` 说明完成情况，未完成步骤会产生 `triage_coverage` 线索。
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

输出脱敏覆盖 `-Dxxx.password=` 等点分/驼峰形式的密钥参数、任意协议 URL 中的 `user:pass@`、AKIA/LTAI 开头的云访问密钥和 JWT。审计 detail 记录已校验参数的摘要（例如 `actions=cpu,memory;minutes=60`），不记录模型原始输入。

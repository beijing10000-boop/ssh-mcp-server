# v0.6.0 · 深度诊断：Nginx、系统日志、Java/JVM、服务详情与单会话采集

本版本新增 8 个只读 MCP 工具，覆盖 Nginx 状态与访问日志、按时间窗口检索系统日志、Java 进程与 JVM 探针、systemd 服务深度诊断、端口与服务映射，以及在一次 SSH 会话内执行多个固定诊断的 `ssh_collect`。所有新动作仍是服务端固定脚本：参数由注册表逐项校验后才生成命令，不接受任意命令、地址或文件路径。

无数据库迁移。原客户端令牌、主机组与资产无需改动；持有日志、端口或服务权限的客户端在服务启动时自动获得对应的新动作（见“授权扩展”）。

## 新增工具与参数

| MCP 工具（动作 id） | 参数 | 说明 | 风险 · 上限 |
| --- | --- | --- | --- |
| `ssh_diagnose_nginx`（nginx） | `minutes`=30（1–1440） | Nginx 二进制、配置、日志路径与轮转文件；进程、监听端口、systemd 状态、upstream/超时配置摘要；窗口内 error.log 级别分布与上游超时、连接失败、无可用上游、worker_connections 不足等线索 | 低 · 30 秒；每个 error.log 只读尾部 20 MB、最多 2 个文件 |
| `ssh_diagnose_nginx_access`（nginx_access） | `minutes`=30、`since`/`until`（Unix 秒）、`path`、`status`（all/4xx/5xx/具体码）、`keyword`、`top`=10（5–30） | 远端 awk 聚合：请求总数、状态码分布、错误请求 TOP URL/IP/UA、每分钟请求与 5xx 趋势、request_time 与 upstream_response_time 统计 | 中 · 40 秒；每个访问日志尾部约 30 MB，跨轮转时另读未压缩轮转文件尾部 10 MB |
| `ssh_diagnose_syslog`（syslog） | `minutes`=30、`since`/`until`、`unit`、`priority`=warning、`keyword`、`pid`、`lines`=120（20–300） | journalctl 优先，无权限、不可用或未覆盖窗口时回退 /var/log 文件并说明来源；按级别/单元计数，OOM、磁盘 I/O、网络链路、服务失败、内核异常、登录失败分类与代表性日志行 | 低 · 30 秒；回退文件只读尾部 20 MB，条目约 16 KB 以内 |
| `ssh_diagnose_java`（java） | 无 | 最多 20 个 Java 进程的 PID、用户、运行时长、RSS、线程与句柄、systemd 单元、JAR/主类、应用名、堆与 GC 参数、日志位置、JDK 版本；只读 /proc，不附加 JVM | 低 · 20 秒；启动命令脱敏，摘要只含 400 字符预览 |
| `ssh_diagnose_jvm`（jvm） | `pid`（必填）、`probes`（heap_info、vm_flags、gc_stat、gc_log；缺省前三项） | jcmd GC.heap_info、jcmd VM.flags、jstat -gc、GC 日志尾部 40 行 | **中** · 30 秒；jcmd 会让 JVM 短暂进入安全点 |
| `ssh_diagnose_service_detail`（service_detail） | `service`（必填）、`minutes`=30（1–1440） | systemd 状态、Result、退出码、重启次数与策略、ExecStart、运行用户、单元文件与 drop-in、cgroup 进程、监听端口、窗口内日志、近 24 小时异常退出/重启记录；不存在的单元返回 `unit_not_found` | 低 · 25 秒；不启动、不重启、不 reset-failed |
| `ssh_diagnose_service_map`（service_map） | 无 | 监听端口 → 进程 → systemd 单元/容器映射，附 RSS 与运行时长 | 低 · 15 秒；最多 80 行 |
| `ssh_collect`（collect） | `actions`（1–6 个固定动作）、`service`、`minutes`=30（1–120） | 同一 SSH 会话内顺序执行所选经典动作，逐步返回 exit_code、summary、findings，并合并带 `source_action` 的 findings | 低 · 总计 120 秒；单步输出 32 KiB |

`since`/`until` 窗口最长 24 小时、最多回溯 30 天，给出时忽略 `minutes`；`keyword` 按字面子串匹配，不能含反斜杠、反引号、`$` 或控制字符；`path` 只接受 Nginx 配置声明的 access_log 或标准日志目录下的文件，符号链接按真实路径再校验。完整说明与 `ssh_collect` 可组合动作清单见 [MCP 接入](MCP.md)。

`GET /api/v1/tools` 与 `ssh_list_tool_catalog` 的每一项新增：`params`（name、type=integer|string|array、required、default、minimum、maximum、choices、pattern、description）、`risk`（low|medium|high）、`extension` 与 `notes`；原有 parameters、service_required、window_required、directory_required、sensitive、standard_only 保持不变。`POST /api/v1/jobs` 与 `POST /api/v1/hosts/{id}/diagnose` 新增 `options` 对象，扩展动作的全部参数放在其中。

## 行为变化

- **同主机排队**：同步 MCP 调用等待同主机名额从 2 秒延长到 30 秒，仍未轮到才返回 `error_code=busy`。AI 平台并发诊断同一主机时不再频繁失败，但单次调用可能多等 30 秒。
- **超时保留证据**：执行超时不再丢弃已读输出，结果标记 `timed_out` 与 `incomplete_reason`（timeout、output_limit、exit_code、stderr），状态为 partial；完全没有输出时才返回 `timeout` 失败。
- **stderr 噪声**：只有致命错误才让结果变为 partial；df 读取 gvfs/FUSE 挂载之类的已知噪声放入 `warnings`，状态保持 success。
- **日志类 summary**：logs、kernel、log_errors、oom 的 summary 带 `entries`（最近 40 行）、`entries_total`、`matched`（OOM、I/O、网络、服务、内核、登录六类）与 `first_at`/`last_at`；诊断账号不在 systemd-journal/adm 组时给出 `journal_access` 警告，提示空结果不可信。
- **service 动作**：读取 LoadState、NRestarts、Restart 等属性；不存在的单元报 `unit_not_found`，不再说成“已停止”；自动重启与失败 Result 给出线索。
- **结构化行**：service_inventory、sockets、health 的 summary 分别带 `units`/`active_counts`、`listening`/`socket_stats`、`top_processes`。
- **错误码**：新增 `busy`、`not_linux`（附 `asset_type`）、`not_ready`（Linux 已登记但停用、公钥未核验或未绑定凭据）；执行阶段的失败也带 `error_code`。`ssh_resolve_target`/`ssh_resolve_host`/`ssh_resolve_hosts` 成功时新增 `asset_type` 与 `mode`（standard 或 gateway，取自资产记录），AI 平台据此跳过 B 模式主机不支持的动作。
- **脱敏**：新增覆盖 `-Dxxx.password=` 等点分/驼峰形式的密钥参数、`db_pwd=` 一类的 *_pwd 键、`--password 值` 这类值在下一个参数里的命令行选项、任意协议 URL 的 `user:pass@`、AKIA/LTAI 云访问密钥与 JWT；`key=value` 规则不再跨行匹配，空值参数不会吞掉下一行。`PWD`、`OLDPWD` 目录变量不脱敏。
- **审计**：诊断审计的 detail 记录已校验参数的摘要（如 `actions=cpu,memory;minutes=60`），不记录原始输入；同步调用失败时也记录同样的摘要（参数校验失败的调用不回写参数）。
- **任务错误字段**：成功任务的良性 stderr（gvfs 等）只放在结果的 `warnings`，不再写入任务的 error 字段，`ssh_get_diagnostic_job` 不会把它当作错误返回。
- **版本号**：统一取自 `sshmcp/__init__.py`，`/healthz` 与应用元数据一致。

## 授权扩展

服务启动时为已启用的客户端一次性补充新动作，并为每个变更的客户端写入审计 `mcp_client_actions_extended`（detail 如 `v0.6.0:java,nginx,nginx_access,service_detail,syslog`）：

| 客户端已有权限 | 自动获得 |
| --- | --- |
| `logs` | nginx、nginx_access、syslog、java、service_detail |
| `log_errors` | syslog |
| `sockets` 或 `service` | service_map |

- `jvm` 不自动扩展，必须由管理员手动勾选。
- `ssh_collect` 按步骤授权：客户端拥有任一可组合步骤即可在目录中看到它，调用时每个步骤都要已授权，否则整体拒绝。
- Web「系统配置 → MCP 接入」新增「编辑权限」：调整动作、全部主机与主机组，令牌不变，从下一次请求起生效（`PUT /api/v1/mcp/clients/{id}`，审计 `mcp_client_update`）。新建与编辑弹窗提供「按 AI Ops Platform 推荐勾选」，不含 jvm、triage、directory、peer_*。

升级后请在「操作审计」中搜索 `mcp_client_actions_extended`，确认各客户端新增的动作符合预期；不需要的动作可用「编辑权限」去掉。

## Web 控制台

- 诊断工作台：扩展动作按 `params` 动态生成输入（整数带范围与默认值，枚举为下拉框，列表为多选，文本附格式说明），提交时放入 `options`；空值不提交，由服务端补默认值。能力卡片显示开销等级、参数名与注意事项。
- 诊断详情：新增“结构化摘要”，展示日志行、分类命中、时间线、嵌套对象与 `ssh_collect` 各步骤（每类最多 50 项并注明省略数）；执行信息增加执行超时、不完整原因、错误代码、开销等级与诊断参数。
- 静态资源地址带版本参数，升级后刷新页面即可加载新脚本。

## 升级

先按 v0.4 发布说明备份完整数据目录与密钥，然后在原部署目录执行：

```bash
cd /data/ssh-mcp-server
git fetch origin
git switch main
git pull --ff-only origin main
docker compose up -d --build --wait --wait-timeout 180
curl -fsS http://127.0.0.1:9099/healthz
```

`/healthz` 应返回 `0.6.0`（`.env` 的 `WEB_BIND_IP` 设成服务器地址时，curl 改用该地址）。

## 兼容性

- **无数据库迁移**：表结构不变。若需回退到 v0.5.0，自动扩展出的动作仍保存在客户端记录中，旧版本不认识这些动作，按未知项忽略。
- **旧客户端不受影响**：新增字段都是附加的，原有字段含义不变；旧令牌继续有效，自动扩展只增加动作。
- **B 模式不支持新动作**：强制命令网关（B 模式）主机执行任何 v0.6.0 新动作都会被拒绝（`unsupported`），批量任务中会跳过这些主机。
- **日志读取权限**：读取完整 journal 需要 root，或诊断账号属于 systemd-journal 或 adm 组；否则只能看到本账号的日志，结果带 `journal_access` 警告。/var/log 回退同样受文件权限限制。
- **JVM 探针**：`jvm` 需以 root 执行（经 runuser 切换到 JVM 所属用户），或诊断账号与 JVM 是同一用户；目标机需有 jcmd/jstat，JVM 未禁用 attach，否则返回能力缺失。
- **批量提交**：`ssh_submit_diagnostics` 不接受 `options`，扩展动作只能以默认参数批量提交；`jvm`、`service_detail` 与 `ssh_collect` 请使用同步工具。
- **调用超时**：同步调用最长可能等待 30 秒排队，再加上动作自身上限（`ssh_collect` 最长 120 秒）。AI 平台调用本 MCP 的超时应不少于“30 秒 + 动作上限 + SSH 连接时间”。

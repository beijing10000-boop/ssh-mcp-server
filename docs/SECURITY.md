# 安全说明与部署验收

1. **默认不对外暴露**：Compose 将端口绑定在 127.0.0.1；如需内网访问，可通过指定 WEB_BIND_IP 和网络 ACL 严格控制。HTTP 不适用于不可信网络；生产须 HTTPS。
2. **独立密钥**：bootstrap.token 仅用于首次初始化；Web 使用飞书 OAuth 会话（HttpOnly Cookie + CSRF），mcp.token 仅用于 MCP。令牌随机产生并保存在 Docker 持久卷；只有拥有卷访问权限的管理员可以查看。不得复制到 GitHub、截图或聊天。
3. **密钥加密**：SSH 私钥、诊断请求与结果采用 Fernet 对称加密存储；数据库、密钥文件权限 0600，目录 0700。数据库与 master.key 不可公开共享，备份须包含两者并限制访问。运行容器使用非 root UID 10001，这不限制目标 SSH 账号使用 root。
4. **两层 SSH 身份**：Web 凭据对应用户公钥 `authorized_keys`；目标服务器自身公钥来自 `/etc/ssh/ssh_host_*.pub`，必须单独核验并固定。批量扫描只能获得候选值。
5. **网络范围**：目前仅允许 RFC1918 IPv4/ULA IPv6 内网 IP；如需跨网段，先配置独立已核验的 SSH 跳板，不允许模型传入任意地址。
6. **只读不是万能**：模式 A 的脚本由应用保证固定命令，但如果 SSH 登陆账号是 root，持有私钥的人仍拥有 root 权限。对于高安全性场景优先使用专用低权限用户或模式 B 的强制命令网关。
7. **模式 B 强制命令**：审核 [gateway/aiops-diagnostic-gateway](../gateway/aiops-diagnostic-gateway) 并部署到目标主机 root 所有的 `/usr/local/sbin/aiops-diagnostic-gateway`，目录不可被普通用户修改。单独生成诊断密钥，authorized_keys 仅允许指定平台出口地址：
   ```text
   restrict,from="平台实际诊断出口IP",command="/usr/local/sbin/aiops-diagnostic-gateway" ssh-ed25519 这里是诊断专用公钥主体
   ```
   配置前备份、部署后用测试账号验证错误的 shell/SCP/转发请求均被拒绝。
8. **MCP 范围**：v0.2 客户端令牌按主机组和诊断动作授权，支持到期与独立撤销；原始令牌只显示一次，数据库保存 SHA256 哈希。范围为组成员关系（未来加入该组的主机也获授权）；“全部主机”同样包含未来新增资产。旧 mcp.token 仍为全权限，迁移完成后停用。当前没有完整组织/租户 RBAC，Web 管理员有全部管理权限。对外部署仍需入口速率限制、HTTPS 与访问控制。
9. **脱敏与日志**：应用遮盖典型关键字段，但模型输出中的诊断数据仍可能含敏感信息；不要采集超出业务授权的日志。审计仅记录主机 ID、动作、时间、状态、错误类型以及（v0.6.0 起）已校验参数的摘要，不记录私钥或模型原始输入。
10. **v0.6.0 新动作的授权、脱敏与读取范围**：
    - **授权扩展**：服务启动时，持有 `logs` 的客户端自动获得 nginx、nginx_access、syslog、java、service_detail（`log_errors` 也扩展出 syslog），持有 `sockets` 或 `service` 的获得 service_map，每个客户端只扩展一次并写入审计 `mcp_client_actions_extended`。这些动作读取的系统日志、Nginx 日志和 Java 启动命令与原有日志权限属于同一敏感级别；不希望某客户端读取它们时，升级后在 Web「编辑权限」中去掉。会附加到 JVM 的 `jvm` 只能手动授权；`ssh_collect` 不是独立权限，每个步骤都按该客户端已有的动作授权检查。编辑权限不更换令牌，记录审计 `mcp_client_update`。
    - **脱敏**：除原有的 password/token/secret 等键值外，新增覆盖 `-Dspring.datasource.password=`、`keyStorePassword=` 等点分或驼峰形式的密钥参数、任意协议 URL 中的 `user:pass@`（jdbc、redis、amqp 等）、AKIA/LTAI 开头的云访问密钥和 JWT。Java 启动命令在摘要中只保留脱敏后的 400 字符预览，完整命令（同样脱敏）仅在 `detail=full` 时返回；服务单元文件中的敏感环境变量值替换为 `[REDACTED]`。脱敏基于规则，不能保证覆盖所有自定义格式。
    - **读取范围限制**：日志类动作只读有界时间窗（经典动作 1–120 分钟；nginx、nginx_access、syslog、service_detail 为 1–1440 分钟，或 `since`/`until` 最长 24 小时、最多回溯 30 天）；文件只读尾部有限字节（error.log 与 syslog 回退文件各 20 MB，访问日志约 30 MB、跨轮转时另读轮转文件 10 MB）；返回行数有上限（经典日志摘要 40 行、syslog `lines` 20–300 且约 16 KB、GC 日志 40 行、Java 进程 20 个、端口映射 80 行），每个动作还有固定的执行时间与输出字节上限。`path`、`unit`、`keyword` 等文本参数先按白名单格式校验再经 shell 转义，`path` 只接受 Nginx 配置声明的或标准日志目录下的文件，`keyword` 按字面匹配。审计 detail 只记录已校验参数的摘要（不超过 240 字符）。
11. **验收要求**：确认 401 鉴权、错误密码、无效私钥、主机公钥变更、未核验主机、停用主机、非法服务名、非内网 IP、SSH 超时、MCP 断连、重启后数据恢复、非管理员无法使用 Web 接口等场景。

## 不应做的事

- 不要将认证令牌填到前端 JS/README 或 GitHub Actions 日志。
- 不要修改代码允许执行任意 Shell 或跳过 SSH 主机公钥核验。
- 不要在未经独立核验的情况下批量自动确认公钥。
- 不要直接删除旧 AI Ops Platform 的 SSH 数据和 Worker。

## 可信指纹来源及批量确认

平台的批量扫描只收集 *candidate* 候选值，**绝不自动写入可信主机公钥**。管理员可从目标机本地可信控制台、经过独立身份验证的 Ansible SSH 会话，或内部可信密钥清单提供 SHA256 指纹。

一份可信指纹清单可以一次性确认最多 1000 台 Linux 主机；后端逐项验证主机资产 ID、SSH 目标的身份快照与 SHA256 指纹，数据库事务保证不匹配时全批回滚。若已登记 IP、端口、跳板或公钥改变，则扫描结果失效，必须重新核验。已有可信公钥与扫描值一致不需要重新人工确认。

Ansible 示例 `scripts/trusted-host-fingerprints.yml` 需要使用 `ANSIBLE_HOST_KEY_CHECKING=True`，且先前的 `known_hosts` 已通过可信渠道核实。不能把首次未经验证的网络握手当成可信基线。

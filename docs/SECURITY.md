# 安全说明与部署验收

1. **默认不对外暴露**：Compose 将端口绑定在 127.0.0.1；如需内网访问，可通过指定 WEB_BIND_IP 和网络 ACL 严格控制。HTTP 不适用于不可信网络；生产须 HTTPS。
2. **独立密钥**：bootstrap.token 仅用于首次初始化；Web 使用飞书 OAuth 会话（HttpOnly Cookie + CSRF），mcp.token 仅用于 MCP。令牌随机产生并保存在 Docker 持久卷；只有拥有卷访问权限的管理员可以查看。不得复制到 GitHub、截图或聊天。
3. **密钥加密**：SSH 私钥采用 Fernet 对称加密存储，数据库与 master.key 不可同一位置公开共享。备份两者并限制目录权限。运行容器使用非 root UID 10001。
4. **两层 SSH 身份**：Web 凭据对应用户公钥 `authorized_keys`；目标服务器自身公钥来自 `/etc/ssh/ssh_host_*.pub`，必须单独核验并固定。批量扫描只能获得候选值。
5. **网络范围**：目前仅允许 RFC1918 IPv4/ULA IPv6 内网 IP；如需跨网段，先配置独立已核验的 SSH 跳板，不允许模型传入任意地址。
6. **只读不是万能**：模式 A 的脚本由应用保证固定命令，但如果 SSH 登陆账号是 root，持有私钥的人仍拥有 root 权限。对于高安全性场景优先使用专用低权限用户或模式 B 的强制命令网关。
7. **模式 B 强制命令**：审核 [gateway/aiops-diagnostic-gateway](../gateway/aiops-diagnostic-gateway) 并部署到目标主机 root 所有的 `/usr/local/sbin/aiops-diagnostic-gateway`，目录不可被普通用户修改。单独生成诊断密钥，authorized_keys 仅允许指定平台出口地址：
   ```text
   restrict,from="平台实际诊断出口IP",command="/usr/local/sbin/aiops-diagnostic-gateway" ssh-ed25519 这里是诊断专用公钥主体
   ```
   配置前备份、部署后用测试账号验证错误的 shell/SCP/转发请求均被拒绝。
8. **MCP 限制**：MCP 令牌拥有已登记主机的诊断权限，应等同于高价值服务凭据。外网部署需要额外细粒度授权、速率限制与审计。当前 v0.1.0 未实现用户级 Host Scope 或组织级 RBAC，不能将全局 MCP 令牌共享给不同权限的团队。
9. **脱敏与日志**：应用遮盖典型关键字段，但模型输出中的诊断数据仍可能含敏感信息；不要采集超出业务授权的日志。审计仅记录主机 ID、动作、时间、状态和错误类型，不记录私钥。
10. **验收要求**：确认 401 鉴权、错误密码、无效私钥、主机公钥变更、未核验主机、停用主机、非法服务名、非内网 IP、SSH 超时、MCP 断连、重启后数据恢复、非管理员无法使用 Web 接口等场景。

## 不应做的事

- 不要将认证令牌填到前端 JS/README 或 GitHub Actions 日志。
- 不要修改代码允许执行任意 Shell 或跳过 SSH 主机公钥核验。
- 不要在未经独立核验的情况下批量自动确认公钥。
- 不要直接删除旧 AI Ops Platform 的 SSH 数据和 Worker。

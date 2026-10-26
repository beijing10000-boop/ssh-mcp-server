# v0.4.1 · Skill 直接查询登记资产

新增只读工具 ssh_resolve_target(address)，只查已登记、启用、公钥核验并绑定凭据的 Linux 资产，仍受 MCP 客户端主机组限制。返回 SSH host_id、name、address、revision、可选 zabbix_hostid 与 device_type。查询不到或未授权返回统一失败，不连接任意 IP、不执行 SSH。内网 IP 校验沿用资产登记规则。

ssh_list_hosts 现在同时返回 address，便于客户端对模糊搜索结果精确核验；ssh_resolve_host 增加 address 和 device_type，并拒绝非 Linux 资产。其他原生参数与行为保持兼容。工具数量由 42 增至 43，无数据库结构修改。

AI Ops Platform v0.9.0 的运维 Skill 可先用 ssh_resolve_target 解析明确 IP，再带 host_id 和 expected_revision 调用现有诊断工具；不需要先到 Zabbix 查询。同 IP 在 Zabbix 重复登记不影响该路径。已有基于 Zabbix Host ID 的工作流仍使用 ssh_resolve_host。

升级前按 v0.4 发布说明备份完整数据目录与密钥，在原部署目录运行：

```bash
cd /data/ssh-mcp-server
git fetch origin
git switch main
git pull --ff-only origin main
docker compose up -d --build --wait --wait-timeout 180
curl -fsS http://127.0.0.1:9099/healthz
```

原凭据、主机组、客户端令牌、动作范围及资产无需重新录入。真实环境仍需验证目标公钥、登录及诊断权限。解析成功不代表全部诊断动作都已获准。

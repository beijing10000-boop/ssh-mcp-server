# SSH MCP Server 工作约定

给 AI 编程助手和贡献者。跨项目约定见 `docs/ENGINEERING.md`（职责边界、MCP 契约、主机身份、降级）与 `docs/UI-GUIDELINES.md`（控制台 UI 与交互）。

## 结构

- `sshmcp/mcp_tools.py`：MCP 工具（`ssh_` 前缀）；`sshmcp/catalog.py`：动作目录、参数说明、风险与推荐授权；`sshmcp/access.py`：客户端令牌与授权。
- `sshmcp/diagnostics.py`：经典诊断动作的远程脚本、执行与结果状态；`sshmcp/observations.py`：解析与 findings；`sshmcp/extensions/`：注册表式扩展动作（nginx、syslog、java/jvm、service、collect）。
- `sshmcp/jobs.py`：诊断任务与并发名额；`sshmcp/store.py`：SQLite、加密与密钥文件；`sshmcp/zabbix.py`：从 Zabbix 同步资产。

## 远程脚本规则

1. **严格只读**：不写文件、不重启、不改配置；参数只能来自注册表校验后的值（`shlex.quote`、整数、枚举），awk 用 `-v` 传值。
2. **兼容 EL7 起的所有目标**：bash 4.2（`$( )` 内不放 `case`）、procps-ng 3.3.10（`ps` 每列一个 `-o`，不要 `-o a=,b=`；进程名等可能含空格的列放最后或改读 `/proc`）、systemd 219（`timedatectl show` 等新子命令不可用时要有回退）、`ss` 单状态过滤时不输出 State 列；GNU 专有选项要有回退或明确标记。
3. **主机缺前提**输出 `CAPABILITY_MISSING:<名称>` 并以 69 退出；不要把“读不到”当成“没有”（例如没找到日志文件不能说没有流量，日志无权限不能报 0 次重启）。
4. **输出有上限**：时间、行数、字节都要限；超时保留已读到的部分并标 `timed_out`/`incomplete_reason`。
5. **脱敏**用 `diagnostics.redact_output`（一份规则）；新的敏感格式加到那里，不在各扩展里另写一套。
6. 符号链接：读取由目标进程参数给出的路径时，文件与目录都不得经过符号链接（`[ -L ]`、`pwd -P` 比对），属主检查用 `stat -L`。

## 接口规则

- MCP 工具名、参数、返回字段只增不改；新增可选参数要保证旧客户端不传时行为不变。改了工具后同步 `docs/MCP.md`，并在 AI Ops Platform 的联合测试 `tests/joint/` 中验证。
- 结果都有 `status`；失败给 `error_code`（见 `docs/ENGINEERING.md`）。
- 推荐给 AI Ops Platform 的授权范围在 `catalog.py` 中定义，覆盖平台托管 Skill 引用的动作；`jvm`、`triage`、`directory`、`peer_*` 需管理员单独决定。

## 提交前

- `python -m ruff format .`、`python -m ruff check --select F401,F811,F821,F841 .`、`python -m pytest -q`（Windows 上需要 `/bin/sh` 的用例会失败，CI 在 Linux 上执行）
- 改了远程脚本：`sh -n`/`dash -n` 语法检查；涉及 `ps` 的改动跑 `tests/test_procps_compat.py`（CI 的 old-procps 任务在 CentOS 7 镜像中执行）
- 改了 `web/*.js`：`node --check`，更新 `web/index.html` 的 `?v=`；共享 ui-kit 只能经 `scripts/sync_ui_kit.py` 修改
- 一个 PR 一类变更；仓库公开，不写真实内网地址与令牌

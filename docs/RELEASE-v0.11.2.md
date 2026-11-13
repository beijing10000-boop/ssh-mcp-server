# v0.11.2 · Java 应用清单带上 Dubbo 版本

> 基线为 v0.11.1（`ee3ff68`）。

不新增 MCP 工具，工具参数不变，无数据库结构变化。`ssh_diagnose_java_apps`（动作 `java_apps`）的 `apps[]` 每一行多出 `dubbo_version` 与 `dubbo_status` 两个字段，其余字段不变（只增不改）。

## 变更

- **每个 Java 应用所带的 Dubbo 版本**。版本只取自文件名：
  - 用 `java -jar` 启动的应用（Spring Boot 的单个大包、WAR）：读应用 JAR 末尾的 ZIP 目录区，取其中 `dubbo-x.y.z.jar` 的名字（`BOOT-INF/lib`、`WEB-INF/lib`、`lib` 都认；按模块引入 Dubbo 时取 `dubbo-common-x.y.z.jar` 等核心模块）。不解压、不读包内任何文件的内容，目标机不需要 `unzip` 或 JDK 工具。
  - 读的是 **JVM 自己打开着的那个文件**（`/proc/<pid>/fd/<n>`），不是启动命令里的路径：发布后磁盘上的 JAR 被删除、或被新版本覆盖而进程还没有重启时，得到的仍是正在运行的那一版。
  - 用主类加类路径启动的应用：看进程打开着的 jar 里有没有 Dubbo 包。
- **`dubbo_status` 区分“没有”和“没能查”**：
  - `found`：取到了版本，见 `dubbo_version`；
  - `present`：有 Dubbo，但文件名里没有版本（不带版本号的 `dubbo.jar`，或 Dubbo 的类被合并进了应用 JAR）；
  - `absent`：应用 JAR 的目录区完整读过，里面没有 Dubbo；
  - `unknown`：没能查，**不代表没有**。出现在：诊断账号不是 root 而进程属于其他用户；应用不是从 JAR 启动、打开的文件里也没有 Dubbo 包（例如会定期关闭 jar 的 Tomcat）；JAR 结尾带归档注释或目录区超过 8 MiB，只搜了末尾 1 MiB 而没有找到；读取超时。
- 同一个应用里出现多个版本的 Dubbo 包（常见于 `com.alibaba` 与 `org.apache` 两个坐标并存）时，该行另有 `dubbo_versions`（按出现顺序，`dubbo_version` 取第一个），并给出 `dubbo_versions_mixed` 提示。

字段说明见 [MCP.md](MCP.md) 的“v0.11.0 新增工具”一节。

## 行为与限制

- 仍然只读：每个 Java 进程多读一次 `/proc/<pid>/fd` 的链接、应用 JAR 结尾的 22 字节和它的目录区（通常几十到几百 KiB，上限 8 MiB）。不附加 JVM、不启动进程、不写文件。
- 输出里只多出名字符合固定格式的 Dubbo 包名（每个进程最多 8 个），不含其他依赖的名字，也不含文件内容。
- 版本来自文件名，不是运行时读到的值：被改过名字的包、嵌套在其他包里的 Dubbo 不识别。
- 额外耗时：在一台跑着 20 个 Java 进程的主机上，整个动作多用约 0.4 秒；仍受原有的 8 秒时间预算与 20 秒超时约束。
- 旧版本服务端采集的结果里没有这两个字段；调用方按“字段不存在即未知”处理即可。

## 升级

1. 备份数据卷中的 `ssh-mcp.sqlite3`、`master.key`、`admin.token`、`mcp.token`。
2. 拉取新代码后 `docker compose up -d --build --wait`，`/healthz` 返回 0.11.2。

已有客户端的授权不变：已经勾选「Java 应用清单」的客户端下一次采集就会带上新字段。控制台脚本没有改动。

## 回滚

检出 v0.11.1（`ee3ff68`）后重建；无数据库变化。回滚后 `apps[]` 里不再有 `dubbo_version` 与 `dubbo_status`。

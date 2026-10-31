"use strict";
// Icons, the theme switch and the narrow-screen drawer come from ui-kit.js.
const icon = UIKit.icon;
function initPresentation() {
  document.documentElement.dataset.density =
    localStorage.getItem("ssh-density") || "comfortable";
  updateDensity();
}
function updateDensity() {
  const button = $("#density-toggle");
  if (button)
    button.setAttribute(
      "aria-pressed",
      document.documentElement.dataset.density === "compact",
    );
}
function breadcrumb() {
  const section = [
    "hosts",
    "zabbix",
    "groups",
    "credentials",
    "proxies",
    "keys",
  ].includes(state.page)
    ? "资产接入"
    : ["diagnostics", "history", "job"].includes(state.page)
      ? "诊断"
      : ["audit", "settings"].includes(state.page)
        ? "治理"
        : "概览";
  $("#breadcrumb-section").textContent = section;
}
const valueText = (v) =>
  typeof v === "object" ? JSON.stringify(v) : String(v ?? "—");
const numberText = (n) =>
  new Intl.NumberFormat("zh-CN", { maximumFractionDigits: 2 }).format(n);
function findingValue(f, threshold = false) {
  const value = threshold ? f.threshold : f.value;
  if (typeof value !== "number") return valueText(value);
  const metric = String(f.metric ?? "");
  if (metric.endsWith("_KiB")) return formatSize(value * 1024);
  const percent =
    metric.endsWith("_percent") ||
    metric.startsWith("disk:") ||
    metric.startsWith("inode:") ||
    metric.startsWith("psi_") ||
    metric.startsWith("io_util:");
  return numberText(value) + (percent ? "%" : "");
}
function metricLabel(key) {
  key = String(key ?? "");
  const names = {
    load_1m: "1 分钟负载",
    cpu_cores: "CPU 核数",
    load_per_core: "每核负载",
    memory_available_percent: "可用内存",
    swap_used_KiB: "Swap 已用",
    MemTotal_KiB: "内存总量",
    MemAvailable_KiB: "可用内存容量",
    SwapTotal_KiB: "Swap 总量",
    SwapFree_KiB: "Swap 可用",
    failed_service_count: "失败服务数",
    oom_matches: "OOM 日志命中",
    NTPSynchronized: "NTP 同步",
    collection_coverage: "采集完整性",
    triage_coverage: "组合采集完整性",
    observed_log_lines: "本次日志行数",
    warning_log_lines: "告警日志行数",
    service_active_state: "服务运行状态",
    container_state: "容器状态",
    file_handles_used_percent: "系统句柄使用率",
    journal_access: "journal 读取权限",
    unit_not_found: "systemd 单元不存在",
    service_restarts: "服务自动重启次数",
    service_result: "上次运行结果",
    log_io_error: "磁盘 / 文件系统 I/O 错误日志",
    log_service: "服务启动失败 / 异常退出日志",
    log_kernel: "内核异常日志",
    listening_ports: "监听端口数",
    load_cpu_divergence: "负载与 CPU 使用背离",
    ssh_identity: "SSH 登录身份",
    readonly_mount: "只读挂载",
    log_source_unavailable: "日志来源不可读",
    reboot_in_window: "窗口内发生重启",
    journal_query_incomplete: "journal 查询未完成",
    no_entries: "窗口内无日志",
    window_not_covered: "日志未覆盖完整窗口",
    priority_approx: "级别按关键字近似",
    nginx_not_found: "未发现 Nginx",
    nginx_binary_mismatch: "Nginx 运行与安装不一致",
    nginx_inactive: "Nginx 未运行",
    nginx_process_not_visible: "Nginx 进程不可见",
    config_test_failed: "Nginx 配置检查失败",
    config_test_unavailable: "Nginx 配置检查不可用",
    error_log_window_not_covered: "error.log 未覆盖完整窗口",
    error_log_read_timeout: "error.log 读取超时",
    refused_path: "拒绝读取的日志路径",
    no_requests: "窗口内无请求",
    log_format_unrecognized: "访问日志格式无法识别",
    status_5xx_count: "5xx 响应数",
    status_499: "客户端主动断开（499）",
    upstream_time_max: "上游最大响应时间",
  };
  if (Object.hasOwn(names, key)) return names[key];
  if (key.startsWith("disk:")) return "磁盘 " + key.slice(5);
  if (key.startsWith("inode:")) return "inode " + key.slice(6);
  if (key.startsWith("psi_"))
    return key
      .replace("psi_cpu", "CPU 压力")
      .replace("psi_memory", "内存压力")
      .replace("psi_io", "I/O 压力")
      .replace("_some_avg10", "（部分任务，10 秒）")
      .replace("_full_avg10", "（全部任务，10 秒）");
  return key;
}
function findingsView(findings = []) {
  const order = { critical: 0, warning: 1, info: 2 };
  const items = [...findings].sort(
    (a, b) => (order[a.level] ?? 3) - (order[b.level] ?? 3),
  );
  if (!items.length)
    return '<p class="empty-state">未触发已实现的规则。请结合采集完整性、历史监控与业务表现判断。</p>';
  const severity = { critical: "严重", warning: "关注", info: "说明" };
  return (
    '<div class="findings-list">' +
    items
      .map((f) => {
        const threshold =
          (typeof f.threshold === "number"
            ? f.metric === "memory_available_percent"
              ? "≤ "
              : "≥ "
            : "") + findingValue(f, true);
        const source = f.source_action
          ? " · 证据：" + esc(actionName(f.source_action))
          : "";
        return (
          `<article class="finding ${Object.hasOwn(order, f.level) ? f.level : "info"}"><div class="finding-title">` +
          `<span class="severity">${esc(severity[f.level] || "说明")}</span><strong>${esc(metricLabel(f.metric))}</strong>` +
          `<span class="finding-value">${esc(findingValue(f))}</span></div>` +
          `<p>${esc(f.hint)}</p><small>规则阈值：${esc(threshold)}${source}</small></article>`
        );
      })
      .join("") +
    "</div>"
  );
}
function metricsView(result) {
  const metrics = result.summary?.metrics || [];
  const visible = metrics
    .filter((m) => m.unit === "%" || m.metric === "load_per_core")
    .slice(0, 30);
  let html = visible.length
    ? '<div class="metric-grid">' +
      visible
        .map((m) => {
          const max = m.metric === "load_per_core" ? Math.max(4, m.value) : 100;
          const level = ["critical", "warning", "info"].includes(m.level)
            ? m.level
            : "info";
          const label = esc(metricLabel(m.metric));
          const threshold =
            m.threshold !== null && m.threshold !== undefined
              ? "规则阈值 " +
                (m.metric === "memory_available_percent" ? "≤ " : "≥ ") +
                esc(m.threshold) +
                (m.unit || "")
              : "当前采样";
          return (
            `<div class="metric-card ${level}"><div><strong>${label}</strong><b>${esc(numberText(m.value))}${m.unit === "%" ? "%" : ""}</b></div>` +
            `<progress value="${Math.max(0, Math.min(max, Number(m.value) || 0))}" max="${max}" aria-label="${label}"></progress>` +
            `<small>${threshold}</small></div>`
          );
        })
        .join("") +
      "</div>"
    : "";
  if (metrics.length)
    html +=
      `<details class="result-details"><summary>全部结构化指标（${metrics.length}）</summary>` +
      table(
        ["指标", "值", "单位"],
        metrics
          .map(
            (m) =>
              `<tr><td>${esc(metricLabel(m.metric))}</td><td>${esc(typeof m.value === "number" ? numberText(m.value) : valueText(m.value))}</td><td>${esc(m.unit || "—")}</td></tr>`,
          )
          .join(""),
      ) +
      "</details>";
  return html;
}
// Generic, bounded rendering of structured summaries (v0.6 log entries,
// matched categories, timelines, nested objects, collection steps). Every
// value is escaped; objects become definition lists, arrays of objects become
// tables, string arrays one line per item, at most STRUCTURED_LIMIT items each.
const STRUCTURED_LIMIT = 50;
const SUMMARY_HIDDEN = [
  "action",
  "title",
  "metrics",
  "assessment",
  "coverage",
  "steps",
  "request",
];
const summaryNames = {
  entries: "代表性日志行",
  entries_total: "窗口内日志行数",
  matched: "分类命中",
  first_at: "最早日志时间",
  last_at: "最晚日志时间",
  journal_access: "journal 读取权限",
  timeline: "时间线",
  completed: "完成步骤",
  total: "步骤总数",
  symptom: "故障场景",
  properties: "服务属性",
  failed_services: "失败服务",
  units: "服务单元",
  active_counts: "按运行状态计数",
  filesystems: "文件系统",
  interfaces: "网络接口",
  listening: "监听端口",
  socket_stats: "套接字统计",
  top_processes: "高 CPU 进程",
  processes: "进程",
  state_counts: "进程状态计数",
  uninterruptible: "D 状态进程",
  cpu_interval: "最近 1 秒 CPU 增量",
  shell_limits: "当前 SSH shell 限制",
  mounts: "挂载",
  readonly_mounts: "只读挂载",
  devices: "块设备",
  containers: "容器",
  capabilities: "诊断命令可用性",
  identity: "登录身份",
  states: "TCP 状态计数",
  firewall_services: "防火墙服务",
  selinux: "SELinux",
  kernel: "内核版本",
  rows: "返回行",
  analysis: "分析数据",
  matched_counts: "分类命中计数",
  window: "时间窗口",
  selection: "筛选条件",
  files: "日志文件",
  log_files: "日志文件",
  totals: "总计",
  codes: "状态码分布",
  top: "TOP 排行",
  bucket_minutes: "趋势粒度（分钟）",
  timing: "耗时统计",
  samples: "样本",
  source: "来源",
  counts: "计数",
  top_units: "单元排行",
  boot: "启动信息",
  binary: "二进制路径",
  version: "版本",
  config: "配置摘要",
  systemd: "systemd 状态",
  errors: "错误日志统计",
  worker_count: "worker 进程数",
  unit: "单元",
  unit_file: "单元文件",
  journal: "单元日志",
  history: "异常退出 / 重启记录",
  listeners: "端口与进程映射",
  by_unit: "按单元归类的端口",
  ports_without_process: "无进程归属的端口",
  java_processes: "Java 进程数",
  heap: "堆",
  flags: "生效参数",
  gc: "GC 统计",
  gc_log: "GC 日志",
};
const matchedNames = {
  oom: "OOM / 内存不足",
  io_error: "磁盘 / 文件系统 I/O 错误",
  network: "网络链路",
  service: "服务启动失败 / 异常退出",
  kernel: "内核异常",
  auth: "登录失败",
};
// Log classifications share observations.LOG_PATTERNS keys wherever they nest.
const childNames = (key) =>
  ["matched", "matched_counts"].includes(key) ? matchedNames : {};
const isRecord = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isScalar = (v) =>
  v === null ||
  v === undefined ||
  ["string", "number", "boolean"].includes(typeof v);
function scalarText(v) {
  if (v === null || v === undefined || v === "") return "—";
  if (typeof v === "boolean") return v ? "是" : "否";
  if (typeof v === "number")
    return Number.isInteger(v)
      ? String(v)
      : String(Math.round(v * 1000) / 1000);
  return typeof v === "string" ? v : JSON.stringify(v) ?? String(v);
}
// Plain text (caller escapes) for table cells and short values.
function compactText(v, depth = 0) {
  if (isScalar(v)) return scalarText(v);
  if (!Object.keys(v).length) return "—";
  if (depth > 2) {
    const text = JSON.stringify(v) ?? "";
    return text.length > 300 ? text.slice(0, 300) + "…" : text;
  }
  const more = (total) =>
    total > STRUCTURED_LIMIT ? `…（另有 ${total - STRUCTURED_LIMIT} 项）` : "";
  if (Array.isArray(v))
    return (
      v
        .slice(0, STRUCTURED_LIMIT)
        .map((x) => compactText(x, depth + 1))
        .join("、") + more(v.length)
    );
  const entries = Object.entries(v);
  return (
    entries
      .slice(0, STRUCTURED_LIMIT)
      .map(([k, x]) => k + "=" + compactText(x, depth + 1))
      .join(" · ") + more(entries.length)
  );
}
// Short token lists (ports, step ids, probe names) stay inline in the grid;
// anything that reads like a log line gets its own block, one per line.
const inlineArray = (v) =>
  Array.isArray(v) &&
  v.length <= 8 &&
  v.every(
    (x) =>
      isScalar(x) && scalarText(x).length <= 40 && !/\s/.test(scalarText(x)),
  );
const looksLikeStep = (v) =>
  isRecord(v) &&
  typeof v.action === "string" &&
  "status" in v &&
  ("summary" in v || "findings" in v);
const countText = (v) =>
  Array.isArray(v)
    ? `（${v.length} 项）`
    : isRecord(v)
      ? `（${Object.keys(v).length} 项）`
      : "";
function omittedNote(total) {
  return total > STRUCTURED_LIMIT
    ? `<p class="help">仅展示前 ${STRUCTURED_LIMIT} 项，省略 ${total - STRUCTURED_LIMIT} 项；完整内容见“完整结构化结果”。</p>`
    : "";
}
const codeBlock = (text) => `<pre class="code-result">${esc(text)}</pre>`;
function structuredView(value, depth = 0, names = {}) {
  if (isScalar(value)) return `<p>${esc(scalarText(value))}</p>`;
  if (depth > 4)
    return codeBlock((JSON.stringify(value, null, 2) ?? "").slice(0, 4000));
  return Array.isArray(value)
    ? structuredList(value, depth)
    : structuredRecord(value, depth, names);
}
function structuredList(items, depth) {
  if (!items.length) return '<p class="muted">（空）</p>';
  const shown = items.slice(0, STRUCTURED_LIMIT);
  let html;
  if (shown.every(isScalar)) html = codeBlock(shown.map(scalarText).join("\n"));
  else if (shown.every((x) => Array.isArray(x) && x.every(isScalar)))
    html = codeBlock(
      shown.map((row) => row.map(scalarText).join("  ")).join("\n"),
    );
  else if (shown.every(looksLikeStep)) html = shown.map(stepView).join("");
  else if (shown.every(isRecord))
    html =
      new Set(shown.flatMap((row) => Object.keys(row))).size > 10
        ? wideRecords(shown, depth)
        : recordTable(shown);
  else
    html =
      '<ul class="reason-list">' +
      shown
        .map((x) => `<li><div>${structuredView(x, depth + 1)}</div></li>`)
        .join("") +
      "</ul>";
  return html + omittedNote(items.length);
}
// Records with many fields (Java processes, unit files) read better one by
// one than as a table with a dozen truncated columns.
function wideRecords(rows, depth) {
  const identity = (row) =>
    ["name", "app", "application", "unit", "service", "pid", "port", "id"]
      .filter((key) => isScalar(row[key]) && row[key] !== null && row[key] !== "")
      .slice(0, 2)
      .map((key) => key + " " + scalarText(row[key]))
      .join(" · ");
  return rows
    .map((row, i) => {
      const title = `第 ${i + 1} 项${identity(row) ? " · " + identity(row) : ""}`;
      return `<details class="result-details"${rows.length <= 3 ? " open" : ""}><summary>${esc(title)}</summary>${structuredRecord(row, depth + 1)}</details>`;
    })
    .join("");
}
function recordTable(rows) {
  const columns = [];
  for (const row of rows)
    for (const key of Object.keys(row))
      if (!columns.includes(key)) columns.push(key);
  const shown = columns.slice(0, 12);
  const cell = (row, key) =>
    `<td>${esc(Object.hasOwn(row, key) ? compactText(row[key]) : "—")}</td>`;
  return (
    table(
      shown.map((key) => esc(key)),
      rows
        .map((row) => `<tr>${shown.map((key) => cell(row, key)).join("")}</tr>`)
        .join(""),
    ) +
    (columns.length > shown.length
      ? `<p class="help">另有 ${columns.length - shown.length} 列未显示：${esc(columns.slice(shown.length).join("、"))}</p>`
      : "")
  );
}
function structuredRecord(record, depth, names = {}) {
  const entries = Object.entries(record).filter(([, v]) => v !== undefined);
  if (!entries.length) return '<p class="muted">（空）</p>';
  const shown = entries.slice(0, STRUCTURED_LIMIT);
  const label = (key) => (Object.hasOwn(names, key) ? names[key] : key);
  // Scalars, short token lists and empty containers share one compact grid.
  const inline = (v) =>
    isScalar(v) || inlineArray(v) || (isRecord(v) && !Object.keys(v).length);
  const flat = shown.filter(([, v]) => inline(v));
  let html = flat.length
    ? '<dl class="execution-meta">' +
      flat
        .map(
          ([key, v]) =>
            `<div><dt>${esc(label(key))}</dt><dd>${esc(compactText(v))}</dd></div>`,
        )
        .join("") +
      "</dl>"
    : "";
  for (const [key, v] of shown) {
    if (inline(v)) continue;
    const title = esc(label(key) + countText(v));
    const body = structuredView(v, depth + 1, childNames(key));
    html +=
      depth === 0
        ? `<details class="result-details" open><summary>${title}</summary>${body}</details>`
        : `<div><p class="help"><strong>${title}</strong></p>${body}</div>`;
  }
  return html + omittedNote(entries.length);
}
// Summary keys not already shown by findings, metrics or the classic tables.
function summaryFields(summary, hidden = []) {
  if (!isRecord(summary)) return "";
  const rest = Object.fromEntries(
    Object.entries(summary).filter(
      ([key, v]) =>
        v !== undefined && !SUMMARY_HIDDEN.includes(key) && !hidden.includes(key),
    ),
  );
  return Object.keys(rest).length
    ? structuredRecord(rest, 0, summaryNames)
    : "";
}
function stepView(step) {
  const facts = [
    step.exit_code !== undefined && step.exit_code !== null
      ? "退出码 " + step.exit_code
      : "退出码未完整返回",
    step.truncated ? "输出截断" : "",
    step.error || "",
  ]
    .filter(Boolean)
    .join(" · ");
  return (
    `<details class="result-details"><summary>${esc(actionName(step.action))} · ${esc(statuses[step.status] || step.status)}</summary>` +
    `<p class="help">${esc(facts)}</p>` +
    metricsView(step) +
    findingsView(step.findings) +
    summaryFields(step.summary) +
    "</details>"
  );
}
const incompleteReasons = {
  timeout: "执行超时",
  output_limit: "输出超过上限被截断",
  exit_code: "命令非零退出",
  stderr: "stderr 含致命错误",
};
function optionsText(options) {
  if (!isRecord(options)) return "";
  return Object.entries(options)
    .filter(([, v]) => v !== null && v !== undefined && v !== "")
    .map(([key, v]) => key + "=" + compactText(v))
    .join(" · ");
}
function diagnosticReport(result, job) {
  const notes =
    `<p class="help">${esc(result.summary?.assessment || "当前采集结果")} · ${esc(result.summary?.coverage || result.evidence || "有界只读快照")}</p>` +
    (Array.isArray(result.warnings) && result.warnings.length
      ? `<p class="help">非致命 stderr 提示（不影响结果完整性）：${esc(result.warnings.join(" / "))}</p>`
      : "");
  const options = optionsText(result.request_options || job.request?.options);
  const meta =
    '<dl class="execution-meta">' +
    [
      [
        "采集耗时",
        result.duration_ms !== undefined ? result.duration_ms + " ms" : "—",
      ],
      ["退出码", result.exit_code ?? "未完整返回"],
      ["来源", sourceName(job.source)],
      ["执行者", job.actor],
      ["输出截断", result.truncated ? "是，结果不完整" : "否"],
      ["采集时间", date(result.captured_at || job.completed_at)],
      ...(result.timed_out !== undefined
        ? [["执行超时", result.timed_out ? "是，已保留超时前的输出" : "否"]]
        : []),
      ...(result.incomplete_reason
        ? [
            [
              "不完整原因",
              Object.hasOwn(incompleteReasons, result.incomplete_reason)
                ? incompleteReasons[result.incomplete_reason]
                : result.incomplete_reason,
            ],
          ]
        : []),
      ...(result.error_code ? [["错误代码", result.error_code]] : []),
      ...(result.risk
        ? [
            [
              "开销等级",
              Object.hasOwn(riskNames, result.risk)
                ? riskNames[result.risk]
                : result.risk,
            ],
          ]
        : []),
      ...(options ? [["诊断参数", options]] : []),
    ]
      .map(([k, v]) => `<div><dt>${k}</dt><dd>${esc(v)}</dd></div>`)
      .join("") +
    "</dl>";
  // Triage keeps its steps at the top level; ssh_collect returns them in summary.
  const steps = (
    Array.isArray(result.steps)
      ? result.steps
      : Array.isArray(result.summary?.steps)
        ? result.summary.steps
        : []
  )
    .map(stepView)
    .join("");
  const extra = summaryFields(result.summary, result.data ? ["analysis"] : []);
  const raw =
    [result.output, result.stderr].filter(Boolean).join("\n") ||
    "没有可用原文，可能未采集完成或已按工具隐私规则裁剪。";
  return (
    `<section class="diagnostic-report"><h3>诊断线索</h3>${findingsView(result.findings)}${notes}${metricsView(result)}` +
    (result.data ? summarizeDiagnostic(result) : "") +
    (extra
      ? `<details class="result-details" open><summary>结构化摘要</summary>${extra}</details>`
      : "") +
    steps +
    meta +
    `<details id="raw-evidence" class="result-details"><summary>原始输出（已脱敏，点击展开）</summary><div class="actions">${btn("copy-raw", "复制原始输出")}${btn("download-result", "下载诊断记录")}</div>` +
    `<pre id="raw-output" class="code-result">${esc(raw)}</pre></details>` +
    `<details class="result-details"><summary>完整结构化结果</summary>${codeBlock(JSON.stringify(result, null, 2))}</details></section>`
  );
}
// Fault scenarios: the template cards here and the triage `symptom` choices.
const faultScenarios = [
  ["cpu_high", "CPU 高", "CPU、进程与 PSI"],
  ["mem_high", "内存高", "内存、RSS、PSI 与 OOM"],
  ["disk_full", "磁盘满", "容量、inode 与挂载"],
  ["io_slow", "I/O 慢", "I/O、PSI 与设备"],
  ["service_down", "服务异常", "服务状态与日志"],
  ["network", "网络异常", "接口、端口与 TCP"],
];
function scenarioTemplates() {
  return (
    '<section class="scenario-section"><div class="section-head"><div><h2>从故障场景开始</h2><p class="muted">先选场景，再确认目标清单。每个场景只运行固定诊断。</p></div></div><div class="scenario-grid">' +
    faultScenarios
      .map(
        ([id, name, description]) =>
          `<button type="button" class="scenario-card" data-action="scenario-template" data-id="${id}">${icon(id === "disk_full" ? "hosts" : "diagnostics")}<strong>${name}</strong><small>${description}</small></button>`,
      )
      .join("") +
    "</div></section>"
  );
}
async function dashboard() {
  const [data, recent] = await Promise.all([
    api("/overview"),
    api("/jobs?page_size=5"),
  ]);
  const f = data.funnel,
    q = data.queue,
    d = data.diagnostics_24h,
    m = data.mcp;
  const empty = !data.hosts
    ? '<section class="welcome"><div><h2>接入第一台 Linux 主机</h2><p>从资产来源开始，绑定凭据、独立核验指纹，再测试 SSH。</p>' +
      `<div class="actions">${btn("open-zabbix", "从 Zabbix 同步", "", "primary")}${btn("open-hosts", "登记主机")}</div></div></section>`
    : "";
  const funnel =
    '<div class="funnel-grid">' +
    [
      ["all", "登记资产", f.registered, "主机与设备总数"],
      ["credential_bound", "绑定凭据", f.credential_bound, "已启用 Linux"],
      ["ready", "核验公钥", f.key_verified, "凭据与已核验公钥齐全"],
      ["verified", "测试通过", f.tested, "当前配置 SSH 测试成功"],
    ]
      .map(
        ([id, label, count, note], i) =>
          `<button type="button" class="funnel-step" data-action="funnel-filter" data-id="${id}"><span class="step-label">${i + 1} / ${label}</span><strong>${count}</strong><small>${note}</small></button>`,
      )
      .join("") +
    `</div><p class="help">SSH 配置完成：${f.key_verified} 台；SSH 验证通过：${f.tested} / ${f.eligible} 台已启用 Linux。配置齐全与连接测试通过分别统计。</p>`;
  const queue =
    `<div class="queue-numbers"><div><strong>${q.active}<small>/4</small></strong><span>SSH 名额占用</span></div>` +
    `<div><strong>${q.pending}<small>/200</small></strong><span>待执行与运行任务</span></div></div>` +
    `<progress aria-label="任务容量" value="${q.pending}" max="200"></progress>` +
    `<p class="help">运行 ${q.running} · 排队 ${q.queued} · 后台最多占用 3 个 SSH 名额</p>`;
  const reasons = d.failure_reasons.length
    ? '<ul class="reason-list">' +
      d.failure_reasons
        .map(
          (r) => `<li><span>${esc(r.reason)}</span><strong>${r.count}</strong></li>`,
        )
        .join("") +
      "</ul>"
    : '<p class="muted">最近 24 小时没有记录失败或部分完成的诊断。</p>';
  const clientAlerts = m.items
    .filter((c) => c.enabled && c.expires_at <= Date.now() / 1000 + 7 * 86400)
    .slice(0, 5);
  const clients =
    `<div class="client-summary"><span>近 24 小时活跃 <b>${m.active_24h}</b></span><span>7 天内到期 <b>${m.expiring_7d}</b></span><span>已过期 <b>${m.expired}</b></span></div>` +
    table(
      ["客户端", "最近接入", "有效期"],
      (clientAlerts.length
        ? clientAlerts
        : m.items.filter((c) => c.enabled).slice(0, 5)
      )
        .map(
          (c) =>
            `<tr><td>${esc(c.name)}</td><td>${date(c.last_used_at)}</td><td>${epochDate(c.expires_at)}</td></tr>`,
        )
        .join(""),
    );
  const findings = data.recent_findings.length
    ? data.recent_findings
        .map(
          (item) =>
            `<div class="recent-finding"><div><strong>${esc(item.host_name)}</strong><small>${esc(actionName(item.action))} · ${date(item.captured_at)}</small></div>` +
            findingsView([item]) +
            btn("job-detail", "查看证据", item.job_id) +
            "</div>",
        )
        .join("")
    : '<p class="empty-state">暂无线索。完成诊断后，这里显示规则结果与证据入口。</p>';
  return (
    '<div id="overview-dashboard">' +
    empty +
    panel("资产接入漏斗", funnel, btn("open-hosts", "管理资产")) +
    '<div class="dashboard-grid">' +
    panel("诊断队列", queue, btn("open-history", "查看任务")) +
    panel(
      "24 小时诊断成功率",
      `<div class="success-rate">${d.success_rate === null ? "—" : d.success_rate + "%"}</div>` +
        `<p class="muted">完整 ${d.counts.success || 0} · 部分 ${d.counts.partial || 0} · 失败 ${d.counts.failed || 0}</p>` +
        `<p class="help">${esc(d.definition)}</p>` +
        reasons,
    ) +
    panel(
      "MCP 客户端（具名）",
      clients +
        '<p class="help">活跃按最近接入时间统计，原始兼容令牌不计入。</p>',
      btn("open-settings/clients", "管理授权"),
    ) +
    panel(
      "最近诊断发现",
      `<p class="help">${esc(data.findings_scope)}</p>` + findings,
    ) +
    "</div>" +
    panel("最近诊断", jobTable(recent.items), btn("open-history", "全部历史")) +
    "</div>"
  );
}
function copyText(text) {
  if (navigator.clipboard) return navigator.clipboard.writeText(text);
  const input = document.createElement("textarea");
  input.className = "clipboard-buffer";
  input.value = text;
  document.body.append(input);
  input.select();
  const ok = document.execCommand("copy");
  input.remove();
  if (!ok) throw Error("复制失败，请展开原文后选择文本复制");
  return Promise.resolve();
}
document.addEventListener("click", async (e) => {
  const b = e.target.closest("[data-action]");
  if (!b || b.disabled) return;
  const a = b.dataset.action,
    id = b.dataset.id;
  if (
    ![
      "density-toggle",
      "funnel-filter",
      "scenario-template",
      "copy-raw",
      "download-result",
    ].includes(a)
  )
    return;
  e.preventDefault();
  e.stopImmediatePropagation();
  try {
    if (a === "density-toggle") {
      const density =
        document.documentElement.dataset.density === "compact"
          ? "comfortable"
          : "compact";
      document.documentElement.dataset.density = density;
      localStorage.setItem("ssh-density", density);
      updateDensity();
    }
    if (a === "funnel-filter") go("hosts?status=" + id);
    if (a === "scenario-template") {
      state.toolCategory = "全部";
      state.diagnosticAction = "triage";
      state.scenario = id;
      await render();
      const form = $("#diagnostic-form");
      form.elements.symptom.value = id;
      updateDiagnosticInputs();
      form.scrollIntoView({ behavior: "smooth", block: "start" });
      $("#target-search").focus({ preventScroll: true });
    }
    if (a === "copy-raw") {
      await copyText($("#raw-output").textContent);
      notice("原始输出已复制");
    }
    if (a === "download-result") {
      const blob = new Blob([JSON.stringify(state.currentJob, null, 2)], {
          type: "application/json",
        }),
        url = URL.createObjectURL(blob),
        link = document.createElement("a");
      link.href = url;
      link.download = "ssh-diagnostic-" + state.currentJob.id + ".json";
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
  } catch (ex) {
    notice(ex.message, true);
  }
});

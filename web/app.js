"use strict";
const $ = (q) => document.querySelector(q);
const esc = (s) =>
  String(s ?? "").replace(
    /[&<>"']/g,
    (x) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        x
      ],
  );
let csrfToken = "";
let currentUser = null;
const state = {
  page: "overview",
  hosts: [],
  groups: [],
  credentials: [],
  proxies: [],
  batchId: null,
  editor: null,
  selected: new Set(),
  hostQuery: "",
  hostGroup: "",
  hostStatus: "all",
  hostPage: 1,
  historyPage: 1,
  historyStatus: "all",
  auditPage: 1,
  auditQuery: "",
  auditStatus: "all",
  manifest: "",
  tools: [],
};
const titles = {
  overview: "运维总览",
  hosts: "主机资产",
  groups: "主机组",
  credentials: "SSH 凭据管理",
  proxies: "SSH 跳板管理",
  keys: "主机公钥核验",
  diagnostics: "诊断工作台",
  history: "诊断历史",
  job: "诊断详情",
  clients: "MCP 接入",
  audit: "操作审计",
  feishu: "飞书管理",
};
let timer = null;
let generation = 0;
let fieldId = 0;
const statuses = {
  success: "已完成",
  partial: "部分完成",
  failed: "失败",
  queued: "排队中",
  running: "执行中",
  cancelled: "已取消",
  untested: "尚未测试",
  interrupted: "已中断",
  finished: "已完成",
};
const date = (s) =>
  s
    ? new Date(
        String(s).includes("T") ? s : String(s).replace(" ", "T") + "Z",
      ).toLocaleString("zh-CN", { timeZone: "Asia/Shanghai", hour12: false })
    : "—";
const badge = (s) =>
  '<span class="status ' + esc(s) + '">' + esc(statuses[s] || s) + "</span>";
const actionName = (action) =>
  state.tools.find((t) => t.id === action)?.name || action;
function go(page) {
  if (location.hash === "#" + page) render();
  else location.hash = page;
}
function pagination(name, data) {
  const pages = Math.max(1, Math.ceil(data.total / data.page_size));
  state[name + "Pages"] = pages;
  return (
    '<div class="pagination"><span class="muted">共 ' +
    data.total +
    " 条 · 第 " +
    data.page +
    " / " +
    pages +
    ' 页</span><div class="actions"><button class="btn small" data-action="page-prev" data-id="' +
    name +
    '" ' +
    (data.page <= 1 ? "disabled" : "") +
    '>上一页</button><button class="btn small" data-action="page-next" data-id="' +
    name +
    '" ' +
    (data.page >= pages ? "disabled" : "") +
    ">下一页</button></div></div>"
  );
}
function hostQuery() {
  return new URLSearchParams({
    q: state.hostQuery,
    status: state.hostStatus,
    ...(state.hostGroup ? { group_id: state.hostGroup } : {}),
  });
}

async function api(path, method = "GET", body) {
  const result = await fetch("/api/v1" + path, {
    method,
    credentials: "same-origin",
    headers: {
      ...(body ? { "Content-Type": "application/json" } : {}),
      ...(method !== "GET" && csrfToken ? { "X-CSRF-Token": csrfToken } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const payload = await result.json().catch(() => ({}));
  if (result.status === 401) {
    csrfToken = "";
    currentUser = null;
    $("#app").hidden = true;
    $("#login").hidden = false;
    throw new Error("身份验证失效，请重新登录");
  }
  if (!result.ok) {
    const info = payload.detail;
    throw new Error(
      typeof info === "string"
        ? info
        : Array.isArray(info)
          ? info.map((e) => e.msg).join("; ")
          : "请求失败（HTTP " + result.status + "）",
    );
  }
  return payload;
}
function notice(text, failure = false) {
  if (failure && $("#editor").open) {
    const e = $("#editor-feedback");
    e.textContent = text;
    e.hidden = false;
    return;
  }
  const box = $("#notice");
  box.hidden = !text;
  box.textContent = text || "";
  box.classList.toggle("error", failure);
}
const btn = (name, text, id = "", kind = "") =>
  '<button class="btn small ' +
  kind +
  '" data-action="' +
  esc(name) +
  '" data-id="' +
  esc(id) +
  '">' +
  esc(text) +
  "</button>";
function panel(title, body, tools = "") {
  return (
    '<section class="panel"><div class="section-head"><h2>' +
    esc(title) +
    '</h2><div class="actions">' +
    tools +
    "</div></div>" +
    body +
    "</section>"
  );
}
function table(head, body) {
  return (
    '<div class="table-wrap"><table><thead><tr>' +
    head.map((x) => "<th>" + x + "</th>").join("") +
    "</tr></thead><tbody>" +
    (body ||
      '<tr><td colspan="' +
        head.length +
        '" class="empty">暂无记录</td></tr>') +
    "</tbody></table></div>"
  );
}
const field = (
  name,
  title,
  value = "",
  type = "text",
  opts = null,
  wide = false,
  help = "",
) => {
  const ident = "field-" + ++fieldId;
  let input = opts
    ? '<select name="' +
      name +
      '">' +
      opts
        .map(
          ([v, t]) =>
            '<option value="' +
            esc(v) +
            '" ' +
            (String(value) === String(v) ? "selected" : "") +
            ">" +
            esc(t) +
            "</option>",
        )
        .join("") +
      "</select>"
    : type === "textarea"
      ? '<textarea name="' +
        name +
        '" autocomplete="off">' +
        esc(value) +
        "</textarea>"
      : type === "checkbox"
        ? '<label class="check"><input type="checkbox" name="' +
          name +
          '" ' +
          (value ? "checked" : "") +
          "/> 启用</label>"
        : '<input type="' +
          type +
          '" name="' +
          name +
          '" value="' +
          esc(value) +
          '" autocomplete="off"/>';
  input = input.replace(/<(input|select|textarea) /, '<$1 id="' + ident + '" ');
  return (
    '<div class="' +
    (wide ? "wide" : "") +
    '"><label for="' +
    ident +
    '">' +
    esc(title) +
    "</label>" +
    input +
    (help ? '<div class="help">' + esc(help) + "</div>" : "") +
    "</div>"
  );
};
function openModal(title, fields, submit) {
  state.editor = submit;
  $("#editor-heading").textContent = title;
  $("#editor-fields").innerHTML = fields;
  $("#editor-feedback").textContent = "";
  $("#editor-feedback").hidden = true;
  $('#editor-form button[type="submit"]').hidden = !submit;
  $("#editor").showModal();
}
function clearEditor() {
  state.editor = null;
  $("#editor-fields").replaceChildren();
  $("#editor-feedback").textContent = "";
}
function closeModal() {
  $("#editor").close();
  clearEditor();
}
function getForm(form, name) {
  return form.elements.namedItem(name)?.value ?? "";
}
function checkbox(form, name) {
  return !!form.elements.namedItem(name)?.checked;
}
function numberOrNull(value) {
  return value ? Number(value) : null;
}
function currentHost(id) {
  return state.hosts.find((h) => String(h.id) === String(id));
}

async function pageOverview() {
  const [o, recent] = await Promise.all([
    api("/overview"),
    api("/jobs?page_size=5"),
  ]);
  const ratio = o.hosts ? Math.round((o.ready / o.hosts) * 100) : 0;
  const cards = [
    ["登记资产", o.hosts, "Linux 主机"],
    ["诊断已就绪", o.ready, "已核验公钥并绑定凭据"],
    ["主机组", o.groups, "资产分组与 MCP 授权"],
    ["24 小时失败操作", o.failed_actions, "查看审计定位原因"],
  ];
  return (
    '<section class="welcome"><div><div class="eyebrow">YOUR INFRASTRUCTURE, IN FOCUS</div><h2>让每次排查，都有据可查。</h2><p>从主机快照到问题线索，在受控范围内完成诊断。</p><div class="actions">' +
    btn("open-diagnostics", "开始诊断", "", "primary") +
    btn("open-hosts", "管理主机") +
    '</div></div><div class="readiness"><span>资产就绪率</span><strong>' +
    ratio +
    '<small>%</small></strong><progress value="' +
    o.ready +
    '" max="' +
    Math.max(1, o.hosts) +
    '" aria-label="资产就绪率"></progress></div></section>' +
    '<div class="stat-grid">' +
    cards
      .map(
        ([name, value, note]) =>
          '<section class="panel stat"><div class="label">' +
          name +
          '</div><div class="number">' +
          value +
          "</div><small>" +
          note +
          "</small></section>",
      )
      .join("") +
    "</div>" +
    '<div class="grid2">' +
    panel(
      "从登记到诊断",
      '<ol class="onboarding"><li><span>01</span><div><strong>准备访问凭据</strong><small>私钥加密保存，支持已登记的 SSH 跳板。</small></div></li><li><span>02</span><div><strong>确认主机身份</strong><small>批量获取公钥，通过可信渠道核对指纹。</small></div></li><li><span>03</span><div><strong>开始受控排查</strong><small>连接测试、诊断任务和历史记录集中管理。</small></div></li></ol>',
    ) +
    panel(
      "独立运行，按需协作",
      '<div class="connection-card"><span class="service-mark">MCP</span><div><strong>AI 平台 → SSH MCP → Linux</strong><p class="muted">只向授权主机执行固定诊断。AI 客户端无需接触 SSH 私钥。</p><code>/mcp · Streamable HTTP</code></div></div><div class="actions">' +
        btn("open-clients", "管理 MCP 接入") +
        btn("open-keys", "查看公钥核验") +
        "</div>",
    ) +
    "</div>" +
    panel("最近诊断", jobTable(recent.items), btn("open-history", "全部历史"))
  );
}

async function pageHosts() {
  const [data, groups, credentials, proxies] = await Promise.all([
    api("/inventory/hosts?" + hostQuery() + "&page=" + state.hostPage),
    api("/groups"),
    api("/credentials"),
    api("/proxies"),
  ]);
  if (state.hostPage > 1 && !data.items.length) {
    state.hostPage--;
    return pageHosts();
  }
  const hosts = data.items;
  state.hosts = hosts;
  state.groups = groups;
  state.credentials = credentials;
  state.proxies = proxies;
  const rows = hosts
    .map(
      (h) =>
        '<tr><td><input class="row-check host-selected" type="checkbox" data-id="' +
        h.id +
        '" aria-label="选中' +
        esc(h.name) +
        '" ' +
        (state.selected.has(h.id) ? "checked" : "") +
        "/></td>" +
        "<td><strong>" +
        esc(h.name) +
        "</strong><small>资产 ID " +
        h.id +
        " · Zabbix Host ID " +
        esc(h.zabbix_hostid || "未关联") +
        "</small></td>" +
        '<td class="mono">' +
        esc(h.address) +
        ":" +
        h.port +
        "<small>" +
        esc(h.username) +
        (h.proxy_id ? " · 跳板 " + h.proxy_id : " · 直连") +
        "</small></td>" +
        "<td>" +
        esc(h.mode === "gateway" ? "B · 受限网关" : "A · 免 Agent") +
        "</td>" +
        "<td>" +
        (!h.enabled
          ? badge("已停用")
          : '<span class="' +
            (h.has_host_key ? "state-ok" : "state-bad") +
            '">' +
            (h.has_host_key ? "公钥已核验" : "待核验公钥") +
            "</span>") +
        "<small>" +
        esc(
          !h.credential_id
            ? "未绑定凭据"
            : statuses[h.last_status] || h.last_status,
        ) +
        "</small></td>" +
        '<td><div class="actions">' +
        btn("edit-host", "编辑", h.id) +
        (h.enabled && h.has_host_key && h.credential_id
          ? btn("test", "测试", h.id) + btn("diagnose-host", "诊断", h.id)
          : "") +
        "</div></td></tr>",
    )
    .join("");
  return panel(
    "Linux 主机资产",
    '<form id="host-search-form" class="toolbar"><input id="host-filter" aria-label="搜索主机" value="' +
      esc(state.hostQuery) +
      '" placeholder="主机名称、IP 或 Zabbix Host ID"/><select id="host-group" aria-label="筛选主机组"><option value="">全部主机组</option>' +
      groups
        .map(
          (g) =>
            '<option value="' +
            g.id +
            '" ' +
            (String(g.id) === state.hostGroup ? "selected" : "") +
            ">" +
            esc(g.name) +
            "</option>",
        )
        .join("") +
      '</select><select id="host-status" aria-label="筛选主机状态">' +
      [
        ["all", "全部状态"],
        ["ready", "可诊断"],
        ["unverified", "待核验公钥"],
        ["failed", "测试失败"],
        ["disabled", "已停用"],
      ]
        .map(
          ([v, t]) =>
            '<option value="' +
            v +
            '" ' +
            (state.hostStatus === v ? "selected" : "") +
            ">" +
            t +
            "</option>",
        )
        .join("") +
      '</select><button class="btn" type="submit">搜索</button></form>' +
      '<div class="selection-bar"><span id="selected-count">已选 ' +
      state.selected.size +
      " 台</span>" +
      btn("select-filtered", "全选筛选结果") +
      btn("clear-selected", "清空") +
      btn("scan-selected", "获取公钥") +
      btn("diagnose-selected", "批量诊断") +
      btn("enable-selected", "启用") +
      btn("disable-selected", "停用", "", "danger") +
      "</div>" +
      table(
        [
          '<input type="checkbox" id="select-page" aria-label="选择本页主机">',
          "主机 / 关联",
          "SSH 路由",
          "权限模式",
          "准备状态",
          "操作",
        ],
        rows,
      ) +
      pagination("host", data),
    btn("import-hosts", "批量导入") +
      btn("new-host", "登记主机", "", "primary"),
  );
}
async function pageGroups() {
  state.groups = await api("/groups");
  return panel(
    "主机组",
    '<p class="intro">主机可以属于多个组。MCP 客户端按组授权，分组调整会影响它能访问的资产。</p>' +
      table(
        ["ID", "主机组名称", "操作"],
        state.groups
          .map(
            (x) =>
              "<tr><td>" +
              x.id +
              "</td><td>" +
              esc(x.name) +
              "</td><td>" +
              btn("edit-group", "编辑", x.id) +
              btn("delete-group", "删除", x.id, "danger") +
              "</td></tr>",
          )
          .join(""),
      ),
    btn("new-group", "新增主机组", "", "primary"),
  );
}
async function pageCredentials() {
  state.credentials = await api("/credentials");
  return panel(
    "加密 SSH 凭据",
    '<p class="intro">只保存加密私钥，不会把已保存的私钥回显到 Web。请为诊断服务单独生成密钥对，勿复用个人管理密钥。</p>' +
      table(
        ["ID", "凭据名称", "创建时间", "操作"],
        state.credentials
          .map(
            (x) =>
              "<tr><td>" +
              x.id +
              "</td><td>" +
              esc(x.name) +
              "</td><td>" +
              esc(x.created_at) +
              "</td><td>" +
              btn("rotate-credential", "轮换", x.id) +
              "</td></tr>",
          )
          .join(""),
      ),
    btn("new-credential", "新增凭据", "", "primary"),
  );
}
async function pageProxies() {
  [state.proxies, state.credentials] = await Promise.all([
    api("/proxies"),
    api("/credentials"),
  ]);
  return panel(
    "SSH 跳板管理",
    '<p class="intro">仅允许登记内网跳板；跳板主机公钥必须事先通过可信渠道核验。</p>' +
      table(
        ["ID", "跳板名称", "SSH 地址", "登录账号", "凭据", "操作"],
        state.proxies
          .map(
            (p) =>
              "<tr><td>" +
              p.id +
              "</td><td>" +
              esc(p.name) +
              "</td><td>" +
              esc(p.address) +
              ":" +
              esc(p.port) +
              "</td><td>" +
              esc(p.username) +
              "</td><td>" +
              esc(
                state.credentials.find((c) => c.id === p.credential_id)?.name ||
                  p.credential_id,
              ) +
              "</td><td>" +
              btn("edit-proxy", "编辑", p.id) +
              "</td></tr>",
          )
          .join(""),
      ),
    btn("new-proxy", "新增跳板", "", "primary"),
  );
}
async function pageKeys() {
  const batches = await api("/host-keys/batches");
  if (!state.batchId && batches.length) state.batchId = batches[0].id;
  let intro =
    '<p class="intro">① 选择目标并批量扫描 SSH 握手公钥 → ② 按服务器实际密钥算法取得可信指纹 → ③ 独立核对后确认保存 → ④ 返回主机资产进行连接测试。扫描本身不会自动信任服务器。</p>';
  let records = "",
    detail = null;
  if (state.batchId) {
    detail = await api(
      "/host-keys/batches/" + encodeURIComponent(state.batchId),
    );
    const batch = detail.batch;
    intro +=
      '<div class="progress-heading">' +
      badge(batch.status) +
      "<strong>" +
      batch.completed +
      " / " +
      batch.total +
      ' 台</strong></div><progress value="' +
      batch.completed +
      '" max="' +
      batch.total +
      '" aria-label="公钥获取进度"></progress>';
    state.keyDetail = detail;
    records = detail.items
      .map((r) => {
        const statusName =
          {
            candidate: "待人工确认",
            changed: "主机公钥发生变化",
            unchanged: "与已有可信公钥一致",
            confirmed: "已核验保存",
            failed: "获取失败",
            stale: "主机配置已变化",
            interrupted: "任务中断",
          }[r.status] || r.status;
        const changed =
          r.previous_fingerprint &&
          r.fingerprint &&
          r.previous_fingerprint !== r.fingerprint;
        const command =
          r.algorithm === "ssh-rsa"
            ? "ssh-keygen -lf /etc/ssh/ssh_host_rsa_key.pub -E sha256"
            : r.algorithm === "ecdsa-sha2-nistp256"
              ? "ssh-keygen -lf /etc/ssh/ssh_host_ecdsa_key.pub -E sha256"
              : "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256";
        return (
          "<tr><td><strong>" +
          esc(r.name || "") +
          "</strong><small>资产 " +
          r.host_id +
          " · " +
          esc(r.address || "") +
          "</small></td>" +
          '<td class="mono">' +
          esc(r.fingerprint || "—") +
          "<small>算法 " +
          esc(r.algorithm || "—") +
          "</small></td>" +
          '<td><span class="' +
          (changed ? "state-bad" : "") +
          '">' +
          esc(statusName) +
          "</span>" +
          (r.previous_fingerprint
            ? "<small>原可信指纹：" + esc(r.previous_fingerprint) + "</small>"
            : "") +
          "</td>" +
          "<td>" +
          esc(r.error || "—") +
          (r.fingerprint
            ? "<small>在目标可信控制台执行：<code>" +
              esc(command) +
              "</code></small>"
            : "") +
          "</td>" +
          "<td>" +
          (r.status === "candidate" || r.status === "changed"
            ? btn("confirm-key", "核验并保存", r.host_id)
            : "—") +
          "</td></tr>"
        );
      })
      .join("");
  }
  const batchlist = batches
    .map(
      (x) =>
        '<option value="' +
        esc(x.id) +
        '" ' +
        (state.batchId === x.id ? "selected" : "") +
        ">" +
        esc(x.created_at) +
        " · " +
        esc(x.status) +
        " · " +
        x.completed +
        "/" +
        x.total +
        "</option>",
    )
    .join("");
  const scanButtons =
    btn("scan-all-unverified", "扫描所有未核验主机", "", "primary") +
    (detail &&
    ["finished", "interrupted"].includes(detail.batch.status) &&
    detail.items.some((r) =>
      ["failed", "stale", "interrupted"].includes(r.status),
    )
      ? btn("retry-failed", "仅重试本批失败主机")
      : "");
  const results = panel(
    "批量扫描与进度",
    intro +
      '<div class="toolbar"><select id="batch-select">' +
      (batchlist || "<option>没有扫描记录</option>") +
      "</select>" +
      btn("refresh", "刷新") +
      "</div>" +
      table(
        ["主机", "候选 SHA256 指纹", "核验状态", "详情与核验命令", "操作"],
        records,
      ),
    scanButtons,
  );
  const matching = detail
    ? detail.items.filter(
        (r) => r.status === "candidate" || r.status === "changed",
      )
    : [];
  const trust = panel(
    "批量导入可信指纹",
    '<p class="muted">批量核验无需逐台点击弹窗。请先通过服务器控制台、Ansible 可信通道或已有可信资产台账取得真实 SHA256 指纹，再按「主机 ID/IP + [可选算法] + SHA256 指纹」逐行粘贴；支持从已开启 SSH 主机身份校验的 Ansible 清单导入。<strong>不能直接复制本页面扫描到的指纹作为可信来源。</strong> 任意一台不匹配，整批不保存。</p>' +
      '<p class="muted">当前批次待确认：' +
      matching.length +
      " 台</p>" +
      '<textarea id="trusted-fingerprints" aria-label="独立可信指纹清单" rows="7" placeholder="1 SHA256:独立可信渠道获取的指纹&#10;172.20.200.93 ssh-ed25519 SHA256:独立可信渠道获取的指纹">' +
      esc(state.manifest) +
      "</textarea>" +
      '<div class="modal-actions">' +
      btn("confirm-batch-from-manifest", "核对并保存可信指纹", "", "primary") +
      "</div>",
  );
  return results + trust;
}
async function pageDiagnostics() {
  const [hosts, tools] = await Promise.all([api("/hosts"), api("/tools")]);
  state.tools = tools;
  const ready = hosts.filter(
    (h) => h.enabled && h.has_host_key && h.credential_id,
  );
  state.diagnosticHosts = ready;
  const options = ready.map((h) => [h.id, h.name + " · " + h.address]);
  return (
    '<div class="page-intro"><p>选择目标与诊断方式。任务在后台执行，离开页面后仍可在历史中查看。</p>' +
    btn("open-history", "查看诊断历史") +
    "</div>" +
    panel(
      "创建诊断任务",
      '<form id="diagnostic-form"><div class="fields">' +
        field(
          "host_id",
          "目标主机",
          state.preselectedId || options[0]?.[0] || "",
          "text",
          options,
        ) +
        field(
          "action",
          "诊断类型",
          "health",
          "text",
          tools.map((t) => [t.id, t.name]),
        ) +
        (state.selected.size
          ? '<div class="wide"><label class="check"><input type="checkbox" name="use_selected" ' +
            (state.useSelection ? "checked" : "") +
            "> 使用资产页选中的 " +
            state.selected.size +
            " 台主机（每批最多 100 台）</label></div>"
          : "") +
        field("service", "systemd 服务名称", "nginx.service") +
        field("minutes", "时间范围（分钟）", 30, "number") +
        field(
          "directory_root",
          "扫描目录",
          "/data",
          "text",
          null,
          true,
          "每次最多扫描 8 秒。仅统计单层目录，可继续深入；不会修改或清理文件。",
        ) +
        '</div><div class="notice diagnostic-help">快照反映采集时刻的状态。日志、目录与流量数据需有相应读取权限；缺失能力会显示为部分完成。</div>' +
        (!options.length && !state.selected.size
          ? '<p class="inline-error">暂无可诊断主机，请先绑定凭据并核验公钥。</p>'
          : "") +
        '<div class="modal-actions"><span class="muted">固定动作 · 无任意命令输入</span><button class="btn primary" type="submit" ' +
        (!options.length && !state.selected.size ? "disabled" : "") +
        ">提交诊断</button></div></form>",
    ) +
    '<div class="capability-grid">' +
    tools
      .map(
        (t) =>
          '<div class="capability"><span class="capability-icon">' +
          (t.sensitive ? "◇" : "⌘") +
          "</span><div><strong>" +
          esc(t.name) +
          "</strong><small>" +
          (t.sensitive ? "按授权范围采集，注意数据边界" : "固定只读采集") +
          "</small></div></div>",
      )
      .join("") +
    "</div>"
  );
}
function jobTable(items) {
  return table(
    ["主机 / 任务", "诊断类型", "来源", "状态", "提交时间", "操作"],
    items
      .map(
        (j) =>
          "<tr><td><strong>" +
          esc(j.host_name) +
          '</strong><small class="mono">' +
          esc(j.id.slice(0, 10)) +
          "</small></td><td>" +
          esc(actionName(j.action)) +
          "</td><td>" +
          esc(j.source === "mcp" ? "MCP 客户端" : "Web 控制台") +
          "</td><td>" +
          badge(j.status) +
          '</td><td class="date">' +
          date(j.created_at) +
          "</td><td>" +
          btn("job-detail", "查看", j.id) +
          "</td></tr>",
      )
      .join(""),
  );
}
async function pageHistory() {
  const query = new URLSearchParams({
    page: state.historyPage,
    status: state.historyStatus,
    ...(state.batchFilter ? { batch_id: state.batchFilter } : {}),
  });
  const data = await api("/jobs?" + query);
  if (state.historyPage > 1 && !data.items.length) {
    state.historyPage--;
    return pageHistory();
  }
  state.pollHistory = data.items.some((j) =>
    ["queued", "running"].includes(j.status),
  );
  return panel(
    state.batchFilter ? "本批诊断任务" : "诊断历史",
    '<div class="toolbar"><select id="history-status" aria-label="筛选任务状态">' +
      ["all", "queued", "running", "success", "partial", "failed", "cancelled"]
        .map(
          (x) =>
            '<option value="' +
            x +
            '" ' +
            (state.historyStatus === x ? "selected" : "") +
            ">" +
            esc(x === "all" ? "全部状态" : statuses[x]) +
            "</option>",
        )
        .join("") +
      "</select>" +
      (state.batchFilter ? btn("all-history", "显示全部历史") : "") +
      '<span class="muted">结果加密保存 · 重启中断可追溯</span></div>' +
      jobTable(data.items) +
      pagination("history", data),
    btn("open-diagnostics", "新建诊断", "", "primary"),
  );
}
async function pageJob() {
  const job = await api("/jobs/" + encodeURIComponent(state.jobId));
  state.currentJob = job;
  const active = ["queued", "running"].includes(job.status);
  const actions =
    btn("open-history", "返回历史") +
    (active
      ? btn("cancel-job", "取消任务", job.id, "danger")
      : btn("retry-job", "重新诊断", job.id));
  const meta =
    '<div class="job-meta"><div><small>目标主机</small><strong>' +
    esc(job.host_name) +
    "</strong></div><div><small>诊断动作</small><strong>" +
    esc(actionName(job.action)) +
    "</strong></div><div><small>提交时间</small><strong>" +
    date(job.created_at) +
    "</strong></div><div><small>状态</small>" +
    badge(job.status) +
    "</div></div>";
  const result = job.result;
  return (
    '<div class="page-intro"><span class="muted mono">任务 ' +
    esc(job.id) +
    '</span><div class="actions">' +
    actions +
    "</div></div>" +
    panel("诊断记录", meta) +
    panel(
      "采集结果",
      active
        ? '<div class="pending-result"><span class="spinner"></span><strong>' +
            (job.status === "queued" ? "等待执行" : "正在采集") +
            "</strong><p>可以离开此页面，结果将在诊断历史中保留。</p></div>"
        : (job.error
            ? '<p class="inline-error">' + esc(job.error) + "</p>"
            : "") +
            (result
              ? (result.note
                  ? '<p class="notice">' + esc(result.note) + "</p>"
                  : "") +
                summarizeDiagnostic(result) +
                '<details class="result-details"><summary>查看结构化结果</summary><pre class="code-result">' +
                esc(JSON.stringify(result, null, 2)) +
                "</pre></details>"
              : '<p class="muted">没有完成采集，尚无结果。</p>'),
    )
  );
}
async function pageClients() {
  const [data, groups, tools] = await Promise.all([
    api("/mcp/clients"),
    api("/groups"),
    api("/tools"),
  ]);
  state.clients = data.items;
  state.groups = groups;
  state.tools = tools;
  state.legacyEnabled = data.legacy_enabled;
  const rows = data.items
    .map(
      (c) =>
        "<tr><td><strong>" +
        esc(c.name) +
        '</strong><small class="mono">' +
        esc(c.prefix) +
        "…</small></td><td>" +
        esc(
          c.all_hosts
            ? "全部已登记主机"
            : c.group_ids
                .map(
                  (id) => groups.find((g) => g.id === id)?.name || "已删除分组",
                )
                .join("、"),
        ) +
        "<small>" +
        c.actions.length +
        " 项诊断权限</small></td><td>" +
        date(new Date(c.expires_at * 1000).toISOString()) +
        "<small>最近使用 " +
        date(c.last_used_at) +
        "</small></td><td>" +
        badge(!c.enabled ? "已撤销" : c.expired ? "已过期" : "有效") +
        "</td><td>" +
        (c.enabled ? btn("revoke-client", "撤销", c.id, "danger") : "—") +
        "</td></tr>",
    )
    .join("");
  return (
    '<div class="page-intro"><p>为每个 AI 平台或集成系统签发独立令牌，限定主机组、工具与有效期。</p></div>' +
    panel(
      "MCP 客户端",
      table(["客户端", "授权范围", "有效期 / 最近使用", "状态", "操作"], rows),
      btn("new-client", "新增客户端", "", "primary"),
    ) +
    '<div class="grid2">' +
    panel(
      "接入配置",
      '<p class="muted">协议为 Streamable HTTP。令牌放在 AI 平台的服务器端加密配置中。</p><pre class="code-result">' +
        esc(
          JSON.stringify(
            {
              url: location.origin + "/mcp",
              headers: { Authorization: "Bearer <客户端令牌>" },
            },
            null,
            2,
          ),
        ) +
        '</pre><p class="help">Zabbix Host ID 通过 ssh_resolve_host 精确映射，不按 IP 或主机名猜测。</p>',
    ) +
    panel(
      "原始兼容令牌",
      "<p>当前状态：" +
        badge(data.legacy_enabled ? "已启用" : "已停用") +
        '</p><p class="muted">原始 mcp.token 拥有全部主机权限。迁移到独立客户端后可在此停用；不会影响飞书登录。</p>' +
        btn(
          "toggle-legacy",
          data.legacy_enabled ? "停用原始令牌" : "启用原始令牌",
          "",
          "danger",
        ),
    ) +
    "</div>"
  );
}

function formatSize(n) {
  if (!Number.isFinite(Number(n))) return "—";
  let v = Number(n),
    unit = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  while (v >= 1024 && i < unit.length - 1) {
    v /= 1024;
    i++;
  }
  return (v >= 10 || i === 0 ? v.toFixed(0) : v.toFixed(1)) + " " + unit[i];
}
function summarizeDiagnostic(result) {
  const d = result?.data;
  if (!d)
    return (
      '<pre class="code-result">' +
      esc(result?.output || result?.stderr || "没有输出") +
      "</pre>"
    );
  const label = result.status === "success" ? "完成" : "部分结果或采集能力不足";
  let title =
    '<p class="muted">' +
    esc(label) +
    " · " +
    esc(d.metric || d.ranking_scope || "目录占用") +
    " · " +
    esc(result.duration_ms) +
    " ms</p>";
  let rows = [],
    header = [];
  if (result.action === "directory") {
    title +=
      '<p class="muted">扫描根目录：<strong>' +
      esc(d.root) +
      "</strong>；根目录占用：" +
      formatSize(d.scanned_root_bytes) +
      "</p>";
    header = ["排名", "目录", "已占用空间"];
    rows = d.top_directories.map(
      (v, i) =>
        "<tr><td>" +
        (i + 1) +
        '</td><td class="mono">' +
        esc(v.directory) +
        "</td><td>" +
        formatSize(v.bytes) +
        "</td></tr>",
    );
  } else if (result.action === "peer_connections") {
    header = ["排名", "远端 IP", "TCP 连接总数", "其中已建立"];
    rows = d.ranking.map(
      (v, i) =>
        "<tr><td>" +
        (i + 1) +
        '</td><td class="mono">' +
        esc(v.peer_ip) +
        "</td><td><strong>" +
        esc(v.tcp_connections) +
        "</strong></td><td>" +
        esc(v.established_connections) +
        "</td></tr>",
    );
  } else if (result.action === "peer_traffic") {
    title +=
      '<p class="muted">' +
      esc(d.sample_seconds) +
      " 秒 TCP 采样 · 两次都存在的 socket：" +
      esc(d.matched_sockets) +
      "（采样 A " +
      esc(d.sample_a_sockets) +
      " / B " +
      esc(d.sample_b_sockets) +
      "）</p>";
    header = ["排名", "远端 IP", "发送增量", "接收增量", "总计", "平均每秒"];
    rows = d.ranking.map(
      (v, i) =>
        "<tr><td>" +
        (i + 1) +
        '</td><td class="mono">' +
        esc(v.peer_ip) +
        "</td><td>" +
        formatSize(v.sent_bytes) +
        "</td><td>" +
        formatSize(v.received_bytes) +
        "</td><td><strong>" +
        formatSize(v.total_bytes) +
        "</strong></td><td>" +
        formatSize(v.avg_bytes_per_second) +
        "/s</td></tr>",
    );
  }
  const caveats = (d.notes || [])
    .map((v) => '<p class="help">· ' + esc(v) + "</p>")
    .join("");
  return (
    title +
    table(header, rows.join("")) +
    (rows.length
      ? ""
      : '<p class="inline-error">本次未获得可用于排行的数据。请查看下方详细结果与能力说明。</p>') +
    caveats
  );
}
function updateDiagnosticInputs() {
  const form = $("#diagnostic-form");
  if (!form) return;
  const action = getForm(form, "action");
  for (const [name, visible] of [
    ["service", ["logs", "service"].includes(action)],
    ["minutes", ["logs", "kernel"].includes(action)],
    ["directory_root", action === "directory"],
  ]) {
    const item = form.elements.namedItem(name);
    if (item) item.closest("div").hidden = !visible;
  }
}
async function pageAudit() {
  const query = new URLSearchParams({
    q: state.auditQuery,
    outcome: state.auditStatus,
    page: state.auditPage,
  });
  const data = await api("/audit/page?" + query);
  return panel(
    "操作审计",
    '<form id="audit-search-form" class="toolbar"><input id="audit-search" aria-label="搜索审计记录" value="' +
      esc(state.auditQuery) +
      '" placeholder="动作、操作者或主机 ID"><select id="audit-status" aria-label="筛选审计结果">' +
      ["all", "success", "partial", "failed", "denied", "cancelled"]
        .map(
          (s) =>
            '<option value="' +
            s +
            '" ' +
            (state.auditStatus === s ? "selected" : "") +
            ">" +
            esc(s === "all" ? "全部结果" : statuses[s] || s) +
            "</option>",
        )
        .join("") +
      '</select><button class="btn" type="submit">搜索</button></form>' +
      table(
        ["时间", "操作者", "动作", "目标", "结果", "说明"],
        data.items
          .map(
            (r) =>
              '<tr><td class="date">' +
              date(r.created_at) +
              '</td><td class="mono">' +
              esc(r.actor) +
              "</td><td>" +
              esc(actionName(r.action)) +
              "</td><td>" +
              esc(r.target) +
              "</td><td>" +
              badge(r.outcome) +
              '</td><td class="mono">' +
              esc(r.detail) +
              "</td></tr>",
          )
          .join(""),
      ) +
      pagination("audit", data),
  );
}

async function pageFeishu() {
  const r = await api("/settings/feishu");
  return panel(
    "飞书登录与授权管理",
    '<p class="intro">SSH MCP 控制台仅允许指定的飞书 Open ID 登录。首次初始化 Token 不再具备日常登录权限。</p>' +
      '<div class="fields">' +
      '<div><label>飞书应用 App ID</label><div class="code-result">' +
      esc(r.lark_app_id) +
      "</div></div>" +
      '<div><label>Web 外部访问地址</label><div class="code-result">' +
      esc(r.web_protocol + "://" + r.web_public_host) +
      "</div></div>" +
      '<div class="wide"><label>飞书回调地址</label><div class="code-result">' +
      esc(
        r.web_protocol + "://" + r.web_public_host + "/api/v1/auth/callback",
      ) +
      "</div></div>" +
      '<div class="wide"><label>App Secret</label><div class="pill">' +
      (r.lark_app_secret_configured ? "已加密配置（不回显）" : "未配置") +
      "</div></div>" +
      '</div><hr class="rule"/>' +
      '<form id="feishu-admins-form"><div class="fields">' +
      field(
        "open_ids",
        "指定管理员 Open ID（英文逗号分隔）",
        r.feishu_admin_open_ids,
        "textarea",
        null,
        true,
        "必须保留当前登录管理员；更改名单后，已移除的账号会立即失去访问权限。",
      ) +
      '</div><div class="modal-actions"><button type="submit" class="btn primary">保存管理员名单</button></div></form>',
  );
}
async function render() {
  clearTimeout(timer);
  const version = ++generation;
  const [page, id] = location.hash.slice(1).split("/");
  state.page = page || "overview";
  if (state.page === "job") state.jobId = id || "";
  if (state.page === "history") state.batchFilter = id || "";
  if (state.page === "keys" && id && state.batchId !== id) {
    state.batchId = id;
    state.manifest = "";
  }
  $("#page-title").textContent = titles[state.page] || "运维总览";
  for (const el of document.querySelectorAll(".nav-link"))
    el.classList.toggle(
      "active",
      el.dataset.page === state.page ||
        (state.page === "job" && el.dataset.page === "history"),
    );
  $("#content").innerHTML =
    '<div class="loading-panel" role="status"><span class="spinner"></span>正在加载…</div>';
  try {
    const pages = {
      overview: pageOverview,
      hosts: pageHosts,
      groups: pageGroups,
      credentials: pageCredentials,
      proxies: pageProxies,
      keys: pageKeys,
      diagnostics: pageDiagnostics,
      history: pageHistory,
      job: pageJob,
      clients: pageClients,
      audit: pageAudit,
      feishu: pageFeishu,
    };
    const html = await (pages[state.page] || pageOverview)();
    if (version !== generation) return;
    $("#content").innerHTML = html;
    if (state.page === "diagnostics") updateDiagnosticInputs();
    updateSelection();
    const pending =
      (state.page === "job" &&
        ["queued", "running"].includes(state.currentJob?.status)) ||
      (state.page === "history" && state.pollHistory) ||
      (state.page === "keys" && state.keyDetail?.batch.status === "running");
    if (pending) timer = setTimeout(render, 3000);
  } catch (e) {
    if (version === generation)
      $("#content").innerHTML =
        '<div class="inline-error" role="alert">' + esc(e.message) + "</div>";
  }
}
function updateSelection() {
  const count = $("#selected-count");
  if (count)
    count.textContent = "已选 " + state.selected.size + " 台（跨页保留）";
  const boxes = [...document.querySelectorAll(".host-selected")];
  boxes.forEach((b) => (b.checked = state.selected.has(Number(b.dataset.id))));
  const page = $("#select-page");
  if (page) {
    const count = boxes.filter((b) => b.checked).length;
    page.checked = !!boxes.length && count === boxes.length;
    page.indeterminate = count > 0 && count < boxes.length;
    page.disabled = !boxes.length;
  }
}

async function login() {
  try {
    currentUser = await api("/auth/me");
    csrfToken = currentUser.csrf || "";
    state.tools = await api("/tools");
    $("#whoami").textContent = currentUser.name + " · 飞书管理员";
    $("#login").hidden = true;
    $("#app").hidden = false;
    await render();
  } catch (e) {
    $("#app").hidden = true;
    $("#login").hidden = false;
    $("#login-error").hidden = false;
    $("#login-error").textContent = e.message;
    try {
      const r = await fetch("/api/v1/setup/status");
      if (r.ok && (await r.json()).setup_required)
        $("#login-error").textContent =
          "首次部署，请先完成飞书绑定与管理员初始化。";
    } catch {}
  }
}
$("#logout").addEventListener("click", async () => {
  try {
    await api("/auth/logout", "POST");
    location.reload();
  } catch (e) {
    notice(e.message, true);
  }
});
$("#reload").addEventListener("click", render);
$("#nav").addEventListener("click", (e) => {
  const b = e.target.closest("[data-page]");
  if (b) {
    notice("");
    go(b.dataset.page);
  }
});
$("#editor-close").addEventListener("click", closeModal);
$("#editor-cancel").addEventListener("click", closeModal);
$("#editor").addEventListener("cancel", () => clearEditor());
$("#editor-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!state.editor) return;
  const save = $("#editor-form").querySelector("button[type=submit]");
  save.disabled = true;
  const error = $("#editor-feedback");
  error.hidden = true;
  error.textContent = "";
  try {
    const result = await state.editor(e.target);
    closeModal();
    notice("保存成功");
    await render();
    if (result?.token) {
      openModal(
        "保存客户端令牌",
        '<div class="wide"><p class="notice">仅显示这一次。关闭后不能再次读取，可撤销后重新签发。</p>' +
          field(
            "new_token",
            "MCP 接入令牌",
            result.token,
            "textarea",
            null,
            true,
          ) +
          "</div>" +
          btn("copy-token", "复制令牌"),
        null,
      );
      $("#editor-fields textarea").readOnly = true;
    }
  } catch (ex) {
    error.textContent = ex.message;
    error.hidden = false;
    error.scrollIntoView({ block: "nearest" });
  } finally {
    save.disabled = false;
  }
});
function hostFields(h = {}) {
  const selected = h.group_ids || [];
  const gs = state.groups
    .map(
      (g) =>
        '<label class="check"><input type="checkbox" class="group-check" value="' +
        g.id +
        '" ' +
        (selected.includes(g.id) ? "checked" : "") +
        "/> " +
        esc(g.name) +
        "</label>",
    )
    .join("");
  return (
    field("name", "资产名称", h.name || "") +
    field("address", "内网 IP 地址", h.address || "") +
    field("port", "SSH 端口", h.port || 22, "number") +
    field("username", "SSH 用户名", h.username || "root") +
    field("zabbix_hostid", "Zabbix Host ID（可选）", h.zabbix_hostid || "") +
    field("credential_id", "SSH 凭据", h.credential_id || "", "text", [
      ["", "未绑定"],
      ...state.credentials.map((c) => [c.id, c.name]),
    ]) +
    field("proxy_id", "跳板（可选）", h.proxy_id || "", "text", [
      ["", "直连"],
      ...state.proxies.map((p) => [p.id, p.name]),
    ]) +
    field("mode", "诊断模式", h.mode || "standard", "text", [
      ["standard", "A · 标准免 Agent"],
      ["gateway", "B · 受限强制命令网关"],
    ]) +
    field(
      "host_key",
      "已核验 SSH 主机公钥",
      "",
      "textarea",
      null,
      true,
      h.id
        ? "留空表示保留当前已核验主机公钥；也可以使用批量公钥核验流程。"
        : "建议先留空，保存后批量获取候选指纹并在可信渠道核实。",
    ) +
    '<div class="wide">' +
    field(
      "enabled",
      "启用资产",
      h.enabled === undefined ? true : Boolean(h.enabled),
      "checkbox",
    ) +
    "</div>" +
    '<div class="wide"><label class="check"><input type="checkbox" name="gateway_approved" ' +
    (h.gateway_approved ? "checked" : "") +
    "/> 已核实受限强制命令网关（仅 B 模式）</label></div>" +
    '<div class="wide"><label>所属主机组</label>' +
    (gs || '<div class="muted">暂无主机组</div>') +
    "</div>"
  );
}
function hostBody(form) {
  return {
    name: getForm(form, "name"),
    address: getForm(form, "address"),
    port: Number(getForm(form, "port")),
    username: getForm(form, "username"),
    zabbix_hostid: getForm(form, "zabbix_hostid") || null,
    credential_id: numberOrNull(getForm(form, "credential_id")),
    proxy_id: numberOrNull(getForm(form, "proxy_id")),
    mode: getForm(form, "mode"),
    gateway_approved: checkbox(form, "gateway_approved"),
    host_key: getForm(form, "host_key"),
    enabled: checkbox(form, "enabled"),
    group_ids: [...form.querySelectorAll(".group-check:checked")].map((x) =>
      Number(x.value),
    ),
  };
}
function keyEditor() {
  return (
    field("name", "凭据名称", "诊断专用 SSH 密钥") +
    field("passphrase", "私钥口令（可选）", "", "password") +
    field(
      "private_key",
      "完整 SSH 私钥（不回显）",
      "",
      "textarea",
      null,
      true,
      "私钥使用应用持久化的 Fernet 主密钥加密后存储。",
    )
  );
}
$("#content").addEventListener("input", (e) => {
  if (e.target.id === "trusted-fingerprints") state.manifest = e.target.value;
});

$("#content").addEventListener("change", (e) => {
  if (e.target.name === "action") updateDiagnosticInputs();
  if (e.target.classList.contains("host-selected")) {
    const id = Number(e.target.dataset.id);
    if (e.target.checked) state.selected.add(id);
    else state.selected.delete(id);
  }
  if (e.target.id === "batch-select") {
    state.batchId = e.target.value;
    state.manifest = "";
    go("keys/" + state.batchId);
  }
  if (e.target.id === "select-page") {
    state.hosts.forEach((h) =>
      e.target.checked ? state.selected.add(h.id) : state.selected.delete(h.id),
    );
  }
  if (e.target.id === "history-status") {
    state.historyStatus = e.target.value;
    state.historyPage = 1;
    render();
  }
  updateSelection();
});
$("#content").addEventListener("submit", async (e) => {
  if (e.target.id === "feishu-admins-form") {
    e.preventDefault();
    const button = e.target.querySelector("button[type=submit]");
    button.disabled = true;
    try {
      await api("/settings/admins", "PUT", {
        open_ids: e.target.elements.open_ids.value,
      });
      notice("管理员名单已保存，权限立即生效。");
    } catch (ex) {
      notice(ex.message, true);
    } finally {
      button.disabled = false;
    }
    return;
  }
  if (e.target.id === "host-search-form") {
    e.preventDefault();
    state.hostQuery = $("#host-filter").value.trim();
    state.hostGroup = $("#host-group").value;
    state.hostStatus = $("#host-status").value;
    state.hostPage = 1;
    state.selected.clear();
    render();
    return;
  }
  if (e.target.id === "audit-search-form") {
    e.preventDefault();
    state.auditQuery = $("#audit-search").value.trim();
    state.auditStatus = $("#audit-status").value;
    state.auditPage = 1;
    render();
    return;
  }
  if (e.target.id !== "diagnostic-form") return;
  e.preventDefault();
  const form = e.target,
    button = form.querySelector("button[type=submit]"),
    version = generation;
  button.disabled = true;
  try {
    const action = getForm(form, "action");
    const host_ids = checkbox(form, "use_selected")
      ? [...state.selected]
      : [Number(getForm(form, "host_id"))];
    const result = await api("/jobs", "POST", {
      host_ids,
      action,
      service: ["logs", "service"].includes(action)
        ? getForm(form, "service")
        : null,
      minutes: Number(getForm(form, "minutes")),
      directory_root:
        action === "directory" ? getForm(form, "directory_root").trim() : null,
    });
    notice("已提交 " + result.total + " 项诊断任务。");
    if (version === generation) {
      state.historyPage = 1;
      state.historyStatus = "all";
      go(
        result.total === 1
          ? "job/" + result.job_ids[0]
          : "history/" + result.batch_id,
      );
    }
  } catch (ex) {
    notice(ex.message, true);
  } finally {
    button.disabled = false;
  }
});
document.addEventListener("click", async (e) => {
  const b = e.target.closest("[data-action]");
  if (!b || b.disabled) return;
  const action = b.dataset.action,
    id = b.dataset.id;
  b.disabled = true;
  try {
    if (action === "refresh") {
      render();
      return;
    }
    if (action.startsWith("open-")) {
      go(action.slice(5));
      return;
    }
    if (action === "page-prev" || action === "page-next") {
      const key = id + "Page";
      state[key] = Math.max(
        1,
        Math.min(
          state[id + "Pages"],
          state[key] + (action === "page-next" ? 1 : -1),
        ),
      );
      await render();
      return;
    }
    if (action === "job-detail") {
      go("job/" + id);
      return;
    }
    if (action === "all-history") {
      state.historyPage = 1;
      go("history");
      return;
    }
    if (action === "cancel-job") {
      await api("/jobs/" + id + "/cancel", "POST");
      notice("已请求取消，连接结束后保留已有结果。");
      await render();
      return;
    }
    if (action === "retry-job") {
      const r = await api("/jobs/" + id + "/retry", "POST");
      go("job/" + r.job_ids[0]);
      return;
    }
    if (action === "clear-selected") {
      state.selected.clear();
      updateSelection();
      return;
    }
    if (action === "enable-selected" || action === "disable-selected") {
      if (!state.selected.size) throw Error("请先选择主机");
      const enabled = action === "enable-selected";
      if (
        !confirm(
          "确认" +
            (enabled ? "启用" : "停用") +
            "所选 " +
            state.selected.size +
            " 台主机？停用会立即阻止新的诊断。",
        )
      )
        return;
      await api("/hosts/bulk-enabled", "POST", {
        host_ids: [...state.selected],
        enabled,
      });
      state.selected.clear();
      await render();
      return;
    }
    if (action === "diagnose-selected") {
      if (!state.selected.size || state.selected.size > 100)
        throw Error("批量诊断请选择 1–100 台主机");
      state.useSelection = true;
      go("diagnostics");
      return;
    }
    if (action === "import-hosts") {
      openModal(
        "批量导入 Linux 主机",
        field(
          "hosts",
          "主机 JSON 数组",
          "[]",
          "textarea",
          null,
          true,
          "每批最多 1000 台。字段：name、address、username、credential_id、zabbix_hostid、group_ids 等；公钥可以留空，任意校验失败会整批回滚。",
        ),
        (form) =>
          api("/hosts/import", "POST", {
            hosts: JSON.parse(getForm(form, "hosts")),
          }),
      );
      return;
    }
    if (action === "new-client") {
      const basic = [
        "connection",
        "health",
        "capabilities",
        "cpu",
        "memory",
        "disk",
        "network",
        "system",
      ];
      openModal(
        "创建 MCP 客户端",
        field("name", "客户端名称", "AI Ops Platform") +
          field("valid_days", "有效期（天）", 90, "number") +
          '<div class="wide"><label class="check"><input type="checkbox" name="all_hosts">授权全部已登记主机（包含未来新增主机）</label></div><fieldset class="wide option-grid"><legend>或选择授权主机组</legend>' +
          state.groups
            .map(
              (g) =>
                '<label class="check"><input type="checkbox" name="client_group" value="' +
                g.id +
                '">' +
                esc(g.name) +
                "</label>",
            )
            .join("") +
          "</fieldset>" +
          '<fieldset class="wide option-grid"><legend>允许的诊断动作</legend>' +
          state.tools
            .map(
              (t) =>
                '<label class="check"><input type="checkbox" name="client_action" value="' +
                t.id +
                '" ' +
                (basic.includes(t.id) ? "checked" : "") +
                ">" +
                esc(t.name) +
                (t.sensitive ? " · 扩展采集" : "") +
                "</label>",
            )
            .join("") +
          "</fieldset>",
        (form) =>
          api("/mcp/clients", "POST", {
            name: getForm(form, "name"),
            valid_days: Number(getForm(form, "valid_days")),
            all_hosts: checkbox(form, "all_hosts"),
            group_ids: [
              ...form.querySelectorAll("[name=client_group]:checked"),
            ].map((x) => Number(x.value)),
            actions: [
              ...form.querySelectorAll("[name=client_action]:checked"),
            ].map((x) => x.value),
          }),
      );
      return;
    }
    if (action === "copy-token") {
      if (!navigator.clipboard)
        throw Error("此访问方式不支持剪贴板，请选择文本后手动复制");
      await navigator.clipboard.writeText(
        $("#editor-fields [name=new_token]").value,
      );
      b.textContent = "已复制";
      return;
    }
    if (action === "revoke-client") {
      const c = state.clients.find((x) => x.id === id);
      if (
        !confirm(
          "撤销「" +
            c.name +
            "」的令牌？该客户端将无法继续访问 MCP，其他客户端不受影响。",
        )
      )
        return;
      await api("/mcp/clients/" + id + "/revoke", "POST");
      await render();
      return;
    }
    if (action === "toggle-legacy") {
      if (
        !confirm(
          state.legacyEnabled
            ? "停用原始 mcp.token？请先确认 AI 平台已改用新的客户端令牌。"
            : "启用原始令牌会授予全部主机和工具权限，确认启用？",
        )
      )
        return;
      await api("/settings/mcp-legacy", "PUT", {
        enabled: !state.legacyEnabled,
      });
      await render();
      return;
    }
    if (action === "new-host" || action === "edit-host") {
      const h = action === "edit-host" ? currentHost(id) : {};
      openModal(
        h.id ? "编辑主机资产" : "登记 Linux 主机",
        hostFields(h),
        (form) =>
          api(
            "/hosts" + (h.id ? "/" + h.id : ""),
            h.id ? "PUT" : "POST",
            hostBody(form),
          ),
      );
    } else if (action === "new-group" || action === "edit-group") {
      const g = state.groups.find((x) => String(x.id) === id);
      openModal(
        g ? "编辑主机组" : "创建主机组",
        field("name", "主机组名称", g?.name || ""),
        (form) =>
          api("/groups" + (g ? "/" + g.id : ""), g ? "PUT" : "POST", {
            name: getForm(form, "name"),
          }),
      );
    } else if (action === "delete-group") {
      if (
        !confirm(
          "删除此分组？主机保留，仅通过该分组授权的 MCP 客户端将失去相应主机访问权限。",
        )
      )
        return;
      await api("/groups/" + id, "DELETE");
      await render();
    } else if (action === "new-credential" || action === "rotate-credential") {
      const prev = state.credentials.find((x) => String(x.id) === id);
      openModal(prev ? "轮换 SSH 私钥" : "新增 SSH 凭据", keyEditor(), (form) =>
        api(
          "/credentials" + (prev ? "/" + prev.id : ""),
          prev ? "PUT" : "POST",
          {
            name: prev?.name || getForm(form, "name"),
            passphrase: getForm(form, "passphrase"),
            private_key: getForm(form, "private_key"),
          },
        ),
      );
      if (prev) $("#editor-fields input[name=name]").value = prev.name;
    } else if (action === "new-proxy" || action === "edit-proxy") {
      const proxy = state.proxies.find((p) => String(p.id) === id) || {};
      openModal(
        proxy.id ? "编辑 SSH 跳板" : "新增 SSH 跳板",
        field("name", "跳板名称", proxy.name || "") +
          field("address", "内网 IP 地址", proxy.address || "") +
          field("port", "SSH 端口", proxy.port || 22, "number") +
          field("username", "SSH 用户名", proxy.username || "root") +
          field(
            "credential_id",
            "SSH 凭据",
            proxy.credential_id || "",
            "text",
            state.credentials.map((c) => [c.id, c.name]),
          ) +
          field(
            "host_key",
            "已核验跳板公钥",
            proxy.host_key || "",
            "textarea",
            null,
            true,
          ),
        (form) =>
          api(
            "/proxies" + (proxy.id ? "/" + proxy.id : ""),
            proxy.id ? "PUT" : "POST",
            {
              name: getForm(form, "name"),
              address: getForm(form, "address"),
              port: Number(getForm(form, "port")),
              username: getForm(form, "username"),
              credential_id: Number(getForm(form, "credential_id")),
              host_key: getForm(form, "host_key"),
            },
          ),
      );
    } else if (action === "test") {
      const value = await api("/jobs", "POST", {
        host_ids: [Number(id)],
        action: "connection",
      });
      go("job/" + value.job_ids[0]);
    } else if (action === "disable-host") {
      if (!confirm("确定停用资产 " + id + "？停用后 MCP 将无法诊断这台主机。"))
        return;
      await api("/hosts/" + id + "/disable", "POST");
      notice("主机已停用");
      render();
    } else if (action === "diagnose-host") {
      state.preselectedId = id;
      state.useSelection = false;
      go("diagnostics");
    } else if (action === "select-filtered") {
      const r = await api("/inventory/ids?" + hostQuery());
      state.selected = new Set(r.host_ids);
      updateSelection();
    } else if (
      action === "scan-selected" ||
      action === "scan-all-unverified" ||
      action === "retry-failed"
    ) {
      let body;
      if (action === "scan-selected") {
        const ids = [...state.selected];
        if (!ids.length) throw new Error("请先勾选至少一台主机");
        body = { host_ids: ids };
      } else if (action === "retry-failed") {
        if (!state.batchId) throw new Error("没有可重试的批次");
        body = { retry_failed_batch: state.batchId };
      } else {
        body = { unverified_only: true };
      }
      const result = await api("/host-keys/scan", "POST", body);
      state.selected.clear();
      state.batchId = result.batch_id;
      state.manifest = "";
      notice(
        "已提交 " +
          result.total +
          " 台主机。请在可信渠道独立核对，再确认公钥。",
      );
      go("keys/" + result.batch_id);
    } else if (action === "confirm-batch-from-manifest") {
      if (!state.batchId) throw new Error("请先扫描目标主机");
      const info = await api(
        "/host-keys/batches/" + encodeURIComponent(state.batchId),
      );
      const eligible = info.items.filter(
        (r) => r.status === "candidate" || r.status === "changed",
      );
      const raw = ($("#trusted-fingerprints")?.value || "").trim();
      if (!raw) throw new Error("请粘贴通过独立可信渠道取得的主机指纹清单");
      const lines = raw
        .split(/\r?\n/)
        .map((x) => x.trim())
        .filter(Boolean);
      const entries = [];
      let skipped = 0;
      for (const [index, line] of lines.entries()) {
        const m = line.match(
          /^(\S+)\s+(?:(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256)\s+)?(SHA256:[A-Za-z0-9+/=_-]+)$/,
        );
        if (!m)
          throw new Error(
            "第 " +
              (index + 1) +
              " 行格式错误：应为「资产 ID/IP [密钥算法] SHA256:...」",
          );
        const match = eligible.find(
          (r) => String(r.host_id) === m[1] || r.address === m[1],
        );
        // Independently gathered Ansible inventories may include several key
        // algorithms and more hosts than the current scan. Use only exact matches.
        if (!match || (m[2] && m[2] !== match.algorithm)) {
          if (!m[2] && !match)
            throw new Error(
              "第 " + (index + 1) + " 行的主机不在待核验批次：" + m[1],
            );
          skipped++;
          continue;
        }
        entries.push({
          host_id: match.host_id,
          independently_verified_sha256: m[3],
        });
      }
      if (!entries.length)
        throw new Error(
          "清单没有当前批次匹配的可信主机指纹，请核对 IP 与密钥算法",
        );
      if (new Set(entries.map((x) => x.host_id)).size !== entries.length)
        throw new Error("同一主机存在重复匹配的可信指纹，请清理重复行");
      if (
        !confirm(
          "将独立核验 " +
            entries.length +
            " 台主机，跳过 " +
            skipped +
            " 行其他主机或不同算法指纹。任意一台不匹配将整批拒绝。确定继续？",
        )
      )
        return;
      const result = await api("/host-keys/confirm-batch", "POST", {
        items: entries,
        confirmed: true,
      });
      state.manifest = "";
      notice(
        "已成功保存 " +
          result.count +
          " 台主机的公钥。可返回主机资产进行 SSH 连接测试。",
      );
      await render();
    } else if (action === "confirm-key") {
      const h = await api("/hosts");
      const asset = h.find((x) => String(x.id) === id);
      const current = await api(
        "/host-keys/batches/" + encodeURIComponent(state.batchId),
      );
      const entry = current.items.find((x) => String(x.host_id) === id);
      openModal(
        "人工核验主机公钥",
        '<div class="wide"><p>主机：<strong>' +
          esc(asset?.name) +
          '</strong></p><p>候选指纹：<strong class="mono">' +
          esc(entry?.fingerprint) +
          '</strong></p><p class="muted">请在目标服务器可信控制台执行 ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256（根据实际协商的公钥算法选择文件），确认指纹后手工填入。</p></div>' +
          field(
            "fingerprint",
            "通过可信渠道独立核验的 SHA256 指纹",
            "",
            "text",
            null,
            true,
          ) +
          '<div class="wide"><label class="check"><input type="checkbox" name="confirmed"/> 我已在可信渠道独立核验，确认本次公钥属于目标服务器</label></div>',
        (form) =>
          api("/host-keys/confirm", "POST", {
            host_id: Number(id),
            independently_verified_sha256: getForm(form, "fingerprint"),
            confirmed: checkbox(form, "confirmed"),
          }),
      );
    }
  } catch (ex) {
    notice(ex.message, true);
  } finally {
    b.disabled = false;
  }
});
window.addEventListener("hashchange", render);
const theme =
  localStorage.getItem("ssh-theme") ||
  (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
document.documentElement.dataset.theme = theme;
$("#theme-toggle").addEventListener("click", () => {
  const value =
    document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = value;
  localStorage.setItem("ssh-theme", value);
});
login();

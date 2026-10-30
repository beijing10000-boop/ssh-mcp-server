/* Zabbix inventory workflow. Shared desktop helpers are defined in app.js. */
function zabbixGroupChoices() {
  if (!state.zabbixGroups.length)
    return '<p class="muted">先测试连接或获取主机组，再选择资产范围。</p>';
  return state.zabbixGroups
    .map(
      (g) =>
        `<label class="check"><input class="zabbix-group-check" type="checkbox" value="${esc(g.groupid)}" ${state.zabbixGroupIds.has(String(g.groupid)) ? "checked" : ""}><span>${esc(g.name)}<small>Group ID ${esc(g.groupid)}</small></span></label>`,
    )
    .join("");
}
function zabbixFeedback(message, error = false) {
  const node = $("#zabbix-feedback");
  if (node) {
    node.textContent = message;
    node.hidden = false;
    node.classList.toggle("error", error);
  } else notice(message, error);
}
function zabbixAcceptGroups(groups) {
  state.zabbixGroups = groups;
  if (!state.zabbixGroupIds.size)
    groups
      .filter((g) => /linux/i.test(g.name))
      .forEach((g) => state.zabbixGroupIds.add(String(g.groupid)));
  const region = $("#zabbix-groups");
  if (region) region.innerHTML = zabbixGroupChoices();
}
function zabbixSelectedCount() {
  const node = $("#zabbix-selected-count");
  if (node) node.textContent = `已选 ${state.zabbixSelected.size} 台`;
}
async function saveZabbixConnection() {
  const form = $("#zabbix-connection-form");
  const token = getForm(form, "token").trim();
  const body = {
    url: getForm(form, "url").trim(),
    token: token || null,
    server: getForm(form, "server").trim(),
    transport: getForm(form, "transport"),
    verify_tls: checkbox(form, "verify_tls"),
    batch_size: Number(getForm(form, "batch_size")),
    interval_ms: Number(getForm(form, "interval_ms")),
  };
  await api("/zabbix/config", "PUT", body);
  form.elements.token.value = "";
}
function zabbixConnectionPanel(config) {
  const cfg = config || {
    url: "",
    server: "",
    transport: "http",
    verify_tls: true,
    batch_size: 20,
    interval_ms: 400,
  };
  return panel(
    "Zabbix MCP 连接配置",
    '<p class="intro">配置资产来源、认证和分批读取参数。保存后可验证 MCP 连接及读取权限。</p><form id="zabbix-connection-form"><div class="fields">' +
      field(
        "url",
        "MCP 地址",
        cfg.url,
        "url",
        null,
        true,
        "填写 Zabbix MCP 的 /mcp 或 /sse 地址。",
      ) +
      field(
        "token",
        "MCP Bearer Token",
        "",
        "password",
        null,
        false,
        cfg.has_token
          ? "已加密保存；留空保留原令牌。"
          : "填写 MCP 接入令牌，非 Zabbix API Token。",
      ) +
      field(
        "server",
        "Zabbix 服务器名称（可选）",
        cfg.server,
        "text",
        null,
        false,
        "上游配置了多个 Zabbix 时填写对应 server 名称。",
      ) +
      field("transport", "传输方式", cfg.transport, "text", [
        ["http", "Streamable HTTP"],
        ["sse", "SSE"],
      ]) +
      field(
        "batch_size",
        "每批资产详情数",
        cfg.batch_size,
        "number",
        null,
        false,
        "推荐 20；响应过大时自动拆成更小批次。",
      ) +
      field(
        "interval_ms",
        "请求间隔（毫秒）",
        cfg.interval_ms,
        "number",
        null,
        false,
        "最低 200；出现限流时会退避重试。",
      ) +
      field("verify_tls", "校验 HTTPS 证书", cfg.verify_tls, "checkbox") +
      '</div><div class="modal-actions"><button type="submit" class="btn">保存连接</button>' +
      btn("zabbix-test", "保存并验证连接与读取权限", "", "primary") +
      '</div></form><div id="zabbix-feedback" class="notice" role="status" hidden></div>',
  );
}

async function pageZabbix() {
  const [settings, runs, credentials, proxies] = await Promise.all([
    api("/zabbix/config"),
    api("/zabbix/runs"),
    api("/credentials"),
    api("/proxies"),
  ]);
  state.credentials = credentials;
  state.proxies = proxies;
  if (!state.zabbixRun && runs.items.length) state.zabbixRun = runs.items[0].id;
  const detail = state.zabbixRun
    ? await api("/zabbix/runs/" + state.zabbixRun + "?page=" + state.zabbixPage)
    : null;
  state.zabbixPolling =
    !!detail && ["queued", "running"].includes(detail.run.status);
  state.zabbixPreview = detail;
  const steps = [
    "连接 Zabbix MCP",
    "选择主机组",
    "预览并登记",
    detail?.run.status === "registered"
      ? "下一步：核验与测试 SSH"
      : "核验与测试 SSH",
  ];
  const complete = [
    settings.config,
    state.zabbixGroups.length,
    detail?.run.status === "registered",
  ];
  const progress =
    '<ol class="sync-steps">' +
    steps
      .map(
        (s, i) =>
          `<li class="${complete[i] ? "complete" : ""}"><span>${i + 1}</span>${s}</li>`,
      )
      .join("") +
    "</ol>";
  const connection = panel(
    "资产来源",
    `<div class="settings-source"><div><strong>${settings.config ? "已配置 Zabbix MCP" : "尚未配置 Zabbix MCP"}</strong>` +
      `<p class="muted">${settings.config ? esc(settings.config.url) : "先到系统配置保存 MCP 地址和令牌，再返回此处选择分组和登记资产。"}</p></div>` +
      `<div class="actions">${btn("open-settings/zabbix", "系统配置", "", settings.config ? "" : "primary")}</div></div>`,
  );
  const types = state.zabbixTypes || ["linux"];
  const typeChoices = [
    ["linux", "Linux 服务器", "当前支持 SSH 排查"],
    ["network", "网络设备", "预留后续诊断接入"],
    ["windows", "Windows 服务器", "先登记资产"],
    ["other", "其他 / 未识别", "先登记并人工核对"],
  ]
    .map(
      ([v, n, h]) =>
        `<label class="check"><input type="checkbox" name="asset_type" value="${v}" ${types.includes(v) ? "checked" : ""}><span>${n}<small>${h}</small></span></label>`,
    )
    .join("");
  const discover = panel(
    "选择同步范围",
    `<form id="zabbix-discover-form"><div class="sync-scope"><div><div class="section-head"><h3>来自 Zabbix 的主机组</h3><div class="actions">${btn("zabbix-groups", "获取主机组")}${btn("zabbix-all-groups", "选择全部")}</div></div>` +
      `<div id="zabbix-groups" class="group-picker">${zabbixGroupChoices()}</div></div>` +
      `<div><h3>资产类型</h3><div class="type-picker">${typeChoices}</div><label class="check"><input type="checkbox" name="monitored_only" ${state.zabbixMonitored === false ? "" : "checked"}>只拉取启用监控的主机</label></div></div>` +
      '<p class="micro">Linux 根据主机组、模板、操作系统标签或资产清单识别；主动 Agent 没有接口 IP 时会提示补充。每个组先核对精简 ID 索引，再分批读取详情。</p>' +
      `<div class="modal-actions"><span class="muted">仅生成预览，登记前可以核对目标与分组。</span><button class="btn primary" type="submit" ${state.zabbixPolling ? "disabled" : ""}>${state.zabbixPolling ? "正在发现资产…" : "拉取资产预览"}</button></div></form>`,
  );
  let preview = "";
  if (detail) {
    const r = detail.run;
    const active = ["queued", "running"].includes(r.status);
    const typeNames = {
      linux: "Linux",
      network: "网络设备",
      windows: "Windows",
      other: "其他",
    };
    const planNames = {
      create: "新增资产",
      update: "更新资产资料",
      adopt: "需确认关联同 IP 资产",
      skip: "跳过",
      conflict: "存在冲突",
    };
    const rows = detail.items
      .map((h) => {
        const locked = h.issue || h.conflict || h.outcome === "registered";
        const plan =
          h.outcome === "registered"
            ? "已登记"
            : h.issue || h.conflict || planNames[h.plan];
        const groups = h.groups
          .map((g) => `<span class="group-tag">${esc(g.name)}</span>`)
          .join("");
        return (
          `<tr><td><input class="zabbix-host-check" type="checkbox" value="${esc(h.hostid)}" ${state.zabbixSelected.has(h.hostid) ? "checked" : ""} ${locked ? "disabled" : ""} aria-label="选择 ${esc(h.name)}"></td>` +
          `<td><strong>${esc(h.name)}</strong><small>Host ID ${esc(h.hostid)}</small></td>` +
          `<td class="mono">${esc(h.address || "需补充 IP")}</td><td>${esc(typeNames[h.asset_type])}</td><td>${groups}</td><td>${esc(plan)}</td></tr>`
        );
      })
      .join("");
    const options =
      field("username", "新资产 SSH 用户名", "root") +
      field("port", "新资产 SSH 端口", 22, "number") +
      field("credential_id", "新资产统一 SSH 凭据", "", "text", [
        ["", "稍后绑定"],
        ...credentials.map((c) => [c.id, c.name]),
      ]) +
      field("proxy_id", "新资产跳板", "", "text", [
        ["", "直连"],
        ...proxies.map((p) => [p.id, p.name]),
      ]);
    preview = panel(
      "资产预览与登记",
      `<div class="sync-progress"><div>${badge(r.status)}<strong>${r.completed} / ${r.total} 台已读取</strong></div>` +
        `<progress max="${Math.max(1, r.total)}" value="${r.completed}" aria-label="资产发现进度"></progress><small>发现时间 ${date(r.created_at)}</small></div>` +
        (r.error ? `<p class="inline-error">${esc(r.error)}</p>` : "") +
        (active
          ? '<p class="muted">后台正在分批读取，可以离开页面。完成后自动显示登记预览。</p>'
          : table(
              [
                "选择",
                "名称 / Host ID",
                "内网 IP",
                "资产类型",
                "Zabbix 主机组",
                "登记计划",
              ],
              rows,
            ) + pagination("zabbix", detail)) +
        (["preview", "registered"].includes(r.status)
          ? `<form id="zabbix-register-form"><div class="fields">${options}<div class="wide"><label class="check"><input type="checkbox" name="adopt_existing">允许关联同 IP、尚未绑定 Host ID 的手工资产</label></div></div>` +
            '<p class="micro">重新拉取会保留已有 SSH 账号、凭据、跳板和公钥；IP 变化需要重新核验。主机组按 Zabbix Group ID 关联，手工分组保留。</p>' +
            `<div class="selection-bar"><span id="zabbix-selected-count">已选 ${state.zabbixSelected.size} 台</span>${btn("zabbix-select-page", "选择本页可登记资产")}${btn("zabbix-clear-selection", "清空选择")}</div>` +
            '<div class="modal-actions"><button class="btn" type="submit" name="register_selected" value="1">登记所选资产</button><button class="btn primary" type="submit" name="register_all" value="1">登记全部符合条件资产</button></div></form>'
          : "") +
        '<div id="zabbix-register-result" class="notice" role="status" hidden></div>' +
        (r.status === "registered"
          ? '<div class="sync-next"><div><strong>登记后，完成 SSH 验证</strong><p class="muted">先绑定凭据，再核验主机公钥，最后执行 SSH 测试。</p></div>' +
            `<div class="actions">${btn("open-hosts", "查看资产")}${btn("open-keys", "核验公钥")}</div></div>`
          : ""),
    );
  }
  const history = runs.items.length
    ? panel(
        "最近同步记录",
        table(
          ["时间", "状态", "读取进度", "操作"],
          runs.items
            .map(
              (r) =>
                `<tr><td>${date(r.created_at)}</td><td>${badge(r.status)}</td><td>${r.completed} / ${r.total}</td><td>${btn("zabbix-view", "查看预览", r.id)}</td></tr>`,
            )
            .join(""),
        ),
      )
    : "";
  return (
    '<div class="page-intro"><p>把监控资产转成可验证的诊断目标，保留 Host ID 与原始主机组。</p></div>' +
    progress +
    connection +
    discover +
    preview +
    history
  );
}
async function submitZabbixForm(form) {
  if (form.dataset.busy) return;
  form.dataset.busy = "1";
  const buttons = [...form.querySelectorAll("button")];
  buttons.forEach((b) => (b.disabled = true));
  try {
    if (form.id === "zabbix-connection-form") {
      await saveZabbixConnection();
      zabbixFeedback("连接配置已加密保存，可以点击验证连接。");
    } else if (form.id === "zabbix-discover-form") {
      const types = [...form.querySelectorAll("[name=asset_type]:checked")].map(
        (x) => x.value,
      );
      if (!state.zabbixGroupIds.size)
        throw Error("请选择至少一个 Zabbix 主机组");
      if (!types.length) throw Error("请选择至少一种资产类型");
      state.zabbixTypes = types;
      state.zabbixMonitored = checkbox(form, "monitored_only");
      const r = await api("/zabbix/runs", "POST", {
        group_ids: [...state.zabbixGroupIds],
        asset_types: types,
        monitored_only: state.zabbixMonitored,
      });
      state.zabbixRun = r.id;
      state.zabbixPage = 1;
      state.zabbixSelected.clear();
      go("zabbix/" + r.id);
    } else if (form.id === "zabbix-register-form") {
      // submitter is recorded synchronously by the shared submit listener.
      const all = form.dataset.submitter === "register_all";
      if (!all && !state.zabbixSelected.size)
        throw Error("请选择资产，或点击登记全部符合条件资产");
      if (state.zabbixSelected.size > 1000) throw Error("每批最多选择 1000 台");
      const body = {
        hostids: all ? null : [...state.zabbixSelected],
        username: getForm(form, "username"),
        port: Number(getForm(form, "port")),
        credential_id: numberOrNull(getForm(form, "credential_id")),
        proxy_id: numberOrNull(getForm(form, "proxy_id")),
        adopt_existing: checkbox(form, "adopt_existing"),
      };
      const result = await api(
        "/zabbix/runs/" + state.zabbixRun + "/register",
        "POST",
        body,
      );
      state.selected = new Set(result.host_ids);
      state.zabbixSelected.clear();
      await render();
      const node = $("#zabbix-register-result");
      node.hidden = false;
      node.textContent =
        `本次登记 ${result.registered} 台，已登记跳过 ${result.skipped} 台，剩余待处理 ${result.remaining} 台。` +
        (result.issues.length
          ? `需处理 ${result.issues.length} 台：` +
            result.issues
              .slice(0, 10)
              .map((x) => `Host ID ${x.hostid} ${x.reason}`)
              .join("；")
          : "可前往资产页获取公钥并测试 SSH。");
    }
  } catch (e) {
    zabbixFeedback(e.message, true);
  } finally {
    delete form.dataset.busy;
    buttons.forEach((b) => (b.disabled = false));
  }
}
async function zabbixAction(action, id) {
  if (action === "zabbix-test") {
    await saveZabbixConnection();
    zabbixFeedback("正在验证 MCP 握手与读取权限…");
    const r = await api("/zabbix/test", "POST");
    zabbixAcceptGroups(r.groups);
    zabbixFeedback(
      `${r.note}。可见主机 ${r.host_count} 台，主机组 ${r.groups.length} 个。`,
    );
  } else if (action === "zabbix-groups") {
    const r = await api("/zabbix/groups", "POST");
    zabbixAcceptGroups(r.items);
    zabbixFeedback(`已获取 ${r.items.length} 个 Zabbix 主机组。`);
  } else if (action === "zabbix-all-groups") {
    state.zabbixGroups.forEach((g) =>
      state.zabbixGroupIds.add(String(g.groupid)),
    );
    $("#zabbix-groups").innerHTML = zabbixGroupChoices();
  } else if (action === "zabbix-view") {
    state.zabbixRun = id;
    state.zabbixPage = 1;
    state.zabbixSelected.clear();
    go("zabbix/" + id);
  } else if (action === "zabbix-select-page") {
    state.zabbixPreview.items
      .filter((h) => !h.issue && !h.conflict && h.outcome !== "registered")
      .forEach((h) => state.zabbixSelected.add(h.hostid));
    document
      .querySelectorAll(".zabbix-host-check:not(:disabled)")
      .forEach((n) => (n.checked = true));
    zabbixSelectedCount();
  } else if (action === "zabbix-clear-selection") {
    state.zabbixSelected.clear();
    document
      .querySelectorAll(".zabbix-host-check")
      .forEach((n) => (n.checked = false));
    zabbixSelectedCount();
  }
}

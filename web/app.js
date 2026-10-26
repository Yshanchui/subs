"use strict";
const $ = (s) => document.querySelector(s),
  esc = (v) =>
    String(v ?? "").replace(
      /[&<>"']/g,
      (c) =>
        ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;",
        })[c],
    );
let csrf = "",
  state = null,
  editing = null,
  working = false,
  noticeTimer;
const formats = [
  [
    "mihomo",
    "Mihomo / Clash Verge",
    "完整 YAML，包含节点、策略组与兼容 ACL 规则",
  ],
  ["clash", "旧版 Clash", "Clash for Windows / 原版 Clash for Android"],
  ["shadowrocket", "Shadowrocket 节点", "在首页添加订阅 URL"],
  [
    "shadowrocket-rules",
    "Shadowrocket 规则",
    "在配置页导入，与节点订阅配合使用",
  ],
];
const pages = {
  overview: ["订阅概览", "源可以暂时关闭，已经生成的订阅仍然可用。"],
  sources: ["订阅源", "保存多个上游地址。更新失败时，继续保留上一次成功缓存。"],
  collections: [
    "订阅集合",
    "组合本地节点与 ACL 规则，为每个客户端生成独立文件。",
  ],
  rules: ["ACL 规则", "自动拉取 ACL4SSR Full 模板，并将规则展开保存在本地。"],
  settings: ["系统设置", "安排更新频率，管理后台登录密码。"],
};
function date(v) {
  return !v || v.startsWith("0001")
    ? "尚未更新"
    : new Date(v).toLocaleString("zh-CN", { hour12: false });
}
function notice(msg, bad = false) {
  clearTimeout(noticeTimer);
  $("#notice").hidden = false;
  $("#notice").className = bad ? "error" : "";
  $("#notice span").textContent = msg;
  if (!bad) noticeTimer = setTimeout(() => ($("#notice").hidden = true), 5500);
}
async function api(path, method = "GET", body) {
  const headers = {};
  if (method !== "GET") {
    headers["Content-Type"] = "application/json";
    if (csrf) headers["X-CSRF-Token"] = csrf;
  }
  const res = await fetch("/api" + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data;
  try {
    data = await res.json();
  } catch {
    throw Error("服务没有返回有效结果，请检查连接。");
  }
  if (!res.ok) {
    if (res.status === 401 && path !== "/login") showLogin();
    throw Error(data.error || "请求失败");
  }
  return data;
}
function showLogin() {
  $("#workspace").hidden = true;
  $("#loginView").hidden = false;
  csrf = "";
  state = null;
  $("#password").value = "";
}
async function load() {
  state = await api("/state");
  $("#workspace").hidden = false;
  $("#loginView").hidden = true;
  render();
}
async function task(button, fn) {
  if (working) return;
  working = true;
  const old = button?.textContent;
  if (button) {
    button.disabled = true;
    button.textContent = "处理中…";
  }
  $("#taskBanner").hidden = false;
  try {
    await fn();
  } catch (e) {
    notice(e.message, true);
  } finally {
    working = false;
    $("#taskBanner").hidden = true;
    if (button && button.isConnected) {
      button.disabled = false;
      button.textContent = old;
    }
  }
}
function updateResult(r) {
  const errs = r.errors || [];
  if (errs.length)
    notice("更新已结束，部分项目未生成新版本：\n" + errs.join("\n"), true);
  else notice("更新完成，本地快照已生成。");
}
function empty(title, body, action, label) {
  return `<div class="empty"><div class="empty-mark">＋</div><h3>${esc(title)}</h3><p>${esc(body)}</p>${action ? `<button class="primary" data-action="${action}">${esc(label)}</button>` : ""}</div>`;
}
function sourceStatus(s) {
  if (s.error)
    return `<span class="badge ${s.nodes ? "warn" : "bad"}">${s.nodes ? "保留旧缓存" : "尚无缓存"}</span>`;
  if (!s.enabled) return '<span class="badge">已停用</span>';
  return s.nodes
    ? '<span class="badge ok">已缓存</span>'
    : '<span class="badge">等待首次更新</span>';
}
function sourceTable(compact = false) {
  if (!state.sources?.length)
    return empty(
      "添加你的第一个订阅源",
      "支持 Clash / Mihomo YAML、Base64 订阅和常见节点 URI。源地址只在管理员后台显示。",
      "add-source",
      "添加订阅源",
    );
  return `<div class="table-wrap"><table><thead><tr><th>订阅源</th><th>本地节点</th><th>最近成功更新</th><th>状态</th>${compact ? "" : "<th>操作</th>"}</tr></thead><tbody>${state.sources
    .map(
      (s) =>
        `<tr><td class="name"><strong>${esc(s.name)}</strong><small>${s.enabled ? "参与聚合" : "已停用，下次生成时排除"}</small></td><td class="mono"><strong>${s.nodes}</strong><div class="source-protocols">${Object.entries(
          s.protocols || {},
        )
          .map(([k, v]) => esc(k) + " " + v)
          .join(
            " / ",
          )}</div></td><td><small>${date(s.updatedAt)}</small></td><td class="error-cell">${sourceStatus(s)}${s.error ? `<small class="text-wrap">${esc(s.error)}</small>` : ""}${s.warnings?.length ? `<small>${s.warnings.map(esc).join("；")}</small>` : ""}</td>${compact ? "" : `<td><div class="actions"><button class="small" data-action="update-source" data-id="${s.id}">更新</button><button class="small" data-action="edit-source" data-id="${s.id}">编辑</button><button class="small danger" data-action="delete-source" data-id="${s.id}">删除</button></div></td>`}</tr>`,
    )
    .join("")}</tbody></table></div>`;
}
function overview() {
  const cached = (state.sources || []).filter((s) => s.nodes).length,
    ready = state.collections.filter((c) => c.publication).length;
  return `<div class="pipeline"><div class="stage"><h2>订阅源</h2><b>${cached}<small> / ${state.sources?.length || 0}</small></b><p>已取得本地缓存</p></div><div class="arrow" aria-hidden="true">→</div><div class="stage snapshot"><h2>本地快照</h2><b>${ready}</b><p>个集合已发布；请求时直接读取磁盘</p></div><div class="arrow" aria-hidden="true">→</div><div class="stage"><h2>客户端格式</h2><b>4</b><p>Mihomo、旧 Clash、Shadowrocket 节点与规则</p></div></div>${!state.acl ? '<div class="summary-note warning">ACL 规则尚未就绪。首次启动会自动下载，也可以前往 ACL 规则页手动更新。</div>' : ""}${state.ruleError ? `<div class="summary-note warning">ACL 最近更新失败：${esc(state.ruleError)}</div>` : ""}<div class="summary-note">更新上游、生成快照、提供订阅是独立的步骤。源被关闭或更新失败，不会删除已发布的文件；刷新客户端也不会请求上游。</div><div class="section-header"><div><h2>订阅源状态</h2><p>先添加源，再更新一次，最后在订阅集合中复制对应客户端的链接。</p></div><button data-action="add-source">添加订阅源</button></div><div class="panel">${sourceTable(true)}</div><div class="section-header"><h2>本地订阅集合</h2><a href="#collections">管理集合</a></div><div class="panel table-wrap"><table><thead><tr><th>集合</th><th>快照时间</th><th>状态</th></tr></thead><tbody>${state.collections.map((c) => `<tr><td><strong>${esc(c.name)}</strong></td><td>${c.publication ? date(c.publication.builtAt) : "尚未生成"}</td><td>${c.error ? `<span class="badge warn">${esc(c.error)}</span>` : c.publication ? '<span class="badge ok">本地可用</span>' : '<span class="badge">等待生成</span>'}</td></tr>`).join("")}</tbody></table></div>`;
}
function collections() {
  return `<div class="section-header"><div><h2>本地订阅文件</h2><p>同一集合分别生成各格式。更换链接会立即使旧链接失效。</p></div><button data-action="add-collection">新建集合</button></div>${
    state.collections.length
      ? state.collections
          .map((c) => {
            const p = c.publication;
            return `<section class="panel collection"><div class="collection-head"><div><h2>${esc(c.name)}</h2><p>${
              c.allSources
                ? "全部已启用订阅源"
                : c.sourceIds
                    .map(
                      (id) =>
                        state.sources.find((s) => s.id === id)?.name ||
                        "已删除源",
                    )
                    .map(esc)
                    .join("、")
            }<br>${p ? "快照生成于 " + date(p.builtAt) : "尚无本地快照"}</p></div><div class="actions"><button class="small primary" data-action="build" data-id="${c.id}">生成快照</button><button class="small" data-action="edit-collection" data-id="${c.id}">编辑</button><button class="small" data-action="rotate" data-id="${c.id}">更换链接</button><button class="small danger" data-action="delete-collection" data-id="${c.id}">删除</button></div></div>${c.error ? `<div class="summary-note warning">${esc(c.error)}</div>` : ""}<div class="table-wrap"><table class="artifact-table"><thead><tr><th>客户端格式</th><th>内容</th><th>订阅地址</th></tr></thead><tbody>${formats
              .map(([key, name, desc]) => {
                const a = p?.artifacts[key];
                const usable = !!a?.sha256;
                return `<tr><td class="format"><strong>${name}</strong><small>${desc}</small></td><td>${usable ? `<span class="badge ${a.error ? "warn" : "ok"}">${a.error ? "保留旧版" : "本地可用"}</span><small>${a.nodes ? a.nodes + " 个节点" : ""}${a.nodes && a.rules ? " / " : ""}${a.rules ? a.rules.toLocaleString() + " 条规则" : ""}</small>${a.excludedNodes ? `<small>协议不兼容：排除 ${a.excludedNodes} 个节点</small>` : ""}${a.excludedRules ? `<small>规则类型不兼容：排除 ${a.excludedRules} 条</small>` : ""}` : '<span class="badge">尚未生成</span>'}${a?.error ? `<small class="text-wrap">${esc(a.error)}${usable ? "；快照时间：" + date(a.updatedAt) : ""}</small>` : ""}</td><td>${usable ? `<div class="actions"><input type="password" class="link-input" readonly aria-label="${esc(name)}订阅地址" value="${esc(link(c, key))}"><button class="small" data-action="copy" data-id="${c.id}" data-format="${key}">复制链接</button><button class="small" data-action="download" data-id="${c.id}" data-format="${key}">下载</button></div>` : "<small>先更新源与 ACL，再生成快照</small>"}</td></tr>`;
              })
              .join(
                "",
              )}</tbody></table></div><div class="collection-foot">Shadowrocket：先在首页添加节点订阅，再在配置页导入规则链接。更改集合范围后，点击“生成快照”才会替换当前文件。</div></section>`;
          })
          .join("")
      : empty(
          "创建一个订阅集合",
          "可以合并全部已启用的源，也可以只选择其中几条。",
          "add-collection",
          "新建集合",
        )
  }`;
}
function link(c, format) {
  return (state.publicUrl || location.origin) + "/s/" + c.token + "/" + format;
}
function rules() {
  const a = state.acl;
  return `<section class="panel"><div class="panel-body"><div class="rule-title"><div><span class="badge ${a ? "ok" : ""}">${a ? "已保存在本地" : "等待首次下载"}</span><h2>ACL4SSR Online Full</h2><p class="muted">策略分组、国内直连、广告拦截与应用分流。</p></div><button class="primary" data-action="update-rules">更新 ACL 规则</button></div><div class="metrics"><div class="metric"><b>${a ? a.rules.toLocaleString() : "—"}</b><span>规则</span></div><div class="metric"><b>${a?.groups || "—"}</b><span>策略组</span></div><div class="metric"><b>${a?.lists || "—"}</b><span>远程列表已展开</span></div></div>${state.ruleError ? `<div class="summary-note warning">${esc(state.ruleError)}</div>` : ""}<dl class="rule-details"><dt>成功更新</dt><dd>${date(a?.updatedAt)}</dd><dt>最近尝试</dt><dd>${date(state.ruleAttemptedAt)}</dd><dt>更新频率</dt><dd>每 ${state.settings.ruleIntervalHours} 小时自动检查</dd><dt>官方来源</dt><dd><a href="https://github.com/ACL4SSR/ACL4SSR" target="_blank" rel="noopener noreferrer">ACL4SSR / ACL4SSR</a></dd><dt>发布方式</dt><dd>下载所有启用的规则集后，在本地生成完整文件。任一下载或解析失败时保留上一版。各客户端不支持的规则类型会在集合页列出排除数量。</dd><dt>许可</dt><dd>CC BY-SA 4.0。生成的规则文件保留来源与许可说明。</dd></dl></div></section><div class="summary-note">“更新规则”会重新生成已有集合，不重新拉取源订阅；“更新源与规则”会同时更新两者。源地址暂时开放时，可单独更新该源。</div>`;
}
function settings() {
  return `<div class="settings-grid"><section class="panel panel-body"><h2>自动更新</h2><form id="settingsForm"><label for="sourceInterval">订阅源更新间隔（分钟）</label><input id="sourceInterval" name="sourceIntervalMinutes" type="number" min="0" max="10080" required value="${state.settings.sourceIntervalMinutes}"><p class="help">0 表示只手动更新；自动更新至少间隔 5 分钟。失败时保留本地缓存。</p><label for="ruleInterval">ACL 更新间隔（小时）</label><input id="ruleInterval" name="ruleIntervalHours" type="number" min="1" max="720" required value="${state.settings.ruleIntervalHours}"><label for="publicUrl">对外地址</label><input id="publicUrl" readonly value="${esc(state.publicUrl || location.origin)}"><p class="help">部署后通过 SUBS_PUBLIC_URL 配置外部 HTTPS 地址。默认仅在本机监听，外网部署方式见 README。</p><button class="primary" type="submit">保存更新设置</button></form></section><section class="panel panel-body"><h2>登录密码</h2><p class="muted">当前账号：${esc(state.username)}</p><form id="passwordForm"><label for="oldPassword">当前密码</label><input id="oldPassword" name="oldPassword" type="password" autocomplete="current-password" required maxlength="72"><label for="newPassword">新密码</label><input id="newPassword" name="newPassword" type="password" autocomplete="new-password" required minlength="12" maxlength="72"><p class="help">12–72 字节。保存后所有会话失效，需要重新登录。</p><button type="submit">修改密码</button></form></section></div><div class="summary-note">数据目录包含源地址、节点凭据、规则和已发布快照。备份完整 data 目录即可迁移；首次设置后的账号密码以数据目录为准。</div>`;
}
function render() {
  if (!state) return;
  let page = location.hash.slice(1) || "overview";
  if (!pages[page]) page = "overview";
  $("#pageTitle").textContent = pages[page][0];
  $("#pageSubtitle").textContent = pages[page][1];
  $("#breadcrumb").textContent = $(`[data-page="${page}"]`).textContent;
  document
    .querySelectorAll("[data-page]")
    .forEach((a) => a.classList.toggle("active", a.dataset.page === page));
  $("#pageContent").innerHTML =
    page === "overview"
      ? overview()
      : page === "sources"
        ? `<div class="section-header"><div><h2>上游订阅</h2><p>编辑或删除源不会直接撤回已发布文件；重新生成集合后生效。</p></div><button class="primary" data-action="add-source">添加订阅源</button></div><div class="panel">${sourceTable()}</div>`
        : page === "collections"
          ? collections()
          : page === "rules"
            ? rules()
            : settings();
}
function openEditor(type, id) {
  const item =
    type === "source"
      ? state.sources.find((s) => s.id === id)
      : state.collections.find((c) => c.id === id);
  editing = { type, id };
  $("#editorTitle").textContent =
    (id ? "编辑" : "新建") + (type === "source" ? "订阅源" : "订阅集合");
  $("#editorError").textContent = "";
  $("#editorFields").innerHTML =
    `<label for="editName">名称</label><input id="editName" name="name" required maxlength="80" value="${esc(item?.name || "")}" placeholder="${type === "source" ? "例如：花云" : "例如：日常使用"}">` +
    (type === "source"
      ? `<label for="editUrl">订阅 URL</label><input id="editUrl" name="url" type="password" autocomplete="off" required maxlength="8192" value="${esc(item?.url || "")}" placeholder="https://…"><p class="help">支持 HTTP(S)；地址按凭据处理，保存在本地数据目录中。</p><label class="check-row"><input name="enabled" type="checkbox" ${item?.enabled !== false ? "checked" : ""}>启用并参与下一次聚合</label><p class="help">保存地址后，点击该源的“更新”抓取节点。</p>`
      : `<label class="check-row"><input name="allSources" id="allSources" type="checkbox" ${item?.allSources !== false ? "checked" : ""}>聚合全部已启用订阅源</label><label>或选择指定源</label><div class="check-list">${(state.sources || []).map((s) => `<label class="check-row"><input name="sourceIds" type="checkbox" value="${s.id}" ${item?.sourceIds?.includes(s.id) ? "checked" : ""}>${esc(s.name)}</label>`).join("") || '<p class="help">还没有订阅源，可以先选择聚合全部。</p>'}</div><p class="help">选择全部时，新添加并启用的源会在下次生成时自动加入。</p>`);
  $("#editor").showModal();
  $("#editName").focus();
}
$("#loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const b = e.submitter;
  b.disabled = true;
  $("#loginError").textContent = "";
  try {
    const d = await api("/login", "POST", {
      username: $("#username").value,
      password: $("#password").value,
    });
    csrf = d.csrf;
    $("#password").value = "";
    await load();
  } catch (err) {
    $("#loginError").textContent = err.message;
  } finally {
    b.disabled = false;
  }
});
$("#editorForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  const v = { name: f.get("name") };
  if (editing.type === "source") {
    v.url = f.get("url");
    v.enabled = f.has("enabled");
  } else {
    v.allSources = f.has("allSources");
    v.sourceIds = f.getAll("sourceIds");
  }
  e.submitter.disabled = true;
  try {
    await api(
      "/" +
        (editing.type === "source" ? "sources" : "collections") +
        (editing.id ? "/" + editing.id : ""),
      editing.id ? "PUT" : "POST",
      v,
    );
    $("#editor").close();
    notice(
      editing.type === "source"
        ? "订阅源已保存。点击“更新”取得本地节点。"
        : "集合已保存。点击“生成快照”发布当前范围。",
    );
    await load();
  } catch (err) {
    $("#editorError").textContent = err.message;
  } finally {
    $("#editorSave").disabled = false;
  }
});
document.addEventListener("submit", (e) => {
  if (e.target.id === "settingsForm") {
    e.preventDefault();
    task(e.submitter, async () => {
      const f = new FormData(e.target);
      await api("/settings", "PUT", {
        sourceIntervalMinutes: Number(f.get("sourceIntervalMinutes")),
        ruleIntervalHours: Number(f.get("ruleIntervalHours")),
      });
      await load();
      notice("更新设置已保存。");
    });
  }
  if (e.target.id === "passwordForm") {
    e.preventDefault();
    task(e.submitter, async () => {
      const f = new FormData(e.target);
      await api("/password", "POST", Object.fromEntries(f));
      showLogin();
      notice("密码已修改，请使用新密码登录。");
    });
  }
});
document.addEventListener("click", async (e) => {
  const b = e.target.closest("button");
  if (!b) return;
  if (b.hasAttribute("data-close")) {
    $("#editor").close();
    return;
  }
  const action = b.dataset.action,
    id = b.dataset.id;
  if (!action) return;
  const c = state?.collections.find((c) => c.id === id);
  if (action === "add-source" || action === "edit-source") {
    openEditor("source", id);
    return;
  }
  if (action === "add-collection" || action === "edit-collection") {
    openEditor("collection", id);
    return;
  }
  if (action === "copy") {
    try {
      await navigator.clipboard.writeText(link(c, b.dataset.format));
      notice("订阅链接已复制。");
    } catch {
      const input = b.previousElementSibling;
      input.type = "text";
      input.focus();
      input.select();
      notice("请手动复制已选中的订阅链接。");
    }
    return;
  }
  if (action === "download") {
    const a = document.createElement("a");
    a.href = link(c, b.dataset.format);
    a.download = "";
    a.rel = "noreferrer";
    document.body.append(a);
    a.click();
    a.remove();
    return;
  }
  if (
    action.startsWith("delete-") &&
    !confirm(
      action === "delete-source"
        ? "删除此源及其缓存？已发布的本地快照会保留。"
        : "删除此集合？它的所有订阅链接会立即失效。",
    )
  )
    return;
  if (
    action === "rotate" &&
    !confirm("更换此集合的订阅链接？旧链接会立即失效，需要在客户端替换。")
  )
    return;
  await task(b, async () => {
    if (action === "update-source")
      updateResult(await api("/sources/" + id + "/refresh", "POST", {}));
    if (action === "update-rules")
      updateResult(await api("/rules/refresh", "POST", {}));
    if (action === "build") {
      const r = await api("/collections/" + id + "/build", "POST", {});
      if (r.warnings?.length)
        notice(
          "快照已生成，部分格式不可用或保留旧版：\n" + r.warnings.join("\n"),
          true,
        );
      else notice("本地快照已生成。");
    }
    if (action === "delete-source") {
      await api("/sources/" + id, "DELETE", {});
      notice("源与缓存已删除，已发布快照保留。");
    }
    if (action === "delete-collection") {
      await api("/collections/" + id, "DELETE", {});
      notice("集合已删除，旧链接已失效。");
    }
    if (action === "rotate") {
      await api("/collections/" + id + "/rotate", "POST", {});
      notice("新链接已生效，旧链接已失效。");
    }
    await load();
  });
});
$("#refreshAll").addEventListener("click", (e) =>
  task(e.target, async () => {
    updateResult(await api("/refresh", "POST", {}));
    await load();
  }),
);
$("#logout").addEventListener("click", async () => {
  try {
    await api("/logout", "POST", {});
  } catch {}
  showLogin();
});
$("#closeNotice").addEventListener("click", () => ($("#notice").hidden = true));
window.addEventListener("hashchange", render);
document.addEventListener("visibilitychange", async () => {
  if (
    document.visibilityState === "visible" &&
    state &&
    !working &&
    !$("#editor").open
  ) {
    try {
      await load();
    } catch {}
  }
});
(async () => {
  try {
    const s = await api("/session");
    csrf = s.csrf;
    await load();
  } catch {
    showLogin();
  }
})();

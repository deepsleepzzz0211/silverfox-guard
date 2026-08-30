// popup 逻辑：展示当前站点状态、拦截统计、总开关
// 状态与事件文案涉及页面来源数据（URL/检测详情），一律 DOM 构建 + textContent，防止注入
const $ = id => document.getElementById(id);

function renderStatus(state) {
  const box = $("statusBox");
  $("enabledToggle").checked = state.enabled;

  box.replaceChildren();
  const strong = document.createElement("b");
  const detail = document.createElement("div");
  detail.style.cssText = "font-size:12.5px;line-height:1.6;word-break:break-all";

  if (!state.enabled) {
    box.className = "status off";
    strong.textContent = "⚠️ 防护已关闭";
    detail.textContent = "当前不会拦截任何网站，建议尽快开启。";
    box.append(strong, detail);
    return;
  }
  const v = state.verdict;
  if (v && v.level === "block") {
    box.className = "status block";
    strong.textContent = "⛔ 当前网站已被判定为危险";
    detail.textContent = `${v.category} · ${state.currentUrl}`;
  } else if (v && v.level === "warn") {
    box.className = "status warn";
    strong.textContent = "⚠️ 当前网站疑似银狐钓鱼站";
    detail.textContent = `${v.detail} · ${state.currentUrl}`;
  } else {
    box.className = "status safe";
    strong.textContent = state.currentUrl.startsWith("http")
      ? "✔ 当前网站未发现异常"
      : "🦊 银狐防护运行中";
    detail.textContent = state.currentUrl.startsWith("http")
      ? "导航级黑名单与启发式检测均未命中。"
      : "正在保护浏览器（当前页面非网页）";
  }
  box.append(strong, detail);
}

chrome.runtime.sendMessage({ type: "getPopupState" }, state => {
  if (!state) return;
  renderStatus(state);
  $("todayCount").textContent = state.stats.today;
  $("totalCount").textContent = state.stats.total;
  $("blCount").textContent = state.blocklistCount;
  $("blUpdated").textContent = state.updatedAt ? new Date(state.updatedAt).toLocaleString("zh-CN") : "内置基线";
  const eventsBox = $("events");
  eventsBox.replaceChildren();
  for (const e of (state.stats.events || []).slice(0, 5)) {
    const row = document.createElement("div");
    const cat = document.createElement("span");
    cat.className = "cat";
    cat.textContent = e.category;
    row.append(
      cat,
      ` · ${new Date(e.time).toLocaleTimeString("zh-CN")} · ${e.url}`
    );
    eventsBox.appendChild(row);
  }
});

$("enabledToggle").addEventListener("change", e => {
  chrome.runtime.sendMessage({ type: "toggleEnabled", enabled: e.target.checked }, () => {
    chrome.runtime.sendMessage({ type: "getPopupState" }, renderStatus);
  });
});

$("btnOptions").addEventListener("click", () => chrome.runtime.openOptionsPage());

$("btnHelp").addEventListener("click", () => {
  chrome.tabs.create({ url: chrome.runtime.getURL("pages/welcome/welcome.html") });
  window.close();
});

$("btnUpdate").addEventListener("click", () => {
  const btn = $("btnUpdate");
  btn.textContent = "⏳ 更新中…";
  btn.disabled = true;
  chrome.runtime.sendMessage({ type: "updateNow" }, res => {
    btn.textContent = res && res.errors && res.errors.length
      ? `✅ 完成（${res.errors.length} 个源失败）`
      : "✅ 更新完成";
    setTimeout(() => { btn.textContent = "🔄 立即更新黑名单"; btn.disabled = false; }, 2500);
    chrome.runtime.sendMessage({ type: "getPopupState" }, state => {
      if (state) $("blCount").textContent = state.blocklistCount;
    });
  });
});

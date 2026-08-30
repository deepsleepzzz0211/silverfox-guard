// options 逻辑：灵敏度 / 数据源开关 / 白名单管理 / 手动更新
const $ = id => document.getElementById(id);

function loadSettings() {
  chrome.runtime.sendMessage({ type: "getSettings" }, ({ settings, whitelist, blocklistMeta }) => {
    $("sensitivity").value = settings.sensitivity || "standard";
    $("srcLgsrc").checked = settings.sources?.lgsrc !== false;
    $("srcOtx").checked = settings.sources?.otx !== false;
    $("srcThreatfox").checked = settings.sources?.threatfox !== false;
    $("srcCybercrime").checked = settings.sources?.cybercrime !== false;
    $("srcYyt").checked = settings.sources?.yyt !== false;
    $("srcUbo").checked = settings.sources?.ubo !== false;
    $("srcInversion").checked = settings.sources?.inversion !== false;
    $("srcOpenphish").checked = settings.sources?.openphish !== false;
    $("srcUrlhaus").checked = settings.sources?.urlhaus !== false;
    $("otxPulseIds").value = settings.otxPulseIds || "";
    renderWhitelist(whitelist);
    if (blocklistMeta) {
      const c = blocklistMeta.counts;
      $("updatedAt").textContent = blocklistMeta.updatedAt
        ? `上次更新：${new Date(blocklistMeta.updatedAt).toLocaleString("zh-CN")} · 已核实 ${c.verified} / 疑似 ${c.suspect} / 钓鱼 ${c.phishing} / 恶意软件 ${c.malware}`
        : "尚未更新，使用内置基线";
    }
  });
}

function saveSettings() {
  const settings = {
    sensitivity: $("sensitivity").value,
    otxPulseIds: $("otxPulseIds").value.trim(),
    sources: {
      lgsrc: $("srcLgsrc").checked,
      otx: $("srcOtx").checked,
      threatfox: $("srcThreatfox").checked,
      cybercrime: $("srcCybercrime").checked,
      yyt: $("srcYyt").checked,
      ubo: $("srcUbo").checked,
      inversion: $("srcInversion").checked,
      openphish: $("srcOpenphish").checked,
      urlhaus: $("srcUrlhaus").checked,
    },
  };
  chrome.runtime.sendMessage({ type: "saveSettings", settings }, () => {});
}

function renderWhitelist(list) {
  const box = $("wlList");
  box.replaceChildren();
  if (!list.length) {
    const empty = document.createElement("div");
    empty.style.cssText = "color:#bbb;border:none";
    empty.textContent = "（空）";
    box.appendChild(empty);
    return;
  }
  for (const dom of list) {
    const row = document.createElement("div");
    const name = document.createElement("span");
    name.textContent = dom;
    const btn = document.createElement("button");
    btn.className = "mini";
    btn.textContent = "移除";
    btn.onclick = () =>
      chrome.runtime.sendMessage({ type: "removeWhitelist", domain: dom }, renderWhitelist);
    row.appendChild(name);
    row.appendChild(btn);
    box.appendChild(row);
  }
}

$("sensitivity").addEventListener("change", saveSettings);
["srcLgsrc", "srcOtx", "srcThreatfox", "srcCybercrime", "srcYyt", "srcUbo", "srcInversion", "srcOpenphish", "srcUrlhaus"].forEach(id =>
  $(id).addEventListener("change", saveSettings)
);
$("otxPulseIds").addEventListener("change", saveSettings);

$("btnAdd").addEventListener("click", () => {
  let dom = $("wlInput").value.trim().toLowerCase();
  dom = dom.replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  if (dom && /^[a-z0-9.-]+\.[a-z]{2,}$/.test(dom)) {
    chrome.runtime.sendMessage({ type: "addWhitelist", domain: dom }, () => {
      $("wlInput").value = "";
      chrome.runtime.sendMessage({ type: "getSettings" }, ({ whitelist }) => renderWhitelist(whitelist));
    });
  } else {
    alert("请输入合法的域名，例如 example.com");
  }
});

$("btnUpdate").addEventListener("click", () => {
  const btn = $("btnUpdate");
  btn.textContent = "⏳ 更新中…";
  btn.disabled = true;
  $("updateResult").textContent = "正在拉取 LGSRC / OpenPhish / URLhaus …";
  chrome.runtime.sendMessage({ type: "updateNow" }, res => {
    btn.textContent = "🔄 更新";
    btn.disabled = false;
    if (!res) { $("updateResult").textContent = "更新失败（后台未响应）"; return; }
    const c = res.counts;
    $("updatedAt").textContent = `上次更新：${new Date(res.updatedAt).toLocaleString("zh-CN")} · 已核实 ${c.verified} / 疑似 ${c.suspect} / 钓鱼 ${c.phishing} / 恶意软件 ${c.malware}`;
    $("updateResult").textContent = res.errors?.length
      ? "部分源失败：\n" + res.errors.join("\n")
      : "✅ 全部数据源更新成功。";
  });
});

loadSettings();

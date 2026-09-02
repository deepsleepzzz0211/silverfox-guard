// 银狐防护 - Service Worker（MV3）
import { analyzeUrl, evaluateUrl, riskyDownload, downloadBlacklistHit } from "../lib/detector.js";
import { updateBlocklist, ensureDailyAlarm, DEFAULT_OTX_PULSE_IDS } from "../lib/updater.js";
import { getDomainAgeDays } from "../lib/domain-age.js";
import { registrableDomain } from "../lib/host.js";
import { buildDnrRules, buildAllowRule } from "../lib/dnr.js";

const DEFAULT_SETTINGS = {
  enabled: true,
  sensitivity: "standard", // standard | strict
  sources: {
    lgsrc: true, otx: true, threatfox: true, cybercrime: true,
    ubo: true, inversion: true, yyt: true, openphish: true, urlhaus: true,
  },
  otxPulseIds: DEFAULT_OTX_PULSE_IDS, // 逗号分隔的 OTX pulse ID，可自行扩展订阅
};
const BLOCKLIST_KEY = "blocklistCache";
const SETTINGS_KEY = "settings";
const WHITELIST_KEY = "whitelist";          // 用户永久白名单（registrable domain 数组）
const TEMP_WHITELIST_KEY = "tempWhitelist"; // {domain: expiryMs}
const STATS_KEY = "stats";                  // {date, today, total, events:[最近10条]}
const DOWNLOAD_BLACKLIST_KEY = "downloadBlacklist"; // {domain: expiryMs} 用户拉黑的下载分发域名，90 天有效
const DOWNLOAD_BLACKLIST_TTL = 90 * 24 * 60 * 60 * 1000;
const DOWNLOAD_BLACKLIST_MAX = 500;
const DNR_STAMP_KEY = "dnrStamp";      // 黑名单签名，变化时才重建 DNR 动态规则
const DNR_ALLOWS_KEY = "dnrAllows";    // {ruleId: {domain, expiry}} 「仍要访问」的会话放行规则
let dnrEnabled = false;                // DNR 网络层拦截是否已生效（规则持久化，跨 SW 重启仍有效）
let dnrCovered = new Set();            // 已被 DNR 规则覆盖的域名（内存重建，用于跳过 webRequest 重复处理）

let blocklist = null; // 内存中的黑名单（blocklistCache 优先，否则内置基线）
let settings = { ...DEFAULT_SETTINGS };

async function loadBaseline() {
  const url = chrome.runtime.getURL("data/blocklist.json");
  const resp = await fetch(url);
  return resp.json();
}

async function loadState() {
  const { [SETTINGS_KEY]: s, [BLOCKLIST_KEY]: cached, [WHITELIST_KEY]: wl, [TEMP_WHITELIST_KEY]: twl, [DOWNLOAD_BLACKLIST_KEY]: dbl } =
    await chrome.storage.local.get([SETTINGS_KEY, BLOCKLIST_KEY, WHITELIST_KEY, TEMP_WHITELIST_KEY, DOWNLOAD_BLACKLIST_KEY]);
  settings = { ...DEFAULT_SETTINGS, ...(s || {}) };
  settings.sources = { ...DEFAULT_SETTINGS.sources, ...(s?.sources || {}) };
  blocklist = cached || (await loadBaseline());
  await chrome.storage.local.set({
    [WHITELIST_KEY]: wl || [],
    [TEMP_WHITELIST_KEY]: twl || {},
    [DOWNLOAD_BLACKLIST_KEY]: dbl || {},
  });
}

// ---------- 统计 ----------
async function recordBlock(category, url) {
  const today = new Date().toISOString().slice(0, 10);
  const { [STATS_KEY]: st } = await chrome.storage.local.get(STATS_KEY);
  const stats = st && st.date === today ? st : { date: today, today: 0, total: 0, events: [] };
  stats.today += 1;
  stats.total += 1;
  stats.events = [{ time: Date.now(), category, url: url.slice(0, 200) }, ...(stats.events || [])].slice(0, 10);
  await chrome.storage.local.set({ [STATS_KEY]: stats });
  updateBadge(stats.today);
}

async function updateBadge(count) {
  if (!count) count = (await getStats()).today;
  await chrome.action.setBadgeText({ text: count ? String(count) : "" });
  await chrome.action.setBadgeBackgroundColor({ color: "#d62828" });
}

async function getStats() {
  const today = new Date().toISOString().slice(0, 10);
  const { [STATS_KEY]: st } = await chrome.storage.local.get(STATS_KEY);
  return st && st.date === today ? st : { date: today, today: 0, total: 0, events: [] };
}

// ---------- 白名单 ----------
// baseDomainOf 由 lib/host.js 的 registrableDomain 单源提供
const baseDomainOf = registrableDomain;

async function isWhitelisted(url) {
  let host;
  try { host = new URL(url).hostname.toLowerCase(); } catch { return false; }
  const rd = baseDomainOf(host);
  const { [WHITELIST_KEY]: wl, [TEMP_WHITELIST_KEY]: twl } =
    await chrome.storage.local.get([WHITELIST_KEY, TEMP_WHITELIST_KEY]);
  if ((wl || []).includes(rd)) return true;
  const expiry = (twl || {})[rd];
  if (expiry && expiry > Date.now()) return true;
  if (expiry) {
    // 过期清理
    const next = { ...twl };
    delete next[rd];
    await chrome.storage.local.set({ [TEMP_WHITELIST_KEY]: next });
  }
  return false;
}

// ---------- 拦截 ----------
const WARNING_PAGE = chrome.runtime.getURL("pages/block/warning.html");
let warnSeq = 0;

// 待展示的拦截记录存 chrome.storage.session（官方最佳实践）：
// MV3 SW 约 30 秒空闲即被卸载，内存 Map 会丢失导致警告页拿到空数据；
// storage.session 会话级持久、不随 SW 终止丢失。
const WARN_KEY = "pendingWarnings";

async function saveWarning(seq, data) {
  const { [WARN_KEY]: map } = await chrome.storage.session.get(WARN_KEY);
  const now = Date.now();
  const entries = Object.entries({ ...(map || {}), [seq]: { ...data, at: now } })
    .filter(([, v]) => now - v.at < 60 * 60 * 1000) // 1 小时过期
    .sort((a, b) => Number(b[0]) - Number(a[0]))
    .slice(0, 50);
  await chrome.storage.session.set({ [WARN_KEY]: Object.fromEntries(entries) });
}

async function readWarning(seq) {
  const { [WARN_KEY]: map } = await chrome.storage.session.get(WARN_KEY);
  return (map || {})[seq] || null;
}

async function deleteWarning(seq) {
  const { [WARN_KEY]: map } = await chrome.storage.session.get(WARN_KEY);
  if (map?.[seq]) {
    const next = { ...map };
    delete next[seq];
    await chrome.storage.session.set({ [WARN_KEY]: next });
  }
}

async function getDownloadBlacklist() {
  const { [DOWNLOAD_BLACKLIST_KEY]: dbl } = await chrome.storage.local.get(DOWNLOAD_BLACKLIST_KEY);
  return dbl || {};
}

async function blockDownloadDomain(host) {
  const dbl = await getDownloadBlacklist();
  const now = Date.now();
  // 清理过期后再入库，保持容量上限
  for (const [dom, expiry] of Object.entries(dbl)) {
    if (expiry <= now) delete dbl[dom];
  }
  dbl[host] = now + DOWNLOAD_BLACKLIST_TTL;
  let entries = Object.entries(dbl).sort((a, b) => b[1] - a[1]);
  if (entries.length > DOWNLOAD_BLACKLIST_MAX) {
    entries = entries.slice(0, DOWNLOAD_BLACKLIST_MAX);
  }
  await chrome.storage.local.set({ [DOWNLOAD_BLACKLIST_KEY]: Object.fromEntries(entries) });
}

// ---------- DNR 网络层拦截（情报黑名单） ----------
// 情报黑名单命中由浏览器网络层直接重定向到警告页（恶意页首帧不可见）；
// 启发式 WARN 层仍走 webRequest 路径。规则持久化，仅在黑名单变化时重建。

async function syncDnrRules() {
  if (!blocklist) return;
  const stamp = JSON.stringify({
    u: blocklist.updatedAt || "",
    c: [Object.keys(blocklist.verified || {}).length, (blocklist.phishing || []).length, (blocklist.malware || []).length],
  });
  const { [DNR_STAMP_KEY]: last } = await chrome.storage.local.get(DNR_STAMP_KEY);
  const { [WHITELIST_KEY]: wl } = await chrome.storage.local.get(WHITELIST_KEY);
  const exclude = new Set(wl || []);
  const { rules, covered } = buildDnrRules(blocklist, { warningBase: WARNING_PAGE, exclude });
  dnrCovered = covered;

  if (last === stamp) {
    dnrEnabled = covered.size > 0;
    await chrome.storage.local.set({ dnrEnabled });
    return;
  }
  try {
    const existing = await chrome.declarativeNetRequest.getDynamicRules();
    await chrome.declarativeNetRequest.updateDynamicRules({
      addRules: rules,
      removeRuleIds: existing.map(r => r.id),
    });
    dnrEnabled = rules.length > 0;
    await chrome.storage.local.set({ [DNR_STAMP_KEY]: stamp, dnrEnabled });
  } catch (e) {
    dnrEnabled = false; // DNR 不可用时整体回退 webRequest 路径，功能不受损
    console.warn("DNR sync failed, webRequest fallback active:", e);
  }
}

function isDnrCovered(host) {
  const labels = host.split(".");
  for (let i = 0; i < labels.length - 1; i++) {
    if (dnrCovered.has(labels.slice(i).join("."))) return true;
  }
  return false;
}

async function addDnrAllowRule(domain) {
  try {
    const rd = registrableDomain(domain);
    const existing = await chrome.declarativeNetRequest.getSessionRules();
    const used = new Set(existing.map(r => r.id));
    let id = 2000000000;
    while (used.has(id)) id++;
    await chrome.declarativeNetRequest.updateSessionRules({ addRules: [buildAllowRule(rd, id)] });
    const { [DNR_ALLOWS_KEY]: map } = await chrome.storage.session.get(DNR_ALLOWS_KEY);
    await chrome.storage.session.set({
      [DNR_ALLOWS_KEY]: { ...(map || {}), [id]: { domain: rd, expiry: Date.now() + 30 * 60 * 1000 } },
    });
  } catch (e) {
    console.warn("DNR allow rule failed:", e);
  }
}

async function cleanupExpiredDnrAllows() {
  const { [DNR_ALLOWS_KEY]: map } = await chrome.storage.session.get(DNR_ALLOWS_KEY);
  if (!map) return;
  const now = Date.now();
  const expired = Object.entries(map).filter(([, v]) => v.expiry <= now).map(([id]) => Number(id));
  if (!expired.length) return;
  await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: expired });
  const next = { ...map };
  expired.forEach(id => delete next[id]);
  await chrome.storage.session.set({ [DNR_ALLOWS_KEY]: next });
}

async function handleNavigation(tabId, url) {
  if (!settings.enabled || !blocklist) return;
  if (await isWhitelisted(url)) return;

  // 用户拉黑的下载分发域名跨站免疫（借鉴 VirusDetector）：命中直接拦截
  let host = "";
  try { host = new URL(url).hostname.toLowerCase(); } catch { return; }
  const dlHit = downloadBlacklistHit(host, await getDownloadBlacklist());
  let verdict = dlHit
    ? { level: "block", category: "已拉黑的下载分发域名", detail: `域名 ${dlHit} 此前被你标记为下载分发域名，跨站生效`, score: 100 }
    : null;

  // 边界优化：仅当启发式已有可疑信号（score>0）时才查询 RDAP 域名年龄，
  // 正常网站零 RDAP 流量、零额外延迟；查询结果带 30 天缓存
  if (!verdict && !dlHit) {
    const first = evaluateUrl(url, blocklist, { sensitivity: settings.sensitivity });
    verdict = first.verdict;
    if (!verdict && first.score > 0) {
      const ageDays = await getDomainAgeDays(url);
      if (ageDays != null) {
        const second = evaluateUrl(url, blocklist, { sensitivity: settings.sensitivity, ageDays });
        verdict = second.verdict;
      }
    }
  }
  if (!verdict) return;

  // DNR 已在网络层拦截并重定向到警告页（带域名参数）的域名：
  // webRequest 路径不再重复处理，统计由警告页 dnr 流程上报
  if (verdict.level === "block" && dnrEnabled && isDnrCovered(host)) return;

  const seq = ++warnSeq;
  try {
    await saveWarning(seq, { url, verdict, tabId });
    await chrome.tabs.update(tabId, { url: `${WARNING_PAGE}?seq=${seq}` });
    await recordBlock(verdict.category, url);
  } catch (e) {
    await deleteWarning(seq).catch(() => {});
    console.warn("silverfox guard: redirect failed", e);
  }
}

chrome.webRequest.onBeforeRequest.addListener(
  details => {
    if (details.type !== "main_frame") return;
    const url = details.url;
    // 警告页自身与扩展页面跳过
    if (url.startsWith("chrome-extension://") || url.startsWith("edge-extension://")) return;
    handleNavigation(details.tabId, url);
  },
  { urls: ["http://*/*", "https://*/*"] }
);

// ---------- 下载防护 ----------
chrome.downloads.onCreated.addListener(async item => {
  if (!settings.enabled) return;
  const url = item.finalUrl || item.url || "";
  // onCreated 时刻 item.filename 可能为空，回退用 URL 路径末段判断扩展名
  let filename = (item.filename || "").split(/[\\/]/).pop();
  if (!filename) {
    try { filename = decodeURIComponent(new URL(url).pathname.split("/").pop() || ""); } catch { filename = ""; }
  }
  const ext = riskyDownload(filename);
  if (!ext) return;
  let host = "";
  try { host = new URL(url).hostname.toLowerCase(); } catch { return; }
  const dlHit = downloadBlacklistHit(host, await getDownloadBlacklist());
  const verdict = dlHit
    ? { category: "已拉黑的下载分发域名" }
    : analyzeUrl(url, blocklist, { sensitivity: settings.sensitivity });
  if (!verdict) return;
  const suffix = dlHit ? "该域名此前被你标记拉黑，跨站生效。" : "";
  chrome.notifications.create({
    type: "basic",
    iconUrl: chrome.runtime.getURL("icons/icon128.png"),
    title: "⚠️ 高风险文件下载警告",
    message: `该文件（${filename}）来自被判定为「${verdict.category}」的网站 ${host}。${suffix}银狐木马常伪装成软件安装包（.exe/.msi/.zip）传播，强烈建议不要运行，立即删除。`,
    priority: 2,
    requireInteraction: true,
  });
  await recordBlock("高风险下载:" + ext, url);
});

// ---------- 更新调度 ----------
async function runUpdate() {
  const baseline = await loadBaseline();
  const merged = await updateBlocklist(
    { ...settings.sources, otxPulseIds: settings.otxPulseIds },
    baseline
  );
  // 合并保留旧缓存中有而基线没有的条目（基线随版本更新，缓存累积最新情报）
  const { [BLOCKLIST_KEY]: cached } = await chrome.storage.local.get(BLOCKLIST_KEY);
  if (cached) {
    for (const [dom, cat] of Object.entries(cached.verified || {})) {
      if (!merged.verified[dom]) merged.verified[dom] = cat;
    }
    const old = new Set([...(cached.suspect || []), ...merged.suspect]);
    merged.suspect = [...old];
    const ph = new Set([...(cached.phishing || []), ...merged.phishing]);
    merged.phishing = [...ph];
    const mw = new Set([...(cached.malware || []), ...merged.malware]);
    merged.malware = [...mw];
  }
  blocklist = merged;
  await chrome.storage.local.set({ [BLOCKLIST_KEY]: merged });
  await syncDnrRules(); // 黑名单变化时重建 DNR 动态规则
  return merged;
}

chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === "daily-blocklist-update") runUpdate().catch(console.warn);
  if (alarm.name === "dnr-allow-cleanup") cleanupExpiredDnrAllows().catch(console.warn);
});

// ---------- 消息接口（popup / options / content / warning 页） ----------
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || typeof msg.type !== "string") { sendResponse(null); return true; }
  // 消息来源校验（官方最佳实践）：拒绝非本扩展的消息；内容脚本消息必须来自某个标签页
  if (sender.id && sender.id !== chrome.runtime.id) { sendResponse(null); return true; }
  const fromContentScript = !!sender.tab;
  (async () => {
    switch (msg.type) {
      case "getWarning": {
        sendResponse(await readWarning(msg.seq));
        break;
      }
      case "continueAnyway": {
        if (!fromContentScript || typeof msg.seq !== "number") { sendResponse(false); break; }
        const data = await readWarning(msg.seq);
        if (data) {
          const rd = registrableDomain(new URL(data.url).hostname);
          const { [TEMP_WHITELIST_KEY]: twl } = await chrome.storage.local.get(TEMP_WHITELIST_KEY);
          const next = { ...(twl || {}), [rd]: Date.now() + 30 * 60 * 1000 };
          await chrome.storage.local.set({ [TEMP_WHITELIST_KEY]: next });
          // seq 流放行同样要放开 DNR 规则，否则回跳原 URL 会被网络层再次拦截
          if (dnrEnabled) await addDnrAllowRule(rd);
          await deleteWarning(msg.seq);
          if (typeof data.tabId === "number" && data.tabId >= 0) {
            await chrome.tabs.update(data.tabId, { url: data.url });
          }
        }
        sendResponse(true);
        break;
      }
      case "continueDnr": {
        // DNR 警告页的「仍要访问」：会话放行规则 + 30 分钟临时白名单 + 回跳站点首页（原始路径在网络层不可知）
        if (!fromContentScript || typeof msg.domain !== "string") { sendResponse(false); break; }
        const domain = msg.domain.toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
        const rd = registrableDomain(domain);
        const { [TEMP_WHITELIST_KEY]: twl2 } = await chrome.storage.local.get(TEMP_WHITELIST_KEY);
        await chrome.storage.local.set({
          [TEMP_WHITELIST_KEY]: { ...(twl2 || {}), [rd]: Date.now() + 30 * 60 * 1000 },
        });
        if (dnrEnabled) await addDnrAllowRule(rd);
        if (typeof sender.tab?.id === "number" && sender.tab.id >= 0) {
          await chrome.tabs.update(sender.tab.id, { url: "https://" + domain + "/" });
        }
        sendResponse(true);
        break;
      }
      case "dnrBlock": {
        // DNR 警告页上报统计
        if (fromContentScript && typeof msg.domain === "string") {
          await recordBlock("威胁情报黑名单（网络层）", "https://" + msg.domain + "/");
        }
        sendResponse(true);
        break;
      }
      case "getPopupState": {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        const url = tab?.url || "";
        const verdict = url.startsWith("http")
          ? analyzeUrl(url, blocklist, { sensitivity: settings.sensitivity })
          : null;
        sendResponse({
          enabled: settings.enabled,
          sensitivity: settings.sensitivity,
          stats: await getStats(),
          currentUrl: url,
          verdict,
          blocklistCount: blocklist
            ? Object.keys(blocklist.verified).length + (blocklist.suspect?.length || 0) +
              (blocklist.phishing?.length || 0) + (blocklist.malware?.length || 0)
            : 0,
          updatedAt: blocklist?.updatedAt || null,
        });
        break;
      }
      case "toggleEnabled": {
        settings.enabled = msg.enabled;
        await chrome.storage.local.set({ [SETTINGS_KEY]: settings });
        sendResponse(true);
        break;
      }
      case "getSettings": {
        const { [WHITELIST_KEY]: wl } = await chrome.storage.local.get(WHITELIST_KEY);
        sendResponse({ settings, whitelist: wl || [], blocklistMeta: blocklist ? { updatedAt: blocklist.updatedAt, counts: counts(blocklist) } : null });
        break;
      }
      case "saveSettings": {
        settings = { ...settings, ...msg.settings };
        await chrome.storage.local.set({ [SETTINGS_KEY]: settings });
        sendResponse(true);
        break;
      }
      case "addWhitelist": {
        const dom = (msg.domain || "").trim().toLowerCase();
        if (dom) {
          const { [WHITELIST_KEY]: wl } = await chrome.storage.local.get(WHITELIST_KEY);
          const next = [...new Set([...(wl || []), dom])];
          await chrome.storage.local.set({ [WHITELIST_KEY]: next });
          sendResponse(next);
        }
        break;
      }
      case "removeWhitelist": {
        const { [WHITELIST_KEY]: wl } = await chrome.storage.local.get(WHITELIST_KEY);
        const next = (wl || []).filter(d => d !== msg.domain);
        await chrome.storage.local.set({ [WHITELIST_KEY]: next });
        sendResponse(next);
        break;
      }
      case "updateNow": {
        const merged = await runUpdate();
        sendResponse({ updatedAt: merged.updatedAt, errors: merged.errors, counts: counts(merged) });
        break;
      }
      case "blockDownloadDomain": {
        if (!fromContentScript || typeof msg.domain !== "string") { sendResponse(false); break; }
        const dom = msg.domain.trim().toLowerCase();
        if (dom) await blockDownloadDomain(dom);
        sendResponse(true);
        break;
      }
      case "contentSuspicion": {
        // content 脚本发现页面 DOM 仿冒特征，记录统计（不重复拦截）
        if (fromContentScript) {
          await recordBlock("页面仿冒特征", sender.tab.url || "");
        }
        sendResponse(true);
        break;
      }
      default:
        sendResponse(null);
    }
  })();
  return true; // 异步 sendResponse
});

function counts(bl) {
  return {
    verified: Object.keys(bl.verified || {}).length,
    suspect: (bl.suspect || []).length,
    phishing: (bl.phishing || []).length,
    malware: (bl.malware || []).length,
  };
}

// ---------- 启动 ----------
chrome.runtime.onInstalled.addListener(details => {
  ensureDailyAlarm().catch(console.warn);
  // 首次安装弹出欢迎引导页（小白友好：讲清楚会发生什么、误拦怎么办）
  if (details.reason === "install") {
    chrome.tabs.create({ url: chrome.runtime.getURL("pages/welcome/welcome.html") }).catch(console.warn);
  }
});
chrome.runtime.onStartup.addListener(() => {
  ensureDailyAlarm().catch(console.warn);
});

loadState()
  .then(() => syncDnrRules()) // SW 启动时确保 DNR 覆盖集与规则就绪（规则持久化，签名一致则跳过重建）
  .then(() => cleanupExpiredDnrAllows())
  .then(() => updateBadge())
  .catch(console.error);

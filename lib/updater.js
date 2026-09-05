// 银狐防护 - 黑名单每日更新
// 远程数据源与 tools/build_blocklist.py 一致：
//   LGSRC Archive_2（已核实银狐恶意网站）/ Archive_3（未核实疑似站点）
//   OTX「SilverFox (银狐)」专项 pulse（LGSRC 作者 LinggGao 维护，详情接口内嵌全部指标，无需鉴权）
//   OpenPhish 社区 feed（通用钓鱼 URL）/ URLhaus text feed（恶意软件分发 URL）
// 拉取失败时沿用上次数据或内置基线 data/blocklist.json。
import { registrableDomain } from "./host.js";

const SOURCES = {
  lgsrcVerified: "https://raw.githubusercontent.com/Lingggao/LGSRC/main/Archive_2.md",
  lgsrcSuspect: "https://raw.githubusercontent.com/Lingggao/LGSRC/main/Archive_3.md",
  otxPulse: "https://otx.alienvault.com/api/v1/pulses/",
  threatfox: "https://threatfox.abuse.ch/export/csv/recent/",
  cybercrime: "http://cybercrime-tracker.net/all.php",
  uboBadware: "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",
  inversion: "https://raw.githubusercontent.com/elliotwutingfeng/Inversion-DNSBL-Blocklists/main/Google_hostnames_light.txt",
  yyt: "https://deepformat.top/yh/fake.txt",
  openphish: "https://openphish.com/feed.txt",
  urlhaus: "https://urlhaus.abuse.ch/downloads/text/",
};

// 默认订阅的 OTX pulse：SilverFox 专项 + AlienVault 官方银狐 pulse
export const DEFAULT_OTX_PULSE_ID = "6a36fe5a3c1568785b59c4d7";
export const DEFAULT_OTX_PULSE_IDS = DEFAULT_OTX_PULSE_ID + ",652d51197fbe59ec2dd072a8";

const DOMAIN_RE = /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/;

function deobfuscate(text) {
  return text.replace(/\[\.\]/g, ".").replace(/\(\.\)/g, ".");
}

function hostOf(token) {
  token = deobfuscate(token).trim().toLowerCase();
  token = token.replace(/^h(?:tt|xx)ps?:\/\//, "");
  if (!token) return "";
  if (!token.includes("://")) token = "http://" + token;
  try {
    const host = new URL(token).hostname || "";
    const h = host.replace(/\.$/, "");
    return DOMAIN_RE.test(h) ? h : "";
  } catch {
    return "";
  }
}

function baseDomain(host) {
  const parts = host.split(".");
  if (parts.length > 2 && ["www", "web", "wap", "m"].includes(parts[0])) {
    return parts.slice(1).join(".");
  }
  return host;
}

// 共享托管平台（恶意样本常借道分发，整域拦截会误杀，直接丢弃）
const SHARED_PLATFORMS = new Set([
  "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
  "sourceforge.net", "dropbox.com", "dropboxusercontent.com",
  "google.com", "microsoft.com", "live.com", "onedrive.com",
  "wordpress.com", "medium.com", "t.me",
]);
// 租户型托管平台（每个子域独立租户，可拦完整子域；裸域名防御性丢弃）
const TENANT_PLATFORMS = new Set([
  "github.io", "gitlab.io", "pages.dev", "vercel.app", "netlify.app",
  "workers.dev", "r2.dev", "azurewebsites.net", "herokuapp.com",
  "firebaseapp.com", "web.app", "glitch.me", "repl.co",
  "000webhostapp.com", "blogspot.com", "amazonaws.com", "cloudfront.net",
  "azureedge.net", "b-cdn.net", "fly.dev", "firebaseio.com", "codeberg.page",
]);
// registrableDomain 由 lib/host.js 单源提供
// 与 tools/build_blocklist.py 的 filter_platform 保持一致
function filterPlatform(host) {
  const reg = registrableDomain(host);
  if (SHARED_PLATFORMS.has(reg)) return null;
  if (TENANT_PLATFORMS.has(reg) && host === reg) return null;
  return baseDomain(host);
}

// LGSRC Archive_2.md：| 日期 | URL | 类别 | 有效载荷 | URLhaus | 编号 |
export function parseLgsrcVerified(text) {
  const out = {};
  for (const line of text.split(/\r?\n/)) {
    const s = line.trim();
    if (!s.startsWith("|")) continue;
    const cells = s.replace(/^\||\|$/g, "").split("|").map(c => c.trim());
    if (cells.length < 3 || !/^\d{4}\//.test(cells[0] || "")) continue;
    const cat = cells[2] || "银狐关联恶意网站";
    for (const cell of [cells[1] || "", cells[3] || ""]) {
      for (const token of cell.split(/\s+/)) {
        const host = hostOf(token);
        const d = host ? filterPlatform(host) : null;
        if (d && !out[d]) out[d] = cat;
      }
    }
  }
  return out;
}

// LGSRC Archive_3.md：``` 代码块内的疑似域名
export function parseLgsrcSuspect(text) {
  const out = new Set();
  let inBlock = false;
  for (const line of text.split(/\r?\n/)) {
    const s = line.trim();
    if (s.startsWith("```")) { inBlock = !inBlock; continue; }
    if (!inBlock) continue;
    for (const token of s.split(/\s+/)) {
      const host = hostOf(token);
      const d = host ? filterPlatform(host) : null;
      if (d) out.add(d);
    }
  }
  return out;
}

// 纯 URL/域名行列表（OpenPhish / URLhaus / CyberCrime / Inversion / YYT）
export function parseUrlList(text) {
  const out = new Set();
  for (const line of text.split(/\r?\n/)) {
    const s = line.trim();
    if (!s || s.startsWith("#")) continue;
    const host = hostOf(s);
    const d = host ? filterPlatform(host) : null;
    if (d) out.add(d);
  }
  return out;
}

// OTX pulse 详情 JSON 的 indicators 内嵌全部指标（无需 API Key）。
// 只取 domain/hostname/URL；哈希与 IP 在浏览器扩展场景不可用。
// 与 LGSRC Archive_2 同作者（LinggGao）且为已核实恶意网站，按「已核实」级别入库。
export function parseOtxPulse(text) {
  const out = {};
  let data;
  try { data = JSON.parse(text); } catch { return out; }
  for (const ind of (data?.indicators || [])) {
    const type = String(ind?.type || "").toLowerCase();
    if (type !== "domain" && type !== "hostname" && type !== "url") continue;
    const host = hostOf(String(ind?.indicator || ""));
    if (!host) continue;
    const d = filterPlatform(host);
    if (d && !out[d]) out[d] = "SilverFox IOC（OTX 专项）";
  }
  return out;
}

// ThreatFox（abuse.ch）CSV：带引号字段，从注释头动态定位列；只取 domain/url 指标，
// 家族名（fk_malware，如 win.valley_rat/win.winos）作为拦截类别展示
export function parseThreatFoxCsv(text) {
  const out = {};
  const lines = text.split(/\r?\n/);
  let idxIoc = 2, idxType = 3, idxMalware = 5; // 兜底默认列序（2026-08 实测）
  for (const line of lines) {
    const s = line.trim();
    if (!s) continue;
    if (s.startsWith("#")) {
      const names = [...s.matchAll(/"([^"]+)"/g)].map(m => m[1]);
      if (names.includes("ioc_value") && names.includes("ioc_type")) {
        idxIoc = names.indexOf("ioc_value");
        idxType = names.indexOf("ioc_type");
        idxMalware = names.indexOf("fk_malware");
      }
      continue;
    }
    const cells = [...s.matchAll(/"((?:[^"]|"")*)"/g)].map(m => m[1].replace(/""/g, '"'));
    if (cells.length <= Math.max(idxIoc, idxType, idxMalware)) continue;
    const type = (cells[idxType] || "").trim().toLowerCase();
    if (type !== "domain" && type !== "url") continue; // ip:port / 哈希类自动丢弃
    const host = hostOf(cells[idxIoc] || "");
    const d = host ? filterPlatform(host) : null;
    if (d && !out[d]) out[d] = "ThreatFox·" + ((cells[idxMalware] || "unknown").trim());
  }
  return out;
}

// uBO uAssets badware.txt（GPL-3.0）：提取 `||domain^` 型 ABP 域名规则。
// 路径规则取主机名部分，$ 选项 / @@ 例外 / 注释 / 含通配符的行跳过。
export function parseAdblockDomains(text) {
  const out = new Set();
  for (const raw of text.split(/\r?\n/)) {
    let s = raw.trim();
    if (!s || s.startsWith("!") || s.startsWith("#") || s.startsWith("@@")) continue;
    if (!s.startsWith("||")) continue;
    s = s.slice(2);
    const end = s.search(/[\^$]/);
    let dom = end === -1 ? s : s.slice(0, end);
    const slash = dom.indexOf("/");
    if (slash !== -1) dom = dom.slice(0, slash);
    if (!dom || /[*?[\]]/.test(dom)) continue;
    const host = hostOf(dom);
    const d = host ? filterPlatform(host) : null;
    if (d) out.add(d);
  }
  return out;
}

// GitHub raw 直连在部分网络（尤其国内）抖动，统一走 jsdelivr CDN 回退
function jsdelivrMirror(url) {
  const m = url.match(/^https:\/\/raw\.githubusercontent\.com\/([^/]+)\/([^/]+)\/([^/]+)\/(.+)$/);
  return m ? `https://cdn.jsdelivr.net/gh/${m[1]}/${m[2]}@${m[3]}/${m[4]}` : null;
}

async function fetchTextSmart(url, ms) {
  try {
    return await fetchWithTimeout(url, ms);
  } catch (e) {
    const mirror = jsdelivrMirror(url);
    if (mirror) {
      try { return await fetchWithTimeout(mirror, ms); } catch { /* 主源+镜像均失败，抛原始错误 */ }
    }
    throw e;
  }
}

async function fetchWithTimeout(url, ms = 60000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    const resp = await fetch(url, { cache: "no-store", signal: ctrl.signal });
    if (!resp.ok) throw new Error(`HTTP ${resp.status} for ${url}`);
    return await resp.text();
  } finally {
    clearTimeout(timer);
  }
}

/**
 * 拉取全部源并合并。单个源失败不影响其他源。
 * @param {object} enabled {lgsrc,otx,threatfox,cybercrime,ubo,inversion,yyt,openphish,urlhaus:boolean, otxPulseIds?:string}
 * @param {object} baseline 内置基线 data/blocklist.json（作为兜底合并）
 * @returns 合并后的黑名单对象
 */
export async function updateBlocklist(enabled, baseline) {
  const verified = { ...(baseline?.verified || {}) };
  let suspect = new Set(baseline?.suspect || []);
  const phishing = new Set(baseline?.phishing || []);
  const malware = new Set(baseline?.malware || []);
  const errors = [];

  const jobs = [];
  if (enabled.lgsrc !== false) {
    jobs.push(
      fetchTextSmart(SOURCES.lgsrcVerified).then(t => {
        Object.assign(verified, parseLgsrcVerified(t));
      }).catch(e => errors.push("LGSRC 已核实: " + e.message)),
      fetchTextSmart(SOURCES.lgsrcSuspect).then(t => {
        parseLgsrcSuspect(t).forEach(d => suspect.add(d));
      }).catch(e => errors.push("LGSRC 疑似: " + e.message))
    );
  }
  if (enabled.otx !== false) {
    const ids = String(enabled.otxPulseIds || DEFAULT_OTX_PULSE_ID)
      .split(/[\s,;]+/).map(s => s.trim()).filter(Boolean).slice(0, 20);
    for (const id of ids) {
      jobs.push(
        fetchWithTimeout(SOURCES.otxPulse + encodeURIComponent(id)).then(t => {
          Object.assign(verified, parseOtxPulse(t));
        }).catch(e => errors.push("OTX pulse " + id.slice(0, 8) + ": " + e.message))
      );
    }
  }
  if (enabled.threatfox !== false) {
    jobs.push(
      fetchWithTimeout(SOURCES.threatfox).then(t => {
        Object.assign(verified, parseThreatFoxCsv(t));
      }).catch(e => errors.push("ThreatFox: " + e.message))
    );
  }
  if (enabled.cybercrime !== false) {
    jobs.push(
      fetchWithTimeout(SOURCES.cybercrime).then(t => {
        parseUrlList(t).forEach(d => malware.add(d));
      }).catch(e => errors.push("CyberCrime Tracker: " + e.message))
    );
  }
  if (enabled.ubo !== false) {
    jobs.push(
      fetchTextSmart(SOURCES.uboBadware).then(t => {
        parseAdblockDomains(t).forEach(d => phishing.add(d));
      }).catch(e => errors.push("uBO badware: " + e.message))
    );
  }
  if (enabled.inversion !== false) {
    jobs.push(
      fetchTextSmart(SOURCES.inversion).then(t => {
        parseUrlList(t).forEach(d => phishing.add(d));
      }).catch(e => errors.push("Inversion-DNSBL: " + e.message))
    );
  }
  if (enabled.yyt !== false) {
    jobs.push(
      fetchWithTimeout(SOURCES.yyt).then(t => {
        // 银狐专项仿冒域名，按已核实级别硬拦（个人源，失败自动降级不影响其他源）
        const mapped = {};
        parseUrlList(t).forEach(d => { mapped[d] = "银狐仿冒域名（YYT 专项）"; });
        Object.assign(verified, mapped);
      }).catch(e => errors.push("YYT 银狐源: " + e.message))
    );
  }
  if (enabled.openphish !== false) {
    jobs.push(
      fetchWithTimeout(SOURCES.openphish).then(t => {
        parseUrlList(t).forEach(d => phishing.add(d));
      }).catch(e => errors.push("OpenPhish: " + e.message))
    );
  }
  if (enabled.urlhaus !== false) {
    jobs.push(
      fetchWithTimeout(SOURCES.urlhaus).then(t => {
        parseUrlList(t).forEach(d => malware.add(d));
      }).catch(e => errors.push("URLhaus: " + e.message))
    );
  }
  await Promise.all(jobs);

  // 已核实域名从疑似/通用列表中剔除，避免级别覆盖混乱
  for (const dom of Object.keys(verified)) {
    suspect.delete(dom);
    phishing.delete(dom);
    malware.delete(dom);
  }

  return {
    verified,
    suspect: [...suspect],
    phishing: [...phishing],
    malware: [...malware],
    updatedAt: new Date().toISOString(),
    errors,
  };
}

export async function ensureDailyAlarm() {
  await chrome.alarms.create("daily-blocklist-update", { periodInMinutes: 24 * 60 });
  // DNR 会话放行规则的 30 分钟过期清理（由 service-worker 的 onAlarm 消费）
  await chrome.alarms.create("dnr-allow-cleanup", { periodInMinutes: 30 });
}

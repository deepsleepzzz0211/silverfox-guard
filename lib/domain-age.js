// 银狐防护 - RDAP 域名年龄查询（借鉴 VirusDetector「域名年龄评分」思路）
// RDAP（RFC 9083）是 WHOIS 的标准化替代，返回 JSON 且多数注册局允许跨域读取。
// 查询结果按 registrable domain 缓存到 chrome.storage.local：
//   成功缓存 30 天（域名年龄只会单调增长），查询失败缓存 6 小时后重试。
// 所有异常都静默降级（返回 null = 不参与评分），绝不因情报查询阻塞或误拦导航。
import { registrableDomain } from "./host.js";

const AGE_PREFIX = "age:";
const SUCCESS_TTL = 30 * 24 * 60 * 60 * 1000;   // 30 天
const FAILURE_TTL = 6 * 60 * 60 * 1000;          // 6 小时
const RDAP_ENDPOINT = "https://rdap.org/domain/"; // IANA bootstrap 跳转服务

// 租户/代码托管平台：注册年龄是平台自己的（几十年），对子域无参考价值，跳过
const PLATFORM_DOMAINS = new Set([
  "github.io", "gitlab.io", "pages.dev", "vercel.app", "netlify.app",
  "workers.dev", "r2.dev", "azurewebsites.net", "herokuapp.com",
  "firebaseapp.com", "web.app", "glitch.me", "repl.co",
  "000webhostapp.com", "blogspot.com", "codeberg.page", "fly.dev",
  "github.com", "gitlab.com", "bitbucket.org", "gitee.com", "gitee.io",
]);

async function fetchRdapAge(registrable, timeoutMs = 3500) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const resp = await fetch(RDAP_ENDPOINT + encodeURIComponent(registrable), {
      cache: "no-store",
      signal: ctrl.signal,
      headers: { Accept: "application/rdap+json, application/json" },
    });
    if (!resp.ok) throw new Error(`RDAP HTTP ${resp.status}`);
    const data = await resp.json();
    const reg = (data.events || []).find(e => e.eventAction === "registration");
    if (!reg?.eventDate) throw new Error("RDAP 无 registration 事件");
    const ts = Date.parse(reg.eventDate);
    if (Number.isNaN(ts)) throw new Error("RDAP 日期无法解析");
    return (Date.now() - ts) / 86400000; // 天
  } finally {
    clearTimeout(timer);
  }
}

/**
 * 查询域名注册年龄（天）。带缓存与全链路降级。
 * @param {string} url 当前导航 URL
 * @returns {Promise<number|null>} 注册天数；无法判断时返回 null
 */
/**
 * 提取适合做 RDAP 查询的 registrable domain；不适合时返回 null（纯函数，可单测）。
 * 排除：非 http(s)、IP/localhost、无点单标签、租户平台（年龄是平台自己的，对子域无参考价值）。
 */
export function rdapTargetFor(url) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return null;
  const host = (u.hostname || "").toLowerCase();
  if (!host || /^[0-9.]+$/.test(host) || host === "localhost" || !host.includes(".")) return null;
  const registrable = registrableDomain(host);
  if (PLATFORM_DOMAINS.has(registrable)) return null;
  return registrable;
}

export async function getDomainAgeDays(url) {
  const registrable = rdapTargetFor(url);
  if (!registrable) return null;

  const key = AGE_PREFIX + registrable;
  try {
    const { [key]: cached } = await chrome.storage.local.get(key);
    if (cached && Date.now() - cached.at < (cached.ok ? SUCCESS_TTL : FAILURE_TTL)) {
      return cached.ok ? cached.ageDays : null;
    }
  } catch { /* 存储异常时继续查询 */ }

  let result = null;
  let ok = false;
  try {
    const ageDays = await fetchRdapAge(registrable);
    result = ageDays;
    ok = true;
  } catch { /* RDAP 不可用/域名不支持 → 静默降级 */ }

  try {
    await chrome.storage.local.set({ [key]: { ok, ageDays: result, at: Date.now() } });
  } catch { /* 缓存写失败不影响返回 */ }
  return result;
}

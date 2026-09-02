// 银狐防护 - 启发式检测引擎
// 三层判定：1) 威胁情报黑名单精确匹配  2) 品牌仿冒/typosquatting 启发式  3) 可疑域名特征评分
// 检测规则依据 CNCERT 2026-05 银狐通报与 360《2025 银狐木马年度报告》归纳的域名特征：
//   仿冒品牌词 + .com.cn/.hl.cn 等可疑后缀、字母重复/缺字/错拼、zh/cn/apps/web/office/pc 模板词、
//   随机字符串子域、punycode 混淆。
import { registrableDomain } from "./host.js";

// 常被银狐仿冒的品牌（来源：LGSRC《常被银狐仿冒的软件列表》精选 + CNCERT 通报）
// official: 品牌官方可注册域名（registrable domain / 已知官网域名后缀）
export const BRANDS = [
  { token: "wps", name: "WPS Office", official: ["wps.cn", "wps.com", "wpscdn.com", "kingsoft.com", "docer.com"] },
  { token: "chrome", name: "Google Chrome", official: ["google.com", "google.cn", "chrome.com", "chromium.org"] },
  { token: "google", name: "Google", official: ["google.com", "google.cn", "googleapis.com"] },
  { token: "wechat", name: "微信", official: ["weixin.qq.com", "wechat.com", "qq.com"] },
  { token: "weixin", name: "微信", official: ["weixin.qq.com", "qq.com"] },
  { token: "dingtalk", name: "钉钉", official: ["dingtalk.com", "alibaba.com"] },
  { token: "oray", name: "贝锐向日葵", official: ["oray.com", "sunlogin.oray.com"] },
  { token: "sunlogin", name: "贝锐向日葵", official: ["oray.com"] },
  { token: "todesk", name: "ToDesk", official: ["todesk.com"] },
  { token: "anydesk", name: "AnyDesk", official: ["anydesk.com"] },
  { token: "teamviewer", name: "TeamViewer", official: ["teamviewer.com"] },
  { token: "i4", name: "爱思助手", official: ["i4.cn"], minTokenLen: 2 },
  { token: "i4tools", name: "爱思助手", official: ["i4.cn"] },
  { token: "letsvpn", name: "快连 VPN", official: [] },
  { token: "kugou", name: "酷狗音乐", official: ["kugou.com"] },
  { token: "kuwo", name: "酷我音乐", official: ["kuwo.cn"] },
  { token: "netease", name: "网易云音乐", official: ["163.com", "netease.com"] },
  { token: "music163", name: "网易云音乐", official: ["163.com"] },
  { token: "meitu", name: "美图秀秀", official: ["meitu.com", "xiuxiu.meitu.com"] },
  { token: "youdao", name: "有道翻译", official: ["youdao.com"] },
  { token: "fanyi", name: "翻译类软件", official: [] },
  { token: "baidu", name: "百度网盘", official: ["baidu.com", "baidupan.com"] },
  { token: "aliyunpan", name: "阿里云盘", official: ["aliyundrive.com", "alibaba.com"] },
  { token: "lanzou", name: "蓝奏云", official: ["lanzou.com", "lanzoui.com", "lanpv.com"] },
  { token: "jianguoyun", name: "坚果云", official: ["jianguoyun.com"] },
  { token: "quark", name: "夸克", official: ["quark.cn", "uc.cn"] },
  { token: "xunlei", name: "迅雷", official: ["xunlei.com"] },
  { token: "thunder", name: "迅雷", official: ["xunlei.com"] },
  { token: "foxit", name: "福昕 PDF", official: ["foxit.com.cn", "foxitsoftware.cn"] },
  { token: "fuxin", name: "福昕 PDF（错拼仿冒）", official: ["foxit.com.cn"] },
  { token: "huorong", name: "火绒安全", official: ["huorong.cn"] },
  { token: "deepseek", name: "DeepSeek", official: ["deepseek.com"] },
  { token: "doubao", name: "豆包", official: ["doubao.com", "bytedance.com"] },
  { token: "feishu", name: "飞书", official: ["feishu.cn", "larksuite.com", "bytedance.com"] },
  { token: "lark", name: "飞书/Lark", official: ["larksuite.com", "feishu.cn"], minTokenLen: 4 },
  { token: "ludashi", name: "鲁大师", official: ["ludashi.com"] },
  { token: "sogou", name: "搜狗", official: ["sogou.com", "sogoucdn.com"] },
  { token: "xunyou", name: "迅游加速器", official: ["xunyou.com"] },
  { token: "jiasuqi", name: "网游加速器", official: [] },
  { token: "mydrivers", name: "驱动之家", official: ["mydrivers.com"] },
  { token: "qudong", name: "驱动类下载站", official: [] },
  { token: "zoom", name: "Zoom", official: ["zoom.us", "zoom.com"] },
  { token: "telegram", name: "Telegram", official: ["telegram.org", "t.me"] },
  { token: "whatsapp", name: "WhatsApp", official: ["whatsapp.com"] },
  { token: "line", name: "LINE", official: ["line.me", "linecorp.com"], minTokenLen: 4 },
  { token: "viber", name: "Viber", official: ["viber.com"], minTokenLen: 5 },
  { token: "winrar", name: "WinRAR", official: ["win-rar.com", "rarlab.com"] },
  { token: "7zip", name: "7-Zip", official: ["7-zip.org"] },
  { token: "xiaohongshu", name: "小红书", official: ["xiaohongshu.com", "xhscdn.com"] },
  { token: "dangbei", name: "当贝", official: ["dangbei.com"] },
  { token: "xiaoheihe", name: "小黑盒", official: ["xiaoheihe.cn"] },
  { token: "kuike", name: "夸克网盘（错拼仿冒）", official: ["quark.cn"] },
  { token: "kuake", name: "夸克网盘（错拼仿冒）", official: ["quark.cn"] },
  { token: "office", name: "Office", official: ["microsoft.com", "office.com", "live.com", "microsoftonline.com"], minTokenLen: 6 },
];

// CNCERT 通报的银狐域名命名模板词
const TEMPLATE_WORDS = ["zh", "apps", "app", "web", "office", "download", "dl", "pc", "ppc", "zn", "zb", "wb", "setup", "install", "soft", "software", "xiazai", "xz"];

// 银狐偏好的 TLD（CNCERT：.hl.cn 占 42.6%、.com.cn 占 30.8%）
const RISKY_TLDS = new Set(["com.cn", "hl.cn", "net.cn", "cyou", "cfd", "sbs", "top", "icu", "xyz", "coco", "icbc"]);
// 银狐偏好的二级地域后缀（如 .com.cn / .hl.cn 之外的可用组合，谨慎加权）
const SOFT_TLDS = new Set(["cn", "cc", "vip", "club", "shop", "site", "online", "buzz", "lol"]);

// 可信租户平台（借鉴 VirusDetector「可信平台白名单」）：每个子域是独立租户，
// 正当项目可能部署在上面（如 github.io 上的开源工具站），跳过品牌仿冒评分避免误报；
// 威胁情报黑名单层不受此豁免（情报已核实的恶意子域照样拦截）。
export const PLATFORM_TRUST = new Set([
  "github.io", "gitlab.io", "pages.dev", "vercel.app", "netlify.app",
  "workers.dev", "r2.dev", "azurewebsites.net", "herokuapp.com",
  "firebaseapp.com", "web.app", "glitch.me", "repl.co",
  "000webhostapp.com", "blogspot.com", "codeberg.page", "fly.dev",
  "gitee.io", "gitee.com", "github.com", "gitlab.com", "bitbucket.org",
]);

// registrableDomain 由 lib/host.js 单源提供

function levenshtein(a, b) {
  if (a === b) return 0;
  const m = a.length, n = b.length;
  if (!m) return n;
  if (!n) return m;
  let prev = new Array(n + 1), curr = new Array(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;
  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    [prev, curr] = [curr, prev];
  }
  return prev[n];
}

// 压缩连续重复字母：chrromsoex -> chromsoex（银狐常见“字母重复”混淆）
function collapseDuplicates(s) {
  return s.replace(/(.)\1{1,}/g, "$1");
}

function isMostlyRandom(sld) {
  if (sld.length < 10) return false;
  const letters = sld.replace(/[^a-z]/g, "");
  if (letters.length < 10) return false;
  const vowels = (letters.match(/[aeiou]/g) || []).length;
  const vowelRatio = vowels / letters.length;
  const maxRun = Math.max(0, ...(letters.match(/[^aeiou]{3,}/g) || [""]).map(r => r.length));
  // 数字占比高（wps_setup_251211 风格）也算随机感
  const digits = (sld.match(/\d/g) || []).length;
  return vowelRatio < 0.2 || maxRun >= 5 || digits / sld.length > 0.4;
}

function tokenBoundary(host, token) {
  // token 是否作为独立片段出现（wps-download.com 命中；wpspp.com 不因 'p' 误命中）
  const padded = "." + host.replace(/[-_.]/g, ".") + ".";
  const t = "." + token + ".";
  if (padded.includes(t)) return true;
  return false;
}

// 银狐常见「品牌词+模板词+数字」连写在一个 label 里（如 wpszh、wps-app25、baiduyunpan），
// 先剥离模板词/尾部数字再做边界判断，避免 wpszh.com.cn 这类连写域名漏检。
function labelAfterStrip(label) {
  let s = label.toLowerCase();
  for (const w of TEMPLATE_WORDS) {
    s = s.split(w).join("-");
  }
  return s.replace(/\d+$/g, "");
}

function brandInHost(host, token) {
  if (tokenBoundary(host, token)) return true;
  return host
    .split(".")
    .some(label => tokenBoundary(labelAfterStrip(label), token) && label.length <= token.length + 8);
}

const indexCache = new WeakMap();

// 为黑名单构建 {域名 -> {level, category}} 索引，O(1) 匹配
function buildIndex(bl) {
  const idx = new Map();
  const add = (dom, level, category) => {
    if (!dom || idx.has(dom)) return;
    idx.set(dom, { level, category });
  };
  for (const [dom, cat] of Object.entries(bl.verified || {})) add(dom, "block", cat || "威胁情报黑名单");
  for (const dom of bl.phishing || []) add(dom, "block", "钓鱼网站");
  for (const dom of bl.malware || []) add(dom, "block", "恶意软件分发站");
  for (const dom of bl.suspect || []) add(dom, "suspect", "LGSRC 未核实疑似站点");
  return idx;
}

function getIndex(bl) {
  let idx = indexCache.get(bl);
  if (!idx) {
    idx = buildIndex(bl);
    indexCache.set(bl, idx);
  }
  return idx;
}

/**
 * 全量评估：无论是否达到拦截阈值都返回 {verdict, score, signals}，
 * 供调用方做"分数>0 才查询 RDAP 年龄"等边界优化。
 * @returns {{verdict: null|{level,category,detail,score}, score: number, signals: string[]}}
 */
export function evaluateUrl(url, bl, opts = {}) {
  const out = { verdict: null, score: 0, signals: [] };
  const below = (score, signals) => {
    out.score = score;
    out.signals = signals;
    const threshold = (opts.sensitivity === "strict" ? 40 : 55);
    if (score >= threshold) {
      out.verdict = { level: "warn", category: "疑似银狐钓鱼站", detail: signals.join("；"), score };
    }
    return out;
  };

  let u;
  try { u = new URL(url); } catch { return out; }
  if (u.protocol !== "http:" && u.protocol !== "https:") return out;
  let host = (u.hostname || "").toLowerCase();
  if (host.endsWith(".")) host = host.slice(0, -1);
  if (!host || /^[0-9.]+$/.test(host) || host === "localhost") return out; // IP/本地跳过（IP 恶意站后续可加）

  const rd = registrableDomain(host);
  const strict = opts.sensitivity === "strict";
  const onPlatform = PLATFORM_TRUST.has(rd);

  // ---- 第 1 层：威胁情报黑名单 ----
  const idx = getIndex(bl);
  // 沿 host → registrable domain 逐级查（父域命中时子域同拦）
  const labels = host.split(".");
  for (let i = 0; i < labels.length - 1; i++) {
    const candidate = labels.slice(i).join(".");
    const hit = idx.get(candidate);
    if (hit) {
      if (hit.level === "block") {
        out.verdict = { level: "block", category: hit.category, detail: `域名 ${candidate} 命中威胁情报黑名单`, score: 100 };
        out.score = 100;
        return out;
      }
      if (hit.level === "suspect") {
        out.verdict = {
          level: "warn",
          category: "疑似恶意网站（未核实）",
          detail: `域名 ${candidate} 被 LGSRC 记录为疑似恶意站点（未核实，可能误报）`,
          score: 60,
        };
        out.score = 60;
        return out;
      }
    }
  }

  let score = 0;
  const signals = [];

  // ---- 第 2 层：品牌仿冒（可信平台豁免）----
  if (!onPlatform) {
    const sld = rd.split(".")[0];
    const sldBase = sld.replace(/\d+$/, "");
    const tld = rd.split(".").slice(1).join(".");
    const riskyTld = RISKY_TLDS.has(tld);
    const softTld = SOFT_TLDS.has(tld);

    let brandSignal = false; // 是否命中任何品牌仿冒信号（用于组合加成）
    for (const brand of BRANDS) {
      if (!brand.token || brand.hidden) continue;
      const minLen = brand.minTokenLen || 3;
      if (brand.token.length < minLen) continue;
      if (!host.includes(brand.token)) continue;
      const isOfficial = (brand.official || []).some(o => rd === o || rd.endsWith("." + o) || o.endsWith("." + rd));
      if (isOfficial) continue;

      // 匹配方式 1：品牌词作为独立片段（wps-download.com、wpszh.com.cn 模板词连写）
      let prefixHit = false;
      if (brandInHost(host, brand.token)) {
        score += 45;
        brandSignal = true;
        signals.push(`域名包含仿冒品牌词「${brand.name}」（${brand.token}）但非官方域名`);
        break;
      }
      // 匹配方式 2：品牌前缀 + 任意短尾缀连写（wpsar.com.cn = wps + ar，无边界无模板词，
      // 是实测漏网形态）；尾缀超过 4 字符不判，避免误伤 zoomcar.com 这类正当前缀站
      const label = host.split(".").find(l =>
        l.startsWith(brand.token) && l.length > brand.token.length && l.length - brand.token.length <= 4);
      if (label) {
        score += 45;
        brandSignal = true;
        signals.push(`域名以仿冒品牌词「${brand.name}」开头（${label}）但非官方域名`);
        break;
      }
    }

    // 组合加成：品牌仿冒 + 银狐偏好后缀（CNCERT 通报 .com.cn/.hl.cn 占 73.4%）
    if (brandSignal && riskyTld) {
      score += 20;
      signals.push(`品牌仿冒 + 银狐偏好后缀 .${tld} 组合`);
    }

    // ---- 第 3 层：域名特征评分 ----
    // typosquatting：与品牌 token 编辑距离过近
    for (const brand of BRANDS) {
      if (!brand.token || brand.token.length < 5) continue;
      const isOfficial = (brand.official || []).some(o => rd === o || rd.endsWith("." + o));
      if (isOfficial) continue;
      const variants = [sldBase, collapseDuplicates(sldBase)];
      for (const v of variants) {
        if (Math.abs(v.length - brand.token.length) > 2) continue;
        const dist = levenshtein(v, brand.token);
        if (dist > 0 && dist <= (strict ? 3 : 2)) {
          score += 50;
          signals.push(`域名「${sld}」与品牌词「${brand.token}」（${brand.name}）高度相似（编辑距离 ${dist}）`);
          break;
        }
      }
    }

    // 可疑 TLD 组合：品牌词/模板词/随机串 + com.cn / hl.cn 等
    if (riskyTld) {
      if (sld.length >= 6 && isMostlyRandom(sld)) {
        score += 35;
        signals.push(`随机风格子域 + 银狐偏好后缀 .${tld}`);
      } else if (TEMPLATE_WORDS.some(w => tokenBoundary(host, w))) {
        score += 25;
        signals.push(`包含银狐模板词 + 银狐偏好后缀 .${tld}`);
      } else if (strict) {
        score += 15;
        signals.push(`使用银狐偏好后缀 .${tld}（严格模式）`);
      }
    } else if (softTld && sld.length >= 8 && isMostlyRandom(sld)) {
      score += 20;
      signals.push(`随机风格域名 + 可疑后缀 .${tld}`);
    }

    // punycode（国际化域名混淆）
    if (host.startsWith("xn--") || host.includes(".xn--")) {
      score += 35;
      signals.push("punycode 国际化域名（常见于品牌伪装）");
    }
  }

  // ---- 第 4 层：域名年龄（借鉴 VirusDetector，RDAP 查询结果由调用方注入）----
  // 新注册域名显著加权（银狐钓鱼域名高频批量注册后速抛）；老域名减分抵消部分可疑分。
  if (typeof opts.ageDays === "number" && Number.isFinite(opts.ageDays)) {
    const d = opts.ageDays;
    if (d <= 120) {
      // S 型衰减：注册当天约 +29，21 天约 +15，120 天后归零
      const bonus = Math.round(30 / (1 + Math.exp((d - 21) / 7)));
      if (bonus > 0) {
        score += bonus;
        signals.push(`域名注册仅 ${Math.max(0, Math.round(d))} 天（新注册域名）`);
      }
    } else if (d >= 365 && score >= 20) {
      score -= 15;
      signals.push(`域名已注册超过 1 年（可信减分）`);
    }
  }

  // 路径关键词加成（仅在已有可疑信号时）
  if (score > 0 && /(^|\/)(download|setup|install|soft|xiazai)/i.test(u.pathname)) {
    score += 10;
    signals.push("URL 路径含软件下载诱导词");
  }

  return below(score, signals);
}

/**
 * 主入口：分析 URL，返回达到阈值的判定或 null（行为与旧版一致）。
 * @param {string} url 完整 URL
 * @param {object} bl  黑名单数据 {verified:{dom:cat}, suspect:[], phishing:[], malware:[]}
 * @param {object} opts {sensitivity, ageDays}
 * @returns {null|{level:'block'|'warn', category, detail, score}}
 */
export function analyzeUrl(url, bl, opts = {}) {
  const { verdict } = evaluateUrl(url, bl, opts);
  return verdict;
}

/** 下载文件风险判断 */
const RISKY_EXTS = [".exe", ".msi", ".scr", ".lnk", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".pif", ".com", ".apk", ".zip", ".rar", ".7z"];
export function riskyDownload(filename) {
  const lower = (filename || "").toLowerCase();
  return RISKY_EXTS.find(ext => lower.endsWith(ext)) || null;
}

/**
 * 下载域名黑名单（借鉴 VirusDetector「跨站免疫」）：用户在某站拉黑的下载分发域名，
 * 在所有站点生效。匹配主机名本身及其父域（含 registrable domain）。
 * @param {string} host 主机名
 * @param {Object<string,number>} map {domain: expiryMs}
 * @returns {null|string} 命中的黑名单域名
 */
export function downloadBlacklistHit(host, map) {
  if (!map || !host) return null;
  const labels = host.toLowerCase().split(".");
  for (let i = 0; i < labels.length - 1; i++) {
    const candidate = labels.slice(i).join(".");
    const expiry = map[candidate];
    if (expiry && expiry > Date.now()) return candidate;
  }
  return null;
}

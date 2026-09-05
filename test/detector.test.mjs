// 检测引擎单元测试：node test/detector.test.mjs
// 覆盖：威胁情报黑名单 / 品牌仿冒 / 域名特征 / RDAP 年龄（VirusDetector 吸收）
// / 可信平台豁免 / 下载域名黑名单，以及官方站豁免与下载扩展名判断。
import { analyzeUrl, riskyDownload, downloadBlacklistHit } from "../lib/detector.js";
import { readFileSync } from "node:fs";

const baseline = JSON.parse(readFileSync(new URL("../data/blocklist.json", import.meta.url), "utf-8"));

const cases = [
  // ---- 第 1 层：威胁情报黑名单 ----
  { name: "已核实银狐黑名单域名 → block", url: "https://kuanicalawdjif.cyou/setup", expect: { level: "block" } },
  { name: "黑名单域名的子域同拦 → block", url: "http://a.b.kuanicalawdjif.cyou/", expect: { level: "block" } },
  { name: "通用钓鱼源域名 → block", url: "https://1056435343.vercel.app/login", expect: { level: "block" } },
  { name: "恶意软件分发源域名 → block", url: "https://0022a601.pphost.net/payload.bin", expect: { level: "block" } },
  { name: "LGSRC 未核实疑似域名 → warn（评分 60）", url: "http://1.24vv.cn/", expect: { level: "warn", category: "疑似恶意网站（未核实）", score: 60 } },

  // ---- 第 2/3 层：启发式（标准灵敏度）----
  { name: "品牌词 + 模板词 + 银狐偏好后缀 → warn", url: "https://wpszh.com.cn/download", expect: { level: "warn" } },
  { name: "品牌词 + 模板词（.com.cn）→ warn", url: "https://wps-app.zh.com.cn/", expect: { level: "warn" } },
  { name: "品牌前缀连写 + 银狐偏好后缀（实测漏网站 wpsar.com.cn）→ warn", url: "https://wpsar.com.cn/", expect: { level: "warn" } },
  { name: "品牌前缀连写的子域同样命中", url: "https://dl.wpsar.com.cn/setup", expect: { level: "warn" } },
  { name: "品牌前缀 + 通用 TLD 的正当站不误伤（标准模式）", url: "https://zoomcar.com/", expect: null },
  { name: "品牌前缀尾缀 4 字符边界 → warn", url: "https://wpsabcd.com.cn/", expect: { level: "warn" } },
  { name: "品牌词 + 下载路径恰好 55 分边界 → warn", url: "https://wpsfoo.com/download", expect: { level: "warn" } },
  { name: "短 token 品牌（爱思 i4）+ 模板词连写 → warn", url: "https://i4down.com.cn/", expect: { level: "warn" } },
  { name: "punycode + 偏好后缀仅严格模式告警", url: "https://xn--g6w251dtkj.hl.cn/", opts: { sensitivity: "strict" }, expect: { level: "warn" } },
  { name: "punycode 标准模式不拦", url: "https://xn--g6w251dtkj.hl.cn/", expect: null },
  { name: "typosquat 编辑距离 3 严格模式 → warn", url: "https://t0sk.hl.cn/", opts: { sensitivity: "strict" }, expect: { level: "warn" } },
  { name: "typosquat 编辑距离 3 标准模式不拦", url: "https://t0sk.hl.cn/", expect: null },
  { name: "随机子域（元音占比 0.18 < 0.2）+ 品牌 → warn", url: "https://wps.bcdvaecvfgh.hl.cn/", expect: { level: "warn" } },
  { name: "随机子域 + punycode 组合（元音占比 0.18 窗口，变异后跌破阈值）→ warn", url: "https://xn--5nq525eloxprh.hl.cn/", expect: { level: "warn" } },
  { name: "随机子域标准模式不拦", url: "https://qwkzmbxhjkl.hl.cn/", expect: null },
  { name: "可信平台豁免：平台域名即使含品牌词+下载路径也不拦", url: "https://wps-tools.github.io/download/", expect: null },
  { name: "typosquat 域名严格模式 → warn", url: "https://chrhome.hl.cn/", opts: { sensitivity: "strict" }, expect: { level: "warn" } },
  { name: "typosquat 域名标准模式不拦（阈值更高）", url: "https://chrhome.hl.cn/", expect: null },
  { name: "官方域名 wps.cn 豁免", url: "https://www.wps.cn/", expect: null },
  { name: "官方子域 docer.com 豁免", url: "https://home.docer.com/", expect: null },
  { name: "正常网站 qq.com 放行", url: "https://www.qq.com/", expect: null },
  { name: "正常网站 github.com 放行", url: "https://github.com/xtaw", expect: null },
  { name: "官方域名 163.com 邮箱子域放行", url: "https://mail.163.com/", expect: null },
  { name: "扩展自身协议跳过", url: "chrome-extension://abc/pages/popup/popup.html", expect: null },

  // ---- 两者结合优化：可信平台豁免（VirusDetector 吸收）----
  { name: "可信平台豁免：github.io 上的品牌项目不误报", url: "https://wps-tools.github.io/", expect: null },
  { name: "平台子域情报命中仍硬拦（豁免不覆盖黑名单层）", url: "https://ofice365.github.io/", expect: { level: "block" } },

  // ---- RDAP 域名年龄（VirusDetector 吸收，ageDays 由调用方注入）----
  { name: "品牌仿冒无年龄信号不达阈值", url: "https://wps-newversion.com/", expect: null },
  { name: "品牌仿冒 + 新注册域名（10 天）→ warn", url: "https://wps-newversion.com/", opts: { ageDays: 10 }, expect: { level: "warn" } },
  { name: "老域名（1000 天）可信减分 → 不拦", url: "https://wps-newversion.com/", opts: { ageDays: 1000 }, expect: null },

  // ---- 下载域名黑名单（跨站免疫，VirusDetector 吸收）----
  { name: "下载黑名单命中父域", fn: () => downloadBlacklistHit("cdn.evil-dl.com", { "evil-dl.com": Date.now() + 1e9 }), expect: "evil-dl.com" },
  { name: "下载黑名单过期条目忽略", fn: () => downloadBlacklistHit("evil-dl.com", { "evil-dl.com": Date.now() - 1 }), expect: null },
  { name: "下载黑名单空表放行", fn: () => downloadBlacklistHit("evil-dl.com", {}), expect: null },

  // ---- 下载防护 ----
  { name: "riskyDownload 识别 exe", fn: () => riskyDownload("WPS2025_setup.exe"), expect: ".exe" },
  { name: "riskyDownload 识别 msi", fn: () => riskyDownload("chrome.msi"), expect: ".msi" },
  { name: "riskyDownload 识别 zip", fn: () => riskyDownload("install.zip"), expect: ".zip" },
  { name: "riskyDownload 放行 pdf", fn: () => riskyDownload("report.pdf"), expect: null },
];

let pass = 0, fail = 0;
for (const c of cases) {
  const got = c.fn ? c.fn() : analyzeUrl(c.url, baseline, c.opts || { sensitivity: "standard" });
  let ok;
  if (c.expect === null) {
    ok = got === null;
  } else if (typeof c.expect === "object") {
    ok = !!got && Object.entries(c.expect).every(([k, v]) => got[k] === v);
  } else {
    ok = got === c.expect;
  }
  if (ok) { pass++; console.log(`  ✔ ${c.name}`); }
  else { fail++; console.log(`  ✘ ${c.name}\n      got: ${JSON.stringify(got)}`); }
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

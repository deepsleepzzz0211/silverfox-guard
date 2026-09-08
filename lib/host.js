// 公共主机名工具：二级 TLD 清单、平台域名集合、官方域名集合 —— 全仓单源。
// 使用方：lib/detector.js、lib/updater.js、lib/domain-age.js、background/service-worker.js。
// 注意：content/content.js 运行在非模块环境无法 import，保留独立副本；
// 修改本清单时必须同步 content.js 中对应副本（官方域名由 generate-official-domains.js 同步生成）。
import { OFFICIAL_DOMAINS as _OFFICIAL_DOMAINS } from "./official-domains.js";

// ---------- 二级 TLD 清单 ----------
export const TWO_LEVEL_TLDS = new Set([
  "com.cn", "net.cn", "org.cn", "gov.cn", "hl.cn", "hk.cn",
  "tw.cn", "com.hk", "co.uk", "com.au",
]);

// ---------- 平台域名集合（从 updater.js / detector.js / domain-age.js 合并） ----------
// 共享托管平台：恶意样本常借道分发，整域拦截会误杀，必须丢弃
export const SHARED_PLATFORMS = new Set([
  "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
  "sourceforge.net", "dropbox.com", "dropboxusercontent.com",
  "google.com", "microsoft.com", "live.com", "onedrive.com",
  "wordpress.com", "medium.com", "t.me",
]);
// 租户平台：每个子域独立租户，可拦完整子域；裸域名防御性丢弃
export const TENANT_PLATFORMS = new Set([
  "github.io", "gitlab.io", "pages.dev", "vercel.app", "netlify.app",
  "workers.dev", "r2.dev", "azurewebsites.net", "herokuapp.com",
  "firebaseapp.com", "web.app", "glitch.me", "repl.co",
  "000webhostapp.com", "blogspot.com", "amazonaws.com", "cloudfront.net",
  "azureedge.net", "b-cdn.net", "fly.dev", "firebaseio.com", "codeberg.page",
]);
// 品牌仿冒跳过集 = 租户平台 ∪ 代码托管平台（对扩展有运营影响，跳过品牌检测）
export const PLATFORM_TRUST = new Set([
  ...TENANT_PLATFORMS, "github.com", "gitlab.com", "gitee.com",
]);

// re-export 官方域名集（供 detector/content 消费）
export { _OFFICIAL_DOMAINS as OFFICIAL_DOMAINS };

// ---------- 核心函数 ----------
/**
 * 提取 registrable domain（可注册主域）：
 * 例：a.b.example.com → example.com；wpsar.com.cn → wpsar.com.cn；a.b.site.co.uk → site.co.uk
 */
export function registrableDomain(host) {
  const parts = host.split(".");
  if (parts.length <= 2) return host;
  const lastTwo = parts.slice(-2).join(".");
  if (TWO_LEVEL_TLDS.has(lastTwo) && parts.length >= 3) return parts.slice(-3).join(".");
  return lastTwo;
}

/**
 * 判断域名是否属于官方域名（3向比对，与 detector isOfficialDomain 一致）
 */
export function isOfficialDomain(rd, brand) {
  return (brand.official || []).some(o => rd === o || rd.endsWith("." + o) || o.endsWith("." + rd));
}

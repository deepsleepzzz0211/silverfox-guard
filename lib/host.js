// 公共主机名工具：二级 TLD 清单与 registrable domain 提取 —— 全仓单源。
// 使用方：lib/detector.js、lib/updater.js、lib/domain-age.js、background/service-worker.js。
// 注意：content/content.js 运行在非模块环境无法 import，保留独立副本；
// 修改本清单时必须同步 content.js 中的 TWO_LEVEL_TLDS 与 tools/build_blocklist.py 的 TWO_LEVEL_TLDS。

export const TWO_LEVEL_TLDS = new Set([
  "com.cn", "net.cn", "org.cn", "gov.cn", "hl.cn", "hk.cn",
  "tw.cn", "com.hk", "co.uk", "com.au",
]);

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

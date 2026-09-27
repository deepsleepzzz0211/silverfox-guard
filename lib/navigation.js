// 导航拦截决策链（T2 从 service-worker handleNavigation 提取）：
// 决策矩阵 = 防护开关 → 白名单 → URL 合法性 → 下载黑名单 → 两阶段评分（RDAP 按需）→ DNR 覆盖去重。
// 纯决策、无 chrome.* 耦合：依赖经 deps 注入（默认绑真实实现），SW 层只做事件注册与副作用。
import { downloadBlacklistHit, evaluateUrl } from "./detector.js";
import { getDomainAgeDays } from "./domain-age.js";

const DEFAULT_DEPS = { downloadBlacklistHit, evaluateUrl, getDomainAgeDays };

/**
 * @param {object} input
 *   url / enabled / blocklist（调用方一次性读取的快照）/ sensitivity / isWhitelisted /
 *   downloadBlacklist / dnrEnabled / isDnrCoveredHost(host)=>bool
 * @param {object} deps 可注入依赖（测试用 mock）
 * @returns {Promise<{action:'skip'|'redirect', reason:string, verdict?:object, host?:string}>}
 */
export async function decideNavigation(input, deps = {}) {
  const d = { ...DEFAULT_DEPS, ...deps };
  const { url, enabled, blocklist, sensitivity, isWhitelisted, downloadBlacklist, dnrEnabled, isDnrCoveredHost } = input;

  if (!enabled || !blocklist) return { action: "skip", reason: "disabled" };
  if (isWhitelisted) return { action: "skip", reason: "whitelisted" };

  let host = "";
  try { host = new URL(url).hostname.toLowerCase(); } catch {
    return { action: "skip", reason: "invalid-url" };
  }

  // 用户拉黑的下载分发域名跨站免疫：命中直接判 block（不查启发式）
  let verdict = null;
  const dlHit = d.downloadBlacklistHit(host, downloadBlacklist || {});
  if (dlHit) {
    verdict = { level: "block", category: "已拉黑的下载分发域名", detail: `域名 ${dlHit} 此前被你标记为下载分发域名，跨站生效`, score: 100 };
  }

  // 边界优化：仅当启发式已有可疑信号（score>0）时才查询 RDAP 域名年龄
  if (!verdict) {
    const first = d.evaluateUrl(url, blocklist, { sensitivity });
    verdict = first.verdict;
    if (!verdict && first.score > 0) {
      const ageDays = await d.getDomainAgeDays(url);
      if (ageDays != null) {
        verdict = d.evaluateUrl(url, blocklist, { sensitivity, ageDays }).verdict;
      }
    }
  }
  if (!verdict) return { action: "skip", reason: "no-verdict", host };

  // DNR 已在网络层拦截的域名：webRequest 路径不重复处理（统计由警告页 dnr 流程上报）
  if (verdict.level === "block" && dnrEnabled && isDnrCoveredHost(host)) {
    return { action: "skip", reason: "dnr-covered", verdict, host };
  }
  return { action: "redirect", verdict, host };
}

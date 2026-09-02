// DNR（declarativeNetRequest）动态规则构建 —— 纯函数，可单测。
// 情报黑名单在网络层同步拦截（恶意页首帧不再可见），启发式/WARN 层仍走 webRequest 路径。
// 规则上限：DNR 动态规则 MAX_NUMBER_OF_DYNAMIC_RULES = 30000，预留余量取 29500；
// 入库顺序 = 优先级：verified（银狐专项）> phishing > malware，溢出部分继续由 webRequest 路径兜底。
import { registrableDomain } from "./host.js";

export const DNR_MAX_RULES = 29500;
export const DNR_ALLOW_PRIORITY = 1000000;

/**
 * 从黑名单构建重定向动态规则。
 * @param {object} bl {verified:{dom:cat}, phishing:[], malware:[]}
 * @param {object} opts {warningBase:string(chrome.runtime.getURL 结果), maxRules?:number, exclude?:Set<string>(registrable domain，永临白名单)}
 * @returns {{rules:Array, covered:Set<string>}} covered = 已被 DNR 覆盖的域名（含被 exclude 排除前先剔除）
 */
export function buildDnrRules(bl, opts = {}) {
  const maxRules = opts.maxRules ?? DNR_MAX_RULES;
  const warningBase = opts.warningBase ?? "";
  const exclude = opts.exclude ?? new Set();
  const rules = [];
  const covered = new Set();
  const seen = new Set();
  let id = 1;

  const add = dom => {
    if (!dom || seen.has(dom) || covered.has(dom)) return;
    if (exclude.has(registrableDomain(dom))) return; // 白名单主域及其子域不构建规则
    if (rules.length >= maxRules) return;
    seen.add(dom);
    covered.add(dom);
    rules.push({
      id: id++,
      priority: 1,
      action: { type: "redirect", redirect: { url: `${warningBase}?dnr=1&d=${encodeURIComponent(dom)}` } },
      condition: { requestDomains: [dom], resourceTypes: ["main_frame"] },
    });
  };

  for (const dom of Object.keys(bl?.verified || {})) add(dom);
  for (const dom of bl?.phishing || []) add(dom);
  for (const dom of bl?.malware || []) add(dom);

  return { rules, covered };
}

/**
 * 「仍要访问」的临时放行规则：按 registrable domain 放行（含子域），
 * 优先级远高于重定向规则，会话级（浏览器重启即失效，另有 30 分钟过期清理）。
 */
export function buildAllowRule(domain, ruleId) {
  return {
    id: ruleId,
    priority: DNR_ALLOW_PRIORITY,
    action: { type: "allow" },
    condition: { requestDomains: [registrableDomain(domain)], resourceTypes: ["main_frame"] },
  };
}

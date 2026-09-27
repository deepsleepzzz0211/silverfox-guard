// lib/navigation.js 决策链单元测试：node test/navigation.test.mjs
// 全部依赖注入 mock，覆盖 handleNavigation 的决策矩阵（T2）
import { decideNavigation } from "../lib/navigation.js";

const BL = { verified: { "wps-fake.com.cn": "银狐" }, suspect: ["maybe.cn"], phishing: ["phish.io"], malware: ["c2.io"] };
const NO_AGE = () => Promise.resolve(null);
const NO_HIT = () => null;

function baseInput(over = {}) {
  return {
    url: "https://wps-fake.com.cn/setup",
    enabled: true,
    blocklist: BL,
    sensitivity: "standard",
    isWhitelisted: false,
    downloadBlacklist: {},
    dnrEnabled: true,
    isDnrCoveredHost: () => false,
    ...over,
  };
}
function baseDeps(over = {}) {
  return {
    evaluateUrl: (url, bl, opts) => ({ verdict: { level: "block", category: "威胁情报黑名单", detail: "x", score: 100 }, score: 100, signals: [] }),
    downloadBlacklistHit: NO_HIT,
    getDomainAgeDays: NO_AGE,
    ...over,
  };
}

const cases = [
  { name: "防护关闭 → skip", fn: async () => (await decideNavigation(baseInput({ enabled: false }), baseDeps())).action, expect: "skip" },
  { name: "blocklist 未加载 → skip", fn: async () => (await decideNavigation(baseInput({ blocklist: null }), baseDeps())).action, expect: "skip" },
  { name: "白名单 → skip", fn: async () => (await decideNavigation(baseInput({ isWhitelisted: true }), baseDeps())).action, expect: "skip" },
  { name: "非法 URL → skip", fn: async () => (await decideNavigation(baseInput({ url: "::bad::" }), baseDeps())).action, expect: "skip" },
  { name: "下载黑名单命中 → redirect（已拉黑类别，不查启发式）", fn: async () => { const d = await decideNavigation(baseInput({ downloadBlacklist: { "wps-fake.com.cn": Date.now() + 1e9 } }), baseDeps({ downloadBlacklistHit: (h, map) => map[h] || null, evaluateUrl: () => { throw new Error("不应调用 evaluateUrl"); } })); return d.action + "|" + d.verdict.category; }, expect: "redirect|已拉黑的下载分发域名" },
  { name: "block 命中但 DNR 已覆盖 → skip（避免重复处理）", fn: async () => (await decideNavigation(baseInput({ isDnrCoveredHost: () => true }), baseDeps())).action, expect: "skip" },
  { name: "block 命中且 DNR 未覆盖 → redirect", fn: async () => (await decideNavigation(baseInput(), baseDeps())).action, expect: "redirect" },
  { name: "首轮 score>0 + RDAP 年龄使判定成立 → redirect（两阶段）", fn: async () => { const d = await decideNavigation(baseInput(), baseDeps({ evaluateUrl: (url, bl, opts) => opts.ageDays ? { verdict: { level: "warn", category: "疑似银狐钓鱼站", detail: "d", score: 65 }, score: 65, signals: [] } : { verdict: null, score: 45, signals: [] }, getDomainAgeDays: () => Promise.resolve(10) })); return d.action + "|" + d.verdict.level; }, expect: "redirect|warn" },
  { name: "首轮 score>0 但 RDAP 失败（null）→ skip", fn: async () => (await decideNavigation(baseInput(), baseDeps({ evaluateUrl: () => ({ verdict: null, score: 45, signals: [] }) }))).action, expect: "skip" },
  { name: "首轮 score=0 → skip 且不触发 RDAP", fn: async () => { let rdapCalls = 0; const d = await decideNavigation(baseInput(), baseDeps({ evaluateUrl: () => ({ verdict: null, score: 0, signals: [] }), getDomainAgeDays: () => { rdapCalls++; return Promise.resolve(10); } })); return d.action + "|" + rdapCalls; }, expect: "skip|0" },
  { name: "warn 级判定也 redirect（疑似层）", fn: async () => { const d = await decideNavigation(baseInput(), baseDeps({ evaluateUrl: () => ({ verdict: { level: "warn", category: "疑似恶意网站（未核实）", detail: "x", score: 60 }, score: 60, signals: [] }) })); return d.action; }, expect: "redirect" },
];

let pass = 0, fail = 0;
for (const c of cases) {
  try {
    const got = await c.fn();
    if (got === c.expect) { pass++; console.log(`  ✔ ${c.name}`); }
    else { fail++; console.log(`  ✘ ${c.name}\n      got: ${JSON.stringify(got)}`); }
  } catch (e) {
    fail++; console.log(`  ✘ ${c.name}\n      threw: ${e.message}`);
  }
}
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

// lib/dnr.js 单元测试：node test/dnr.test.mjs
import { buildDnrRules, buildAllowRule, DNR_MAX_RULES } from "../lib/dnr.js";

const bl = {
  // 注：黑名单入库时已由 updater/构建脚本完成共享平台过滤，DNR 构建器不做重复过滤
  verified: { "wps-fake.com.cn": "银狐", "evil.com": "银狐" },
  phishing: ["phish.net", "evil.com"], // evil.com 重复 → 去重
  malware: ["c2host.io", "sub.phish.net"], // phish.net 主域被白名单排除，其子域也应排除
};

const { rules, covered } = buildDnrRules(bl, { warningBase: "chrome-extension://abc/pages/block/warning.html", exclude: new Set(["phish.net"]) });

const allow = buildAllowRule("sub.evil.com", 2000000001);

const cases = [
  { name: "规则数 = 去重去白名单后 3 条", fn: () => rules.length, expect: 3 },
  { name: "verified 优先获得低位 id", fn: () => rules.find(r => r.condition.requestDomains[0] === "evil.com").id, expect: 2 },
  { name: "重定向目标携带域名参数", fn: () => rules[0].action.redirect.url.includes("dnr=1&d=" + encodeURIComponent("wps-fake.com.cn")), expect: true },
  { name: "规则仅作用于 main_frame", fn: () => rules.every(r => r.condition.resourceTypes.includes("main_frame") && r.condition.requestDomains.length === 1), expect: true },
  { name: "白名单主域不建规则（含其子域）", fn: () => covered.has("phish.net"), expect: false },
  { name: "covered 集合与规则一一对应", fn: () => covered.size, expect: 3 },
  { name: "上限裁剪：maxRules=1 时仅 verified 头名入库", fn: () => buildDnrRules(bl, { warningBase: "x", maxRules: 1 }).rules.length, expect: 1 },
  { name: "默认上限 29500", fn: () => DNR_MAX_RULES, expect: 29500 },
  { name: "allow 规则按 registrable domain 放行", fn: () => allow.condition.requestDomains[0], expect: "evil.com" },
  { name: "allow 优先级高于重定向", fn: () => allow.priority > rules[0].priority, expect: true },
];

let pass = 0, fail = 0;
for (const c of cases) {
  const got = c.fn();
  if (got === c.expect) { pass++; console.log(`  ✔ ${c.name}`); }
  else { fail++; console.log(`  ✘ ${c.name}\n      got: ${JSON.stringify(got)}`); }
}
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

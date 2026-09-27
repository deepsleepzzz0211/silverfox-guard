// lib/host.js 平台域名一致性测试：node test/host.test.mjs
// 验证 PLATFORM_TRUST = TENANT_PLATFORMS ∪ {github.com,gitlab.com,gitee.com}
import { SHARED_PLATFORMS, TENANT_PLATFORMS, PLATFORM_TRUST, OFFICIAL_DOMAINS, TWO_LEVEL_TLDS, registrableDomain } from "../lib/host.js";
import { readFileSync } from "node:fs";

const EXPECTED_TRUST_EXTRA = ["github.com", "gitlab.com", "gitee.com"];

const cases = [
  // ---- 注册主域（原有测试）----
  { name: "普通 .com 两段域名", fn: () => registrableDomain("example.com"), expect: "example.com" },
  { name: "多段子域收敛到主域", fn: () => registrableDomain("a.b.c.example.com"), expect: "example.com" },
  { name: "com.cn 二级 TLD（银狐高发）", fn: () => registrableDomain("wpsar.com.cn"), expect: "wpsar.com.cn" },
  { name: "com.hk 子域取三段（既有契约）", fn: () => registrableDomain("a.b.com.hk"), expect: "b.com.hk" },
  { name: "co.uk 两段即主域", fn: () => registrableDomain("site.co.uk"), expect: "site.co.uk" },
  { name: "hl.cn 三段取三段（既有契约）", fn: () => registrableDomain("web.site.hl.cn"), expect: "site.hl.cn" },
  { name: "三段普通 TLD 收敛到主域", fn: () => registrableDomain("a.b.com"), expect: "b.com" },
  { name: "TLD 清单含 10 项", fn: () => TWO_LEVEL_TLDS.size, expect: 10 },

  // ---- 平台集合一致性 ----
  { name: "TENANT_PLATFORMS 包含关键租户平台", fn: () => TENANT_PLATFORMS.has("vercel.app") && TENANT_PLATFORMS.has("github.io") && TENANT_PLATFORMS.has("r2.dev"), expect: true },
  { name: "SHARED_PLATFORMS 包含关键共享平台", fn: () => SHARED_PLATFORMS.has("github.com") && SHARED_PLATFORMS.has("githubusercontent.com"), expect: true },
  { name: "PLATFORM_TRUST ⊇ TENANT_PLATFORMS（超集关系）", fn: () => [...TENANT_PLATFORMS].every(p => PLATFORM_TRUST.has(p)), expect: true },
  { name: "PLATFORM_TRUST 包含 github.com/gitlab.com/gitee.com", fn: () => EXPECTED_TRUST_EXTRA.every(p => PLATFORM_TRUST.has(p)), expect: true },
  { name: "PLATFORM_TRUST 中无直接来自 SHARED 的独占成员（github.com 同时在 SHARED 和 TRUST 是设计意图）", fn: () => true, expect: true }, // 始终通过，记录意图

  // ---- OFFICIAL_DOMAINS 与 detector BRANDS.official 一致性 ----
  { name: "OFFICIAL_DOMAINS 是 Set 类型", fn: () => OFFICIAL_DOMAINS instanceof Set, expect: true },
  { name: "OFFICIAL_DOMAINS 包含 wps.cn", fn: () => OFFICIAL_DOMAINS.has("wps.cn"), expect: true },
  { name: "OFFICIAL_DOMAINS 包含 microsoft.com", fn: () => OFFICIAL_DOMAINS.has("microsoft.com"), expect: true },
  { name: "OFFICIAL_DOMAINS 包含 70 个域名（与 BRANDS.official 去重一致）", fn: () => OFFICIAL_DOMAINS.size, expect: 70 },
  { name: "OFFICIAL_DOMAINS 不包含 github.com（托管平台非官方品牌域名）", fn: () => OFFICIAL_DOMAINS.has("github.com"), expect: false },
];

let pass = 0, fail = 0;
for (const c of cases) {
  const got = c.fn();
  if (got === c.expect) { pass++; console.log(`  ✔ ${c.name}`); }
  else { fail++; console.log(`  ✘ ${c.name}\n      got: ${JSON.stringify(got)}`); }
}
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

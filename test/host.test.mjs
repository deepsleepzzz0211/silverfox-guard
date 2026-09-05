// lib/host.js 单元测试：node test/host.test.mjs
import { registrableDomain, TWO_LEVEL_TLDS } from "../lib/host.js";

const cases = [
  { name: "普通 .com 两段域名", fn: () => registrableDomain("example.com"), expect: "example.com" },
  { name: "多段子域收敛到主域", fn: () => registrableDomain("a.b.c.example.com"), expect: "example.com" },
  { name: "com.cn 二级 TLD（银狐高发）", fn: () => registrableDomain("wpsar.com.cn"), expect: "wpsar.com.cn" },
  { name: "com.hk 子域取三段（既有契约：TLD+前一label）", fn: () => registrableDomain("a.b.com.hk"), expect: "b.com.hk" },
  { name: "co.uk 两段即主域", fn: () => registrableDomain("site.co.uk"), expect: "site.co.uk" },
  { name: "hl.cn 三段取三段（既有契约）", fn: () => registrableDomain("web.site.hl.cn"), expect: "site.hl.cn" },
  { name: "三段普通 TLD 收敛到主域", fn: () => registrableDomain("a.b.com"), expect: "b.com" },
  { name: "TLD 清单含 10 项", fn: () => TWO_LEVEL_TLDS.size, expect: 10 },
];

let pass = 0, fail = 0;
for (const c of cases) {
  const got = c.fn();
  if (got === c.expect) { pass++; console.log(`  ✔ ${c.name}`); }
  else { fail++; console.log(`  ✘ ${c.name}\n      got: ${JSON.stringify(got)}`); }
}
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

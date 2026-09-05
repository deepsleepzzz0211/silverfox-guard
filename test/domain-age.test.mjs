// lib/domain-age.js 纯函数（rdapTargetFor）单元测试：node test/domain-age.test.mjs
import { rdapTargetFor } from "../lib/domain-age.js";

const cases = [
  { name: "普通 https 域名 → registrable domain", fn: () => rdapTargetFor("https://www.wps-fake.com.cn/setup"), expect: "wps-fake.com.cn" },
  { name: "http 也允许（子域收敛到主域）", fn: () => rdapTargetFor("http://evil.example.net/"), expect: "example.net" },
  { name: "chrome-extension 协议排除（点分 host 也排除）", fn: () => rdapTargetFor("chrome-extension://abc.def/pages/x"), expect: null },
  { name: "纯 IP 排除", fn: () => rdapTargetFor("http://1.2.3.4/x"), expect: null },
  { name: "localhost 排除", fn: () => rdapTargetFor("http://localhost:8000/x"), expect: null },
  { name: "无点单标签排除", fn: () => rdapTargetFor("http://intranet/"), expect: null },
  { name: "租户平台 github.io 排除（RDAP 查的是平台年龄，无参考价值）", fn: () => rdapTargetFor("https://ofice365.github.io/"), expect: null },
  { name: "vercel.app 租户排除", fn: () => rdapTargetFor("https://a.b.vercel.app/"), expect: null },
  { name: "非 URL 垃圾输入排除", fn: () => rdapTargetFor("not-a-url"), expect: null },
];

let pass = 0, fail = 0;
for (const c of cases) {
  const got = c.fn();
  if (got === c.expect) { pass++; console.log(`  ✔ ${c.name}`); }
  else { fail++; console.log(`  ✘ ${c.name}\n      got: ${JSON.stringify(got)}`); }
}
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

// 变异测试器：验证单元测试的有效性。
// 每个变异体对源码做一处微小改动并运行映射的测试文件：
//   任一测试失败 → KILLED（测试有效）；全部通过 → SURVIVED（测试盲区）。
// 用法: node tools/mutation_test.mjs [仅报告不修改]
// 变异范围：lib/ 纯函数层（content/service-worker 为 chrome/DOM 耦合层，不在范围内）。
import { readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

// 变异体清单：find 必须在目标文件中唯一出现
const MUTANTS = [
  // ---- lib/detector.js ----
  { file: "lib/detector.js", desc: "标准阈值 55 → 40（应被『不达阈值』用例杀死）", find: "? 40 : 55", replace: "? 40 : 40", tests: ["test/detector.test.mjs"] },
  { file: "lib/detector.js", desc: "严格阈值 40 → 55（应被『仅严格模式告警』用例杀死）", find: "? 40 : 55", replace: "? 55 : 55", tests: ["test/detector.test.mjs"] },
  { file: "lib/detector.js", desc: "品牌边界命中分 45 → 0", find: "score += 45;\n        brandSignal = true;\n        signals.push(`域名包含仿冒品牌词", replace: "score += 0;\n        brandSignal = true;\n        signals.push(`域名包含仿冒品牌词", tests: ["test/detector.test.mjs"] },
  { file: "lib/detector.js", desc: "品牌前缀命中分 45 → 0（wpsar 案例）", find: "score += 45;\n        brandSignal = true;\n        signals.push(`域名以仿冒品牌词「", replace: "score += 0;\n        brandSignal = true;\n        signals.push(`域名以仿冒品牌词「", tests: ["test/detector.test.mjs"] },
  { file: "lib/detector.js", desc: "品牌×银狐后缀组合分 20 → 0", find: "if (brandSignal && riskyTld) {\n      score += 20;", replace: "if (brandSignal && riskyTld) {\n      score += 0;", tests: ["test/detector.test.mjs"] },
  { file: "lib/detector.js", desc: "品牌前缀尾缀上限 4 → 3", find: "l.length - brand.token.length <= 4", replace: "l.length - brand.token.length <= 3", tests: ["test/detector.test.mjs"] },
  { file: "lib/detector.js", desc: "严格模式编辑距离 3 → 2", find: "dist <= (strict ? 3 : 2)", replace: "dist <= 2", tests: ["test/detector.test.mjs"] },
  { file: "lib/detector.js", desc: "RISKY_TLDS 丢失 com.cn", find: 'Set(["com.cn", "hl.cn"', replace: 'Set(["hl.cn"', tests: ["test/detector.test.mjs"] },
  { file: "lib/detector.js", desc: "punycode 加分 35 → 0", find: "score += 35;\n      signals.push(\"punycode", replace: "score += 0;\n      signals.push(\"punycode", tests: ["test/detector.test.mjs"] },
  { file: "lib/detector.js", desc: "下载路径诱导词丢失 download", find: "(download|setup|install|soft|xiazai)", replace: "(setup|install|soft|xiazai)", tests: ["test/detector.test.mjs"] },
  { file: "lib/detector.js", desc: "短 token 品牌 minTokenLen 3 → 5", find: "const minLen = brand.minTokenLen || 3;", replace: "const minLen = brand.minTokenLen || 5;", tests: ["test/detector.test.mjs"] },
  { file: "lib/detector.js", desc: "随机域名判定字母数门槛 10 → 20", find: "if (letters.length < 10) return false;", replace: "if (letters.length < 20) return false;", tests: ["test/detector.test.mjs"] },
  { file: "lib/detector.js", desc: "元音占比阈值 0.2 → 0.15", find: "vowelRatio < 0.2", replace: "vowelRatio < 0.15", tests: ["test/detector.test.mjs"] },
  { file: "lib/detector.js", desc: "黑名单命中级别 block → warn", find: 'if (hit.level === "block") {', replace: 'if (hit.level === "warn") {', tests: ["test/detector.test.mjs"] },
  { file: "lib/detector.js", desc: "疑似站点评分 60 → 55（verdict 字面量）", find: "score: 60,", replace: "score: 55,", tests: ["test/detector.test.mjs"] },
  { file: "lib/detector.js", desc: "可信平台豁免失效", find: "if (!onPlatform) {", replace: "if (true) {", tests: ["test/detector.test.mjs"] },
  { file: "lib/host.js", desc: "PLATFORM_TRUST 丢失 github.io", find: '"github.io", "gitlab.io"', replace: '"githubx.io", "gitlab.io"', tests: ["test/host.test.mjs", "test/detector.test.mjs"] },

  // ---- lib/updater.js ----
  { file: "lib/updater.js", desc: "LGSRC [.] 混淆还原失效", find: 'text.replace(/\\[\\.\\]/g, ".")', replace: 'text.replace(/\\[x\\]/g, ".")', tests: ["test/otx.test.mjs"] },
  { file: "lib/updater.js", desc: "hxxp 混淆还原失效（等价变异：URL 构造器本就解析非标准协议）", find: 'token.replace(/^h(?:tt|xx)ps?:\\/\\//, "")', replace: 'token.replace(/^https?:\\/\\//, "")', equiv: true, tests: ["test/otx.test.mjs"] },
  { file: "lib/updater.js", desc: "baseDomain 丢失 m. 前缀剥离", find: '["www", "web", "wap", "m"]', replace: '["www", "web", "wap"]', tests: ["test/otx.test.mjs"] },
  { file: "lib/updater.js", desc: "域名正则拒绝两字母 TLD", find: "[a-z]{2,}$", replace: "[a-z]{3,}$", tests: ["test/otx.test.mjs"] },
  { file: "lib/updater.js", desc: "SHARED_PLATFORMS 丢失 github.com", find: '"github.com", "githubusercontent.com"', replace: '"githubx.com", "githubusercontent.com"', tests: ["test/otx.test.mjs"] },
  { file: "lib/updater.js", desc: "租户平台裸域名防御丢弃反转", find: "TENANT_PLATFORMS.has(reg) && host === reg", replace: "TENANT_PLATFORMS.has(reg) && host !== reg", tests: ["test/otx.test.mjs"] },
  { file: "lib/updater.js", desc: "OTX 指标不再接受 url 类型", find: 'type !== "domain" && type !== "hostname" && type !== "url"', replace: 'type !== "domain" && type !== "hostname"', tests: ["test/otx.test.mjs"] },
  { file: "lib/updater.js", desc: "ThreatFox 只认 domain 丢弃 url", find: 'type !== "domain" && type !== "url"', replace: 'type !== "domain"', tests: ["test/otx.test.mjs"] },

  // ---- lib/host.js ----
  { file: "lib/host.js", desc: "TLD 清单丢失 com.hk", find: '"com.hk", "co.uk"', replace: '"com.hkk", "co.uk"', tests: ["test/host.test.mjs"] },
  { file: "lib/host.js", desc: "两段域名短路条件破坏", find: "if (parts.length <= 2) return host;", replace: "if (parts.length <= 3) return host;", tests: ["test/host.test.mjs"] },
  { file: "lib/host.js", desc: "二级 TLD 三段判定破坏", find: "TWO_LEVEL_TLDS.has(lastTwo) && parts.length >= 3", replace: "TWO_LEVEL_TLDS.has(lastTwo) && parts.length > 3", tests: ["test/host.test.mjs"] },

  // ---- lib/dnr.js ----
  { file: "lib/dnr.js", desc: "covered 集合不再记录", find: "seen.add(dom);\n    covered.add(dom);", replace: "seen.add(dom);", tests: ["test/dnr.test.mjs"] },
  { file: "lib/dnr.js", desc: "白名单排除从主域放宽为全串", find: "if (exclude.has(registrableDomain(dom))) return;", replace: "if (exclude.has(dom)) return;", tests: ["test/dnr.test.mjs"] },
  { file: "lib/dnr.js", desc: "规则上限边界 > 改 >=", find: "if (rules.length >= maxRules) return;", replace: "if (rules.length > maxRules) return;", tests: ["test/dnr.test.mjs"] },
  { file: "lib/dnr.js", desc: "allow 规则优先级降为 1", find: "priority: DNR_ALLOW_PRIORITY,", replace: "priority: 1,", tests: ["test/dnr.test.mjs"] },
  { file: "lib/dnr.js", desc: "allow 放行域不再取主域", find: "condition: { requestDomains: [registrableDomain(domain)], resourceTypes: [\"main_frame\"] },", replace: "condition: { requestDomains: [domain], resourceTypes: [\"main_frame\"] },", tests: ["test/dnr.test.mjs"] },
  { file: "lib/dnr.js", desc: "重定向规则资源类型改为 xhr", find: 'condition: { requestDomains: [dom], resourceTypes: ["main_frame"] },', replace: 'condition: { requestDomains: [dom], resourceTypes: ["xmlhttprequest"] },', tests: ["test/dnr.test.mjs"] },

  // ---- lib/domain-age.js ----
  { file: "lib/domain-age.js", desc: "协议白名单检查失效", find: 'if (u.protocol !== "http:" && u.protocol !== "https:") return null;', replace: "if (false) return null;", tests: ["test/domain-age.test.mjs"] },
  { file: "lib/domain-age.js", desc: "IP 地址不再排除", find: "/^[0-9.]+$/.test(host)", replace: "/^x$/.test(host)", tests: ["test/domain-age.test.mjs"] },
  { file: "lib/domain-age.js", desc: "localhost 不再排除（等价变异：已被无点单标签检查覆盖）", find: 'host === "localhost"', replace: 'host === "localhostx"', equiv: true, tests: ["test/domain-age.test.mjs"] },
  { file: "lib/domain-age.js", desc: "租户平台 RDAP 豁免失效", find: "if (TENANT_PLATFORMS.has(registrable)) return null;", replace: "if (false) return null;", tests: ["test/domain-age.test.mjs"] },
];

function runTests(testFiles) {
  for (const t of testFiles) {
    const r = spawnSync(process.execPath, [t], { encoding: "utf8", timeout: 60000 });
    if (r.status !== 0) return false;
  }
  return true;
}

// 基线：原代码必须全绿，否则变异结果无意义
const ALL_TESTS = [...new Set(MUTANTS.flatMap(m => m.tests))];
console.log("基线检查:", ALL_TESTS.join(" "));
if (!runTests(ALL_TESTS)) {
  console.error("基线测试未通过，先修复再变异测试");
  process.exit(2);
}
console.log("基线全绿。开始变异，共", MUTANTS.length, "个变异体\n");

let killed = 0, survived = 0, equivSurvived = 0, skipped = 0;
const survivors = [];
for (const m of MUTANTS) {
  const src = readFileSync(m.file, "utf8");
  const count = src.split(m.find).length - 1;
  if (count !== 1) {
    skipped++;
    console.log(`  ⚠ 跳过（find 出现 ${count} 次）: ${m.desc}`);
    continue;
  }
  try {
    writeFileSync(m.file, src.replace(m.find, m.replace));
    if (runTests(m.tests)) {
      if (m.equiv) {
        equivSurvived++;
        console.log(`  ≈ EQUIV-SURVIVED（等价变异，预期存活）  ${m.desc}`);
      } else {
        survived++;
        survivors.push(m.desc);
        console.log(`  ○ SURVIVED  ${m.desc}`);
      }
    } else {
      killed++;
      console.log(`  ● KILLED    ${m.desc}`);
    }
  } finally {
    writeFileSync(m.file, src); // 无论结果如何立即还原
  }
}

const effective = MUTANTS.length - skipped - equivSurvived;
console.log(`\n变异得分: 共 ${MUTANTS.length} 个变异体（跳过 ${skipped}，等价存活 ${equivSurvived}）`);
console.log(`杀死 ${killed} / 有效 ${effective}，杀除率 ${(killed / effective * 100).toFixed(0)}%`);
if (survivors.length) {
  console.log("存活变异体（测试盲区）:");
  for (const s of survivors) console.log("  -", s);
  process.exit(1);
}

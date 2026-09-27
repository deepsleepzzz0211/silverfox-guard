// 生成 lib/official-domains.js：从 lib/detector.js 的 BRANDS 提取所有官方域名
// 用法：node tools/generate-official-domains.js
import { readFileSync, writeFileSync } from "node:fs";

const src = readFileSync("lib/detector.js", "utf8");
const re = /official:\s*\[([^\]]*)\]/g;
const domains = new Set();
let m;
while ((m = re.exec(src)) !== null) {
  for (const d of (m[1] || "").matchAll(/"([^"]+)"/g)) domains.add(d[1]);
}

const sorted = [...domains].sort();
const lines = [
  '// ⚠️ 由 tools/generate-official-domains.js 自动生成，勿手动编辑。',
  '// 数据来源：lib/detector.js 的 BRANDS[].official 去重。',
  '// 生成命令：node tools/generate-official-domains.js',
  '// 内容脚本（content.js）使用此文件的副本，两者均由此脚本同步保证一致性。',
  '',
  "export const OFFICIAL_DOMAINS = new Set([",
  ...sorted.map(d => `  "${d}",`),
  "]);",
  "",
];

writeFileSync("lib/official-domains.js", lines.join("\n"));
console.log(`generated lib/official-domains.js: ${sorted.length} domains`);

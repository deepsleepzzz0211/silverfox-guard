// OTX pulse / ThreatFox CSV / ABP 规则 / LGSRC 解析单元测试：node test/otx.test.mjs
import { parseOtxPulse, parseThreatFoxCsv, parseAdblockDomains, parseLgsrcVerified, parseLgsrcSuspect, parseUrlList, DEFAULT_OTX_PULSE_ID } from "../lib/updater.js";
import { readFileSync } from "node:fs";

const fixture = JSON.stringify({
  name: "SilverFox (银狐)",
  indicators: [
    { type: "domain", indicator: "wps-office-mb.com" },
    { type: "hostname", indicator: "2260web.cdn-sogou.com.cn" },
    { type: "URL", indicator: "https://bddownload.oss-cn-hongkong.aliyuncs.com/x64_WPS_Office_Setup.zip" },
    { type: "URL", indicator: "https://github.com/evil/repo/mal.exe" }, // 共享平台 → 丢弃
    { type: "FileHash-SHA256", indicator: "7d9c7fabd525a058351c31fda2a8c34102afd2dc446500ecca9bd59d36bd8fa2" }, // 哈希 → 丢弃
    { type: "IPv4", indicator: "1.2.3.4" }, // IP → 丢弃
    { type: "domain", indicator: "wps-office-mb.com" }, // 重复 → 去重
  ],
});

const TFX_FIXTURE = [
  "################################################################",
  "# Last updated: 2026-08-30 01:39:33 UTC                        #",
  '# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_alias","malware_printable","last_seen_utc","confidence_level","is_compromised","reference","tags","anonymous","reporter"',
  '"2026-08-30 01:39:33", "1891291", "mbond38982.workers.dev", "domain", "botnet_cc", "php.shin_webshell", "None", "php.shin_webshell", "", "50", "True", "None", "None", "0", "xscon"',
  '"2026-08-30 01:34:48", "1891289", "3dd25cbfe76db155615283f905992030468f3da9", "sha256_hash", "payload", "win.vidar", "None", "Vidar", "", "95", "False", "None", "None", "0", "Grim"',
  '"2026-08-30 01:30:00", "1891280", "https://wps-fake.com.cn/setup.exe", "url", "payload_delivery", "win.valley_rat", "None", "ValleyRAT", "", "80", "False", "None", "None", "0", "LingGao"',
  '"2026-08-30 01:20:00", "1891270", "1.2.3.4:8080", "ip:port", "botnet_cc", "win.gh0st", "None", "Gh0st", "", "80", "False", "None", "None", "0", "x"',
].join("\n");

const ABP_FIXTURE = [
  "! Title: uBlock Origin badware filters",
  "||wps-fake.com.cn^",
  "||evil-cdn.net^$all",
  "@@||good.com^",
  "||bad.com/path^$script",
  "||with-wildcard.*^",
  "||plain-domain.net",
].join("\n");

const LGSRC_FIXTURE = [
  "| 日期 | URL | 类别 | 有效载荷 | URLhaus | 编号 |",
  "|---|---|---|---|---|---|",
  "| 2026/01/01 | hxxp://wps-fake[.]cn/setup.exe | 仿冒WPS | payload.zip | - | 1 |",
  "| 2026/01/02 | http://m.baidu-pan-fake.com/x | 仿冒网盘 | | | 2 |",
  "| 2026/01/03 | https://github.com/evil/repo | 恶意样本 | | | 3 |",
  "",
  "其他文本行应被忽略",
].join("\n");

const LGSRC_SUSPECT_FIXTURE = [
  "前置说明文字",
  "```",
  "0xx.io",
  "github.io",
  "```",
].join("\n");

const cases = [
  // ---- LGSRC 解析 ----
  { name: "LGSRC: [.] 与 hxxp 混淆还原", fn: () => "wps-fake.cn" in parseLgsrcVerified(LGSRC_FIXTURE), expect: true },
  { name: "LGSRC: m. 前缀剥离", fn: () => parseLgsrcVerified(LGSRC_FIXTURE)["baidu-pan-fake.com"], expect: "仿冒网盘" },
  { name: "LGSRC: github.com 共享平台丢弃", fn: () => "github.com" in parseLgsrcVerified(LGSRC_FIXTURE), expect: false },
  { name: "LGSRC 疑似: 域名提取与 .io 两字母 TLD", fn: () => parseLgsrcSuspect(LGSRC_SUSPECT_FIXTURE).has("0xx.io"), expect: true },
  { name: "LGSRC 疑似: 裸租户平台域名丢弃", fn: () => parseLgsrcSuspect(LGSRC_SUSPECT_FIXTURE).has("github.io"), expect: false },
  { name: "parseUrlList: 正常域名保留", fn: () => parseUrlList("c2host.io").has("c2host.io"), expect: true },

  // ---- OTX pulse ----
  { name: "domain/hostname/URL 提取为已核实域名", fn: () => "wps-office-mb.com" in parseOtxPulse(fixture), expect: true },
  { name: "中文二级 TLD 主机名保留完整子域", fn: () => "2260web.cdn-sogou.com.cn" in parseOtxPulse(fixture), expect: true },
  { name: "租户型对象存储子域保留（仅拦该 bucket）", fn: () => "bddownload.oss-cn-hongkong.aliyuncs.com" in parseOtxPulse(fixture), expect: true },
  { name: "共享平台 github.com 指标丢弃", fn: () => Object.values(parseOtxPulse(fixture)).length, expect: 3 },
  { name: "默认 pulse ID 为 SilverFox 专项", fn: () => DEFAULT_OTX_PULSE_ID, expect: "6a36fe5a3c1568785b59c4d7" },

  // ---- ThreatFox CSV ----
  { name: "TFX: domain 与 url 指标入库且带家族类别", fn: () => parseThreatFoxCsv(TFX_FIXTURE)["wps-fake.com.cn"], expect: "ThreatFox·win.valley_rat" },
  { name: "TFX: workers.dev 租户子域保留", fn: () => "mbond38982.workers.dev" in parseThreatFoxCsv(TFX_FIXTURE), expect: true },
  { name: "TFX: sha256/ip:port 指标丢弃（仅 2 条入库）", fn: () => Object.keys(parseThreatFoxCsv(TFX_FIXTURE)).length, expect: 2 },

  // ---- ABP 规则 ----
  { name: "ABP: ||domain^ 与 $ 选项规则提取", fn: () => parseAdblockDomains(ABP_FIXTURE).has("evil-cdn.net") && parseAdblockDomains(ABP_FIXTURE).has("wps-fake.com.cn"), expect: true },
  { name: "ABP: 路径规则取主机名", fn: () => parseAdblockDomains(ABP_FIXTURE).has("bad.com"), expect: true },
  { name: "ABP: @@例外/通配符行跳过（共 4 条）", fn: () => parseAdblockDomains(ABP_FIXTURE).size, expect: 4 },
];

let pass = 0, fail = 0;
for (const c of cases) {
  const got = c.fn();
  if (got === c.expect) { pass++; console.log(`  ✔ ${c.name}`); }
  else { fail++; console.log(`  ✘ ${c.name}\n      got: ${JSON.stringify(got)}`); }
}
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

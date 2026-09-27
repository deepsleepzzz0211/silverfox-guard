// 端到端测试（T4）：真实浏览器加载扩展，验证拦截链路。
// 安全设计（绝无真实恶意流量）：
//   1) DNR 链路测试用测试专用扩展副本，基线注入 e2e-block.invalid
//      （RFC 2606 预留 TLD，永不解析）——DNR 生效则重定向警告页；
//      DNR 失效则 DNS 错误页（无害），测试响亮失败。零外部接触。
//   2) 内容脚本测试用 --host-resolver-rules 把 banner.e2e.test 映射到
//      本地服务器（Chrome 原生 DNS 映射，不改 hosts、不查外部 DNS）。
//   3) 全新浏览器 profile，测试结束即弃。
// 浏览器：系统已装的 Chrome 或 Edge（playwright-core channel 模式，零下载）。
// 用法：node test/e2e.test.mjs（需先 python tools/build_dist.py 生成 dist/）
import { chromium } from "playwright-core";
import { spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { readFileSync, existsSync, mkdirSync, copyFileSync, rmSync, writeFileSync, readdirSync, statSync } from "node:fs";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DIST_EXT = join(ROOT, "dist", "silverfox-guard");
const E2E_DOMAIN = "e2e-block.invalid";
const BANNER_HOST = "banner.e2e.test";

// 注意：本机环境对 fs.cpSync 的目录递归复制有沙箱限制（静默退出），改用单文件复制
function copyDir(src, dest) {
  mkdirSync(dest, { recursive: true });
  for (const name of readdirSync(src)) {
    const s = join(src, name), t = join(dest, name);
    if (statSync(s).isDirectory()) copyDir(s, t);
    else copyFileSync(s, t);
  }
}

function findBuild() {
  if (!existsSync(join(DIST_EXT, "manifest.json"))) {
    console.log("dist/ 缺失，执行 tools/build_dist.py ...");
    const r = spawnSync("python", ["tools/build_dist.py"], { cwd: ROOT, encoding: "utf8" });
    if (r.status !== 0) throw new Error("build_dist.py 失败:\n" + r.stdout + r.stderr);
  }
  // 测试专用副本：注入 e2e 域名（绝不改动发布产物）
  const tmp = mkdtempSync(join(tmpdir(), "sfg-e2e-"));
  const ext = join(tmp, "ext");
  copyDir(DIST_EXT, ext);
  const blPath = join(ext, "data", "blocklist.json");
  const bl = JSON.parse(readFileSync(blPath, "utf8"));
  bl.verified[E2E_DOMAIN] = "E2E 测试注入（非真实情报）";
  writeFileSync(blPath, JSON.stringify(bl));
  return { ext, tmp };
}

function resolveExecutable() {
  if (process.env.CHROME_PATH && existsSync(process.env.CHROME_PATH)) return process.env.CHROME_PATH;
  if (process.platform === "linux") {
    for (const p of ["/usr/bin/google-chrome", "/usr/bin/google-chrome-stable"]) {
      if (existsSync(p)) return p; // ubuntu-latest 自带
    }
  }
  try {
    const p = chromium.executablePath(); // 本机 ms-playwright 缓存
    if (p && existsSync(p)) return p;
  } catch { /* none */ }
  return null;
}

function startServer() {
  const pages = join(ROOT, "test", "pages");
  const mime = { ".html": "text/html", ".exe": "application/octet-stream", ".zip": "application/zip", ".pdf": "application/pdf" };
  return new Promise(resolve => {
    const srv = createServer((req, res) => {
      const path = req.url.split("?")[0] === "/" ? "/index.html" : req.url.split("?")[0];
      const file = join(pages, path);
      try {
        const data = readFileSync(file);
        res.writeHead(200, { "Content-Type": mime[file.slice(file.lastIndexOf("."))] || "text/plain" });
        res.end(data);
      } catch {
        res.writeHead(404); res.end("not found");
      }
    });
    srv.listen(0, "127.0.0.1", () => resolve({ srv, port: srv.address().port }));
  });
}

async function waitFor(fn, timeoutMs = 15000, step = 250) {
  const deadline = Date.now() + timeoutMs;
  let lastErr;
  while (Date.now() < deadline) {
    try { const v = await fn(); if (v) return v; } catch (e) { lastErr = e; }
    await new Promise(r => setTimeout(r, step));
  }
  throw new Error("waitFor 超时: " + (lastErr?.message || "条件未满足"));
}

let pass = 0, fail = 0, skipped = 0;
function report(name, ok, note = "") {
  if (ok) { pass++; console.log(`  ✔ ${name}`); }
  else if (note === "SKIP") { skipped++; console.log(`  ○ SKIP  ${name}`); }
  else { fail++; console.log(`  ✘ ${name}${note ? "\n      " + note : ""}`); }
}

const executablePath = resolveExecutable();
if (!executablePath) {
  console.log("未找到可用 Chrome/Chromium，e2e 跳过");
  process.exit(0);
}
console.log("E2E browser:", executablePath);

const { ext, tmp } = findBuild();
const { srv, port } = await startServer();
const profile = mkdtempSync(join(tmpdir(), "sfg-profile-"));

let context;
try {
  context = await chromium.launchPersistentContext(profile, {
    executablePath,
    headless: true,
    args: [
      `--disable-extensions-except=${ext}`,
      `--load-extension=${ext}`,
      `--host-resolver-rules=MAP ${BANNER_HOST} 127.0.0.1`,
      ...(process.platform === "linux" ? ["--no-sandbox"] : []),
    ],
  });

    // ---- 用例 1：DNR 请求级拦截全链路 ----
  try {
    const page = await context.newPage();
    // DNR 规则在 SW 启动后异步建立；ERR_SOCKS/ERR_NAME 注入前的重定向可能让 goto 抛错，统一轮询判定
    let landed = false, catText = "";
    for (let i = 0; i < 10 && !landed; i++) {
      try { await page.goto(`https://${E2E_DOMAIN}/`, { timeout: 8000 }); } catch { /* ERR_ABORTED/DNS 均可能 */ }
      landed = page.url().includes("warning.html");
      if (landed) {
        // 等页面稳定后再断言（重定向进行中 content 不可读）
        await page.waitForLoadState("load").catch(() => {});
        const el = await page.waitForSelector("#category", { timeout: 5000 }).catch(() => null);
        if (el) catText = await el.textContent();
      } else {
        await new Promise(r => setTimeout(r, 500));
      }
    }
    report("DNR: 访问黑名单域名被重定向到警告页", landed && catText.includes("E2E 测试注入"),
      landed ? `类别文案异常: ${catText}` : `DNR 未生效（安全失败：.invalid 不连接外部）`);

    // ---- 用例 2：「仍要访问」放行 ----
    if (landed) {
      await page.click("#btnContinue");
      await waitFor(() => !page.url().includes("warning.html"), 8000).catch(() => {});
      const url = page.url();
      report("警告页「仍要访问」放行生效（不再二次拦截）", !url.includes("warning.html"),
      `URL: ${url}（DNS 错误页 = .invalid 永不解析的预期结果；若放行失效会再次停在 warning.html）`);
    } else {
      report("警告页「仍要访问」放行生效", false, "SKIP");
    }
    await page.close();
  } catch (e) {
    report("DNR: 访问黑名单域名被重定向到警告页", false, e.message.slice(0, 150));
  }

  // ---- 用例 3：内容脚本仿冒横幅（本地映射域名，无外部 DNS）----
  try {
    const page = await context.newPage();
    await page.goto(`http://${BANNER_HOST}:${port}/fake-wps.html`, { timeout: 10000 });
    const banner = await waitFor(() => page.$("#silverfox-guard-banner"), 10000)
      .then(() => true).catch(() => false);
    report("内容脚本：仿冒 WPS 页注入红色警告条", banner);
    await page.close();
  } catch (e) {
    report("内容脚本：仿冒 WPS 页注入红色警告条", false, e.message.slice(0, 150));
  }
} finally {
  await context?.close().catch(() => {});
  srv.close();
  rmSync(tmp, { recursive: true, force: true });
  rmSync(profile, { recursive: true, force: true });
}

console.log(`\ne2e: ${pass} passed, ${fail} failed${skipped ? `, ${skipped} skipped` : ""}`);
process.exit(fail ? 1 : 0);

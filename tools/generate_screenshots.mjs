// 生成商店上架截图（T6）：1280x800，用 Playwright 驱动本机 Chromium。
// popup/options 页面的 chrome.* API 用 addInitScript 桩替换（展示模拟数据，纯视觉用途）。
// 产物：store/screenshots/*.png
import { chromium } from "playwright-core";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const OUT = join(ROOT, "store", "screenshots");
mkdirSync(OUT, { recursive: true });

// chrome.* 桩：popup / options 页面在普通标签页中无法访问扩展 API，注入假数据展示 UI
const CHROME_STUB = `
  window.chrome = {
    runtime: {
      sendMessage: (msg, cb) => {
        const state = {
          enabled: true, sensitivity: "standard",
          stats: {
            date: "2026-09-09", today: 7, total: 132,
            events: [
              { time: Date.now() - 1000 * 60 * 3, category: "威胁情报黑名单（网络层）", url: "https://wps-fake.com.cn/setup" },
              { time: Date.now() - 1000 * 60 * 42, category: "疑似银狐钓鱼站", url: "https://wpsar.com.cn/" },
              { time: Date.now() - 1000 * 60 * 95, category: "高风险下载:.exe", url: "https://cdn-suspicious.top/wps_setup.exe" },
            ],
          },
          currentUrl: "https://www.gov.cn/",
          verdict: null,
          blocklistCount: 45231,
          updatedAt: new Date().toISOString(),
          settings: { sensitivity: "standard", sources: {} },
          whitelist: [],
          blocklistMeta: { updatedAt: new Date().toISOString(), counts: { verified: 8420, suspect: 1394, phishing: 3208, malware: 32209 } },
        };
        if (msg?.type === "getPopupState") cb(state);
        else if (msg?.type === "getSettings") cb({ settings: state.settings, whitelist: [], blocklistMeta: state.blocklistMeta });
        else if (cb) cb(true);
      },
      getURL: p => "chrome-extension://example/" + p,
      openOptionsPage: () => {},
    },
    tabs: { query: (q, cb) => cb([{ id: 1, url: "https://www.gov.cn/" }]), update: () => {}, create: () => {} },
    storage: { local: { get: async () => ({}), set: async () => {} }, session: { get: async () => ({}), set: async () => {} } },
    alarms: { create: () => {} },
    action: { setBadgeText: () => {}, setBadgeBackgroundColor: () => {} },
  };
`;

const ext = join(ROOT, "dist", "silverfox-guard");
const extUrl = `file:///${ext.replace(/\\/g, "/")}`;
// popup 是 320px 窄卡片：iframe 包装居中于渐变背景，凑商店 1280x800 规格
const wrapperPath = join(OUT, "_popup_wrapper.html");
writeFileSync(wrapperPath, `<!doctype html><html><head><meta charset="utf-8"><style>
  body { margin:0; height:100vh; display:flex; align-items:center; justify-content:center;
         background: linear-gradient(135deg, #2b2d42, #404258); }
  iframe { width: 340px; height: 620px; border: none; border-radius: 14px;
           box-shadow: 0 16px 48px rgba(0,0,0,.5); background: #f8f8fa; }
</style></head><body>
<iframe src="${extUrl}/pages/popup/popup.html"></iframe>
</body></html>`);

const shots = [
  { name: "01-popup.png", url: `file:///${wrapperPath.replace(/\\/g, "/")}`, stub: true, viewport: { width: 1280, height: 800 } },
  { name: "02-warning.png", url: `${extUrl}/pages/block/warning.html?dnr=1&d=wpsar.com.cn`, stub: true, viewport: { width: 1280, height: 800 } },
  { name: "03-options.png", url: `${extUrl}/pages/options/options.html`, stub: true, viewport: { width: 1280, height: 800 } },
  { name: "04-welcome.png", url: `${extUrl}/pages/welcome/welcome.html`, stub: false, viewport: { width: 1280, height: 800 } },
];

const browser = await chromium.launch({ headless: true });
try {
  for (const s of shots) {
    const context = await browser.newContext({ viewport: s.viewport ?? { width: 1280, height: 800 }, deviceScaleFactor: 1 });
    const page = await context.newPage();
    if (s.stub) await page.addInitScript(CHROME_STUB);
    await page.goto(s.url, { waitUntil: "load" });
    await page.waitForTimeout(600); // 等渲染/桩数据
    if (s.clip) await page.screenshot({ path: join(OUT, s.name), clip: s.clip });
    else await page.screenshot({ path: join(OUT, s.name), fullPage: false });
    await context.close();
    console.log("generated", s.name);
  }
} finally {
  await browser.close();
}
console.log("done →", OUT);

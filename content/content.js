// 银狐防护 - 页面级仿冒特征检测（content script）
// 补充导航层漏网的站点：对已进入的页面做 DOM 特征检查，
// 命中后在页面顶部注入红色警告条，并上报 background 记录统计。
// 检测思路对应调研报告 §1.3/§1.4：仿冒品牌下载站常在标题/正文声称
// 「WPS/Chrome/向日葵/爱思助手…官网下载」，并提供 .exe/.msi/.zip 安装包。
// 借鉴 VirusDetector：MutationObserver 动态扫描新下载链接、
// ICP 备案被动信号、三选一下载确认弹窗（放行/取消/拉黑下载域名跨站免疫）。

(() => {
  if (window.__silverfoxGuardChecked) return;
  window.__silverfoxGuardChecked = true;

  // 与 lib/detector.js 的 BRANDS 官方域名保持一致的精简表
  const OFFICIAL_DOMAINS = [
    "wps.cn", "wps.com", "kingsoft.com", "docer.com",
    "google.com", "google.cn", "chromium.org", "bing.com", "microsoft.com",
    "qq.com", "wechat.com", "weixin.qq.com",
    "dingtalk.com", "alibaba.com",
    "oray.com", "todesk.com", "anydesk.com", "teamviewer.com",
    "i4.cn", "kugou.com", "kuwo.cn", "163.com", "netease.com",
    "meitu.com", "youdao.com", "baidu.com", "baidupan.com",
    "aliyundrive.com", "lanzou.com", "lanzoui.com", "lanpv.com",
    "jianguoyun.com", "quark.cn", "uc.cn", "xunlei.com",
    "foxit.com.cn", "foxitsoftware.cn", "huorong.cn",
    "deepseek.com", "doubao.com", "feishu.cn", "larksuite.com",
    "ludashi.com", "sogou.com", "xunyou.com", "mydrivers.com",
    "zoom.us", "zoom.com", "telegram.org", "whatsapp.com",
    "win-rar.com", "rarlab.com", "7-zip.org",
    "xiaohongshu.com", "xhscdn.com", "dangbei.com", "xiaoheihe.cn",
  ];

  // 标题/正文中的品牌声称词 → 品牌名（用于警告文案）
  const BRAND_WORDS = [
    ["wps", "WPS Office"], ["chrome", "Google Chrome"], ["谷歌浏览器", "Google Chrome"],
    ["微信", "微信"], ["weixin", "微信"], ["wechat", "微信"],
    ["钉钉", "钉钉"], ["dingtalk", "钉钉"],
    ["向日葵", "贝锐向日葵"], ["oray", "贝锐向日葵"], ["sunlogin", "贝锐向日葵"],
    ["todesk", "ToDesk"], ["anydesk", "AnyDesk"], ["teamviewer", "TeamViewer"],
    ["爱思助手", "爱思助手"], ["i4tools", "爱思助手"],
    ["letsvpn", "快连 VPN"], ["快连", "快连 VPN"],
    ["酷狗", "酷狗音乐"], ["酷我", "酷我音乐"], ["网易云音乐", "网易云音乐"],
    ["美图秀秀", "美图秀秀"], ["有道", "有道翻译"],
    ["百度网盘", "百度网盘"], ["阿里云盘", "阿里云盘"], ["蓝奏云", "蓝奏云"],
    ["坚果云", "坚果云"], ["夸克", "夸克网盘"], ["迅雷", "迅雷"],
    ["福昕", "福昕 PDF"], ["foxit", "福昕 PDF"], ["火绒", "火绒安全"],
    ["deepseek", "DeepSeek"], ["豆包", "豆包"], ["飞书", "飞书"],
    ["鲁大师", "鲁大师"], ["搜狗", "搜狗"], ["迅游", "迅游加速器"],
    ["驱动之家", "驱动之家"], ["winrar", "WinRAR"], ["7-zip", "7-Zip"],
    ["office", "Microsoft Office"],
  ];

  const RISKY_LINK_RE = /\.(exe|msi|scr|lnk|bat|cmd|js|hta|pif|zip|rar|7z)(\?|#|$)/i;
  const DOWNLOAD_WORDS = /(官方下载|本地下载|高速下载|电信下载|联通下载|立即下载|普通下载|离线安装包|纯净版|破解版)/;
  // ICP 备案号（被动信号）：页面正文出现「粤ICP备12345678号」等或链接到工信部/公安备案
  const ICP_RE = /[京津沪渝冀晋蒙辽吉黑苏浙皖闽赣鲁豫鄂湘粤桂琼川贵云藏陕甘青宁新]ICP(备|证)\s*\d+号(-\d+)?|ICP备案号|ICP证\s*\d+/i;
  const BEIAN_LINK_RE = /beian\.(gov\.cn|miit\.gov\.cn)|beian\.mps\.gov\.cn/i;

  // 搜索引擎/知识社区平台豁免：搜索结果与讨论页的标题/正文天然包含品牌词，
  // 对这些平台做品牌声称检测必然误报（实测：cn.bing.com 搜 deepseek 被误拦）
  const TWO_LEVEL_TLDS = new Set(["com.cn", "net.cn", "org.cn", "gov.cn", "hl.cn", "hk.cn"]);
  function registrableDomain(h) {
    const parts = h.split(".");
    if (parts.length <= 2) return h;
    const lastTwo = parts.slice(-2).join(".");
    if (TWO_LEVEL_TLDS.has(lastTwo) && parts.length >= 3) return parts.slice(-3).join(".");
    return lastTwo;
  }
  const SEARCH_PLATFORMS = new Set([
    "bing.com", "google.com", "google.cn", "baidu.com", "sogou.com", "so.com",
    "sm.cn", "duckduckgo.com", "yahoo.com", "yandex.com", "yandex.ru",
    "toutiao.com", "zhihu.com", "csdn.net", "juejin.cn", "jianshu.com",
    "bilibili.com", "douyin.com", "wikipedia.org", "baijiahao.baidu.com",
    "weibo.com", "xiaohongshu.com", "github.com", "gitee.com", "microsoft.com",
    "live.com", "cnki.net", "wanfangdata.com.cn",
  ]);
  // 搜索结果 URL 形态兜底（覆盖未收录的搜索引擎）：/search 路径或 q/wd/query 等参数
  const SEARCH_URL_RE_PATH = /(^|\/)search/i;
  const SEARCH_URL_RE_QUERY = /[?&](q|pq|wd|word|query|kw|key|search)=/i;

  function isSearchContext() {
    if (SEARCH_PLATFORMS.has(registrableDomain(host))) return true;
    try {
      const u = new URL(location.href);
      return SEARCH_URL_RE_PATH.test(u.pathname) || SEARCH_URL_RE_QUERY.test(u.search);
    } catch {
      return false;
    }
  }

  const host = location.hostname.toLowerCase();
  if (host === "localhost" || /^[0-9.]+$/.test(host) || !host.includes(".")) return;

  const isOfficial = OFFICIAL_DOMAINS.some(o => host === o || host.endsWith("." + o));
  let suspiciousPage = false; // 页面被判定为仿冒后，下载确认升级为“三选一”弹窗
  const armed = new WeakSet();

  function pageText() {
    const t = [];
    t.push(document.title || "");
    const h = document.querySelector("h1");
    if (h) t.push(h.textContent || "");
    return t.join(" ").toLowerCase();
  }

  function bodyText() {
    return (document.body?.innerText || "").slice(0, 20000);
  }

  function icpSignal() {
    const text = bodyText();
    const claimed = ICP_RE.test(text) || [...document.querySelectorAll('a[href]')]
      .some(a => BEIAN_LINK_RE.test(a.getAttribute("href") || ""));
    return claimed;
  }

  function findDownloadLinks() {
    const links = new Map(); // href -> link 对象（去重，同一 URL 的多个按钮共享处理）
    for (const a of document.querySelectorAll('a[href]')) {
      const href = (a.getAttribute("href") || "").trim();
      if (href.startsWith("javascript:") || href === "#") continue;
      try {
        const u = new URL(href, location.href);
        if (!/^https?:$/.test(u.protocol)) continue;
        if (RISKY_LINK_RE.test(u.pathname + u.search)) {
          const key = u.href;
          if (!links.has(key)) links.set(key, { url: u.href, cross: u.hostname !== location.hostname, els: [] });
          links.get(key).els.push(a);
        }
      } catch { /* 忽略非法 href */ }
    }
    return [...links.values()];
  }

  // 点击可疑下载链接前拦截确认；已判定仿冒的页面使用“三选一”弹窗
  function armDownloadConfirm(links) {
    for (const l of links) {
      for (const el of l.els) {
        if (armed.has(el)) continue;
        armed.add(el);
        el.addEventListener("click", ev => {
          if (el.__sgAllow) { el.__sgAllow = false; return; } // 弹窗里点了“继续打开”
          ev.preventDefault();
          ev.stopPropagation();
          if (suspiciousPage) showDownloadModal(l);
          else simpleConfirm(l);
        }, true);
      }
    }
  }

  function simpleConfirm(l) {
    const ok = window.confirm(
      `【银狐防护】该链接指向可执行/压缩文件：\n${l.url}\n\n` +
      `银狐木马常伪装成软件安装包（.exe/.msi/.zip）传播。` +
      `请确认这是你信任的官方网站。\n\n确定要继续打开该文件吗？`
    );
    if (ok) allowOnce(l);
  }

  function allowOnce(l) {
    const el = l.els[0];
    el.__sgAllow = true;
    el.click();
  }

  // 三选一弹窗：放行一次 / 取消 / 拉黑该下载域名（写入跨站黑名单，90 天有效）
  // 全部用 DOM 构建 + textContent，页面数据（链接 URL）不可信，禁止 innerHTML 拼接
  function showDownloadModal(l) {
    if (document.getElementById("sg-dl-modal")) return;
    const targetHost = (() => { try { return new URL(l.url).hostname; } catch { return l.url; } })();
    const overlay = document.createElement("div");
    overlay.id = "sg-dl-modal";
    overlay.style.cssText =
      "position:fixed;inset:0;z-index:2147483647;background:rgba(0,0,0,.55);" +
      "display:flex;align-items:center;justify-content:center;font-family:'Microsoft YaHei','Segoe UI',sans-serif;";
    const card = document.createElement("div");
    card.style.cssText =
      "background:#fff;border-radius:14px;max-width:520px;width:92%;overflow:hidden;" +
      "box-shadow:0 12px 40px rgba(0,0,0,.35);";
    const head = document.createElement("div");
    head.style.cssText = "background:#d62828;color:#fff;padding:16px 20px;font-size:16px;font-weight:bold";
    head.textContent = "⚠️ 可疑下载确认 · 银狐防护";
    const body = document.createElement("div");
    body.style.cssText = "padding:18px 20px;font-size:14px;line-height:1.8;color:#333";
    const line1 = document.createElement("div");
    line1.textContent = "当前页面疑似仿冒站点，其下载链接指向：";
    const urlLine = document.createElement("div");
    urlLine.style.cssText = "word-break:break-all;color:#a11d16";
    urlLine.textContent = l.url;
    const line2 = document.createElement("div");
    line2.textContent = "银狐木马常伪装成软件安装包传播，运行即可能被远程控制。";
    line2.style.cssText = "font-size:12px;color:#888";
    body.append(line1, urlLine, line2);
    const row = document.createElement("div");
    row.style.cssText = "display:flex;gap:10px;padding:0 20px 20px;";
    const mk = (text, bg, fg, fn) => {
      const b = document.createElement("button");
      b.textContent = text;
      b.style.cssText = `flex:1;padding:10px 0;border:none;border-radius:8px;cursor:pointer;font-size:13px;font-family:inherit;background:${bg};color:${fg}`;
      b.onclick = () => { overlay.remove(); fn && fn(); };
      return b;
    };
    row.append(
      mk("🚫 拉黑该下载域名", "#d62828", "#fff", () => {
        try { chrome.runtime.sendMessage({ type: "blockDownloadDomain", domain: targetHost }, () => {}); } catch {}
        showToast(`已拉黑 ${targetHost}（90 天内所有站点拦截该域名的下载）`);
      }),
      mk("取消", "#e8e8ed", "#333"),
      mk("继续打开（本次）", "#2e7d32", "#fff", () => allowOnce(l))
    );
    card.append(head, body, row);
    overlay.appendChild(card);
    document.documentElement.appendChild(overlay);
  }

  function showToast(msg) {
    const t = document.createElement("div");
    t.textContent = msg;
    t.style.cssText =
      "position:fixed;bottom:24px;left:50%;transform:translateX(-50%);z-index:2147483647;" +
      "background:#333;color:#fff;padding:10px 18px;border-radius:8px;font-size:13px;" +
      "font-family:'Microsoft YaHei',sans-serif;box-shadow:0 4px 16px rgba(0,0,0,.3)";
    document.documentElement.appendChild(t);
    setTimeout(() => t.remove(), 3000);
  }

  function injectBanner(brand, reasons) {
    if (document.getElementById("silverfox-guard-banner")) return;
    suspiciousPage = true;
    const bar = document.createElement("div");
    bar.id = "silverfox-guard-banner";
    bar.style.cssText =
      "position:fixed;top:0;left:0;right:0;z-index:2147483646;background:#d62828;color:#fff;" +
      "font-family:'Microsoft YaHei','Segoe UI',sans-serif;font-size:14px;line-height:1.6;" +
      "padding:10px 16px;display:flex;gap:12px;align-items:center;box-shadow:0 2px 8px rgba(0,0,0,.3);";
    const text = document.createElement("div");
    text.style.flex = "1";
    const line1 = document.createElement("div");
    const strong = document.createElement("b");
    strong.textContent = "银狐防护警示：";
    line1.append("⚠️ ", strong, `本页面疑似仿冒「${brand}」的下载站，请勿下载运行任何安装包！`);
    const line2 = document.createElement("span");
    line2.textContent = reasons;
    line2.style.cssText = "opacity:.85;font-size:12px";
    text.append(line1, line2);
    const btn = document.createElement("button");
    btn.textContent = "知道了";
    btn.style.cssText =
      "background:rgba(255,255,255,.15);border:1px solid rgba(255,255,255,.6);color:#fff;" +
      "border-radius:6px;padding:6px 14px;cursor:pointer;font-size:13px;";
    btn.onclick = () => bar.remove();
    bar.append(text, btn);
    document.documentElement.appendChild(bar);
  }

  function report(reasons) {
    try { chrome.runtime.sendMessage({ type: "contentSuspicion", reasons }, () => {}); } catch { /* 扩展上下文失效时忽略 */ }
  }

  function check() {
    const text = pageText();
    const links = findDownloadLinks();
    armDownloadConfirm(links); // 下载点击确认对所有页面生效（armed 去重，可重复调用）

    const claimed = BRAND_WORDS.find(([w]) => text.includes(w.toLowerCase()));
    if (!claimed || isOfficial || isSearchContext()) return;
    // 仿冒下载站必然带可执行/压缩包链接；无链接的页面（新闻/评测/百科）提及品牌词属正常
    if (!links.length) return;

    const brand = claimed[1];
    const reasons = [];
    reasons.push(`页面标题/正文声称与「${brand}」相关，但当前域名（${host}）非官方域名`);
    if (DOWNLOAD_WORDS.test(text)) reasons.push("存在“官方下载/高速下载”等诱导词");
    reasons.push(`页面含 ${links.length} 个可执行/压缩包下载链接${links.some(l => l.cross) ? "（部分跨域）" : ""}`);
    // ICP 备案被动信号（借鉴 VirusDetector）：仿冒站通常无备案或有假备案
    reasons.push(icpSignal() ? "页面出现 ICP 备案字样（可能伪造，仍需警惕）" : "未发现 ICP 备案信息");
    injectBanner(brand, reasons.join("；"));
    report(reasons.join("；"));
  }

  // 动态扫描：SPA/延迟渲染的下载按钮出现后同样纳入确认保护（1.2s 节流）
  let scanTimer = null;
  const observer = new MutationObserver(() => {
    if (scanTimer) return;
    scanTimer = setTimeout(() => {
      scanTimer = null;
      if (document.getElementById("sg-dl-modal")) return;
      armDownloadConfirm(findDownloadLinks());
    }, 1200);
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => { check(); observer.observe(document.body, { childList: true, subtree: true }); });
  } else {
    check();
    observer.observe(document.body, { childList: true, subtree: true });
  }
})();

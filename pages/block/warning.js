// 警告页逻辑：展示拦截详情，处理“继续访问”（30 分钟临时白名单）
const params = new URLSearchParams(location.search);
const seq = parseInt(params.get("seq") || "0", 10);
const btnBack = document.getElementById("btnBack");
const btnContinue = document.getElementById("btnContinue");

chrome.runtime.sendMessage({ type: "getWarning", seq }, data => {
  if (!data) {
    document.getElementById("category").textContent = "拦截信息已过期";
    document.getElementById("reason").textContent = "未找到本次拦截记录，可能因扩展重载导致。";
    btnContinue.disabled = true;
    btnContinue.style.opacity = ".5";
    return;
  }
  document.getElementById("category").textContent = data.verdict.category;
  document.getElementById("url").textContent = data.url;
  document.getElementById("reason").textContent = data.verdict.detail;
});

btnBack.addEventListener("click", () => {
  // 不用 history.back()：被拦 URL 往往就是上一条历史，返回会被再次重定向回警告页（形成“点不动”的循环），
  // 新标签页直达时也没有历史可回。因此直接导航到浏览器新标签页（确定性安全页）。
  chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
    const tab = tabs[0];
    if (tab && typeof tab.id === "number" && tab.id >= 0) {
      chrome.tabs.update(tab.id, { url: "chrome://newtab/" }, () => {
        if (chrome.runtime.lastError) {
          // 极少数环境禁止扩展导航到 chrome:// 页面，退回空白页
          chrome.tabs.update(tab.id, { url: "about:blank" }, () => void chrome.runtime.lastError);
        }
      });
    } else {
      window.close();
    }
  });
});

btnContinue.addEventListener("click", () => {
  // background 收到消息后写入 30 分钟临时白名单，并把本 tab 回跳到原 URL；本页无需自行导航
  chrome.runtime.sendMessage({ type: "continueAnyway", seq }, () => {});
});

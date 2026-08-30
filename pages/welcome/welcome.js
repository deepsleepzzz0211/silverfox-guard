// 欢迎页：点击"开始保护"关闭引导（首次安装时由 background 自动打开）
document.getElementById("btnStart").addEventListener("click", () => {
  window.close();
  // 部分浏览器不允许脚本关闭非脚本打开的标签页，给个兜底提示
  setTimeout(() => {
    document.querySelector(".foot").textContent = "直接关闭这个标签页也可以";
  }, 300);
});

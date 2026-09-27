# 商店 Listing 文案

> Chrome Web Store / Edge Add-ons 提交时使用。Edge 可直接复用；CWS 建议分类见下。

## 名称

- 中文：银狐防护 SilverFox Guard - 钓鱼网站拦截
- 英文：SilverFox Guard - Anti-Phishing

## 简短描述（摘要，≤132 字符）

中文：
> 拦截银狐木马钓鱼网站与仿冒软件下载站。9 源威胁情报每日更新 + 四层检测，本地运行不上传数据。

英文：
> Blocks Silver Fox trojan phishing sites and fake software download sites. 9 threat-intel feeds, 4-layer detection, fully local.

## 详细描述

**银狐木马正在通过仿冒 WPS、Chrome、百度网盘、向日葵等软件官网的钓鱼下载站大肆传播**——黑产用 AI 批量生成高仿页面、搜索引擎投毒引流，诱导下载伪装成安装包的远控木马，专门针对财务与办公人员。

【银狐防护】在浏览器内构建四道防线：

✅ **威胁情报硬拦截**——内置 45,000+ 恶意域名（银狐专项 LGSRC/OTX/ThreatFox + 通用钓鱼 OpenPhish/URLhaus 等 9 源），命中直接在网络层拦截，恶意页面完全不会加载；名单每日自动更新

✅ **启发式仿冒识别**——即使情报未收录的新钓鱼站，也会被"品牌仿冒 + 银狐域名特征 + 新注册域名"三层评分捕获，提前告警

✅ **页面级仿冒识别**——页面声称是某品牌官网但域名不对、还提供安装包？红色警告条立即提示

✅ **下载防护**——可疑页面上点击 .exe/.msi/.zip 安装包会弹出三选一确认，误拦可一键放行，恶意下载域名可跨站拉黑

🔒 **隐私承诺**：所有检测本地完成，不上传任何浏览数据；无广告、无追踪。

⚠️ 误拦了？警告页一键放行（30 分钟内不再拦截），或加入白名单永久豁免。

适用人群：所有 Windows 办公用户，尤其是财务、采购、行政岗位。

## 分类

- Edge Add-ons：**Security**（安全）
- Chrome Web Store：**Productivity**（CWS 无独立安全分类；如出现"安全"相关分类选项则选之）
- 语言：中文（简体）+ English

## 截图清单（store/screenshots/）

1. 01-popup.png — 工具栏弹窗：当前站点状态与拦截统计
2. 02-warning.png — 网络层拦截警告页
3. 03-options.png — 设置页：数据源开关/白名单/灵敏度
4. 04-welcome.png — 首次安装欢迎引导

（规格 1280×800，符合 CWS/Edge 上传要求；如需更多可补充模拟钓鱼页警告条截图）

## 提交备注（Notes for certification，Edge 专用）

本扩展为钓鱼网站防护工具，核心拦截逻辑：declarativeNetRequest 动态规则（本地黑名单，仅 main_frame）+ 观察式 webRequest 启发式告警。测试方法：加载扩展后访问仓库 test/pages/ 内的本地模拟钓鱼页（python -m http.server 启动），或将任一黑名单域名加入 data/blocklist.json 后导航验证警告页。远程代码声明：否（仅每日拉取纯文本情报数据，本地解析）。

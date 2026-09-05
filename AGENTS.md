# AGENTS.md — 银狐防护 SilverFox Guard

Chrome/Edge MV3 扩展：拦截银狐木马（Winos/ValleyRAT/游蛇）钓鱼网站与仿冒软件下载站。原生 JS，无构建框架。

## 常用命令

```bash
node test/detector.test.mjs      # 检测引擎单测（30 用例，改 lib/ 或 content/ 后必跑）
node test/otx.test.mjs           # 情报源解析单测（11 用例，改 lib/updater.js 后必跑）
python tools/build_blocklist.py  # 重建内置基线 data/blocklist.json（需联网拉 9 源）
python tools/build_dist.py       # 打包 dist/silverfox-guard/ + zip（产物不入库）
node tools/mutation_test.mjs     # 变异测试：验证单测有效性（杀除率应保持 100%）
git tag vX.Y.Z && git push origin main --tags   # 发版：CI 测试→重建基线→打包→挂 Release
```

无 lint/typecheck 配置；`node --check <file>` 可做语法校验。

## 架构边界

- `lib/detector.js`：检测引擎，**必须保持纯函数同步**（禁用 chrome.* API），异步上下文（RDAP 域名年龄）由 service worker 查好后经 `opts.ageDays` 注入——这是单测能直接跑的原因。
- `background/service-worker.js`：拦截调度分两层——**DNR 网络层**（情报黑名单命中由 declarativeNetRequest 请求级 redirect，规则由 `lib/dnr.js` 纯函数构建、黑名单签名变化才重建）+ **观察式 webRequest/tabs.update**（启发式告警层，MV3 已移除阻塞式）、下载防护、消息路由。
- `lib/updater.js`：9 个情报源的拉取/解析/合并；`tools/build_blocklist.py` 是它的 Python 镜像。
- `content/content.js`：页面级检测；`lib/domain-age.js`：RDAP 查询（3.5s 超时，结果缓存 30 天）。

## 强约束（改前必读）

1. **MV3 SW 约 30 秒空闲即卸载**：任何跨事件状态必须落 `chrome.storage.session/local`，禁止内存 Map 做唯一存储。
2. **权限最小化已人工裁剪**（webNavigation/tabs 已移除；declarativeNetRequest 为 v1.1.0 请求级拦截特意加入，勿随意再加）：新增 chrome.* API 前先确认权限，别随手加权限。
3. **二级 TLD 清单**在 5 个文件各有一份（detector.js / service-worker.js `baseDomainOf` / updater.js / domain-age.js / content.js），**改一处必须同步全部**——已知技术债，曾因此出过整域误放行 bug。
4. **共享托管平台（github.com、raw.githubusercontent.com 等）绝不整域拉黑**，只能丢弃或拦完整子域；updater.js 与 build_blocklist.py 的豁免清单必须一致。
5. **content.js 与 popup.js 禁止用 innerHTML 拼接页面来源数据**（URL/标题不可信），一律 DOM 构建 + textContent。
6. **搜索引擎/知识社区页面必须豁免品牌声称检测**（URL 形态 + 平台域名两层），否则搜索结果页必然误报（踩过坑：cn.bing.com 搜 deepseek）。
7. 品牌仿冒的"官方域名"清单在 detector.js `BRANDS` 与 content.js `OFFICIAL_DOMAINS` 两处，需同步。

## 版本与发布

- 每次发版必须递增 `manifest.json` 的 `version`，并在 README「版本记录」加条目；CI 校验 tag 与 manifest 一致，不一致拒绝发布。
- `.github/workflows/release.yml`：tag 触发 → 单测 → 云端重建情报基线（失败降级仓库内基线）→ 打包挂 Release。

## 仓库与网络

- 远程：github.com/deepsleepzzz0211/silverfox-guard（public，main 分支）；本地直连 GitHub 不稳，git/curl 需走代理 `http://127.0.0.1:7897`（remote 用了 gh-proxy.com 镜像前缀）。
- `docs/` 已 gitignore（调研报告仅本地）；`pages/guide/guide.html` 是面向用户的图文安装指南，**必须随扩展分发**，勿移入 docs/。
- `data/blocklist.json` 虽可由脚本重建，但作为离线首启兜底**必须入库**。

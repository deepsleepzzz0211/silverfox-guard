# Changelog

本项目的所有显著变更记录于此。格式遵循 [Keep a Changelog 1.1.0](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循语义化版本（SemVer）。

## [Unreleased]

### Planned
- 浏览器端到端测试（官方 --load-extension 方案）
- Chrome Web Store / Edge Add-ons 上架材料（权限 justification、截图）

## [1.1.1] - 2026-08-30

### Added
- 变异测试器 `tools/mutation_test.mjs`：39 个变异体（常量篡改/条件翻转/语句删除），杀除率 100%，持续守护测试有效性
- `lib/domain-age.js` 抽出纯函数 `rdapTargetFor` 并补 9 个单测（协议/IP/localhost/租户平台排除）
- LGSRC 解析器（Archive_2/3）导出并补 6 个单测（`[.]` 与 hxxp 混淆还原、`m.` 前缀剥离、共享平台与裸租户域名丢弃）
- 检测引擎测试从 30 扩至 41 用例：补齐阈值边界、typosquat 编辑距离 3、随机子域元音占比窗口、合法 punycode 域名、短品牌 token（i4）等盲区

### Changed
- 测试总数从 58 扩至 85 用例；`node tools/mutation_test.mjs` 纳入常规验证手段

## [1.1.0] - 2026-08-30

### Added
- **DNR 请求级拦截**：情报黑名单命中在浏览器网络层直接重定向到警告页，恶意页面首帧不再可见；规则由 `lib/dnr.js` 纯函数构建（verified 优先、上限 29,500 条、白名单排除），溢出部分自动由 webRequest 路径兜底
- 「仍要访问」同时写入 DNR 会话放行规则（按 registrable domain 含子域，优先级高于拦截规则），30 分钟闹钟自动清理过期规则
- CHANGELOG.md（Keep a Changelog 1.1.0 格式）与 PRIVACY.md 隐私政策
- GitHub Release 说明自动注入对应版本的 changelog 分节（`tools/extract_changelog.py`）
- AGENTS.md 工程约束文档入库；新增 lib/host.js 与 lib/dnr.js 单测（17 用例，累计 58）

### Changed
- `registrableDomain` 合并为 `lib/host.js` 单源，统一 detector/updater/domain-age/service-worker 四处实现（content.js 副本同步 TLD 清单至 10 项）
- 品牌官方域名判定统一为 `isOfficialDomain`，layer2/layer3 同一口径
- manifest 新增 `declarativeNetRequest` 权限与 `web_accessible_resources`（警告页重定向目标）

### Fixed
- seq 警告页「仍要访问」回跳原站会被 DNR 规则二次拦截的循环风险（放行时同步写会话 allow 规则）

## [1.0.7] - 2026-08-30

### Fixed
- 临时白名单主域提取补齐二级 TLD 清单，修复 `com.hk` 等域名整域误入白名单的问题
- RDAP 查询超时对齐 3.5 秒（此前代码为 8 秒，与文档不符）
- 下载警告文件名回退到 URL 路径末段，修复 `onCreated` 时刻 `filename` 为空导致的漏报

### Security
- 清除文档与用户指南中的硬编码本地路径，全库扫描通过

## [1.0.6] - 2026-08-30

### Added
- 接入五个新情报源（共 9 源）：ThreatFox 家族标注 CSV、CyberCrime Tracker（Gh0st 系 C2）、YYT 银狐专项源、uBO badware 规则、Inversion-DNSBL
- GitHub raw 类源统一 jsdelivr CDN 回退
- 追加 OTX 官方银狐 pulse（第二个订阅）

## [1.0.5] - 2026-08-30

### Added
- 接入 OTX「SilverFox (银狐)」专项情报 pulse（LGSRC 同作者维护、每日更新，无需 API Key）
- 设置页可开关数据源并追加订阅其他公开 pulse

## [1.0.4] - 2026-08-30

### Fixed
- 品牌前缀连写漏报（实测案例 `wpsar.com.cn`）：新增品牌前缀匹配（尾缀 ≤4 字符）与「品牌仿冒 × 银狐偏好后缀」组合加分

## [1.0.3] - 2026-08-30

### Fixed
- 图文安装指南移入扩展包内（此前指向被 dist 排除的 docs/ 目录导致 404）
- 警告页「返回安全页面」改为直接打开新标签页（原 history.back() 会被再次重定向回被拦站点）

## [1.0.2] - 2026-08-30

### Fixed
- 搜索结果页误报（实测案例 cn.bing.com 搜 deepseek）：搜索引擎/知识社区平台域名豁免、搜索 URL 形态识别、无实际下载链接的页面不再告警

## [1.0.1] - 2026-08-30

### Changed
- 拦截记录迁移 `chrome.storage.session`，修复 Service Worker 卸载后警告页丢数据
- 移除未使用的 `webNavigation`/`tabs` 权限
- 全部 UI 改 DOM 构建，防扩展 UI 注入
- 消息接口增加来源校验

### Added
- `dist/` 打包脚本

## [1.0.0] - 2026-08-30

### Added
- 首个功能完整版：四层导航检测（情报黑名单 / 品牌仿冒 / 域名特征 / RDAP 年龄）、页面级仿冒检测、下载三选一确认与跨站拉黑、欢迎引导页
- 内置 7800+ 条情报基线（LGSRC / OpenPhish / URLhaus）

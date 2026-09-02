# Changelog

本项目的所有显著变更记录于此。格式遵循 [Keep a Changelog 1.1.0](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循语义化版本（SemVer）。

## [Unreleased]

### Planned
- DNR 请求级拦截迁移（情报黑名单在网络层同步拦截）
- `registrableDomain` 多处实现合并为 `lib/host.js` 单源

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

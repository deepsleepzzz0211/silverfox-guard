# 银狐防护 SilverFox Guard

Chrome / Edge 浏览器扩展（Manifest V3，原生 JS），拦截银狐木马（Winos/ValleyRAT/游蛇，Gh0stRAT 系黑产远控）的钓鱼网站与仿冒软件下载站。

## 功能

- **导航级拦截（四层检测）**：威胁情报黑名单（父域命中子域同拦）→ 品牌仿冒启发式（50+ 高频品牌、typosquatting、`wpszh`/`wpsar` 连写形态）→ 银狐域名特征评分（.com.cn/.hl.cn 偏好后缀、模板词、随机子域、punycode）→ RDAP 域名年龄（新注册加权、老域名减分）。命中后整页重定向警告页，可"仍要访问"（30 分钟临时放行）
- **误报控制**：官方域名豁免、github.io 等租户平台豁免、搜索引擎/知识社区页面豁免、白名单管理
- **页面级检测**：品牌声称 + 非官方域名 + 安装包链接 → 注入红色警告条；MutationObserver 动态扫描延迟渲染的下载按钮
- **下载防护**：可疑页面下载 .exe/.msi/.zip 等弹三选一确认（放行一次 / 取消 / 拉黑域名）；被拉黑的下载域名跨站免疫 90 天
- **首页体验**：首次安装弹出欢迎引导，工具栏弹窗显示当前站点状态与拦截统计

## 数据源（每日自动更新，设置页可逐项开关）

LGSRC 银狐专项（已核实/疑似）· OTX「SilverFox (银狐)」pulse · ThreatFox 家族标注 IOC（ValleyRAT/Winos/Gh0st）· CyberCrime Tracker（Gh0st 系 C2）· YYT 银狐仿冒域名专项 · uBO badware 规则 · Inversion-DNSBL · OpenPhish · URLhaus

拉取失败自动降级（上次缓存 → 内置 7800+ 条基线）；共享托管平台（github.com 等）整域豁免防误杀；GitHub raw 类源自动走 jsdelivr CDN 回退。

## 安装（Chrome / Edge 通用）

1. Chrome 打开 `chrome://extensions/`，Edge 打开 `edge://extensions/`
2. 开启「开发者模式」→「加载已解压的扩展程序」→ 选择 `dist/silverfox-guard/`（或源码根目录）
3. 首次安装自动弹出欢迎引导；建议装完在设置页点一次「🔄 更新」拉取最新全源情报

小白用户可看扩展内的图文指南（工具栏小狐狸 → ❓帮助，即 `pages/guide/guide.html`）。重新构建产物：`python tools/build_dist.py`。

**发版**：`git tag vX.Y.Z && git push origin main --tags` → CI 跑单元测试、重建情报基线（失败降级仓库内基线）、打包 zip 挂 GitHub Release（tag 须与 `manifest.json` 的 version 一致）。

## 测试

```bash
node test/detector.test.mjs   # 检测引擎 30 用例
node test/otx.test.mjs        # 情报源解析 11 用例
```

## 目录结构

```
├── manifest.json                            # MV3 清单
├── background/service-worker.js             # 拦截调度 / 下载防护 / 消息 / 统计
├── lib/{detector,updater,domain-age}.js     # 检测引擎 / 9 源更新器 / RDAP 年龄
├── content/content.js                       # 页面级检测 + 下载三选一确认
├── data/blocklist.json                      # 内置基线（构建脚本生成）
├── pages/{block,popup,options,welcome,guide}/
├── tools/{build_blocklist,build_dist}.py    # 基线构建 / dist 打包
└── test/                                    # 单测 + 本地模拟钓鱼页
```

## 版本记录

- **1.0.7**（2026-08-30）：上传前审查整改——白名单主域提取补齐二级 TLD、RDAP 超时对齐 3.5s、下载警告文件名回退 URL、清除硬编码本地路径
- **1.0.5–1.0.6**（2026-08-30）：接入 OTX 银狐专项 pulse 与 ThreatFox / CyberCrime / YYT / uBO / Inversion，共 9 源；jsdelivr CDN 回退
- **1.0.4**（2026-08-30）：品牌前缀连写检测（实测漏网站 `wpsar.com.cn` 案例）
- **1.0.0–1.0.3**（2026-08-30）：首个完整版：四层检测、页面级检测、下载三选一与跨站拉黑、欢迎引导、RDAP 年龄与平台豁免、搜索结果页误报修复

## 免责声明

启发式检测存在误报可能，白名单与情报数据仅供防护参考，不构成安全保证；请勿下载运行来源不明的安装包。

# CCK 账号管理器

**添加自定义账号，批量管理，一键启动** —— 把散落各处的 AI 编程工具账号集中到一处。

同时使用多个 AI 编程工具时，账号凭证往往散落在剪贴板、备忘录、各种客户端登录态里：额度用完才发现、换台机器要挨个重新登录、哪个号还能用全靠记忆。CCK 让你把这些账号装进一个管理器。

## 下载

- Windows 安装包：<https://cck.btluo.com/download>
- 在线版：<https://cck.btluo.com>

## 核心用法

### 1. 添加自定义账号

把你自己的凭证录入 CCK，作为账号管理的起点：

- 支持 12 个客户端家族：Qoder（Work CN / CN IDE / 国际版）、Trae（CN / SOLO / 国际版）、CodeBuddy（含 WorkBuddy / 国际版）、千问办公、Codex CLI、Cursor、Kiro
- 凭证自动校验：JWT 签发方识别，自动区分 Trae / CodeBuddy / Codex 家族；投错分类会给出纠正提示
- 添加时可选在线验证（额度查询通过才入库，死号当场拦截；离线可跳过）
- 凭证仅保存在本机：系统级加密（Windows DPAPI），不上传服务器

### 2. 批量管理

所有账号一屏总览，额度状态自动刷新：

- 进入「我的账号」即并发查询全部账号额度，逐账号展示
- 统一额度口径：credits / 积分 / fast requests / 请求数按平台自动适配
- 用量可视化：进度条 + 百分比 + 套餐档位徽标（Free / Pro / 订阅）
- 死号检测：凭证被平台拒绝时红色标记 + 「已封禁」徽标，平台购买的账号可发起自动退款
- 支持备注标签，工作号 / 个人号一眼区分

### 3. 一键启动（官方版）

在列表中选中账号，凭证自动就位，直接拉起对应客户端，无需手动复制粘贴 token：

- Qoder / Trae / CodeBuddy / 千问办公 / Codex / Cursor / Kiro 全家族支持
- 从 [cck.btluo.com](https://cck.btluo.com/download) 下载官方版体验

> 本仓库为开源版，包含自定义账号与批量管理完整功能；一键启动在官方发行版中提供。

### 账号商城（平台服务）

除管理自己的账号外，也可直接购买平台预置账号：

- 余额购买、兑换码充值
- 死号自动退款（服务端复核后按剩余额度比例退回余额）

## 支持的客户端

| 家族 | 客户端 |
|------|--------|
| Qoder | Qoder Work CN / Qoder CN IDE / Qoder 国际版 |
| Trae | TRAE CN（统一客户端，TraeCode CN / TraeWork CN 已合并）/ Trae 国际版 |
| CodeBuddy | CodeBuddy/WorkBuddy / CodeBuddy 国际版 |
| 其他 | 千问办公 / Codex CLI / Cursor IDE / Kiro IDE |

## 安全设计

- `contextIsolation: true` + `sandbox: true` + `nodeIntegration: false`，渲染进程只能通过 `contextBridge` 暴露的白名单 IPC 通道访问主进程能力
- 凭证类数据（会话 token、自定义账号）通过 Electron `safeStorage`（Windows 上为 DPAPI）加密后落盘
- CSP 禁止加载任意外部脚本；外链打开走主进程协议白名单（仅 http/https）
- 诊断日志写入前脱敏（JWT / 设备令牌 / 私钥 / token 类字段一律掩码）
- 文件锁单实例（带 PID 存活检测，防闪退后锁死）

## 开发

```bash
npm install
npm start        # 运行
npm run dev      # 运行并打开 DevTools
npm test         # 自定义账号模块测试
npm run build    # 打包 Windows 安装包（electron-builder + NSIS）
```

要求：Node.js ≥ 18，Windows（打包目标为 win x64）。

## 项目结构

```
├── main.js                 # 主进程：窗口管理 + IPC handler
├── preload.js              # contextBridge 白名单 IPC 接口
├── lib/
│   ├── api-client.js       # 后端 API 调用封装（双域名容灾）
│   ├── quota-checker.js    # 额度查询调度（按分类分发到各 context 模块）
│   ├── qwenwork-context.js # 千问办公额度查询
│   ├── codex-context.js    # Codex CLI 额度查询
│   ├── cursor-context.js   # Cursor IDE 额度查询
│   ├── kiro-context.js     # Kiro IDE 额度查询
│   ├── vscdb-secret.js     # state.vscdb 只读访问（sql.js）
│   ├── custom-accounts.js  # 自定义账号校验/存储逻辑
│   ├── local-store.js      # 本地配置存储（敏感值 safeStorage 加密）
│   ├── net-helper.js       # 共享网络请求工具
│   └── cck-logger.js       # 脱敏诊断日志
├── renderer/
│   ├── index.html
│   ├── css/style.css
│   └── js/app.js           # 渲染进程逻辑
├── test/                   # 测试
└── assets/icon.ico
```

## 开源版与官方版差异

本开源版包含自定义账号、批量管理与额度查询。官方发行版额外提供：

- **一键启动**（选中账号，凭证注入后拉起对应 IDE/CLI）
- 设备身份修复与全新无痕重置
- 网络 IP 轮换

后两项能力涉及对第三方客户端本地状态的深度写入，不在开源范围内。两个版本共用同一后端与更新通道。

## License

[MIT](./LICENSE)

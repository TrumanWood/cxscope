# Checkmarx 漏洞看板 · 交互 Demo

可交互的纯静态页面集合，数据全部为内置 mock，**不会发起任何网络请求**。

- **`current-page-demo.html`（推荐）**：与当前正式页面同一套代码构建的最新 Demo，
  不需要 proxy.py、不需要真实 API Key，双击即可体验完整交互；
- `demo-1/2/3`：早期三套布局原型，可对比不同详情容器/布局形态。

## 打开方式

直接双击 `demo/index.html`（演示入口页），或单独打开：

| 文件 | 内容 | 详情形态 |
| --- | --- | --- |
| `current-page-demo.html` | 当前正式页面（Demo 1 布局：项目筛选 + 严重级别标签 + 扫描链接 + 本地扫描） | 右侧可拖拽抽屉 |
| `demo-1-classic.html` | 经典控制台（顶部工具栏 + 单行筛选 + 全宽表格） | 右侧抽屉 |
| `demo-2-board.html` | 看板分栏（左侧项目导航 + KPI 卡片 + 表格/详情同屏） | 固定 Inspector 面板 |
| `demo-3-dark.html` | 深色作战室（多项目 Tab + 深色大屏） | 居中弹窗 |

### 当前页面版 Demo（current-page-demo.html）

- 登录页已预填演示 API Key（`DEMO-API-KEY`），直接点「登录」即可；
- 登录后自动选择演示项目，展示 3 个项目的最新扫描结果（10 条漏洞）；
- 与正式页面一致：项目/分支/扫描时间筛选、严重级别标签（项目/分支/严重级别选择会被记住并在刷新后恢复）、搜索、CSV 导出、
  右侧抽屉（含漏洞说明 / 攻击向量 / 数据流 / 修复建议 / 参考链接，各区块均支持一键复制；漏洞名称一行右侧可一键复制完整 9 项漏洞信息；可拖拽宽度）、
  扫描链接直达、本地扫描模拟（项目名可从已有项目下拉筛选选择，也可输入新名称模拟新建；多文件夹并行进度 + 结果回填；
  文件夹路径与项目名会被记住，并从「最近扫描」一键填入）、设置/退出登录；
- 顶栏带「DEMO · 模拟数据」徽标，本地扫描与扫描链接弹窗内均有演示说明。

演示态可直接带 URL 参数打开：

```
#state=board              自动登录进入看板
#state=board&open=2       进入看板并打开第 3 条漏洞详情
#state=board&modal=scan   进入后打开本地扫描弹窗
#state=board&modal=link   进入后打开扫描链接弹窗
```

早期 Demo 1/2/3 的 URL 参数（如 `#state=board&open=f-001`）保持原有行为。

### 构建与测试

```powershell
# 重新生成正式页面 index.html + 当前页面版 Demo（注入演示 mock 层）
python app/build.py

# 当前页面版 Demo 的端到端测试（67 项断言：登录/自动选择项目/项目下拉搜索/筛选与记忆/抽屉拖拽/
# 漏洞说明、修复建议、参考链接、攻击向量与数据流一键复制（剪贴板文本只含标准空格）/
# 漏洞名称一行右侧完整漏洞信息一键复制/扫描链接/
# 本地扫描模拟（项目名组合框筛选已有项目、新项目手输标记、键盘 ↓ 高亮与 Esc 关闭下拉）/退出登录/零网络请求/无 JS 报错）
node tests/demo-page.mjs

# 早期三套布局 Demo 的构建与冒烟测试
python demo/_build/build.py
node demo/_build/test-demos.mjs
```

## 相关文件

- 正式页面源码：`app/`（`python app/build.py` 生成 `index.html` 与 `demo/current-page-demo.html`）
- 当前页面版 Demo 的 mock 层：`app/demo-mock.js`（拦截 Checkmarx API 调用，数据由 `tests/mock_cxone.py` 生成并注入）
- 早期布局 Demo 源码：`demo/_build/`
- 截图：`demo/shots/`

## 说明

- 正式页面需要 `python proxy.py` + 真实 Checkmarx One API Key；Demo 页面完全离线；
- 正式页面完整使用说明见仓库根目录 `README.md`。
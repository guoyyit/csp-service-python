# CSP Service (Python / FastAPI)

本地可验证的**内容安全策略（Content-Security-Policy）生成与注入**服务，并收集、
去重、限速、持久化浏览器上报的 CSP 违规事件。所有能力均可通过本地 HTTP 请求模拟，
无需真实浏览器。

## 功能一览

| # | 能力 | 实现要点 |
|---|------|----------|
| 1 | 按路由与资源类型配置 CSP，默认策略 + 子范围继承/覆盖，热更新 | 最长前缀匹配；指令级覆盖、模式/report-uri 逐项继承；配置不可变快照整体原子替换，更新不中断在途请求 |
| 2 | 内联脚本/样式的一次性 nonce | 每响应生成一个 `secrets` 随机数，同时写入 CSP 头与 HTML 内的 `<script>`/`<style>`；同响应一致、跨响应必不同，带碰撞历史防护 |
| 3 | 强制执行 / 仅报告两种模式 | 模式只决定发 `Content-Security-Policy` 还是 `Content-Security-Policy-Report-Only`，策略计算完全相同；report-only 不中断响应 |
| 4 | 违规上报收集、去重、限速 | 五元组 SHA-256 指纹去重；滑动窗口限速 + 记录数硬上限，刷量不会导致存储无界增长 |
| 5 | 历史查询 / 聚合 / 重启恢复 | SQLite 持久化；按 `open`/`handled` 状态过滤；按指令聚合计数；重启后记录与处理状态不丢失 |
| 6 | 并发安全 | 配置快照不可变、nonce 生成器加锁、报告存储串行化写事务；配置更新只影响新请求，在途请求保留旧版本（可通过响应头解释） |

## 快速开始

```bash
uv sync
uv run uvicorn main:app --port 8000
```

演示页面：

- `GET /` — 默认策略作用域（enforce）
- `GET /admin` — 子作用域（继承默认指令，可覆盖模式/指令）
- `GET /healthz` — 健康检查

查看首页响应头可见 CSP 与解释性响应头：

```bash
curl -s -D - -o /dev/null http://127.0.0.1:8000/
# Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-xxxx'; ...
# X-CSP-Config-Version: 3
# X-CSP-Matched-Prefix: /
# X-CSP-Mode: enforce
```

## 配置语义

配置整体为**不可变快照**：每个请求在进入中间件时获取一次快照，整次响应用同一快照
计算策略与版本号；`PUT /csp/config` 原子替换快照，因此**新请求用新策略、在途请求
保持旧策略**，`X-CSP-Config-Version` 可以解释每个响应来自哪一版配置。

### 配置 JSON 结构

```json
{
  "default": {
    "prefix": "/",
    "directives": {
      "default-src": ["'self'"],
      "img-src": ["'self'", "data:"]
    },
    "mode": "enforce",
    "report_uri": "/csp/report"
  },
  "scopes": [
    {
      "prefix": "/admin",
      "directives": {"script-src": ["'self'", "https://cdn.example.com"]},
      "mode": "report-only",
      "report_uri": null
    }
  ]
}
```

| 字段 | 说明 |
|------|------|
| `default` | 根作用域（prefix 固定为 `/`），所有请求至少匹配它 |
| `scopes[].prefix` | 路由前缀，**段边界匹配**：`/admin` 匹配 `/admin/x`，但不匹配 `/administrator` |
| `directives` | CSP 指令名 → 来源表达式数组（保留顺序）。子作用域对**同名指令整体替换**（CSP 本身没有按来源合并语义），未覆盖的指令从父作用域继承 |
| `mode` | `enforce` 或 `report-only`；子作用域缺省时继承父作用域；最终缺省为 `enforce` |
| `report_uri` | 违规上报地址；缺省继承父作用域；渲染时自动附加为 `report-uri` 指令 |

匹配链按前缀长度排序（`/` → `/admin` → `/admin/panel`），逐级应用继承与覆盖。

### Nonce 语义

- 每个 HTTP 响应生成**一个** 128 位 URL-safe 随机 nonce；
- 自动注入 `script-src` 与 `style-src` 指令（指令缺省时回退使用 `default-src` 的来源）；
- 对 `text/html` 响应体，所有**内联** `<script>`/`<style>` 开标签注入同一个
  `nonce="…"`；带 `src` 的外链脚本和已有 nonce 的标签不动；
- 同一响应头与页面内的 nonce 必须一致；不同响应的 nonce 必不同（有界历史去重）。

## HTTP API

| 方法 & 路径 | 说明 |
|-------------|------|
| `GET /csp/config` | 查看当前生效配置（含版本号） |
| `PUT /csp/config` | 热更新配置；非法配置返回 `400` 且**保留**在用策略；成功返回新旧版本号 |
| `POST /csp/report` | 接收浏览器违规上报，兼容两种格式（见下），返回 202/429/507 |
| `GET /csp/reports?status=open\|handled&limit=&offset=` | 历史查询（按最近上报倒序分页） |
| `GET /csp/reports/aggregate` | 按 `violated_directive` 聚合：去重事件数、原始上报次数、未处理数 |
| `POST /csp/reports/{fingerprint}/handled` | 标记为已处理（幂等） |

### 上报格式

同时兼容：

1. 传统 report-uri：`{"csp-report": {"document-uri": ..., "violated-directive": "script-src 'self'", ...}}`
2. Reporting API：`[{"type": "csp-violation", "body": {"documentURL": ..., "effective-directive": "script-src", ...}}]`（也接受单个 item 对象）

### 去重、限速与容量

- **指纹**：`document_uri + violated_directive（取指令名部分）+ blocked_uri +
  source_file + line_number` 的 SHA-256；相同指纹只保留一条记录，重复上报累加
  `count` 并刷新 `last_seen`。
- **限速**：滑动窗口（默认 60 秒，每窗口 100 次提交，含重复），超限返回
  `429 {"reason": "rate_limited"}`。
- **容量硬上限**：默认 10000 条去重记录，达到上限返回 `507
  {"reason": "storage_full"}`；重复上报只更新计数、不新增行。两者共同保证存储
  有界。
- 可通过 `ReportStore(path, RateLimitConfig(...))` 调整参数（环境变量化可按需扩展）。

### 本地模拟示例

```bash
# 1) 热更新：/admin 仅报告
curl -X PUT localhost:8000/csp/config -H 'content-type: application/json' --data @config.json

# 2) 模拟浏览器上报
curl -X POST localhost:8000/csp/report -H 'content-type: application/json' -d '{
  "csp-report": {
    "document-uri": "http://app/checkout",
    "violated-directive": "script-src '\''self'\''",
    "blocked-uri": "http://evil.example/inject.js",
    "line-number": 42
  }
}'

# 3) 查询 / 聚合 / 处理
curl "localhost:8000/csp/reports?status=open"
curl "localhost:8000/csp/reports/aggregate"
curl -X POST "localhost:8000/csp/reports/<fingerprint>/handled"
```

## 持久化

违规记录存于 SQLite（默认 `data/csp-reports.db`，自动建目录，WAL 模式）。
重启服务后记录、计数、`open/handled` 状态全部保留；限速滑动窗口仅存内存
（重启刷新窗口是可接受的语义）。测试可用内存库 `ReportStore(":memory:")`。

## 并发模型说明

- `PolicyStore.snapshot()` 返回不可变 `PolicyConfig`（frozen dataclass），无锁读取；
  更新在锁内整体替换引用，版本号单调递增。
- 在途请求即使在更新之后才执行解析，仍基于旧快照得到旧版本结果，
  `X-CSP-Config-Version` / `X-CSP-Matched-Prefix` / `X-CSP-Mode` 可解释该结果。
- `NonceGenerator` 内部加锁并维护有界碰撞历史；`ReportStore` 用 RLock 串行化
  “限速判断 → 去重判断 → 写库”的完整流程，避免并发下重复插入与窗口竞争。

## 测试

```bash
uv run pytest
```

覆盖：

- `tests/test_policy.py` — 继承/覆盖、最长前缀匹配、指令渲染、nonce 注入与版本快照；
- `tests/test_nonce.py` — 唯一性、并发唯一性、HTML 注入边界；
- `tests/test_reports.py` — 两种上报格式归一化、指纹去重、滑动窗口限速、容量上限、
  聚合、状态流转、并发写入；
- `tests/test_persistence.py` — 重启后记录/计数/状态恢复；
- `tests/test_app.py` — HTTP 层 nonce 头体一致、模式切换不改变策略、热更新、
  非法配置拒绝、上报生命周期、并发请求一致性；
- `tests/test_concurrency.py` — 在途请求保留旧策略、更新期间并发读取、
  真实 HTTP 流量下反复热更新。

## 代码结构

```
csp_service/
  config.py   # 配置模型、校验解析、不可变快照存储
  policy.py   # 最长前缀解析、继承合并、CSP 头渲染（含 nonce）
  nonce.py    # 线程安全 nonce 生成器、HTML 注入
  reports.py  # 上报归一化/指纹、SQLite 存储、去重限速聚合
  app.py      # FastAPI 装配：CSP 中间件 + 管理/上报 API + 演示页面
main.py       # uvicorn 入口
tests/        # 自动化测试
```

# CSP Service（内容安全策略服务）

一个可本地验证的内容安全策略（Content-Security-Policy）生成、注入与违规上报收集服务，
基于 FastAPI + ASGI 中间件 + SQLite 实现。

## 能力总览

| # | 能力 | 实现位置 |
|---|------|----------|
| 1 | 按路由配置 CSP，默认策略 + 子路由继承/覆盖，热更新不影响在途请求 | `app/policy_manager.py`、`app/models.py` |
| 2 | 内联脚本/样式一次性 nonce，响应头与页面内容同一响应一致、跨响应不同 | `app/nonce.py`、`app/middleware.py` |
| 3 | enforce / report-only 两种模式，只改响应头名，不改变策略计算 | `app/header.py`、`app/middleware.py` |
| 4 | 违规报告去重、按签名限速、存储有界，刷量不会导致无界增长 | `app/reports/service.py`、`ratelimit.py` |
| 5 | 违规历史查询、聚合、已处理/未处理状态、SQLite 重启不丢数据 | `app/reports/store.py` |
| 6 | 快照不可变 + 锁保护引用替换，并发线程安全；在途请求保持旧版本策略 | `PolicySnapshot`、`CSPMiddleware` |
| 7 | 自动化测试与本文档 | `tests/` |

## 快速开始

```bash
uv sync
uv run uvicorn main:app --reload --port 8000
```

打开 http://127.0.0.1:8000/ 可看到演示页面；响应头中的
`Content-Security-Policy` 与页面里 `<script>/<style>` 上的 `nonce` 完全一致。

默认持久化文件（可用环境变量 `CSP_CONFIG_PATH` / `CSP_DB_PATH` 覆盖）：

- `data/csp_policy.json`：当前策略配置（每次热更新原子落盘，重启恢复）
- `data/csp_reports.db`：违规上报 SQLite 数据库（WAL 模式）

## 策略配置模型

```jsonc
{
  "version": 2,                 // 由服务维护，每次更新 +1
  "mode": "enforce",            // 全局默认模式：enforce | report-only
  "report_uri": "/csp/report",  // 由服务统一注入 report-uri，禁止在规则中配置
  "rules": [
    {
      "path": "/",              // 必须以 / 开头；按路径段边界前缀匹配
      "directives": {
        "default-src": ["'self'"],
        "script-src": ["'self'"]
      }
                         // 不写 mode 即继承上层
    },
    {
      "path": "/admin",
      "directives": {
        "script-src": ["'self'", "https://cdn.example.com"]
      },
      "mode": "report-only"     // 仅该子范围切换为仅报告模式
    }
  ]
}
```

### 继承与覆盖语义

- 匹配按路径段边界进行：规则 `/admin` 命中 `/admin`、`/admin/x`，
  但**不**命中 `/administrator`。
- 请求路径沿继承链（`/` → `/admin` → `/admin/api` …）合并指令：
  - **同名指令**：子范围的源列表**整体覆盖**父范围（不做逐项合并）；
  - **不同名指令**：子范围新增，持续向下继承；
  - **模式**：取继承链上最深层显式声明的 `mode`，缺省用全局模式。
- `report-uri` / `report-to` 由服务统一管理，规则中配置会被拒绝。

### 热更新与并发语义

- 每次请求在进入中间件时获取一个**不可变快照引用**：
  即使处理过程中策略被更新，本请求仍按旧快照计算，
  响应头 `X-CSP-Policy-Version` 标明所用版本，结果可解释。
- 热更新先解析校验、再在锁内整体替换快照引用并原子写盘；
  非法配置返回 `400` 且旧策略保持不变。

### 两种模式

| 模式 | 响应头 | 浏览器行为 |
|------|--------|-----------|
| `enforce` | `Content-Security-Policy` | 拦截违规并上报 |
| `report-only` | `Content-Security-Policy-Report-Only` | 只上报、不拦截，正常响应不受影响 |

两种模式下指令与 nonce 的计算完全相同，仅响应头名称不同。

## HTTP 接口

### 页面与策略

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/` | 演示 HTML 页（自动注入 nonce） |
| GET | `/healthz` | 健康检查 |
| GET | `/csp/config` | 查看当前策略配置与版本 |
| PUT | `/csp/config` | 原子热更新策略，body 为上述配置模型（`version` 由服务维护） |

```bash
curl -X PUT http://127.0.0.1:8000/csp/config \
  -H 'Content-Type: application/json' \
  -d '{"mode":"enforce","report_uri":"/csp/report","rules":[
        {"path":"/","directives":{"default-src":["'"'"'self'"'"'"]}},
        {"path":"/admin","directives":{"script-src":["'"'"'self'"'"'"]},
                     "mode":"report-only"}]}'
```

### 违规上报与处理

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/csp/report` | 接收浏览器标准 `application/csp-report` 格式（`{"csp-report": {...}}`） |
| GET | `/csp/reports?status=open\|resolved&limit=&offset=` | 历史查询，可按处理状态过滤 |
| GET | `/csp/reports/aggregate` | 按「违规指令 + 被拦截资源」聚合次数 |
| GET | `/csp/reports/counts` | 签名总数、累计次数、open/resolved 计数 |
| PATCH | `/csp/reports/{id}` | 更新处理状态：`{"status":"resolved"}` / `{"status":"open"}` |

上报响应：

```json
{ "accepted": true, "reason": "stored", "id": 1, "count": 2,
  "duplicate": true, "pruned": 0 }
```

- `accepted=false, reason="rate_limited"`：同类违规在窗口内超过限速；
- `accepted=false, reason="payload_too_large"`：单条超过 16KB 上限。

### 去重、限速与有界存储

- **去重键** = `document-uri | 违规指令名 | blocked-uri | source-file | 行 | 列`
  的 SHA-256；重复事件不新增记录，只累加 `count` 与 `last_seen`。
- **限速**：滑动窗口（默认 60 秒/签名 10 次，可在 `ReportService` 构造时调整），
  按去重签名隔离；被限流的上报不落库。限流器自身对跟踪的 key 数有硬上限并惰性回收。
- **有界存储**：默认最多保留 10000 个不同违规签名，超限按最旧记录优先删除，
  防止恶意刷量撑爆磁盘。
- **持久化**：所有写操作即时提交到 SQLite，重启后记录、计数与处理状态均保留。

## 本地模拟浏览器上报

```bash
curl -X POST http://127.0.0.1:8000/csp/report \
  -H 'Content-Type: application/json' \
  -d '{"csp-report":{
        "document-uri":"http://127.0.0.1:8000/",
        "violated-directive":"script-src '"'"'self'"'"'",
        "blocked-uri":"http://evil.example/a.js",
        "line-number":3,"column-number":8}}'
```

重复发送同一请求可观察 `duplicate=true` 与 `count` 累加；高频发送可观察
`rate_limited`；随后可在 `/csp/reports/aggregate` 看到聚合结果。

## 测试

```bash
uv run pytest
```

覆盖：策略继承与覆盖、路径边界、非法配置校验、快照隔离与热更新、
nonce 头/页面一致性与跨响应唯一性、两种模式切换、去重/限速/容量裁剪、
SQLite 重启恢复、状态流转，以及多线程并发下的 nonce 分配、策略读取、
更新与在途请求版本隔离、并发上报落库。

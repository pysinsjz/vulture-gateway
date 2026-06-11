# 对接总纲 —— 端点总表 · 错误矩阵 · 公共头

> 桌面端对接的**单一入口**。各端点细节见对应流程文档：[auth](./auth.md) · [skill-plugin-lifecycle](./skill-plugin-lifecycle.md) · [llm-proxy](./llm-proxy.md) · [bootstrap](./bootstrap.md) · [distribution](./distribution.md) · [clawhub-integration](./clawhub-integration.md)。

---

## 1. 三个端点族

桌面端只与网关 `https://<gateway>` 通信。按 base 与契约分三族：

| 族 | base | 鉴权 | 成功体 | 错误体 | 即时吊销 |
|---|---|---|---|---|---|
| **OAuth** | `/oauth` | 公共客户端 + PKCE / refresh（无 `client_secret`） | OAuth token JSON | `{ error, error_description }`（RFC 6749） | n/a（令牌签发环节） |
| **管理 API** | `/api/v1` | `Bearer`（`bootstrap`、`app/latest` 为公开例外） | JSON 实体 / `204` | **真实 HTTP 状态码** + `ApiError{ error, message }` | ✓ `token_version` |
| **LLM 代理** | `/v1` | `Bearer` | OpenAI JSON（含 SSE） | **OpenAI** `{ error:{ message, type, code } }`（含网关自身 401/402/403/413/429） | ✓ `token_version` |

> **不使用** web-go 的 `response.Success/Fail` 200-信封；管理 API 全线 RESTful（ADR-0011）。
> `/api/v1/skills`、`/api/v1/plugins` 由网关鉴权后转发内网 ClawHub（fork 裁剪版），桌面端无感。

---

## 2. 端点总表

绝对路径 · 方法 · 鉴权 · 说明。

### OAuth（`/oauth/*`）
| 方法 路径 | 鉴权 | 说明 |
|---|---|---|
| `GET /oauth/authorize` | 公开（浏览器入口） | 302 跳 Casdoor；失败回跳 `redirect_uri?error=&state=` |
| `GET /oauth/callback/casdoor` | 公开（Casdoor 回调） | 换 Casdoor token、签发 GW_CODE（TTL 60s） |
| `POST /oauth/token` | PKCE / refresh | `grant_type=authorization_code`（换 token）或 `refresh_token`（轮换，含 60s 幂等宽限窗） |

### 管理 API（`/api/v1/*`，`Bearer`）
| 方法 路径 | 鉴权 | 成功 | 说明 |
|---|---|---|---|
| `GET /api/v1/bootstrap` | **公开** | `200`+`ETag` | 启动聚合；`(channel,X-App-Version,X-Platform)` 分桶 |
| `GET /api/v1/app/latest` | **公开** | `200` | 宿主 App 自更新检查 |
| `POST /api/v1/auth/logout` | Bearer 或 body `refresh_token` 兜底 | `204` | 吊销当前 Device |
| `GET /api/v1/devices` | Bearer | `200` 数组 | 已授权 Device 列表 |
| `DELETE /api/v1/devices/{device_id}` | Bearer | `204` | 吊销指定 Device |
| `POST /api/v1/telemetry/install` | Bearer | `200` | 安装遥测（best-effort） |
| `GET /api/v1/skills` | Bearer | `200` `Page<T>` | skill 列表（无搜索，sort+游标+filter） |
| `GET /api/v1/skills/{slug}` | Bearer | `200` | skill 详情 |
| `GET /api/v1/skills/{slug}/versions` | Bearer | `200` `Page<T>` | 版本历史 |
| `GET /api/v1/skills/{slug}/versions/{version}` | Bearer | `200` | 指定版本（含 `artifact.sha256`） |
| `GET /api/v1/skills/{slug}/resolve?hash=` | Bearer | `200` | 指纹 → 版本（skill 更新检测） |
| `GET /api/v1/skills/{slug}/download?version=` | Bearer | **`302`** | 跳短时效存储 URL（R2 backed） |
| `POST /api/v1/skills/-/security-verdicts` | Bearer | `200` | 批量安全裁决（1–100） |
| `GET /api/v1/plugins` | Bearer | `200` `Page<T>` | plugin 列表 |
| `GET /api/v1/plugins/{name}/versions/{version}` | Bearer | `200` | plugin 指定版本 |
| `GET /api/v1/plugins/{name}/download?version=` | Bearer | **`302`** | 跳短时效存储 URL |
| `GET /api/v1/plugins/{name}/versions/{version}/artifact/download` | Bearer | **`302`** | npm-pack `.tgz` |
| `GET /api/v1/plugins/{name}/versions/{version}/security` | Bearer | `200` | 单个安装阻断查询（无批量） |

> plugin 升级走**版本比较**（非指纹）：`GET /api/v1/plugins/{name}` 取最新版本与 `lock.plugins[name].version` 比较。

### LLM 代理（`/v1/*`，`Bearer`，OpenAI 兼容）
| 方法 路径 | 鉴权 | 说明 |
|---|---|---|
| `GET /v1/models` | Bearer | 代理 litellm 模型列表 |
| `POST /v1/chat/completions` | Bearer | 流式/非流式推理；顺序：鉴权→订阅→窗口预检→转发 |

---

## 3. 全局错误矩阵

桌面端拦截器按 **HTTP 状态码 + 族** 分流。

| 状态 | 适用族 | code / 形态 | 含义 | 处理 |
|---|---|---|---|---|
| `204` | 管理 API | 空体 | logout/DELETE 成功 | — |
| `302` | 管理 API | `Location` | skill/plugin 下载跳存储 URL | 跟随直连存储 |
| `304` | 管理 API | — | bootstrap 无变化 | 用本地缓存 |
| `400` | 全部 | `ApiError` / OpenAI | 参数错（如 hash 非 64hex、超上下文窗） | 修正请求 |
| `401` | 全部 | `ApiError` / OAuth `invalid_grant` / OpenAI | access 失效 / RT 复用 | 刷新（single-flight）或重登 |
| `402` | LLM | OpenAI `no_active_subscription` | 无有效订阅 | 引导订阅 |
| `403` | 管理 / LLM | `ApiError` / OpenAI | Device 被吊销 / `blockedFromDownload` | 重登 / 拒装 |
| `404` | 管理 API | `ApiError` | slug/name 不存在 | 提示不存在 |
| `410` | 管理 API | `ApiError` | 版本已软删除 | 提示下架、换版本 |
| `413` | LLM | OpenAI `request_too_large` | 请求体超 25MB | 裁剪附件/分批 |
| `423`/`409` | 管理 API | `ApiError` | 扫描中 / 质量不达标 | 稍后重试 |
| `429` | LLM | OpenAI `usage_window_exceeded`（+`Retry-After`/`X-Window-*-Reset`） | 用量窗口触顶 | 展示恢复时间 |
| `429` | LLM | OpenAI（其他 code） | 上游供应商限流 | 按 `Retry-After` 退避 |
| `5xx` | 全部 | `ApiError` / OpenAI | 内部 / 上游不可用 | 退避重试，附 `x-litellm-call-id` |

> 安全阻断（`security-verdicts.decision=fail` / `trust.blockedFromDownload`）与完整性校验失败（sha256 不符）属业务级，桌面端**拒装 / 丢弃重下**。

---

## 4. 公共请求头

| 头 | 适用 | 说明 |
|---|---|---|
| `Authorization: Bearer <access JWT>` | 所有需登录端点 | access TTL 30min；claims：`sub`/`device_id`/`token_version`/`exp` |
| `X-App-Version` | skill/plugin、bootstrap、app/latest | 桌面 App 版本（兼容过滤 / 强更判断） |
| `X-Platform` | skill/plugin、bootstrap、app/latest | 平台架构（如 `darwin-arm64`） |
| `If-None-Match` | bootstrap 轮询 | 上次 `ETag`，无变化得 `304` |

| 响应头 | 适用 | 说明 |
|---|---|---|
| `x-litellm-call-id` | LLM | 透传，报障时附上 |
| `Retry-After` / `X-Window-5h-Reset` / `X-Window-Week-Reset` | LLM 429 | 窗口恢复时间 |

> 网关**剥除**上游成本敏感头（`x-litellm-response-cost` 等），桌面端不可见。

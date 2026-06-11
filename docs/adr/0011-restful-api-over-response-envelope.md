# 管理 API 用 RESTful 状态码而非 200-信封

面向桌面端的管理 API（`/api/v1/*`，skill/plugin/devices/bootstrap/app 等）一律返回**真实 HTTP 状态码** + `ApiError{ error, message }` 错误体，成功直接返回 JSON 实体或 `204`——**不**采用 web-go 房子风格的 `response.Success/Fail`（HTTP 200 + `{code,message,data}` 信封）。

理由是桌面端要对接的三条线本就有两条用真实状态码：OAuth 端点（`/oauth/*`）遵循 RFC 6749 的 `{error,error_description}`，LLM 代理（`/v1/*`）贴 OpenAI 的 `{error:{message,type,code}}`——两者的错误形态由外部规范固定、无法套信封。若管理 API 单独用 200-信封，桌面端就要维护三套判错逻辑，且这一套还得忽略 HTTP 状态码、改读 body 里的业务码。统一成 RESTful 后，桌面端一个拦截器 `switch(httpStatus)` 即可覆盖全部三条线；完整错误矩阵见 `docs/flows/api-conventions.md`。

代价是本项目桌面契约**有意偏离** web-go 的 `response.Success/Fail` 约定——这是面向「单一桌面客户端 + 代理 litellm/ClawHub」的取舍，与 web-go 那种多前端共用统一信封的场景不同。

## 备选方案

- **沿用 web-go `response.Success/Fail` 200-信封** —— 否决：`/oauth/*` 与 `/v1/*` 的错误形态externally 固定、套不进信封，最终仍是三套不一致；且强迫客户端忽略 HTTP 状态码、改解析 body 业务码。
- **混合：真实状态码 + body 仍用 `{code,message,data}` 信封** —— 否决：`code` 字段相对 HTTP 状态码冗余，徒增 body 噪声，没有比纯 `ApiError` 更多的信息。

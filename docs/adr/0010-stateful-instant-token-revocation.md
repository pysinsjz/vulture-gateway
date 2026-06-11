# 有状态即时 token 吊销

尽管 access token 是 JWT，网关让吊销**即时生效**，而非等到 token TTL 自然过期。每个 access JWT 携带 `device_id` + `token_version`；网关在 Redis 维护每个 Device 当前有效的 `token_version`，`JWTAuth` 中间件在每个认证请求上做「签名校验 **加一次 O(1) 的 Redis 比对**」。登出、Web 控制台吊销设备、refresh token 复用（判盗）检测，都只需 bump 该 Device 的 `token_version`，即可即时作废该 Device 所有在途 access token。refresh token 每次使用轮换；出示已被取代的 refresh token 视为被盗，作废整个 token 家族。

这是有意用「严格无状态」换取「即时吊销」；每请求成本是一次 Redis 查询，且 Redis 本就在技术栈内。

## 备选方案

- **短 access TTL、接受吊销空窗（完全无状态）** —— 否决：被吊销的 Device 在其 access token 过期前（至多一个 TTL）仍能继续使用。

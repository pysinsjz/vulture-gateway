# 网关即 OAuth 授权服务器、Casdoor 在上游

桌面端对**网关**（而非直接对 Casdoor）执行 OAuth 2.0 授权码 + PKCE 流程。网关暴露 `/oauth/authorize`、`/oauth/callback/casdoor`、`/oauth/token`，对桌面端充当授权服务器（Authorization Server），同时作为 Casdoor 上游的 OIDC client：浏览器被「网关 → Casdoor」重定向去完成实际登录，Casdoor 回到网关回调，网关签发自己的授权码（绑定桌面端的 PKCE challenge）以及自己的 JWT + refresh token。因此桌面端与 Casdoor 零耦合，网关完全掌控面向桌面端的 token 契约（增删上游渠道绝不触及桌面端）。

## 备选方案

- **桌面端直接作 Casdoor 的 OIDC client**、事后再到网关换 Casdoor token —— 否决：使桌面端耦合 Casdoor，并把 token 契约割裂到两方。

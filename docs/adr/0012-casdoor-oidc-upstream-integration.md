# Casdoor OIDC 上游接入：go-oidc + issuer discovery + nonce

> **⚠️ Superseded by [ADR-0013](0013-self-built-identity-authentication.md)（2026-06-22）。** Casdoor 上游与全部 oidc 代码已删，改为网关内置自建认证。本文保留作历史记录。

ADR-0002/0009 已定「身份委托 Casdoor、网关作授权服务器、Casdoor 在上游」，网关侧 OAuth 全流程已对着 stub 上游（`internal/auth/upstream.go`）实现并测试。本 ADR 定**真实 Casdoor OIDC client（`oidc` 模式）的接入实现决策**。

- **用 `coreos/go-oidc` + `golang.org/x/oauth2`，而非手写 token 交换。** `Exchange` 经 OIDC discovery（`/.well-known/openid-configuration`）拿端点、用 Casdoor 的 JWKS 本地验签 `id_token`，从已验证 token 取 `sub` 作 `User.Subject`（稳定 GUID，邮箱/渠道变更不影响身份）。验签 / JWKS 轮换 / discovery 不手搓。配置上游从显式 `authorize_url/token_url` 收敛为单个 **`issuer`**，其余端点自动得到。
- **加 `nonce`。** authorize 时生成随机 nonce 存入 `AuthzRequest`、带进上游 authorize URL，`Exchange` 时由 go-oidc verifier 校验 `id_token.nonce` 逐字相等。`linkedState` 已提供 CSRF 防护，nonce 再防 id_token 注入/重放；code flow 下规范列为 RECOMMENDED，此处 plumbing 近零成本故采纳。
- **dev 经 SSH 隧道访问 Casdoor，不放行安全组 8000。** 浏览器与网关都在本机，经 `ssh -L 8000:localhost:8000` 以 `http://127.0.0.1:8000` 访问 Casdoor。issuer、Casdoor `origin`、discovery 文档、`iss` claim 四者统一为 `http://127.0.0.1:8000`，避免 host 不一致导致 go-oidc 验签失败。约束：登录全程隧道须保持连通。
- **dev 仅开 Casdoor 邮箱+密码渠道。** 邮箱验证码/手机/微信有外部依赖（SMTP/短信/微信开放平台），拿到凭据后纯 Casdoor 后台开启，不动网关代码——正是委托 IdP 的收益。
- **client_secret 经环境变量 `VG_OAUTH_UPSTREAM_CLIENT_SECRET` 注入**，不入配置文件 / git；scope 取 `openid`。
- **oidc upstream 用 httptest 假 provider 单测全路径**（discovery / 验签 / nonce / sub 提取 / iss·nonce·签名·过期失败分支），CI 安全；另对真 Casdoor 做一次隧道端到端冒烟，不替代单测。

## 备选方案

- **手写 token POST + 自取 Casdoor 证书验签 / 调 `/api/userinfo`** —— 否决：JWKS 拉取·缓存·轮换与 token 校验安全细节易错，不该手搓标准 OIDC client。
- **放行安全组 8000 直连 `8.136.147.138:8000`** —— 否决：dev 无需对公网暴露 Casdoor；隧道更安全，且把所有 URL 收敛到 localhost 反而消除了 issuer 不一致的坑。
- **code flow 不加 nonce（最小实现）** —— 否决：此处成本近零且 go-oidc 内建，没有不加的理由。
- **oidc 段不写自动化测试、仅手动验证** —— 否决：验签/discovery/nonce 恰是最该被测试钉住处。

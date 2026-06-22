# 身份委托给自托管 Casdoor

> **⚠️ Superseded by [ADR-0013](0013-self-built-identity-authentication.md)（2026-06-22）。** 因数据主权 + 简化部署，已反转本决策：认证能力内聚进网关、删除 Casdoor 上游。本文保留作历史记录。

网关需要四种登录渠道（邮箱密码、邮箱验证码、手机验证码、微信扫码）外加未来的社交聚合登录。我们不在网关内逐个实现这些渠道（及微信 OAuth 流程、短信对接），而是将**整个身份能力委托给一个自托管的 Casdoor 实例**作为 Identity Provider：由它持有各登录渠道与托管登录页，网关通过 **OIDC** 对接，将 Casdoor 认证出的 subject 映射到网关自己的单层 User，并签发网关自己的 JWT + Device。Casdoor 是 Go 原生（与技术栈一致）、开箱支持微信扫码 + 手机/邮箱验证码，且可共用 PostgreSQL。

## 备选方案

- **在网关内用库自建各渠道** —— 否决：重复实现 IdP 已解决的微信 OAuth + 短信对接。
- **Logto / Keycloak** —— 否决：微信支持弱 / 不明确；Keycloak 是偏重的 Java 栈。

# 内聚自建身份认证：删 Casdoor 上游，网关内置 SigninMethod

**Supersedes ADR-0002（身份委托 Casdoor）、ADR-0012（Casdoor OIDC 上游接入）。保留 ADR-0003（浏览器中转 PKCE）、ADR-0009（网关作授权服务器）、ADR-0010（即时吊销）。**

ADR-0002 当初将身份委托给自托管 Casdoor，理由是「不在网关内重复实现微信 OAuth + 短信对接」。现因**数据主权**（用户/凭据数据必须落在网关自己的库，不经第三方 IdP）与**简化部署**（去掉 Casdoor 容器及其独立 postgres）两个驱动，**反转该决策**：把认证能力内聚进网关，删除 Casdoor 上游依赖与全部 oidc 代码，自建邮箱/手机的「密码 + 验证码」登录，并把架构对齐 Casdoor，以便未来第三方登录直接参考 Casdoor 代码迁移。

代价是明确的：网关从此**自行承担全部认证安全责任**（密码存储、防爆破、验证码防刷、找回流程、传输加密、未来合规），这部分原由 Casdoor 兜底。本 ADR 即为接管这份责任而立。

## 决策

- **范围：开放注册（to C）。** `email` + `phone` 两种登录标识 × 「密码 + 验证码」两种方式；为未来第三方（社会化）登录留扩展点。Phase 1 **不做** MFA / WebAuthn / 企业 SSO（LDAP/SAML）/ 管理后台——这些是 Casdoor 的重量级能力，本次内聚刻意不背。SMTP（邮件验证码/找回）与短信渠道（手机验证码）成为 Phase 1 硬依赖。

- **数据模型：`User` + `Identity` 分离表，不用 Casdoor 宽表。** `User` 是身份主体（保留 `subject` 作稳定身份锚）；`Identity` 是一个 User 的多条登录身份（`type`=email/phone/oauth，`identifier`，`secret`=密码 hash 或空，`provider`）。一人多登录方式（email + 手机 + 未来微信）天然落在「一个 User → 多条 Identity」。否决 Casdoor 那张几十列的宽表：要它的扩展性，不要它的宽表实现。

- **验证码登录＝登录即注册。** 验证码通过时若该 `identifier` 无 `Identity`，自动建 `User` + `Identity`（`secret` 留空，表示尚未设密码、只能验证码登录）。密码登录要求账号已存在且 `secret` 非空。「设置/补充密码」流程后置 Phase 2。

- **单一 `SigninMethod` 抽象 + `Kind` 派发 + registry。** 所有登录方式（password / email_code / sms_code / 未来 social）收进一个接口与一个配置驱动的 registry，登录页遍历同一 list 渲染。接口用 `Kind` 区分执行路径：`Direct`（本地校验，走 `Verify`）与 `Redirect`（跳外部 IdP，走 `AuthorizeURL`+`Exchange`）。Phase 1 仅实现 `Direct` 三方式；`Redirect` 抽象**保留定义但无实现**，作为未来从 Casdoor 迁移 social provider 的接入点。（诚实记录：Casdoor 原本是 `signinMethods` + `providers` 两个列表，本设计比它更统一，代价是 `Direct` 实现不用 `AuthorizeURL`、`Redirect` 实现不用 `Verify` 的轻微不内聚。）

- **身份解析锚点（方案A，下游零改动）。** 本地 `SigninMethod.Verify` 内部完成 `Identity → User` 解析（含登录即注册建号），**返回 `User.uuid` 作为 subject**。下游 `ResolveOrCreateBySubject(subject)` → 签 GW_CODE → access JWT → refresh 轮换 → 即时吊销 → 设备，**一行不改**（这条链路已由 A1/A2/A3 端到端验证，不为模型纯粹重构它）。`User.subject` 语义升级：本地用户＝自身 uuid，未来 social＝`provider:sub`。

- **`provider` 表对齐 Casdoor，Phase 1 用 config seed。** 建一张精简 `provider` 表，字段对齐 Casdoor 核心列（`category`=email/sms/oauth，`type`=具体厂商，`client_id`/`client_secret`/`host`/`port`…）。Phase 1 只放 email/sms 两类，配置入口用 config 启动 seed（喂进 DB 或内存 registry），**不做后台 UI**；未来 social 直接加行 + 搬 Casdoor 适配器。

- **密码传输：测试期 RSA 公钥前端加密 + 一次性 token 防重放（与 Casdoor cert 加密同构）。** 服务端持 RSA 密钥对，登录页下发公钥；前端 RSA-OAEP 加密密码后提交，后端私钥解密 → bcrypt 校验。加密载荷拼入登录页一次性 token（CSRF/authz token，本会话一次性）防重放。**边界明确：防窃听不防 MITM，不是 HTTPS 的替代品。**

- **安全基线。** bcrypt（cost 12）；密码 ≥ 8 位不强制复杂度组合；OTP 6 位数字 / 有效期 5 分钟 / Redis 存 / 重发间隔 60s / 单码最多试 5 次；验证码按 `dest + IP` 限发（防短信邮件轰炸）；密码登录失败按 `identifier + IP` 计数，5 次锁 15 分钟；登录页表单一次性 CSRF token。

- **删除与回退。** 删除 `internal/auth/upstream.go` 的 `oidcUpstream`/`stubUpstream`、`/oauth/callback/casdoor` 上游回调、`config` 的 `oauth.upstream`；停用 Casdoor 容器。**无快速回退**——这是「彻底自建」的代价，已接受。

## 阶段

- **Phase 1（MVP）：** `User`/`Identity`/`provider` 模型；`SigninMethod` registry；`password`/`email_code`/`sms_code` 三实现；RSA 密码加密；网关渲染登录页（保留浏览器中转 PKCE，ADR-0003）；开放注册；bcrypt + 限流 + 验证码防刷；删 Casdoor。→ 登录全链路自建跑通、数据全在自己库、Casdoor 容器可停。
- **Phase 2：** 找回密码（邮箱验证码）、无密码账号设密码、密码策略、登录/认证审计。
- **Phase 3：** 第三方登录（参考 Casdoor 迁移 provider 适配器，落 `Redirect` 类 method）、邮箱验证。
- **生产上线硬门槛：** HTTPS（域名 + 证书 + 反代）。RSA 前端加密仅为测试期过渡 + 纵深防御，**不因有了它而取消 HTTPS 要求**。

## 备选方案

- **保留 Casdoor、仅降级为可选 provider（代码留、容器停、回退靠配置）** —— 否决：要彻底删、贴 Casdoor 同构自建以便未来迁移；留着 oidc/stub 是包袱，且数据主权要求默认链路完全不经第三方。
- **双抽象（内置 `LocalAuthenticator` + 外部 `UpstreamIDP` 分离）** —— 否决：选单一 `SigninMethod` 列表，统一注册/配置/渲染，更贴 Casdoor 心智。
- **`User` 宽表（Casdoor 原样）** —— 否决：分离表对「一人多身份」和「未来加第三方」扩展更干净。
- **identity-based 下游重构（去掉 `subject`）** —— 否决：不动已验证的 GW_CODE/JWT/refresh 链路。
- **纯 config 渠道、不建 `provider` 表** —— 否决：未来 social 迁移要返工，对齐 Casdoor 才能低摩擦搬代码。
- **明文 / 对称简单加密传密码** —— 否决：无 HTTPS 下密文可被抓包重放（密文＝等价密码），等于没加密；RSA 公钥加密 + 一次性 token 才真正多挡了重放。
- **强制 HTTPS 作为内聚前置** —— 推迟到生产上线门槛：测试期用 RSA 过渡放行，但 ADR 钉死生产必须 HTTPS。

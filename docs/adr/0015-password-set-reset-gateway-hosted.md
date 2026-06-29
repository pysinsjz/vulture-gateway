# 密码「设置 / 重置」：网关托管页 + 桌面端零逻辑入口

**承接 ADR-0013 Phase 2（找回密码、无密码账号设密码、密码策略）。复用 ADR-0013 的 `SigninMethod`/`Identity`/RSA 加密/OTP/限流基线，复用 ADR-0003 浏览器中转。**

ADR-0013 自建了「密码 + 验证码」登录，但只实现了**校验**已有密码（`passwordMethod.Verify`），把**写入/更新 `secret`**（设置、重置、找回）显式推到 Phase 2。本 ADR 兑现该 Phase 2：让 User 能给账号设置首个密码、重置已有密码，覆盖登录态（在桌面端设置入口发起）与登出态（在登录页「忘记密码」发起）两种场景。

桌面端此前已按「桌面自渲染表单 + Tauri invoke 调 API」的设想做了一套内存 mock（`PasswordDialog.tsx` + `passwordProtocol.ts`）。本 ADR **反转该设想**：所有 UI 与逻辑都在网关层，桌面端只做「打开浏览器」的入口。理由是与 ADR-0013 的网关托管登录页架构对齐——密码明文只在网关自己的页面里经 RSA 加密产生、绝不进桌面进程，认证安全责任全部内聚在网关，桌面端不背任何凭据处理。

## 决策

- **网关托管密码页 `GET /oauth/password`，桌面端零逻辑入口。** 复用 `login_page_tmpl.go` 模式：网关渲染页面、内嵌 RSA 公钥、浏览器内 `SubtleCrypto` RSA-OAEP(SHA-256) 加密新密码后提交。桌面端「设置/重置密码」按钮只 `open_browser(url)`，不渲染表单、不持密码、不解析响应。现有桌面 mock（`PasswordDialog.tsx` + `passwordProtocol.ts`）**作废**，降级为开浏览器按钮。

- **两条入口、两种身份证明。**
  - **登录态（绑定路径）：** 桌面端用 Bearer 调新端点 `POST /api/v1/auth/password-link`（走现有 `JWTAuth`）铸一个 **Password Link** 一次性 token，返回 `{ url: "<gateway>/oauth/password?t=<token>" }`，桌面 `open_browser` 打开。页面持 `t` → 预绑定该 User、邮箱预填。
  - **登出态（验证码路径）：** 登录页 `/oauth/login` 加「忘记密码?」链接 → `GET /oauth/password`（无 `t`）→ 要求输入标识 + OTP 证明身份。

- **OTP 默认必需，唯一例外是「登录态首设」。** 规则按服务端 `secret` 状态派发：`secret` 为空 + 持有效 Password Link → **首设免 OTP**（Bearer 已证明身份）；`secret` 非空（改密）→ **不论登录态都要 OTP**，防会话劫持即改密；登出态 → 一律 OTP。

- **密码是账号级，写到 User 所有本地身份。** 设置/重置成功后，把新 bcrypt hash 写入该 User 名下所有 `provider` 为空的 Identity（email/phone），oauth 身份不写。新增 `IdentityRepository.UpdateSecretByUserUUID`，多行更新在事务内完成。**Set/Reset 由服务端依 `secret` 是否为空判定，客户端不声明。**

- **OTP 用途隔离。** 发码/验码 key 带 `purpose`：登录 `otp:login:<id>`、改密 `otp:pwreset:<id>`，`SendCode/Verify` 增 `purpose` 参数。重发冷却与尝试计数各用途独立，登录侧行为不变（默认 `login`）。

- **发码授权靠页面作用域，不靠 Bearer。** 关键约束：托管密码页跑在系统浏览器里，**没有桌面端的 Bearer**——这正是 Password Link 存在的理由（桌面用 Bearer 换页面作用域的 `t`）。因此改密发码是页面作用域端点 `POST /oauth/password/send-code`：绑定路径由 `t` 定位账号自有标识、登出路径由页面一次性 CSRF token + 提交的标识授权。**唯一的 Bearer 端点是 `password-link`**（由桌面调，不在浏览器里调）。

- **Password Link 承载。** 复用 GWCodeStore 同款 Redis 单次码模式：key `pwlink:<token>` → `{user_uuid}`，TTL 5 分钟、Take 时即删（单次有效、防重放）。

- **安全基线沿用 ADR-0013 并收紧密码策略。** bcrypt（cost 12）；RSA-OAEP 前端加密 + 一次性 token 防重放（防窃听不防 MITM，不替代 HTTPS）；OTP 6 位 / 5 分钟 / 60s 重发 / 单码试 5 次 / 按 `dest+IP` 限发；改密失败按 `identifier+IP` 计数并锁定（复用 `RateLimiter`）。**密码策略：最小 8 / 最大 64 字符、必须同时含字母与数字**（较 ADR-0013 登录基线的「≥8 不强制复杂度」更严，因这是凭据创建入口）。

## 备选方案

- **保留桌面原生表单，仅把 mock 换成真实 Tauri invoke 调 API** —— 否决：密码明文会进桌面进程、桌面要持 RSA 公钥与处理凭据，违背「认证安全责任内聚网关」；且与 ADR-0013 托管登录页架构割裂。
- **统一 email/phone + OTP 单流程，桌面纯开 URL、零 token**（更贴「桌面只做点击」）—— 否决：登录态用户已认证却仍要重输标识 + 收码，UX 退化；选绑定 token 路径换更顺体验，代价是桌面多一次 `password-link` 调用。
- **密码挂在单条验证过的 Identity（身份级）** —— 否决：会出现「邮箱能密码登录、手机不能」的割裂心智；选账号级，一次设置全标识可用。
- **登录态改密只凭 Password Link、免二次证明** —— 否决：会话被劫持即可改密夺号；改密一律 OTP。

## 阶段

- **本期：** `POST /api/v1/auth/password-link` 端点（Bearer）+ Password Link Redis 存储；`GET/POST /oauth/password` 托管页（绑定 + 验证码两路径，浏览器内 RSA）+ 页面作用域 `POST /oauth/password/send-code`（带 purpose）；OTP purpose 隔离；`IdentityRepository.UpdateSecretByUserUUID`；登录页「忘记密码」链接；桌面端按钮改为「调 `password-link` → `open_browser`」，删除 `PasswordDialog`/`passwordProtocol` mock。
- **回写契约：** 落地后回写 `contracts/gateway-api.md`（auth/password 段）与桌面端 CONTEXT。
- **生产门槛：** 同 ADR-0013，HTTPS 为硬要求，RSA 前端加密仅纵深防御。

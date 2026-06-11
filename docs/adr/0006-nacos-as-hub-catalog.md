# Skill/Plugin 注册中心 = 裁剪版 ClawHub fork（取代 nacos）

> 本 ADR 取代原「nacos 作 Hub 目录后端」的决定。

经对 ClawHub（OpenClaw 的开源 skill/plugin 注册中心）做源码级调研后，决定**用「重度 fork + 裁剪」的 ClawHub 作为 Skill/Plugin 注册中心，取代 nacos**。nacos 是配置中心，表达不了版本化制品、指纹更新检测、semver+tag 权威、兼容门禁等完整制品生命周期；ClawHub 这套机制成熟且正是所需。

我们 fork ClawHub 并**裁掉公开市场部分**（GitHub OAuth 身份、账龄门控、公开发布、举报/审核状态机、发布者反滥用、排行榜、星标/评论、souls、外部 Codex/VT 扫描 worker、向量搜索可选），**保留注册中心内核**（Convex 数据模型、v1 HTTP API、publish/resolve/install/update/pin 生命周期、skill/code-plugin/bundle-plugin family 区分、compat 门禁、capability tags、security-verdicts 契约），并**接入我们的身份（Casdoor / 网关 JWT）与制品存储**。完整生命周期见 `docs/flows/skill-plugin-lifecycle.md`。

## 备选方案

- **维持 nacos** —— 否决：配置中心无法表达版本化制品 / 指纹 / 兼容门禁。
- **自托管整套 ClawHub** —— 否决：拖入 Convex + GitHub 身份 + 多个外部依赖（OpenAI/Resend/VT/Codex worker），与 Casdoor/Postgres 栈冲突，且公开市场机器 v1 全不需要。
- **Go 原生重写一个 ClawHub 兼容实现** —— 备选：技术栈最一致，但需从零实现整套生命周期；选择 fork 是为复用 ClawHub 已验证的实现、加快落地。

## 后续影响 / 风险（待跟进）

- **引入 Convex** 作为注册中心后端（ClawHub 的函数运行时 + 文件存储）。需评估 **Convex 自托管（OSS self-host）** 可行性——这是本方案最大的依赖风险（ClawHub 官方部署文档面向 Convex 云）。
- **制品存储**若要从 Convex `_storage` 切到我们的对象存储（OSS/S3），需改 ClawHub 的上传/下载路径——非平凡改动。
- **身份桥接**：ClawHub 原 GitHub OAuth 需替换为信任网关签发的身份；v1 发布者 = 管理员 / 运营（curated 目录）。

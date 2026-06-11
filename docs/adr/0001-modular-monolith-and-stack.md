# 模块化单体 + Go/PostgreSQL 技术栈

网关横跨六个域（身份、Skill Hub、Plugin Hub、积分/订阅、MCP、LLM 代理）。我们将其构建为**单一 Go 可部署单体**——内部按域分模块、共享同一数据库——而非微服务，以避免 v1 阶段的分布式复杂度；其中 **LLM 代理模块**保持清晰边界，便于未来当其流式 / 高并发特性需要时独立抽出。技术栈沿用团队既有的 web-go 约定——Gin + GORM + Wire（手动注入）+ Redis + nacos——但有一处**刻意偏离**：使用 **PostgreSQL 取代 web-go 默认的 MySQL**。litellm 作为独立上游容器运行。

## 后续影响

- DAO 层连接的是 PostgreSQL，而非 web-go 模式里硬编码的 `"mysql"` dbName——这是有意为之，勿「改回」MySQL。

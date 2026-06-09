# Modular monolith on Go + PostgreSQL

The Gateway spans six domains (identity, skill hub, plugin hub, credits/subscription, MCP, LLM proxy). We build it as a single Go deployable with internal modules per domain sharing one database — not microservices — to avoid distributed complexity at v1; the LLM-proxy module is kept behind a clean boundary so it can be extracted later when its streaming / high-concurrency profile demands it. The stack follows the team's existing web-go conventions — Gin + GORM + Wire (manual injection) + Redis + nacos — with one deliberate deviation: **PostgreSQL instead of web-go's default MySQL**. litellm runs as a separate upstream container.

## Consequences

- The DAO layer connects to PostgreSQL, not the `"mysql"` dbName the web-go pattern hardcodes — this is intentional, don't "fix" it back to MySQL.

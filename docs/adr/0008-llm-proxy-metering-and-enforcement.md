# LLM proxy metering and window enforcement

The Gateway meters LLM usage by forcing `stream_options.include_usage` and reading the provider/litellm-reported usage from the final stream chunk (falling back to a local tokenizer estimate only when usage is absent). Enforcement is **optimistic**: a request is admitted as long as neither Usage Window is already at its cap, then the actual Credit cost is deducted after completion — so a single request may overshoot a cap by its own size, matching Claude Code's behavior. Window consumption is stored as a Redis **sorted set** per User/window (timestamp → credits), summed over the rolling range and trimmed by score; atomic Redis ops handle concurrent draw-down from the same window. Partial or client-disconnected responses are charged for the tokens actually generated; hard errors that produced no usage are free.

## Considered Options

- **Reservation / hold** (pre-estimate from max_tokens, reserve, reconcile after) — rejected for v1: it prevents overshoot but adds real complexity and needs reliable max-token bounding.
- **Bucketed approximate counters** — rejected: the ZSET sliding window is accurate and per-user event volume is modest enough to afford it.

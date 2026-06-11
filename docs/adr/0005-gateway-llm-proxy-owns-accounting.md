# 网关即 LLM 代理、自拥窗口记账

网关对桌面端暴露 **OpenAI 兼容** 接口（`/v1/chat/completions` 等），并挡在 litellm 前的请求路径上。它认证 User/Device，预检两个 Usage Window，转发给 litellm（由其路由到各供应商并返回 token usage），用 Model Price 将 token 折算为 Credit，记录 Billable Event 并扣减两个窗口（结束后扣费，流式亦然）。litellm 退化为上游模型路由器与供应商 key / 配置持有方；它**不**负责计费。

## 备选方案

- **litellm 原生 virtual key + budget** —— 否决：其预算基于日历周期，无法表达 ADR-0004 的 5h 滚动 + 每周 + 分模型模型。

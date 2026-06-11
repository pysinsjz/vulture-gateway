# LLM 代理的计量与窗口强制

网关对 LLM 用量的计量方式：强制 `stream_options.include_usage`，从最后一个流式 chunk 读取供应商 / litellm 上报的 usage（仅当 usage 缺失时才用本地 tokenizer 估算兜底）。enforcement 采用**乐观**策略：只要两个 Usage Window 都未触顶就放行请求，结束后再扣减实际 Credit——因此单个请求可能把某窗超出其自身大小，与 Claude Code 行为一致。窗口消耗以 Redis **有序集合（sorted set）**按 User / 窗口存储（timestamp → credits），在滚动范围内求和、按 score 修剪；同一窗口的并发扣减由 Redis 原子操作处理。部分响应或客户端中途断开按实际已生成的 token 计费；未产生任何 usage 的硬错误不计费。

## 备选方案

- **预留 / 扣额（按 max_tokens 预估、预留、结束对账）** —— v1 否决：能杜绝超额但增加真实复杂度，且需可靠的 max-token 上界。
- **分桶近似计数器** —— 否决：ZSET 滑动窗精确，且单用户事件量足够小、负担得起。

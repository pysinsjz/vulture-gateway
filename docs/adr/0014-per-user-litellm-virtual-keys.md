# 按用户签发 litellm Virtual Key：归因 + 纵深防御，网关窗口仍权威

**补强 ADR-0005（网关自拥窗口记账）、ADR-0008（计量与窗口强制）。不推翻二者：网关侧滚动窗口仍是权威限额。**

ADR-0005 让 litellm 退化为「上游模型路由器 + 供应商 key 持有方」，全网关共用**一把** virtual key（`internal/litellm/client.go` 构造期注入），按用户的限额全在网关侧做（5h 滚动窗 + 周窗 + Credit）。它当时**否决**了「litellm 原生 virtual key + budget」，理由是 litellm 预算基于日历周期、表达不了滚动窗——该理由今天仍成立。

本 ADR 在**不改限额权威**的前提下，给每个 User 签一把专属 litellm Virtual Key，目的有二：
- **A 归因**：litellm 后台按 key / `user_id` 天然聚合出每用户上游花费与日志。
- **B 纵深防御**：每把 key 带一个粗粒度 `max_budget` 当「保险丝」，仅在网关计量失效时兜底，平时永不触发。

明确**不做 C**（改由 litellm 原生 budget 限额）——那等于推翻 ADR-0005，把已验证的窗口计费链路推倒重来。

## 决策

- **两种 key 角色分离。** **Master Key**＝网关持有的 litellm 管理员 key，只用来签发/改/删用户 key，**永不转发推理**，走环境变量注入（`${LITELLM_MASTER_KEY}`，四环境 YAML 只留占位）。**User Virtual Key**＝每个 User 一把、由网关用 Master Key 签出的 litellm key，转发推理时按用户注入。原「全网关共享单 key」的配置项删除。

- **User : Virtual Key = 1:1。** 限额是 User 级（CONTEXT.md：Credit/窗口都挂 User），不做 Device 级分 key——Device 隔离无计费意义，只会让归因变碎。轮换时签新废旧，任一时刻只一把 active。

- **新表 `user_virtual_keys`，`litellm_key` 明文落库。** 字段：`user_uuid`（uniqueIndex 落实 1:1）、`litellm_key`（完整 `sk-...`，转发注入用）、`key_alias`（`user-{uuid}`）、`token_id`（litellm 返回，改/删引用）、`status`（active/revoked）、时间戳。**`litellm_key` 明文存属显式接受的安全权衡**（理由：内网可信 / DB 整体加密），非疏漏——它等同上游凭证，泄库即被盗刷；将来收紧时，应用层 AES-GCM 加密是独立可加的一层，不影响数据模型。

- **`GetOrCreateVirtualKey(userUUID)` 单一入口，eager + lazy 双触发。** **Eager（主）**：注册成功流程里签一次，且**失败不阻断注册**（只记日志/告警，lazy 会补）。**Lazy（兜底）**：推理转发前再调一次，覆盖「本功能上线前的存量用户」与「eager 失败的空洞」。

- **防双签 + 防孤儿。** 签 key 是对 litellm 的外部副作用、不在 DB 事务内，并发首签会签出孤儿 key。三重防护：① Redis 分布式锁（`lock:vkey:{uuid}`，秒级过期）圈住整个 get-or-create；② DB `user_uuid` 唯一约束兜底；③ 万一插入仍冲突，把刚签出的 key 调 litellm `/key/delete` 删掉。

- **签发参数。** `key_alias=user-{uuid}`、`user_id={uuid}`（end-user 归因）、`models`＝**签发时动态拉 litellm 当前全部模型 id 显式写入**（见下「修订」）、`duration` 不设（永久，生命周期由网关管）、`rpm_limit` 不设（网关侧无 rpm 概念，加了反成一处不一致）。**保险丝 `max_budget=9999999` 且不带 `budget_duration`**——管道铺好但**数值故意大到永不触发，B 当前挂空**；保险丝的真实数值依赖套餐定价，而定价文档仍 park（见 memory），**待定价落地后重算**，届时再决定是否加 `budget_duration` 让熔断自动重置。

  **【修订 2026-06-25】`models` 不再留空＝全部。** 原决策让 key 留空 models（litellm 渲染为 "All Proxy Models" 通配，把模型访问控制全交给网关/套餐层）。实测发现这会让每把用户 key 在 litellm 后台都是通配全开、不可审计具体模型，遂改为：**签发前网关用 Master Key 调 litellm `GET /v1/models` 拉当前全部模型 id，显式逐个写进 key 的 `models`**。语义仍是「当前全部模型」（自动跟随 litellm 新增/下线，无需手工维护清单），但 key 上是**显式枚举**而非通配，后台可审计、可为将来按套餐裁剪留口。**拉取失败或清单为空一律拒签**（返错由 lazy 重试），**绝不退回全开 key**——宁可本次签发失败也不发出通配 key。模型访问控制的「网关/套餐职责」定位不变，此修订只改 key 上的表达形式。

  **【修订 2026-06-29，Supersedes 2026-06-25】`models`＝单一 model access group 名（`vulture`）。** 上版「显式枚举全量」虽可审计，但把模型集合**冻结在签发时刻**——litellm 新增模型后存量 key 看不到，运维没有「改一处即对所有 key 生效」的入口。本次改为：**签发恒下发 `models: ["<组名>"]`**（组名取自 `config.llm.model_access_group`，默认 `vulture`），组成员在 litellm 侧用 `model_info.access_groups` 维护。模型集合的真相源迁回 litellm 配置侧，改组即对后续所有 key 生效、无需重签。要点：
  - **`/v1/models` 展示无需网关介入（已实测）**：litellm 在 `GET /v1/models` 会自动把 access group 展开成组内真实模型 id，桌面端经用户 key 转发即拿到正确清单——`ListModels` 链路零改动。
  - **fail-open 被结构性消除**：恒下发非空 `["组名"]`，不再有空 models→通配全开的歧义；新失效态是「组错配为空/不存在 → key 解析为零模型」（fail-closed，安全方向）。遂**删去**上版「拉清单、空则拒签」的全开闸与 `AdminClient.ListModelIDs`（已无调用方）；网关**不**再做签发前枚举校验（组成员归属 litellm 运维侧）。
  - **存量 key 不主动迁移**：仅新签发的 key 用组形式；存量「冻结明细」key 维持原样，靠失败处理 ② 的 401/403 自愈轮换惰性重签成组形式。
  - **运维前置**：上线时需在 litellm 侧把该开放的模型打上 `access_groups:["vulture"]`，否则新 key 可用模型塌缩到组内现有成员。

- **请求链路：Admin / Proxy 双客户端 + service 层解析 + Redis 缓存。** 拆出 **Admin Client**（持 Master Key，做 `Generate/Delete/Update`）与改造后的 **Proxy Client**（`ChatCompletions`/`ListModels` 方法签名加 key 参，去掉构造期单 key）。key 解析收敛在 service 层：handler 多传 `userUUID` → service `GetOrCreate` → Proxy Client 注入。热路径加 Redis 缓存（`vkey:{uuid}`→key，带 TTL），DB 为真相源、缓存失效回查。`/v1/models` 同样走用户 key。**现有门禁（订阅 402 / 体积 413 / 窗口预检 429）与计量逻辑一行不改，本次只替换 key 注入。**

- **失败处理。** ① 推理时 `GetOrCreate` 失败（litellm 不可达）→ 返 OpenAI 形态 `upstream_unavailable`(502)，**不退回共享 key**。② 库里 key 被 litellm 拒绝（上游 401/403，如 key 被手工删）→ **一次性自愈**：标 `revoked` + 清缓存 + 重新签发 + 对本次请求重试一次，仅一次防死循环；该自愈发生在 handler 的「上游非 200」分支（流式响应体尚未开写，无部分写入风险）。

- **生命周期 v1 范围。** 仅「签发 + 自愈轮换」。Device 吊销（ADR-0010）**不动** User Virtual Key（key 是 User 级，被吊销设备过不了网关鉴权）。删用户/封用户流程当前**不存在**，故不接线；但 `VirtualKeyService` **预留删除某用户 key 的方法**作接缝，将来真做删/封用户时一行接入。

- **目标实例切换。** 网关 LLM 接入从旧实例 `8.136.147.138:4000` 切到新实例 `https://litellm-0w6x.srv1477684.hstgr.cloud`；`baseURL` 必须与 Master Key 同实例，否则签发全 401。

## 备选方案

- **C：改由 litellm 原生 budget 限额（弃网关窗口）** —— 否决：推翻 ADR-0005/0008，litellm 日历预算表达不了 5h 滚动窗，且要重做已验证的计费链路。
- **不签 key、用 litellm end-user（`user` 参数）在共享 key 下归因** —— 否决：能拿归因（A），但拿不到干净的每用户预算保险丝（B）与隔离；且用户已明确要「按用户用不同 key」。
- **Device 级分 key（1:N）** —— 否决：限额是 User 级，Device 分 key 让归因碎片化、无计费收益。
- **`litellm_key` 加密落库** —— 推荐但本次未采纳：明文为显式接受的权衡，加密留作未来独立可加层。
- **只 lazy、不 eager** —— 备选：注册流程零外部依赖、更稳；本次仍选双触发让正常路径一注册即有 key，eager 失败有 lazy 兜底，不牺牲注册可靠性。
- **不加 Redis 锁、只靠 DB 唯一约束 + 冲突回删** —— 否决（取更稳版）：Redis 已为 metering 重度依赖，加锁成本低、一致性更干净。
- **保险丝带 `budget_duration` 自动重置** —— 推迟：保险丝设计与数值依赖定价文档，本次先放 9999999 占位、不带 duration，待定价落地再定。

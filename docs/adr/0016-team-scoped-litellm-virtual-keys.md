# 按 team 签发 litellm Virtual Key：归因 + 分层 + 模型权限单一真相源

**Supersedes ADR-0014 的「签发参数」与「模型权限表达」部分。** 不动 ADR-0014 的其它决策（key 角色分离、User:Key=1:1、防双签、自愈轮换、生命周期）；不动 ADR-0005/0008（网关窗口计费权威）。

## 背景

ADR-0014 修订 2026-06-29 让签发恒下发 `models: ["<access group>"]`（默认 `vulture`），把模型集合的真相源迁回 litellm 的 model access group 配置侧。运营实践暴露三个不够用：

1. **模型权限维度不够分层**：access group 只是「模型集合」一个轴，无法表达后续付费分层（free/pro/elite/ultra）里「不同 plan 看到不同模型 / 不同预算保险丝」的多维概念。
2. **归因维度不够**：litellm 后台按 key/user_id 聚合，但没有「这把 key 归属哪个 plan 团」的天然维度，运营查 "team-pro 用户上游花了多少" 得手工聚合。
3. **运营 single-source-of-truth 缺失**：plan 维度的预算/费率/模型配比未来要做时，再开一份配置就会和 access group 并存——litellm 原生的 team 概念正好就是这层抽象，已在管理后台提供 UI 入口。

litellm 的 team 概念正好是这层抽象：每个 team 有自己的 `team_id`/`team_alias`/`models`/`max_budget`，签发时下发 `team_id` 即把 key 归属到该 team。

## 决策

- **签发参数从 `models: ["<access group>"]` 改为 `team_id: <uuid>`，`models` 字段彻底不下发。** litellm `/key/generate` 的 `team_id` 让 key 归属指定 team；team 的 `models` 列表是该 key 可达模型的单一真相源。**`models` 字段省略**是有意为之的 workaround——见下「litellm bug #3275」。

- **alias 寻址：配置存 `default_team_alias`，签发前调 `/team/list` 解析为 `team_id`，零缓存。** 各环境的 litellm 实例 UUID 可能漂移（dev 调试期 team 被删重建是常态），配置存稳定的 alias 而非脆弱的 UUID；解析不缓存，team 重建后下一次签发立刻恢复，无须缓存失效机制。签发本来就是低频操作（人均生命周期 ~1.x 次：注册 eager + 首次推理 lazy + 偶发自愈），多一次 `/team/list` HTTP 调用开销可忽略。

- **alias 解析的 fail-closed 语义。** 三种失败都让签发返错（lazy 重试 / 推理返 `upstream_unavailable` 502）：
  - `/team/list` HTTP 失败 → 透传错误；
  - alias 在 litellm 不存在（运维未建好）→ `team alias %q 在 litellm 不存在`；
  - alias 匹配多个 team（同名重复，litellm 允许）→ `team alias %q 匹配多个 team_id: [...]（运维需消除歧义）`，**不静默取第一个**——歧义状态必须暴露给运维修正，与「fail-closed 是安全方向」一脉相承。

- **litellm bug #3275 workaround：省略 `models` 字段，而非下发 `["all-team-models"]` 字面值。** litellm UI 选 "All Team Models" 会让 key 持有 `models: ["all-team-models"]` 字面值，但调 `/v1/models` 时返回的就是字符串 "all-team-models" 占位本身，**不会展开为 team 的真实模型清单**（详见 [BerriAI/litellm#3275](https://github.com/BerriAI/litellm/issues/3275)）。官方解决路径是绕过 UI 直接调 API、`models` 字段不下发——litellm 此时会按 team 的 models 列表展开。已在 dev 实例 `http://47.110.248.193:4000` 实测：用 team-pro UUID `a7e93ef5-f00f-4737-9d17-4148acbec528` 签发后调 `/v1/models` 正确返回 `[Auto, deepseek/deepseek-v4-flash, qwen3.7-plus, deepseek/deepseek-v4-pro]` 4 个真实模型 id。

- **`user_virtual_keys` 表新增 `team_alias VARCHAR(50) NOT NULL DEFAULT ''` 列。** 签发 / Replace 时把当前 `default_team_alias` 快照写入该列。**用途为未来订阅升级流程留钩子**——当用户付费升 plan（team-pro → team-ultra）时，订阅域可用 `team_alias != currentSubscription.TeamAlias` 这一个判断知道哪些 key 需轮换重签，无需查 litellm。次要用途：观测/审计（key 历史归属在 gateway 侧落档，不依赖 litellm 数据保留策略）。

- **`DefaultTeamAlias` 在所有环境必填（无 viper 默认）。** `config.validate()` 强制非空——fail-loud 防 prod YAML 漏配静默回退到 dev 默认。每个环境 YAML 显式配置：dev/test `team-pro`，staging/prod 上线时 `team-free`。各 env 的 litellm 实例 team alias 命名规约一致（运维约定），UUID 因实例不同而不同——alias 寻址消除环境差异。

- **AdminClient 契约：低层 `ListTeams() ([]Team, error)`，业务逻辑在 service。** `Team` 只暴露 `{ID, Alias}` 两字段（litellm 响应里的 spend/budget/models 不暴露——业务只用 alias 寻址）。alias filter / 重复处理 / 空 fallback 在 `VirtualKeyService.resolveTeamID` 实现——与现有 `GenerateKey`/`DeleteKey` 的「HTTP 端点 1:1 包装」风格一致。litellm `/team/list` 默认不分页（team 数预期 <10），暂不实现分页处理，代码注释占位「超出后再加分页」。

- **删除 `llm.model_access_group` 配置项 + `VirtualKeyService.accessGroup` 字段 + `defaultModelAccessGroup` 常量 + `GenerateKeyParams.Models` 字段。** 模型权限的真相源完全迁到 litellm 侧的 team 配置，access group 这层概念从代码彻底消失。litellm 侧的 `vulture` access group 配置作为部署最后一步删除（确认无 key 引用后）。

- **存量数据：用户确认已手工处理（无 prod 真实用户）；不做迁移脚本 / backfill。** dev 阶段 user_virtual_keys 表的存量行 `team_alias` 列默认空串，下次自愈轮换时自动刷新——不阻断任何路径。

- **现有自愈轮换路径（ADR-0014 失败处理 ②）零结构性变化。** `RevokeAndRegenerate` 内部本来就调 `sign()`，sign 内会 resolve 当前最新 team_id；Replace 调用点带新的 `defaultTeamAlias`。team 被删重建场景的覆盖：旧 key 走推理被 401/403 → 现有自愈触发 → resolve 拿到新 UUID 签新 key，零额外设计。

## 部署顺序（每个环境独立做）

1. **litellm UI 确认 team 存在 + 该开放的模型挂上 team 的 models 列表**（dev 已确认 4 个 team；staging/prod 上线前手工建好 `team-free` 并配模型）。**这步先于代码部署**——否则部署后第一次签发就 fail-closed。
2. **代码部署**（gateway 启动时 GORM AutoMigrate 自动加 `team_alias` 列）。
3. **YAML 同步**：删 `llm.model_access_group`，加 `llm.default_team_alias`。
4. **跑 `scripts/smoke_team_vkey.py` 验证端到端链路**（list team → generate 不带 models → `/v1/models` 断言展开非占位 → cleanup）。
5. **litellm UI 删 `vulture` access group**（最后做，避免部署窗口期 in-flight 旧路径请求被 401）。

## 备选方案

- **保留 access group + 加 team_id 双下发** —— 否决：litellm 行为是 team 收紧 key 的 models，再传 `models: ["vulture"]` 等于声称 key 能用一个叫 "vulture" 的"模型"，是 access group 名不是模型 id，逻辑错位；维护两套权限源容易冲突；本 ADR 反复强调的「单一真相源」工程纪律违背。
- **配置存 team UUID 而非 alias** —— 否决：dev 调试期 team 被删重建会让 UUID 漂移，YAML 得跟着改；alias 是逻辑稳定 identifier，跨环境保持一致。
- **alias 解析加缓存** —— 推迟：签发本来就低频（每用户人均 ~1.x 次/生命周期），多一次 `/team/list` HTTP 开销可忽略；加缓存反而引入失效机制 / TTL 调参 / 多实例一致性等复杂度；将来签发频率上去再加。
- **alias 重复时取第一个，记 warning** —— 否决：哪个"第一个"取决于 litellm 内部排序，行为不确定；用户可能签到错误 team。模糊匹配是运维配置错误，fail-closed 让 ops 修，比无声选第一个更安全。
- **`team_alias` 列改为 `team_id`** —— 否决：UUID 在 dev 经常变（同 alias 寻址理由），表里 UUID 跟实际签发时点漂移；alias 是稳定 logical identifier，落 alias 更稳。
- **主动 backfill 存量 user_virtual_keys 行** —— 否决：用户确认存量已处理，无需迁移；且 backfill 要批量删/重签 litellm key，有失败/回滚风险，工程成本不抵收益。

# Vulture Gateway

The backend gateway that serves an existing desktop general-purpose AI agent: it owns identity, the skill/plugin marketplaces, the credit economy, MCP provisioning, and the default LLM access for that agent.

## Language

### Core actors

**Desktop Agent**:
The standalone desktop application (built in a separate project) that runs a general-purpose AI agent. It is the gateway's sole client type.
_Avoid_: client, app, desktop client

**Gateway**:
This project. The single backend that every Desktop Agent talks to for auth, marketplaces, credits, MCP, and LLM access.
_Avoid_: server, backend, API

### Identity

**User**:
The single unit of identity. Credits, marketplace entitlements, and LLM usage all belong to a User. There is no team or organization tier.
_Avoid_: account, member, customer

**Identity Provider**:
The self-hosted Casdoor instance that owns every login channel (email password, email/phone code, WeChat QR, social) and authenticates Users on the Gateway's behalf over OIDC. The Gateway never implements channels itself.
_Avoid_: auth server, SSO, IAM, Casdoor (use the role name)

**Identity**:
One login channel a User authenticates through (email, phone, WeChat, …). Channels are owned and aggregated by the Identity Provider; the Gateway maps the IdP's authenticated subject to its own User. A User may have many Identities, all resolving to the same User.
_Avoid_: login, credential, provider account

**Device**:
An authorized Desktop Agent installation bound to a User. Each authorization creates one Device, which holds the long-lived credential and can be viewed and revoked individually.
_Avoid_: session, client, installation

### Capabilities the agent consumes

**Skill**:
A declarative agent capability — an instruction/prompt package with metadata that the LLM loads at runtime to perform a class of task. Read by the agent's model, not installed into the app.
_Avoid_: ability, prompt pack, tool

**Plugin**:
An extension of the Desktop Agent application itself — code/binary/UI that is installed into the client process. Distinct from a Skill, which the model reads rather than the app installs.
_Avoid_: extension, add-on, module

**MCP Server**:
A service exposing tools/resources over the Model Context Protocol that the Desktop Agent connects to as an MCP client. The Gateway hosts these remotely and fronts them behind a single entry it routes and authenticates; new ones can be added gateway-side without changing the agent.
_Avoid_: tool server, MCP endpoint

### Credit economy

**Credit**:
The unit that measures a User's consumption inside a Usage Window. Every Billable Event deducts Credit. It is a usage counter scoped to the active windows — not a stored, carried-over wallet balance; it resets as windows roll over.
_Avoid_: point, token, balance, wallet

**Billable Event**:
Any action that deducts Credit from a User, priced by its own rule. The mechanism is deliberately extensible to many event types; the only one implemented now is LLM usage.
_Avoid_: charge, transaction, usage record

**Usage Window**:
A rolling time window that caps how much Credit a User may consume — a 5-hour window and a 7-day window run concurrently. Hitting either cap blocks further Billable Events until that window rolls over. The caps come from the User's Plan, and the model is designed to allow per-model caps later (v1 uses a single shared pool).
_Avoid_: billing cycle, quota period, rate-limit bucket

**Plan**:
A paid subscription tier a User can subscribe to. Defines the Credit caps for each Usage Window. Every Plan is paid — there is no free tier.
_Avoid_: package, recharge plan, free tier

**Subscription**:
A User's active enrollment in a Plan. It is what determines the Usage Window caps governing that User's consumption.
_Avoid_: membership, recharge

**Model Price**:
The per-model rule that converts raw LLM usage (input/output tokens and multimodal units) into Credit, including the markup over the upstream provider's cost. It is how usage becomes a Billable Event amount.
_Avoid_: rate, tariff, cost

### Marketplaces

**Skill Hub**:
The marketplace and upgrade channel for Skills. Backed by a skill registry (nacos) and exposes an API that returns the available skill list.
_Avoid_: skill store, skill market

**Plugin Hub**:
The marketplace and upgrade channel for Plugins.
_Avoid_: plugin store, plugin market

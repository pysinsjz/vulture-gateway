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
The Gateway's own built-in authentication subsystem (ADR-0013). It owns the login channels (email/phone password, email/phone code, future social), renders the login page, and authenticates Users itself — no third-party IdP. Login channels are modeled as a single `SigninMethod` registry; future social logins plug in as `Redirect`-kind methods. (Superseded the earlier delegated-Casdoor design, ADR-0002/0012.)
_Avoid_: auth server, SSO, IAM, Casdoor

**Identity**:
One login channel a User authenticates through, persisted as a row in the `Identity` table (`type`=email/phone/oauth, `identifier`, `secret`=password hash or empty, `provider`). A User may have many Identities, all resolving to the same User; authentication resolves Identity → User and returns the stable `User` subject downstream.
_Avoid_: login, credential, provider account

**Password Credential**:
The `secret` (bcrypt hash) a User authenticates with on the password channel. It is **account-level**, not per-channel: setting it writes the same hash to every local Identity of the User (`provider` empty; oauth Identities excluded), so email and phone log in with one password. An empty `secret` means the User has no Password Credential and can only sign in by code.
_Avoid_: password (the raw input), per-identity password

**Set vs Reset**:
The two operations over a Password Credential. **Set** is first creation, when no Password Credential exists yet. **Reset** replaces an existing one. The distinction is derived server-side from whether `secret` is empty — not asserted by the client.
_Avoid_: change password, update password, forgot password

**Password Link**:
A one-time, short-lived token that binds a signed-in Desktop Agent to the Gateway-hosted password page, proving which User without the user re-entering an identifier. Minted by an authenticated Gateway call and consumed once when the page opens. Distinct from the code-proven path a signed-out user takes from the login page's "forgot password" link.
_Avoid_: reset token, magic link, deep link

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

**User Virtual Key**:
The per-User upstream credential the Gateway mints (one active key per User, 1:1) and injects when forwarding that User's LLM calls. Its purpose is per-User attribution and a defense-in-depth budget backstop — the Gateway's Usage Windows remain the authoritative cap, not this key (ADR-0014). Distinct from the Master Key, which the Gateway uses only to mint/revoke User Virtual Keys and never forwards inference with.
_Avoid_: api key, token, user key, litellm key (unqualified)

### Marketplaces

**Skill Hub**:
The marketplace and upgrade channel for Skills, exposing the available skill list to the Desktop Agent.
_Avoid_: skill store, skill market

**Plugin Hub**:
The marketplace and upgrade channel for Plugins.
_Avoid_: plugin store, plugin market

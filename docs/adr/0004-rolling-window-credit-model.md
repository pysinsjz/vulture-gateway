# Claude-Code-style rolling-window credit model

Subscriptions govern usage through two concurrent **rolling windows** — a 5-hour window and a 7-day window — each capping how much Credit a User may consume; hitting either cap blocks LLM use until that window rolls over. Credit is therefore a usage counter scoped to the active windows, **not** a stored, carried-over wallet balance, and it resets as windows roll. Deduction is modelled as a generic, extensible **Billable Event** (priced per rule); v1 implements exactly one event type (LLM usage), with per-model caps designed-for but not yet enabled (a single shared pool in v1). Every Plan is paid — there is no free tier.

## Consequences

- litellm's calendar-period budgets cannot express this model — see ADR-0005.
- There is no persistent balance ledger; accounting is window-scoped counters.

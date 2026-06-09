# Gateway is the LLM proxy and owns window accounting

The Gateway exposes an **OpenAI-compatible** API (`/v1/chat/completions`, …) to the Desktop Agent and sits in the request path in front of litellm. It authenticates the User/Device, pre-checks both Usage Windows, forwards to litellm (which routes to providers and returns token usage), converts tokens → Credit via Model Price, and records the Billable Event + draws down both windows (charge-after-completion, even when streaming). litellm is reduced to an upstream model router and provider-key/config holder; it does **not** own billing.

## Considered Options

- **litellm-native virtual keys + budgets** — rejected: its budgets are calendar-duration based and cannot express the 5h-rolling + weekly + per-model model from ADR-0004.

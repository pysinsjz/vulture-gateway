# Identity delegated to self-hosted Casdoor

The Gateway needs four login channels (email password, email code, phone code, WeChat QR) plus future social aggregation. Rather than implement each channel — and the WeChat OAuth dance and SMS plumbing — in the Gateway, we delegate all of identity to a self-hosted **Casdoor** instance acting as the Identity Provider: it owns the channels and the hosted login UI, and the Gateway integrates over OIDC, mapping Casdoor's authenticated subject to its own single-tier User and issuing its own JWT + Device. Casdoor is Go-native (matches the stack), supports WeChat QR + phone/email codes out of the box, and can share PostgreSQL.

## Considered Options

- **Build channels in-gateway with libraries** — rejected: re-implements WeChat OAuth + SMS integration the IdP already solves.
- **Logto / Keycloak** — rejected: weaker/uncertain WeChat support; Keycloak is a heavy Java stack.

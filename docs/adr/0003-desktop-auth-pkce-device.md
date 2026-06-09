# Desktop login via browser-relay PKCE with first-class Devices

A native desktop app has no browser cookie context and shouldn't embed each login channel. The Desktop Agent authenticates by launching the system browser to the (Casdoor-backed) hosted login page, then receives an authorization code back via deeplink / loopback port and exchanges it (PKCE) for a JWT access + refresh token. Each authorization creates a first-class, individually revocable **Device** to which the refresh token is bound, so a User can view and revoke authorized installations. Channel growth changes only the web login page, never the app.

## Considered Options

- **Embedded in-app login** — rejected: forces per-channel native integration (especially WeChat / Google OAuth).
- **Device Authorization Grant (enter-code flow)** — a viable fallback, but worse desktop UX.

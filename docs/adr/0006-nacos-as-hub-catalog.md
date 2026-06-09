# nacos as the Skill/Plugin Hub catalog backend

Both Hubs store catalog metadata (name, version, compatibility, artifact URL) as **nacos config entries**; the actual Skill/Plugin artifacts live in object storage, and the Gateway reads nacos to serve the skill/plugin list API to the Desktop Agent. Chosen over the conventional "DB table + object storage" because the team already runs nacos, and its config push / grayscale lets the catalog change without a Gateway release. Plugin entries additionally carry platform/arch and minAppVersion for client-side compatibility filtering.

## Consequences

- nacos is now a source of truth for product catalog data, not just service config — back it up and version it accordingly.

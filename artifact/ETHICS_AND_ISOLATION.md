# Ethics and isolation

All evaluation traffic targeted an isolated virtual laboratory owned by the authors (IoT Virtual Lab).

- The agent may query lab status and send packets only to the configured lab subnet.  
- Prompts forbid starting, stopping, respawning, or resetting lab devices.  
- No live third-party systems, public Internet hosts, or production OT devices were targeted.  
- Evaluated weaknesses are intentionally seeded or known protocol-edge behaviours; this artifact is not a zero-day disclosure package.  

Secrets (API keys, host credentials, environment-specific material) are excluded from this release.

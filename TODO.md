# TODO — InfraDoctor

## Done

- [x] v0.1 — CLI, root, OS, menu, reports, sanitize
- [x] v0.2 — SSH Module (socket activation, listen address, DSA, AllowUsers, PermitEmptyPasswords, GatewayPorts, PermitTunnel, PermitUserEnvironment)
- [x] v0.3 — Firewall Module (effective stack, DOCKER-USER)
- [x] v0.4 — Networking Module (listening ports, routing, DNS)
- [x] v0.5 — Docker Module (containers, networks, storage, privileged/host mode)
- [x] v0.6 — Storage Module (df, inodes, disk analysis, journal size)
- [x] v0.7 — Systemd Module (failed units, timers, sockets)
- [x] v0.8 — Security Baseline Module (sudo, updates, fail2ban, kernel, UID 0)
- [x] Nginx Module — host + container-aware detection & config diagnosis
- [x] Exposure Summary — cross-module overview in Markdown + JSON
- [x] Code-based matching — `Code` field on Check/Recommendation, stable skip logic
- [x] JSON output — includes `exposure_summary` with top-3 recommendations
- [x] Structured Recommendation model (severity, context, impact, action, command, safe)
- [x] Code quality: typed status constants, doc comments, helpers, dead code

## Future

- [ ] SSH: authorized_keys for all shell users (not just root)
- [ ] Networking: MTU, interface metrics
- [ ] Docker: compose projects, healthcheck details
- [ ] Storage: save directory size report between runs
- [ ] Journal module (journalctl output summary)
- [ ] Archive/compression (tar.zst)
- [ ] GitHub Actions release

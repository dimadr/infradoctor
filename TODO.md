# TODO — InfraDoctor

## v0.1 — CLI (current)

- [x] `infradoctor doctor` command
- [x] Root check
- [x] OS, kernel, hostname detection
- [x] Interactive menu (`1,3,5` / `all`)
- [x] Input validation
- [x] `report.md` + `report.json`
- [x] Secret masking (passwords, tokens, keys)
- [x] Plugins → Modules refactoring

## v0.2 — SSH Module

- [ ] Service status
- [ ] Configuration
- [ ] Authentication
- [ ] Permissions
- [ ] Security
- [ ] Recommendations

## v0.3 — Firewall Module

- [ ] iptables / nftables / ufw detection
- [ ] Rules audit
- [ ] Default policies
- [ ] Recommendations

## v0.4 — Networking Module

- [ ] Interfaces
- [ ] Routing
- [ ] Listening ports
- [ ] DNS
- [ ] MTU
- [ ] Recommendations

## v0.5 — Nginx Module

- [ ] Service status
- [ ] Configuration validation
- [ ] Virtual hosts
- [ ] TLS
- [ ] Logs
- [ ] Recommendations

## v0.6 — Docker Module

- [ ] Service status
- [ ] Containers
- [ ] Images
- [ ] Networks
- [ ] Volumes
- [ ] Compose
- [ ] Recommendations

## Future

- [ ] Systemd module
- [ ] DNS module
- [ ] Fail2ban module
- [ ] Storage module
- [ ] Journal module
- [ ] Archive/compression (tar.zst)
- [ ] GitHub Actions release

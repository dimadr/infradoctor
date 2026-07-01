# InfraDoctor

> Read-only Linux server diagnostics.

---

## Русский

**Для чего это делается**

Диагностика Linux-сервера одной командой. Быстро понять состояние SSH,
веб-сервера, Docker, сети, фаервола — без установки агентов и без отправки
данных наружу.

**Как работает**

1. `sudo infradoctor doctor`
2. Проверка root
3. Определение ОС, ядра, hostname
4. Поиск установленных компонентов
5. Интерактивный выбор: `1,3,5` или `all`
6. Read-only диагностика каждого компонента
7. Маскирование секретов
8. `report.md` + `report.json`

**Что использует для работы**

- Go 1.22, только стандартная библиотека
- Чтение файлов (`/etc/os-release`, конфиги, `/proc/`)
- `os/exec` для запуска штатных команд (`systemctl`, `ss`, `iptables`, `docker`)
- `regexp` для маскирования паролей, токенов и ключей

**Ничего не собирает, ничего не отсылает**

- Нет `net/http`
- Нет внешних API
- Нет телеметрии
- Нет auto-update
- Нет curl/wget/nc

**Не вносит изменений — только анализ**

- Read-only: никакие конфиги не меняются
- Сервисы не перезапускаются
- Пакеты не устанавливаются
- Firewall не трогается

**Выдает отчет + рекомендации**

- `report.md` — читаемый Markdown с статусами и рекомендациями
- `report.json` — машиночитаемый JSON для обработки
- `exposure_summary` — сводка экспозиции в обоих форматах
- Каждый чек и рекомендация имеют `code` для стабильного маппинга
- Каждый модуль содержит секции (Configuration, Service, Security)
- Рекомендации: "PermitRootLogin should be 'no'"

**Структура проекта**

```
infradoctor/
├── cmd/infradoctor/main.go
├── internal/
│   ├── core/
│   ├── detect/
│   ├── ui/
│   ├── report/
│   │   ├── json.go
│   │   ├── markdown.go
│   │   ├── summary.go          # Exposure Summary
│   │   ├── sanitize.go
│   │   └── sanitize_test.go
│   └── modules/
│       ├── interface.go
│       ├── registry.go
│       ├── helpers.go
│       ├── ssh.go
│       ├── firewall.go
│       ├── networking.go
│       ├── docker.go
│       ├── storage.go
│       ├── systemd.go
│       ├── security.go
│       └── nginx.go
├── testdata/
├── reports/examples/
├── go.mod
├── README.md
├── TODO.md
└── LICENSE
```

**Дорожная карта**

- [x] v0.1 — CLI, root, OS, menu, reports, sanitize
- [x] v0.2 — SSH Module
- [x] v0.3 — Firewall Module (effective stack, DOCKER-USER)
- [x] v0.4 — Networking Module (listening ports, routing, DNS)
- [x] v0.5 — Docker Module (containers, networks, storage)
- [x] v0.6 — Storage Module (df, inodes, disk analysis)
- [x] v0.7 — Systemd Module (failed units, timers, sockets)
- [x] v0.8 — Security Baseline Module (sudo, updates, fail2ban, kernel)
- [x] Nginx Module (host + container)
- [x] Exposure Summary (Markdown + JSON)
- [x] Code-based check/recommendation matching



---

## English

**Purpose**

Single-command Linux server diagnostics. Check SSH, web server, Docker,
network, firewall — no agents, no data egress.

**How it works**

1. `sudo infradoctor doctor`
2. Root check
3. OS, kernel, hostname detection
4. Component discovery
5. Interactive selection: `1,3,5` or `all`
6. Read-only diagnostics per component
7. Secret masking
8. `report.md` + `report.json`

**What it uses**

- Go 1.22, stdlib only
- File reads (`/etc/os-release`, configs, `/proc/`)
- `os/exec` for system commands
- `regexp` for secret masking

**Privacy**

No network. No telemetry. No API calls. Nothing leaves the machine.

**Safety**

Read-only. No config changes. No service restarts. No package installs.

**Output**

- `report.md` — human-readable with statuses and recommendations
- `report.json` — machine-readable for automation
- `exposure_summary` section in both formats
- Each check and recommendation has a stable `code` field
- Each module has sections (Configuration, Service, Security, ...)
- Recommendations: "PermitRootLogin should be 'no'"

**Project structure**

```
infradoctor/
├── cmd/infradoctor/main.go
├── internal/
│   ├── core/
│   ├── detect/
│   ├── ui/
│   ├── report/
│   │   ├── json.go
│   │   ├── markdown.go
│   │   ├── summary.go
│   │   ├── sanitize.go
│   │   └── sanitize_test.go
│   └── modules/
│       ├── interface.go
│       ├── registry.go
│       ├── helpers.go
│       ├── ssh.go
│       ├── firewall.go
│       ├── networking.go
│       ├── docker.go
│       ├── storage.go
│       ├── systemd.go
│       ├── security.go
│       └── nginx.go
├── testdata/
├── reports/examples/
├── go.mod
├── README.md
├── TODO.md
└── LICENSE
```

**Roadmap**

- [x] v0.1 — CLI, root, OS, menu, reports, sanitize
- [x] v0.2 — SSH Module
- [x] v0.3 — Firewall Module (effective stack, DOCKER-USER)
- [x] v0.4 — Networking Module (listening ports, routing, DNS)
- [x] v0.5 — Docker Module (containers, networks, storage)
- [x] v0.6 — Storage Module (df, inodes, disk analysis)
- [x] v0.7 — Systemd Module (failed units, timers, sockets)
- [x] v0.8 — Security Baseline Module (sudo, updates, fail2ban, kernel)
- [x] Nginx Module (host + container)
- [x] Exposure Summary (Markdown + JSON)
- [x] Code-based check/recommendation matching

---

## License

MIT License — see [LICENSE](LICENSE).

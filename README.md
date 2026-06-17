<div align="center">
  <h1>🛡️ DIMP Domain Impersonation Monitoring Platform</h1>
  <p><strong>Continuous detection of typosquatting, homoglyph domains, cloned webpages, and phishing infrastructure targeting your brand.</strong></p>
  <br/>
  <img src="https://img.shields.io/badge/Python-3.12-blue?logo=python" />
  <img src="https://img.shields.io/badge/FastAPI-0.111-009688?logo=fastapi" />
  <img src="https://img.shields.io/badge/React-19-61dafb?logo=react" />
  <img src="https://img.shields.io/badge/Docker-Compose-2496ed?logo=docker" />
  <img src="https://img.shields.io/badge/PostgreSQL-16-336791?logo=postgresql" />
  <img src="https://img.shields.io/badge/Celery-5.4-37814a?logo=celery" />
  <img src="https://img.shields.io/badge/license-MIT-green" />
</div>

---

## Overview

DIMP monitors the internet for domains that may impersonate your organisation and automatically analyses them for phishing risk. It generates typosquatting variants, queries certificate transparency logs, probes live sites for login forms, compares screenshots visually, and integrates with public threat intelligence feeds — all surfaced in a real-time React dashboard.

**Key capabilities:**

| Capability | Details |
|---|---|
| Domain discovery | 5,000+ typosquat variants per domain · CT log queries · homoglyphs · TLD sweeps · extra-word patterns |
| Domain analysis | DNS · WHOIS/RDAP · SSL certificates · HTTP metadata · redirect chains · ASN/geo lookup |
| Webpage detection | Playwright screenshots · pHash visual similarity · TF-IDF content similarity · DOM structure · login form detection · favicon comparison |
| Threat intelligence | OpenPhish · URLhaus · urlscan.io · VirusTotal (API key optional) |
| Risk scoring | 16-factor 0–100 score → Low / Medium / High / Critical severity |
| Alerting | Email (SMTP) · Slack webhook · MS Teams webhook · SIEM JSON webhook · UDP syslog |
| Reporting | HTML · PDF (WeasyPrint) · CSV · JSON with executive summary |
| API | Full REST API with JWT auth, RBAC, OpenAPI docs |

---

## Quick start

### Prerequisites

- Docker ≥ 24 and Docker Compose v2
- 4 GB RAM minimum (Playwright Chromium needs ~1.5 GB)

### 1. Clone

```bash
git clone https://github.com/YOUR_ORG/dimp.git
cd dimp
```

### 2. Configure

```bash
cp .env.example .env
```

Edit `.env` and set at minimum:

```env
SECRET_KEY=<run: openssl rand -hex 32>
```

Everything else has working defaults for local Docker Compose.

### 3. Start

```bash
docker compose up -d
```

This starts 6 containers: `db`, `redis`, `backend`, `worker`, `worker-screenshots`, `beat`, `frontend`.

### 4. Migrate database

```bash
docker compose exec backend alembic upgrade head
```

### 5. Create admin account

```bash
curl -s -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","full_name":"Admin","password":"changeme123"}' \
  | python3 -m json.tool
```

> This endpoint is only available until the first user exists.

### 6. Open the dashboard

- **Dashboard:** http://localhost:3000
- **API docs:** http://localhost:8000/docs

---

## Architecture

```
┌────────────────────────────────────────────────────────┐
│                  Browser (port 3000)                   │
│         React 19 · Recharts · Tailwind-like CSS        │
└────────────────────┬───────────────────────────────────┘
                     │ HTTPS / REST + JWT
┌────────────────────▼───────────────────────────────────┐
│              FastAPI backend (port 8000)                │
│   Auth · Assets · Findings · Scans · Dashboard · Reports│
└────────┬───────────────────────────┬───────────────────┘
         │ SQLAlchemy (async)        │ Celery task dispatch
┌────────▼──────────┐   ┌───────────▼─────────────────────┐
│   PostgreSQL 16   │   │     Redis 7 (broker + results)   │
└───────────────────┘   └───────────┬─────────────────────┘
                                    │
        ┌───────────────────────────▼──────────────────────┐
        │              Celery workers                       │
        │  ┌─────────────────┐  ┌──────────────────────┐   │
        │  │  Discovery      │  │  Screenshots          │   │
        │  │  DNS · WHOIS    │  │  Playwright Chromium  │   │
        │  │  SSL · HTTP     │  │  pHash similarity     │   │
        │  │  Risk scoring   │  │  TF-IDF · DOM sim     │   │
        │  │  TI feeds       │  └──────────────────────┘   │
        │  └─────────────────┘                             │
        └──────────────────────────────────────────────────┘
                        │ queries
        ┌───────────────▼──────────────────────────────────┐
        │  External OSINT                                   │
        │  crt.sh · OpenPhish · URLhaus · urlscan.io · VT   │
        └──────────────────────────────────────────────────┘
```

### Docker Compose services

| Service | Image | Role |
|---|---|---|
| `db` | postgres:16-alpine | Primary data store (15 tables) |
| `redis` | redis:7-alpine | Celery broker + result backend |
| `backend` | Custom Python 3.12 | FastAPI API server (Uvicorn) |
| `worker` | Custom Python 3.12 | Celery scan workers (general queue) |
| `worker-screenshots` | Custom Python 3.12 | Playwright screenshot workers |
| `beat` | Custom Python 3.12 | Celery Beat scheduled scans |
| `frontend` | Node 20 → Nginx | React SPA |

---

## Project structure

```
dimp/
├── .env.example                    # All environment variables documented
├── .gitignore
├── .github/
│   ├── workflows/ci.yml            # GitHub Actions: backend tests + frontend build + Docker
│   └── ISSUE_TEMPLATE/
├── Dockerfile.backend              # FastAPI + WeasyPrint
├── Dockerfile.worker               # Celery + Playwright Chromium
├── docker-compose.yml
├── requirements.txt
├── alembic.ini
├── alembic/env.py                  # DB migration environment
│
├── app/
│   ├── main.py                     # FastAPI app factory, CORS, lifespan
│   ├── core/
│   │   ├── config.py               # Pydantic Settings (reads .env)
│   │   └── security.py             # JWT creation/verification, bcrypt
│   ├── db/session.py               # Async + sync SQLAlchemy engines
│   ├── models/__init__.py          # 15 ORM models (all DB tables)
│   ├── schemas/__init__.py         # Pydantic v2 request/response schemas
│   ├── api/
│   │   ├── deps.py                 # Auth, RBAC, pagination dependencies
│   │   └── v1/endpoints/
│   │       ├── auth.py             # Login, register, /me
│   │       ├── assets.py           # Monitored assets + keywords + allowlist
│   │       ├── findings.py         # Findings list, detail, status workflow
│   │       ├── scans.py            # Trigger + poll scan jobs
│   │       ├── dashboard.py        # Stats, charts, trend data
│   │       └── reports.py          # Report generation + download
│   ├── workers/
│   │   ├── tasks.py                # Celery app + scan orchestration + Beat schedule
│   │   └── scanner/
│   │       ├── discovery.py        # Typosquat variants + CT log queries
│   │       ├── dns_collector.py    # A/AAAA/MX/NS/TXT/CNAME
│   │       ├── whois_collector.py  # WHOIS/RDAP normalisation
│   │       ├── ssl_collector.py    # TLS cert extraction
│   │       ├── http_collector.py   # HTTP metadata + login form detection
│   │       ├── screenshot_capture.py  # Playwright screenshot + favicon hash
│   │       ├── similarity_engine.py   # pHash + TF-IDF + DOM + favicon
│   │       ├── domain_analyser.py  # Full per-domain pipeline orchestrator
│   │       ├── risk_scorer.py      # 16-factor 0–100 scoring engine
│   │       ├── ti_feeds.py         # TI feed orchestrator
│   │       └── feeds/
│   │           ├── openphish.py    # OpenPhish free feed
│   │           ├── urlhaus.py      # URLhaus API
│   │           ├── urlscan.py      # urlscan.io search API
│   │           └── virustotal.py   # VirusTotal URL report
│   └── services/
│       ├── alerting_service.py     # Email + Slack + MS Teams alerting
│       ├── siem_service.py         # SIEM webhook + UDP syslog forwarding
│       ├── report_service.py       # HTML + CSV + JSON report generation
│       └── pdf_report.py           # PDF via WeasyPrint + Jinja2 template
│
├── frontend/
│   ├── Dockerfile                  # Node build → Nginx SPA
│   ├── package.json
│   └── src/
│       ├── App.js                  # Router + auth guard
│       ├── index.css               # Dark design system (CSS variables)
│       ├── pages/
│       │   ├── Login.js
│       │   ├── Dashboard.js        # Stats cards + 4 charts
│       │   ├── Findings.js         # Filterable findings table + export
│       │   ├── FindingDetail.js    # Full finding detail + workflow
│       │   ├── Assets.js           # Asset management + keywords
│       │   ├── Scans.js            # Scan history + trigger + progress
│       │   └── Reports.js          # Report generation + download
│       ├── components/
│       │   ├── layout/Sidebar.js   # Navigation sidebar
│       │   └── ui/index.js         # ScoreBar, SeverityBadge, StatusPill…
│       ├── context/AuthContext.js  # JWT auth provider
│       ├── services/api.js         # Axios client + all API calls
│       └── utils/format.js         # Date, score, severity formatters
│
└── tests/
    └── unit/
        └── test_risk_scorer.py     # Risk scorer + discovery engine tests
```

---

## Database models

| # | Table | Purpose |
|---|---|---|
| 1 | `users` | Auth, RBAC (admin / analyst / viewer) |
| 2 | `monitored_assets` | Protected domains to scan |
| 3 | `brand_keywords` | Brand keywords per asset |
| 4 | `allowed_domains` | Safe domain allowlist |
| 5 | `discovered_domains` | All candidate suspicious domains |
| 6 | `domain_dns_records` | A, AAAA, MX, NS, TXT, CNAME per domain |
| 7 | `domain_whois_records` | WHOIS/RDAP registration data |
| 8 | `ssl_certificates` | Cert issuer, SANs, validity dates |
| 9 | `webpage_snapshots` | HTML hash, login form flags, brand keywords |
| 10 | `similarity_results` | pHash, TF-IDF, DOM, favicon scores |
| 11 | `threat_intel_matches` | OpenPhish, URLhaus, PhishTank feed hits |
| 12 | `findings` | Risk-scored findings with status workflow |
| 13 | `alerts` | Alert dispatch records per channel |
| 14 | `scan_jobs` | Celery scan job tracking |
| 15 | `reports` | Generated report metadata |

---

## Risk scoring (16 factors)

| Factor | Max pts | Notes |
|---|---|---|
| Domain similarity | 25 | Edit distance + visual score |
| Visual similarity (pHash) | 15 | Screenshot perceptual hash |
| Login / credential form | 10 | Detected via BeautifulSoup |
| Suspicious domain keyword | 10 | login, secure, verify, bank… |
| Threat intel feed hit | 10 | OpenPhish, URLhaus, VT |
| Domain age < 30 days | 10 | WHOIS creation date |
| HTML content similarity | 5 | TF-IDF cosine |
| Favicon hash match | 5 | pHash of favicon image |
| External form action | 5 | Form posts to different domain |
| Suspicious hosting / ASN | 5 | Bulletproof ASN list |
| Free / abused TLD | 5 | .xyz .tk .ml .ga .cf… |
| MX records present | 3 | Active mail capability |
| High-risk hosting country | 3 | RU/CN/KP/NG… |
| Recently issued cert | 2 | SSL cert < 7 days old |
| Active website | 2 | HTTP 2xx/3xx response |
| Valid non-expired SSL | **-5** | Reduces score (legit signal) |

**Severity:** Low 0–30 · Medium 31–60 · High 61–80 · Critical 81–100

---

## API reference

All endpoints require `Authorization: Bearer <token>` except login/register.

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/auth/login` | Get JWT access token |
| `POST` | `/api/v1/auth/register` | First-run admin registration |
| `GET` | `/api/v1/auth/me` | Current user profile |
| `GET/POST` | `/api/v1/assets` | List / create monitored assets |
| `PATCH/DELETE` | `/api/v1/assets/{id}` | Update / delete asset |
| `GET/POST` | `/api/v1/assets/{id}/keywords` | Brand keywords |
| `GET/POST` | `/api/v1/assets/{id}/allowlist` | Safe domain list |
| `GET` | `/api/v1/findings` | Findings (filters: severity, status, type) |
| `GET` | `/api/v1/findings/{id}` | Full finding detail |
| `PATCH` | `/api/v1/findings/{id}/status` | Update workflow status |
| `POST` | `/api/v1/scans` | Trigger manual scan |
| `GET` | `/api/v1/scans` | Scan job history |
| `GET` | `/api/v1/scans/{id}` | Poll job status |
| `GET` | `/api/v1/dashboard/stats` | Summary card data |
| `GET` | `/api/v1/dashboard/findings-trend` | 30-day trend |
| `GET` | `/api/v1/dashboard/findings-by-severity` | Chart data |
| `GET` | `/api/v1/dashboard/findings-by-source` | Chart data |
| `GET` | `/api/v1/dashboard/findings-by-tld` | Chart data |
| `POST` | `/api/v1/reports` | Generate report |
| `GET` | `/api/v1/reports/{id}/download` | Download report file |

Interactive docs: **http://localhost:8000/docs**

---

## Environment variables

See `.env.example` for the full annotated list.

| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | ✅ | JWT signing key (`openssl rand -hex 32`) |
| `DATABASE_URL` | ✅ | Async PostgreSQL URL |
| `DATABASE_URL_SYNC` | ✅ | Sync PostgreSQL URL (Alembic) |
| `REDIS_URL` | ✅ | Redis connection string |
| `SLACK_WEBHOOK_URL` | Optional | Slack alerting |
| `TEAMS_WEBHOOK_URL` | Optional | MS Teams alerting |
| `SIEM_WEBHOOK_URL` | Optional | SIEM/SOAR webhook |
| `URLSCAN_API_KEY` | Optional | urlscan.io search API |
| `VIRUSTOTAL_API_KEY` | Optional | VirusTotal URL reports |
| `SMTP_HOST` | Optional | Email alerting |

---

## Development

```bash
# Backend (local, needs Postgres + Redis running)
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # edit DATABASE_URL / REDIS_URL
PYTHONPATH=. alembic upgrade head
PYTHONPATH=. uvicorn app.main:app --reload

# Celery worker
PYTHONPATH=. celery -A app.workers.tasks.celery_app worker -l info

# Frontend (separate terminal)
cd frontend && npm install && npm start

# Tests
PYTHONPATH=. pytest tests/ -v

# Lint
pip install ruff && ruff check app/
```

---

## Deployment notes

- Place a reverse proxy (nginx / Caddy / Traefik) in front of `backend:8000` with TLS
- Set `DEBUG=false` and a strong `SECRET_KEY` in production
- Use managed PostgreSQL and Redis in production (RDS, ElastiCache, etc.)
- The Playwright worker image is ~1.5 GB — store images in a registry (ECR, GHCR)
- Volume-mount `/app/data` to persistent storage for screenshots and reports
- Screenshot capture is the most resource-intensive step — scale `worker-screenshots` independently

---

## Roadmap

- [ ] LDAP / SSO authentication
- [ ] Bulk domain import via CSV
- [ ] Takedown workflow integration (ICANN UDRP API, abuse@registrar)
- [ ] Passive DNS enrichment (SecurityTrails / DNSDB)
- [ ] Logo detection via ML image classifier
- [ ] Telegram / PagerDuty alerting channels
- [ ] Multi-tenant support (per-organisation data isolation)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md). Please do not open public issues for vulnerabilities.

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">
  Built with FastAPI, React, PostgreSQL, Celery, and Playwright.<br/>
  Developed for SOC and threat intelligence operations.
</div>

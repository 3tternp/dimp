# Domain Impersonation Monitoring Platform (DIMP)

Continuous monitoring platform that discovers and analyses suspicious domains
impersonating your organisation — typosquatting, homoglyph domains, cloned
webpages, and phishing infrastructure.

---

## Quick start (Docker Compose)

```bash
# 1. Clone and configure
cp .env.example .env
# Edit .env — set SECRET_KEY, SMTP/Slack/Teams credentials as needed

# 2. Start all services
docker compose up -d

# 3. Run DB migrations
docker compose exec backend alembic upgrade head

# 4. Register the first admin account (one-time only)
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@yourdomain.com","full_name":"Admin","password":"changeme123"}'

# 5. Open the dashboard
open http://localhost:3000

# 6. Interactive API docs
open http://localhost:8000/docs
```

---

## Architecture

```
Browser → FastAPI (port 8000) → PostgreSQL
                ↓
           Redis / Celery
                ↓
    ┌──────────────────────────┐
    │    Scanner workers       │
    │  • Discovery engine      │
    │  • DNS / WHOIS / SSL     │
    │  • HTTP metadata         │
    │  • Screenshot (Phase 3)  │
    │  • Similarity (Phase 3)  │
    │  • Threat intel (Phase 5)│
    └──────────────────────────┘
```

### Services (Docker Compose)

| Service | Image | Port | Purpose |
|---|---|---|---|
| `db` | postgres:16-alpine | — | Primary data store |
| `redis` | redis:7-alpine | — | Celery broker + result backend |
| `backend` | Custom Python | 8000 | FastAPI API server |
| `worker` | Custom Python | — | Celery scan workers |
| `worker-screenshots` | Custom Python | — | Playwright screenshot workers |
| `beat` | Custom Python | — | Celery Beat scheduler |
| `frontend` | Custom Node/Nginx | 3000 | React dashboard |

---

## Project structure

```
dimp/
├── app/
│   ├── main.py                    # FastAPI application entry point
│   ├── core/
│   │   ├── config.py              # Pydantic Settings (reads .env)
│   │   └── security.py            # JWT + bcrypt password utilities
│   ├── db/
│   │   └── session.py             # Async + sync SQLAlchemy engines
│   ├── models/
│   │   └── __init__.py            # All 15 ORM models (14 DB tables + reports)
│   ├── schemas/
│   │   └── __init__.py            # Pydantic v2 request/response schemas
│   ├── api/
│   │   ├── deps.py                # Auth dependencies, pagination
│   │   └── v1/
│   │       ├── __init__.py        # Router registration
│   │       └── endpoints/
│   │           ├── auth.py        # Login, register, /me
│   │           ├── assets.py      # Monitored assets, keywords, allowlist
│   │           ├── findings.py    # Findings list, detail, status update
│   │           ├── scans.py       # Trigger scans, view scan history
│   │           ├── dashboard.py   # Stats, charts, trend data
│   │           └── reports.py     # Report generation, download
│   ├── workers/
│   │   ├── tasks.py               # Celery app + orchestration tasks
│   │   └── scanner/
│   │       ├── discovery.py       # Typosquat + CT log discovery engine
│   │       ├── dns_collector.py   # DNS A/AAAA/MX/NS/TXT/CNAME collector
│   │       ├── whois_collector.py # WHOIS / RDAP collector
│   │       ├── ssl_collector.py   # SSL/TLS certificate extractor
│   │       ├── http_collector.py  # HTTP metadata + form detection
│   │       ├── domain_analyser.py # Full pipeline orchestrator per domain
│   │       └── risk_scorer.py     # 16-factor 0-100 risk scoring engine
│   └── services/
│       ├── alerting_service.py    # Email, Slack, Teams, SIEM alerting
│       └── report_service.py      # HTML, CSV, JSON report generation
├── alembic/                       # DB migrations
├── tests/unit/                    # Unit tests
├── docker-compose.yml
├── requirements.txt
├── .env.example
└── README.md
```

---

## Database models

| # | Table | Purpose |
|---|---|---|
| 1 | `users` | Authentication and RBAC (admin / analyst / viewer) |
| 2 | `monitored_assets` | Protected domains to monitor |
| 3 | `brand_keywords` | Brand keywords per asset |
| 4 | `allowed_domains` | Safe domain allowlist |
| 5 | `discovered_domains` | All candidate suspicious domains |
| 6 | `domain_dns_records` | A, AAAA, MX, NS, TXT, CNAME per domain |
| 7 | `domain_whois_records` | WHOIS / RDAP registration data |
| 8 | `ssl_certificates` | SSL cert issuer, SAN, validity |
| 9 | `webpage_snapshots` | HTML hash, login form detection, keywords |
| 10 | `similarity_results` | pHash, TF-IDF, DOM, favicon similarity scores |
| 11 | `threat_intel_matches` | OpenPhish, URLhaus, PhishTank hits |
| 12 | `findings` | Risk-scored findings with workflow status |
| 13 | `alerts` | Alert dispatch records per channel |
| 14 | `scan_jobs` | Celery scan job tracking |
| 15 | `reports` | Generated report metadata |

---

## API reference (summary)

All endpoints require `Authorization: Bearer <token>` except `/auth/login` and `/auth/register`.

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/auth/login` | Obtain JWT token |
| `GET` | `/api/v1/auth/me` | Current user profile |
| `GET` | `/api/v1/assets` | List monitored assets |
| `POST` | `/api/v1/assets` | Add monitored domain |
| `GET` | `/api/v1/findings` | List findings (filterable) |
| `GET` | `/api/v1/findings/{id}` | Finding detail with DNS/WHOIS/SSL/screenshots |
| `PATCH` | `/api/v1/findings/{id}/status` | Update finding workflow status |
| `POST` | `/api/v1/scans` | Trigger manual scan |
| `GET` | `/api/v1/scans/{id}` | Poll scan job progress |
| `GET` | `/api/v1/dashboard/stats` | Dashboard summary cards |
| `GET` | `/api/v1/dashboard/findings-trend` | Daily finding counts (30 days) |
| `POST` | `/api/v1/reports` | Generate report (HTML/CSV/JSON/PDF) |
| `GET` | `/api/v1/reports/{id}/download` | Download generated report |

Full interactive docs: `http://localhost:8000/docs`

---

## Risk scoring (16 factors)

| Factor | Max pts |
|---|---|
| Domain similarity (edit distance / visual similarity) | 25 |
| Visual screenshot similarity (pHash/dHash) | 15 |
| Login / credential form present | 10 |
| Suspicious keyword in domain | 10 |
| Threat intel feed hit | 10 |
| Domain age < 30 days | 10 |
| HTML / content similarity (TF-IDF) | 5 |
| Favicon hash match | 5 |
| External form action (form posts elsewhere) | 5 |
| Suspicious hosting / ASN | 5 |
| Free/abused TLD (.xyz, .tk, .ml…) | 5 |
| MX records present | 3 |
| High-risk hosting country | 3 |
| Recently issued certificate (< 7 days) | 2 |
| Active website | 2 |
| Valid non-expired SSL *(reduces score)* | -5 |

**Severity mapping:** Low 0–30 · Medium 31–60 · High 61–80 · Critical 81–100

---

## Development

```bash
# Install deps
pip install -r requirements.txt

# Run API locally (needs Postgres + Redis)
PYTHONPATH=. uvicorn app.main:app --reload

# Run Celery worker
PYTHONPATH=. celery -A app.workers.tasks.celery_app worker -l info

# Run DB migrations
PYTHONPATH=. alembic upgrade head

# Run tests
PYTHONPATH=. pytest tests/ -v
```

---

## Build phases

| Phase | Scope | Status |
|---|---|---|
| 1 | Infrastructure: Docker, DB schema, auth | ✅ Complete |
| 2 | Discovery: typosquatting, CT logs, DNS | ✅ Complete |
| 3 | Analysis: SSL, WHOIS, HTTP, risk scoring | ✅ Complete |
| 4 | Dashboard: React UI, reports, alerting | 🔲 Next |
| 5 | Threat intel feeds, PDF reports, SIEM | 🔲 Next |

---

## Environment variables

See `.env.example` for the full list. Key variables:

| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | ✅ | JWT signing key — generate with `openssl rand -hex 32` |
| `DATABASE_URL` | ✅ | Async PostgreSQL connection string |
| `REDIS_URL` | ✅ | Redis connection string |
| `SLACK_WEBHOOK_URL` | Optional | Slack alerting |
| `TEAMS_WEBHOOK_URL` | Optional | MS Teams alerting |
| `URLSCAN_API_KEY` | Optional | urlscan.io integration |
| `SMTP_HOST` | Optional | Email alerting |

<div align="center">
  <h1>🛡️ DIMP — Domain Impersonation Monitoring Platform</h1>
  <p><strong>Continuous detection of typosquatting, homoglyph domains, cloned webpages, and phishing infrastructure targeting your brand.</strong></p>
  <br/>
  <img src="https://img.shields.io/badge/Python-3.12+-blue?logo=python" />
  <img src="https://img.shields.io/badge/FastAPI-0.111-009688?logo=fastapi" />
  <img src="https://img.shields.io/badge/React-19-61dafb?logo=react" />
  <img src="https://img.shields.io/badge/Docker-Compose-2496ed?logo=docker" />
  <img src="https://img.shields.io/badge/PostgreSQL-16-336791?logo=postgresql" />
  <img src="https://img.shields.io/badge/Celery-5.4-37814a?logo=celery" />
  <img src="https://img.shields.io/badge/license-MIT-green" />
</div>

---

## 📋 Overview

DIMP monitors the internet for domains that may impersonate your organisation and automatically analyses them for phishing risk. It generates typosquatting variants, queries certificate transparency logs, probes live sites for login forms, compares content visually, and integrates with 6 public threat intelligence feeds — all surfaced in a real-time React dashboard.

**Key capabilities:**

| Capability | Details |
|---|---|
| 🔍 Domain discovery | 5,000+ typosquat variants per domain, CT log queries (crt.sh), homoglyphs, TLD sweeps, extra-word patterns |
| 🌐 Domain analysis | DNS (A/AAAA/MX/NS/TXT/CNAME), WHOIS/RDAP, SSL certificates, HTTP metadata, redirect chains, login form detection |
| 📊 Similarity detection | pHash visual similarity, TF-IDF content similarity, DOM structure comparison, favicon hash matching |
| 🕵️ Threat intelligence | OpenPhish, PhishTank, ThreatFox (Abuse.ch), URLhaus (Abuse.ch), urlscan.io, VirusTotal |
| ⚖️ Risk scoring | 16-factor weighted 0-100 score with Low / Medium / High / Critical severity classification |
| 🔔 Alerting | Email (SMTP), Slack webhook, MS Teams webhook, SIEM JSON webhook, UDP syslog |
| 📄 Reporting | HTML, PDF (WeasyPrint), CSV, JSON with executive summary |
| 🔑 API | Full REST API with JWT auth, role-based access control (admin/analyst/viewer), OpenAPI 3.1 docs |

---

## 📸 Screenshots

### 🔐 Login
![Login](docs/screenshots/dimp-login.png)

### 📊 Dashboard
![Dashboard](docs/screenshots/dimp-dashboard.png)

### 🚨 Findings
![Findings](docs/screenshots/dimp-findings.png)

### 🔎 Finding Detail — esample.com (Typosquatting, Medium)
![Finding Detail](docs/screenshots/dimp-finding-detail.png)

### 🔎 Finding Detail — example.co.uk (TLD Variation, Low)
![Finding Detail - example.co.uk](docs/screenshots/dimp-finding-couk.png)

### 🌐 Finding Detail — WHOIS, SSL & DNS
![Finding WHOIS](docs/screenshots/dimp-finding-whois.png)

### 🛡️ Monitored Assets
![Assets](docs/screenshots/dimp-assets.png)

### 📡 Scan History
![Scans](docs/screenshots/dimp-scans.png)

### 📄 Reports
![Reports](docs/screenshots/dimp-reports.png)

### ⚙️ Settings
![Settings](docs/screenshots/dimp-settings.png)

### ℹ️ Platform Info
![Platform Info](docs/screenshots/dimp-platform.png)

### 📘 API Docs (Swagger)
![Swagger](docs/screenshots/dimp-swagger.png)

---

## 🚀 Quick start

### Option 1: Docker Compose (recommended)

#### Prerequisites

- Docker >= 24 and Docker Compose v2
- 4 GB RAM minimum

#### 1. Clone and configure

```bash
git clone https://github.com/3tternp/dimp.git
cd dimp
cp .env.example .env
# Generate a secret key
sed -i "s/changeme-generate-with-openssl-rand-hex-32/$(openssl rand -hex 32)/" .env
```

#### 2. Start all services

```bash
docker compose up -d
```

This starts 7 containers: `db`, `redis`, `backend`, `worker`, `worker-screenshots`, `beat`, `frontend`.

#### 3. Create admin account

```bash
curl -s -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@yourorg.com","full_name":"Admin","password":"YourSecurePass123"}' \
  | python3 -m json.tool
```

> This endpoint is only available until the first user exists.

#### 4. Open the dashboard

- **Dashboard:** http://localhost:3000
- **API docs:** http://localhost:8000/docs

### Option 2: Local development (without Docker)

#### Prerequisites

- Python 3.12+
- PostgreSQL 16+
- Redis 7+
- Node.js 20+ and npm

#### 1. Clone and configure

```bash
git clone https://github.com/3tternp/dimp.git
cd dimp
cp .env.example .env
```

Edit `.env` and update the database/Redis URLs to point to `localhost`:

```env
SECRET_KEY=<run: openssl rand -hex 32>
DATABASE_URL=postgresql+asyncpg://dimp:dimp_pass@localhost:5432/dimp
DATABASE_URL_SYNC=postgresql+psycopg2://dimp:dimp_pass@localhost:5432/dimp
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/1
SCREENSHOT_DIR=./data/screenshots
REPORT_DIR=./data/reports
```

#### 2. Set up the database

```bash
sudo -u postgres psql -c "CREATE USER dimp WITH PASSWORD 'dimp_pass';"
sudo -u postgres psql -c "CREATE DATABASE dimp OWNER dimp;"
```

#### 3. Install backend dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
mkdir -p data/screenshots data/reports
```

#### 4. Run migrations and start the backend

```bash
alembic upgrade head
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

#### 5. Install and start the frontend

```bash
cd frontend && npm install && npm start
```

#### 6. Create admin account and open the dashboard

```bash
curl -s -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@yourorg.com","full_name":"Admin","password":"YourSecurePass123"}' \
  | python3 -m json.tool
```

- **Dashboard:** http://localhost:3000
- **API docs:** http://localhost:8000/docs

> **Note:** Without Celery workers, scans run synchronously in a background thread. For production use, start Celery workers separately:
> ```bash
> celery -A app.workers.tasks.celery_app worker -Q scans,default -c 4 -l info
> ```

---

## 🏗️ Architecture

```
+---------------------------------------------------------+
|                  Browser (port 3000)                    |
|         React 19 . Recharts . Dark theme CSS            |
+------------------------+--------------------------------+
                         | REST + JWT
+------------------------v--------------------------------+
|              FastAPI backend (port 8000)                 |
|   Auth . Assets . Findings . Scans . Dashboard . Reports|
+---------+--------------------------+--------------------+
          | SQLAlchemy (async)       | Background thread / Celery
+---------v-----------+   +----------v--------------------+
|   PostgreSQL 16     |   |     Redis 7 (broker + cache)  |
+---------------------+   +----------+--------------------+
                                     |
         +---------------------------v---------------------+
         |              Scan Pipeline                      |
         |  +------------------+  +---------------------+  |
         |  |  Discovery       |  |  Analysis            | |
         |  |  Typosquat gen   |  |  DNS . WHOIS . SSL   | |
         |  |  CT log queries  |  |  HTTP . Login detect  | |
         |  +------------------+  |  TI feeds . Scoring   | |
         |                        +---------------------+  |
         +-------------------------------------------------+
                         | queries
         +---------------v---------------------------------+
         |  External OSINT / Threat Intel                   |
         |  crt.sh . OpenPhish . PhishTank . ThreatFox     |
         |  URLhaus . urlscan.io . VirusTotal              |
         +-------------------------------------------------+
```

### 🔄 Scan pipeline

When a scan is triggered (manually or via schedule), the pipeline:

1. **Discovery** — generates typosquat variants (character substitution, deletion, transposition, homoglyphs, TLD variations, extra words) and queries crt.sh certificate transparency logs
2. **DNS resolution** — queries A, AAAA, MX, NS, TXT, CNAME records; non-resolving domains are scored minimally and skipped
3. **WHOIS lookup** — registrar, creation/expiry dates, registrant info, privacy detection
4. **SSL collection** — certificate issuer, SANs, validity, self-signed/expired detection
5. **HTTP metadata** — page title, meta description, redirect chains, login form detection, credential field detection, external form actions, brand keyword matching
6. **Threat intelligence** — checks domain against OpenPhish, PhishTank, ThreatFox, URLhaus, urlscan.io, and VirusTotal feeds
7. **Similarity computation** — pHash visual similarity, TF-IDF content similarity, DOM structure comparison, favicon hash matching
8. **Risk scoring** — 16-factor weighted scoring engine produces a 0-100 risk score
9. **Finding creation** — domains exceeding the asset's risk threshold generate findings with severity classification and recommended actions

### 🐳 Docker Compose services

| Service | Image | Role |
|---|---|---|
| `db` | postgres:16-alpine | Primary data store (15 tables) |
| `redis` | redis:7-alpine | Celery broker + result backend |
| `backend` | Custom Python 3.12 | FastAPI API server (Uvicorn) |
| `worker` | Custom Python 3.12 | Celery scan workers (general queue) |
| `worker-screenshots` | Custom Python 3.12 | Playwright screenshot workers |
| `beat` | Custom Python 3.12 | Celery Beat scheduled scans |
| `frontend` | Node 20 -> Nginx | React SPA |

---

## 📁 Project structure

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
├── Makefile                        # Common dev commands (up, down, logs, migrate, test)
├── alembic.ini
├── alembic/
│   ├── env.py                      # DB migration environment
│   ├── script.py.mako              # Migration template
│   └── versions/                   # Migration files
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
│   │       ├── reports.py          # Report generation + download
│   │       └── settings.py         # Profile, password, user management
│   ├── workers/
│   │   ├── tasks.py                # Celery app + scan orchestration + Beat schedule
│   │   └── scanner/
│   │       ├── discovery.py        # Typosquat variants + CT log queries
│   │       ├── domain_analyser.py  # Full per-domain pipeline orchestrator
│   │       ├── dns_collector.py    # A/AAAA/MX/NS/TXT/CNAME
│   │       ├── whois_collector.py  # WHOIS/RDAP normalisation
│   │       ├── ssl_collector.py    # TLS cert extraction
│   │       ├── http_collector.py   # HTTP metadata + login form detection
│   │       ├── screenshot_capture.py  # Playwright screenshot + favicon hash
│   │       ├── similarity_engine.py   # pHash + TF-IDF + DOM + favicon
│   │       ├── risk_scorer.py      # 16-factor 0-100 scoring engine
│   │       ├── ti_feeds.py         # TI feed orchestrator
│   │       └── feeds/
│   │           ├── openphish.py    # OpenPhish free feed (cached, no key)
│   │           ├── phishtank.py    # PhishTank verified phishing DB (no key)
│   │           ├── threatfox.py    # Abuse.ch ThreatFox IOC DB (no key)
│   │           ├── urlhaus.py      # Abuse.ch URLhaus API (no key)
│   │           ├── urlscan.py      # urlscan.io search API (optional key)
│   │           └── virustotal.py   # VirusTotal domain report (optional key)
│   └── services/
│       ├── alerting_service.py     # Email + Slack + MS Teams alerting
│       ├── siem_service.py         # SIEM webhook + UDP syslog forwarding
│       ├── report_service.py       # HTML + CSV + JSON report generation
│       └── pdf_report.py           # PDF via WeasyPrint + Jinja2 template
│
├── frontend/
│   ├── Dockerfile                  # Node build -> Nginx SPA
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
│       │   ├── Reports.js          # Report generation + download
│       │   └── Settings.js         # Profile, password, users, platform info
│       ├── components/
│       │   ├── layout/Sidebar.js   # Navigation sidebar
│       │   └── ui/index.js         # ScoreBar, SeverityBadge, StatusPill...
│       ├── context/AuthContext.js  # JWT auth provider
│       ├── services/api.js         # Axios client + all API calls
│       └── utils/format.js         # Date, score, severity formatters
│
├── docs/
│   └── screenshots/                # App screenshots for README
│
└── tests/
    └── unit/
        └── test_risk_scorer.py     # Risk scorer + discovery engine tests
```

---

## 🗄️ Database schema (15 tables)

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
| 11 | `threat_intel_matches` | OpenPhish, PhishTank, ThreatFox, URLhaus feed hits |
| 12 | `findings` | Risk-scored findings with status workflow |
| 13 | `alerts` | Alert dispatch records per channel |
| 14 | `scan_jobs` | Scan job tracking and progress |
| 15 | `reports` | Generated report metadata |

---

## ⚖️ Risk scoring (16 factors)

| Factor | Max pts | Notes |
|---|---|---|
| Domain similarity | 25 | Edit distance + visual score |
| Visual similarity (pHash) | 15 | Screenshot perceptual hash |
| Login / credential form | 10 | Detected via BeautifulSoup |
| Suspicious domain keyword | 10 | login, secure, verify, bank... |
| Threat intel feed hit | 10 | OpenPhish, PhishTank, ThreatFox, URLhaus, urlscan, VT |
| Domain age < 30 days | 10 | WHOIS creation date |
| HTML content similarity | 5 | TF-IDF cosine |
| Favicon hash match | 5 | pHash of favicon image |
| External form action | 5 | Form posts to different domain |
| Suspicious hosting / ASN | 5 | Bulletproof ASN list |
| Free / abused TLD | 5 | .xyz .tk .ml .ga .cf... |
| MX records present | 3 | Active mail capability |
| High-risk hosting country | 3 | RU/CN/KP/NG... |
| Recently issued cert | 2 | SSL cert < 7 days old |
| Active website | 2 | HTTP 2xx/3xx response |
| Valid non-expired SSL | **-5** | Reduces score (legit signal) |

**Severity mapping:** Low 0-30 | Medium 31-60 | High 61-80 | Critical 81-100

---

## 🕵️ Threat intelligence feeds

| Feed | API Key | Description |
|---|---|---|
| [OpenPhish](https://openphish.com) | Not required | Live phishing URL feed (cached hourly) |
| [PhishTank](https://phishtank.org) | Not required | Community-verified phishing URL database |
| [ThreatFox](https://threatfox.abuse.ch) | Not required | Abuse.ch IOC database (malware, botnet, C2) |
| [URLhaus](https://urlhaus.abuse.ch) | Not required | Abuse.ch malware URL database |
| [urlscan.io](https://urlscan.io) | Optional | Website scanning and analysis API |
| [VirusTotal](https://www.virustotal.com) | Optional | Multi-engine domain reputation |

Feeds that don't require API keys work out of the box. For enhanced coverage, add optional API keys in `.env`.

---

## 📡 API reference

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
| `GET` | `/api/v1/findings/{id}` | Full finding detail with DNS, WHOIS, SSL, snapshots |
| `PATCH` | `/api/v1/findings/{id}/status` | Update workflow status |
| `POST` | `/api/v1/scans` | Trigger manual scan |
| `GET` | `/api/v1/scans` | Scan job history |
| `GET` | `/api/v1/scans/{id}` | Poll job status and progress |
| `GET` | `/api/v1/dashboard/stats` | Summary card data |
| `GET` | `/api/v1/dashboard/findings-trend` | 30-day trend chart data |
| `GET` | `/api/v1/dashboard/findings-by-severity` | Severity distribution |
| `GET` | `/api/v1/dashboard/findings-by-source` | Discovery source distribution |
| `GET` | `/api/v1/dashboard/findings-by-tld` | TLD distribution |
| `GET/PATCH` | `/api/v1/settings/profile` | View / update profile |
| `POST` | `/api/v1/settings/change-password` | Change password |
| `GET/POST` | `/api/v1/settings/users` | List / create users (admin) |
| `PATCH/DELETE` | `/api/v1/settings/users/{id}` | Update / delete user (admin) |
| `GET` | `/api/v1/settings/platform` | Platform info and capabilities |
| `POST` | `/api/v1/reports` | Generate report (HTML/PDF/CSV/JSON) |
| `GET` | `/api/v1/reports/{id}/download` | Download report file |

Interactive docs: **http://localhost:8000/docs**

---

## 🔧 Environment variables

See `.env.example` for the full annotated list.

| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | Yes | JWT signing key (`openssl rand -hex 32`) |
| `DATABASE_URL` | Yes | Async PostgreSQL URL |
| `DATABASE_URL_SYNC` | Yes | Sync PostgreSQL URL (Alembic) |
| `REDIS_URL` | Yes | Redis connection string |
| `CELERY_BROKER_URL` | Yes | Celery broker URL (Redis) |
| `CELERY_RESULT_BACKEND` | Yes | Celery result backend URL (Redis) |
| `URLSCAN_API_KEY` | Optional | urlscan.io search API key |
| `VIRUSTOTAL_API_KEY` | Optional | VirusTotal API key |
| `SLACK_WEBHOOK_URL` | Optional | Slack alerting webhook |
| `TEAMS_WEBHOOK_URL` | Optional | MS Teams alerting webhook |
| `SIEM_WEBHOOK_URL` | Optional | SIEM/SOAR JSON webhook |
| `SMTP_HOST` | Optional | Email alerting SMTP server |

---

## 🚢 Deployment notes

- Place a reverse proxy (nginx / Caddy / Traefik) in front of `backend:8000` with TLS
- Set `DEBUG=false` and a strong `SECRET_KEY` in production
- Use managed PostgreSQL and Redis in production (RDS, ElastiCache, etc.)
- Volume-mount `/app/data` to persistent storage for screenshots and reports
- Screenshot capture is the most resource-intensive step — scale `worker-screenshots` independently
- The platform works without Celery for development (scans run in background threads)

---

## 🗺️ Roadmap

- [ ] LDAP / SSO authentication
- [ ] Bulk domain import via CSV
- [ ] Takedown workflow integration (ICANN UDRP API, abuse@registrar)
- [ ] Passive DNS enrichment (SecurityTrails / DNSDB)
- [ ] Logo detection via ML image classifier
- [ ] Telegram / PagerDuty alerting channels
- [ ] Multi-tenant support (per-organisation data isolation)
- [ ] Additional TI feeds (AlienVault OTX, Google Safe Browsing)

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## 🔒 Security

See [SECURITY.md](SECURITY.md). Please do not open public issues for vulnerabilities.

## 📜 License

MIT — see [LICENSE](LICENSE).

---

<div align="center">
  Built with FastAPI, React, PostgreSQL, Celery, and Playwright.<br/>
  Developed for SOC and threat intelligence operations.
</div>

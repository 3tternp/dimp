# Contributing to DIMP

Thank you for your interest in contributing.

## Development setup

```bash
# 1. Clone
git clone https://github.com/YOUR_ORG/dimp.git
cd dimp

# 2. Backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 3. Environment
cp .env.example .env
# Edit .env — set DATABASE_URL and REDIS_URL to local instances

# 4. Database
alembic upgrade head

# 5. Run API
PYTHONPATH=. uvicorn app.main:app --reload

# 6. Frontend (separate terminal)
cd frontend && npm install && npm start
```

## Branch strategy

| Branch    | Purpose                      |
|-----------|------------------------------|
| `main`    | Stable, tagged releases      |
| `develop` | Integration branch           |
| `feat/*`  | Feature branches             |
| `fix/*`   | Bug fixes                    |
| `chore/*` | Dependency/config updates    |

## Pull request checklist

- [ ] `PYTHONPATH=. pytest tests/ -v` passes
- [ ] `cd frontend && npm run build` succeeds (no errors)
- [ ] New scanner modules have corresponding unit tests
- [ ] No secrets, API keys, or credentials in code
- [ ] `.env.example` updated if new env vars added
- [ ] `requirements.txt` updated if new packages added

## Code style

- Python: follow PEP 8, use type hints, docstrings on all public functions
- JavaScript: functional React components, hooks, no class components
- SQL: always use SQLAlchemy ORM — no raw SQL strings
- Secrets: environment variables only — never `settings.py` literals

## Adding a new threat intel feed

1. Create `app/workers/scanner/feeds/your_feed.py`
2. Implement `fetch(domain: str) -> list[dict]` returning normalised records
3. Register in `app/workers/scanner/ti_feeds.py`
4. Add API key env var to `.env.example`
5. Write a unit test with a mocked HTTP response

## Questions

Open a GitHub Discussion or reach out via the issue tracker.

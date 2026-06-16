.PHONY: up down logs migrate test lint frontend-build

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f

migrate:
	docker compose exec backend alembic upgrade head

test:
	PYTHONPATH=. pytest tests/ -v

lint:
	ruff check app/

frontend-build:
	cd frontend && npm run build

shell-backend:
	docker compose exec backend bash

shell-db:
	docker compose exec db psql -U dimp dimp

generate-secret:
	@openssl rand -hex 32

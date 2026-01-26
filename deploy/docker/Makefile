# =============================================================================
# RedOPS Docker Makefile
# =============================================================================

.PHONY: help build up down restart logs shell test clean

COMPOSE := docker compose
ENV_FILE := .env

# Default target
help:
	@echo "RedOPS Docker Commands"
	@echo "======================"
	@echo ""
	@echo "Basic Commands:"
	@echo "  make build          Build all containers"
	@echo "  make up             Start core services (api, worker, scheduler, db, redis)"
	@echo "  make down           Stop all services"
	@echo "  make restart        Restart all services"
	@echo "  make logs           Follow logs from all services"
	@echo ""
	@echo "Development Commands:"
	@echo "  make dev            Start with dev tools (adminer, redis-commander)"
	@echo "  make observability  Start with observability stack (prometheus, grafana, jaeger)"
	@echo "  make all            Start all services including optional ones"
	@echo ""
	@echo "Utility Commands:"
	@echo "  make shell          Open shell in api container"
	@echo "  make db-shell       Open PostgreSQL shell"
	@echo "  make redis-cli      Open Redis CLI"
	@echo "  make test           Run tests in container"
	@echo "  make migrate        Run database migrations"
	@echo ""
	@echo "Cleanup Commands:"
	@echo "  make clean          Stop and remove containers"
	@echo "  make clean-all      Remove containers, volumes, and images"
	@echo ""

# =============================================================================
# Build
# =============================================================================

build:
	$(COMPOSE) build

build-no-cache:
	$(COMPOSE) build --no-cache

# =============================================================================
# Core Services
# =============================================================================

up:
	$(COMPOSE) up -d api worker scheduler postgres redis
	@echo ""
	@echo "RedOPS is starting..."
	@echo "  API:      http://localhost:$${API_PORT:-8000}"
	@echo "  Health:   http://localhost:$${API_PORT:-8000}/health"
	@echo ""

down:
	$(COMPOSE) down

restart: down up

# =============================================================================
# Development Mode
# =============================================================================

dev:
	$(COMPOSE) --profile dev up -d
	@echo ""
	@echo "RedOPS Dev Mode is starting..."
	@echo "  API:             http://localhost:$${API_PORT:-8000}"
	@echo "  Adminer (DB):    http://localhost:$${ADMINER_PORT:-8080}"
	@echo "  Redis Commander: http://localhost:$${REDIS_COMMANDER_PORT:-8081}"
	@echo ""

# =============================================================================
# Observability Mode
# =============================================================================

observability:
	$(COMPOSE) --profile observability up -d
	@echo ""
	@echo "RedOPS with Observability is starting..."
	@echo "  API:        http://localhost:$${API_PORT:-8000}"
	@echo "  Prometheus: http://localhost:$${PROMETHEUS_PORT:-9090}"
	@echo "  Grafana:    http://localhost:$${GRAFANA_PORT:-3000}"
	@echo "  Jaeger:     http://localhost:$${JAEGER_UI_PORT:-16686}"
	@echo ""

# =============================================================================
# All Services
# =============================================================================

all:
	$(COMPOSE) --profile dev --profile observability up -d
	@echo ""
	@echo "All RedOPS services are starting..."
	@echo ""

# =============================================================================
# Logs
# =============================================================================

logs:
	$(COMPOSE) logs -f

logs-api:
	$(COMPOSE) logs -f api

logs-worker:
	$(COMPOSE) logs -f worker

logs-scheduler:
	$(COMPOSE) logs -f scheduler

# =============================================================================
# Shell Access
# =============================================================================

shell:
	$(COMPOSE) exec api /bin/bash

db-shell:
	$(COMPOSE) exec postgres psql -U redops -d redops

redis-cli:
	$(COMPOSE) exec redis redis-cli

# =============================================================================
# Testing
# =============================================================================

test:
	$(COMPOSE) exec api python -m pytest tests/ -v

test-coverage:
	$(COMPOSE) exec api python -m pytest tests/ --cov=redops --cov-report=html

# =============================================================================
# Database
# =============================================================================

migrate:
	$(COMPOSE) exec api alembic upgrade head

migrate-create:
	@read -p "Migration name: " name; \
	$(COMPOSE) exec api alembic revision --autogenerate -m "$$name"

migrate-rollback:
	$(COMPOSE) exec api alembic downgrade -1

db-reset:
	$(COMPOSE) down -v postgres
	$(COMPOSE) up -d postgres
	@echo "Waiting for PostgreSQL to be ready..."
	@sleep 5
	$(COMPOSE) exec api alembic upgrade head

# =============================================================================
# Health Checks
# =============================================================================

health:
	@echo "Checking service health..."
	@curl -sf http://localhost:$${API_PORT:-8000}/health && echo "API: OK" || echo "API: FAILED"
	@$(COMPOSE) exec -T postgres pg_isready -U redops -d redops && echo "PostgreSQL: OK" || echo "PostgreSQL: FAILED"
	@$(COMPOSE) exec -T redis redis-cli ping | grep -q PONG && echo "Redis: OK" || echo "Redis: FAILED"

# =============================================================================
# Cleanup
# =============================================================================

clean:
	$(COMPOSE) down --remove-orphans

clean-all:
	$(COMPOSE) down -v --remove-orphans --rmi local
	@echo "Removed all containers, volumes, and local images"

prune:
	docker system prune -f
	docker volume prune -f

# =============================================================================
# Status
# =============================================================================

status:
	$(COMPOSE) ps

stats:
	docker stats --no-stream $(shell $(COMPOSE) ps -q)

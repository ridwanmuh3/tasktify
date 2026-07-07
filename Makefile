# =========================
# Tasktify - Workspace Makefile
# =========================

.DEFAULT_GOAL := help

BACKEND_DIR := backend

help:
	@echo "Tasktify workspace targets"
	@echo ""
	@echo "Setup:"
	@echo "  make env              Create backend .env when missing"
	@echo "  make keys             Generate production JWT keys"
	@echo "  make vendor           Vendor Go backend dependencies for Docker"
	@echo ""
	@echo "Run local services:"
	@echo "  make dev              Run DB, auth, todo, gateway"
	@echo "  make backend          Run DB, auth, todo, gateway only"
	@echo "  make dev-api          Run DB, auth, todo, gateway"
	@echo "  make dev-db           Start local PostgreSQL only"
	@echo "  make dev-down         Stop local PostgreSQL"
	@echo "  make gateway          Run gateway locally"
	@echo "  make auth             Run auth-service locally"
	@echo "  make todo             Run todo-service locally"
	@echo ""
	@echo "Compose:"
	@echo "  make up               Start stack"
	@echo "  make up-build         Build images, start stack"
	@echo "  make down             Stop stack"
	@echo "  make clean            Stop stack and remove volumes"
	@echo "  make compose-config   Validate production Compose config"
	@echo "  make bench-config     Validate benchmark Compose config"
	@echo "  make hostinger-bench  Run client k6, upload artifacts, calculate on VPS"
	@echo "  make ps               Show production Compose services"
	@echo "  make logs             Follow all logs"
	@echo "  make logs-gateway     Follow gateway logs"
	@echo "  make logs-auth        Follow auth logs"
	@echo "  make logs-todo        Follow todo logs"
	@echo "  make logs-caddy       Follow Caddy logs"
	@echo ""
	@echo "Build/test:"
	@echo "  make build            Build backend binaries"
	@echo "  make test             Run backend Go tests"
	@echo "  make check            Validate Compose configs"
	@echo "  make falcon-check     Run Falcon KAT/tests and benchmark config checks"

env:
	$(MAKE) -C $(BACKEND_DIR) env

keys keygen:
	$(MAKE) -C $(BACKEND_DIR) keygen

vendor:
	$(MAKE) -C $(BACKEND_DIR) vendor

gateway run-gateway:
	$(MAKE) -C $(BACKEND_DIR) run-gateway

auth run-auth:
	$(MAKE) -C $(BACKEND_DIR) run-auth

todo run-todo:
	$(MAKE) -C $(BACKEND_DIR) run-todo

backend:
	$(MAKE) -C $(BACKEND_DIR) backend

dev dev-api dev-db dev-down:
	$(MAKE) -C $(BACKEND_DIR) $@

up:
	$(MAKE) -C $(BACKEND_DIR) up

up-build:
	$(MAKE) -C $(BACKEND_DIR) up-build

down:
	$(MAKE) -C $(BACKEND_DIR) down

clean:
	$(MAKE) -C $(BACKEND_DIR) clean

compose-config:
	$(MAKE) -C $(BACKEND_DIR) compose-config

bench-config:
	$(MAKE) -C $(BACKEND_DIR) bench-config

ps:
	$(MAKE) -C $(BACKEND_DIR) ps

logs:
	$(MAKE) -C $(BACKEND_DIR) logs

logs-gateway:
	$(MAKE) -C $(BACKEND_DIR) logs-gateway

logs-auth:
	$(MAKE) -C $(BACKEND_DIR) logs-auth

logs-todo:
	$(MAKE) -C $(BACKEND_DIR) logs-todo

logs-caddy:
	$(MAKE) -C $(BACKEND_DIR) logs-caddy

build:
	$(MAKE) -C $(BACKEND_DIR) build

proto compile-proto:
	$(MAKE) -C $(BACKEND_DIR) compile-proto

test:
	$(MAKE) -C $(BACKEND_DIR) test

check:
	$(MAKE) -C $(BACKEND_DIR) check

falcon-kat falcon-check wait-bench:
	$(MAKE) -C $(BACKEND_DIR) $@

bench-up bench-down bench-logs bench-run bench bench-sign bench-sign-remote:
	$(MAKE) -C $(BACKEND_DIR) $@

hostinger-bench-up hostinger-bench-down hostinger-bench-logs hostinger-health:
	$(MAKE) -C $(BACKEND_DIR) $@

client-k6 client-k6-isolated client-k6-stress client-k6-attack:
	$(MAKE) -C $(BACKEND_DIR) $@

hostinger-upload hostinger-calc hostinger-fetch hostinger-bench:
	$(MAKE) -C $(BACKEND_DIR) $@

attack-adversarial attack-adversarial-bench attack-adversarial-remote:
	$(MAKE) -C $(BACKEND_DIR) $@

.PHONY: help env keys keygen vendor gateway run-gateway auth run-auth todo run-todo backend dev dev-api dev-db dev-down up up-build down clean compose-config bench-config ps logs logs-gateway logs-auth logs-todo logs-caddy build proto compile-proto test check falcon-kat falcon-check wait-bench bench-up bench-down bench-logs bench-run bench bench-sign bench-sign-remote hostinger-bench-up hostinger-bench-down hostinger-bench-logs hostinger-health client-k6 client-k6-isolated client-k6-stress client-k6-attack hostinger-upload hostinger-calc hostinger-fetch hostinger-bench attack-adversarial attack-adversarial-bench attack-adversarial-remote

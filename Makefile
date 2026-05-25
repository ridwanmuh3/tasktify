# =========================
# Tasktify - Workspace Makefile
# =========================

.DEFAULT_GOAL := help

BACKEND_DIR := backend
FRONTEND_DIR := frontend

help:
	@echo "Tasktify workspace targets"
	@echo ""
	@echo "Setup:"
	@echo "  make env              Create backend .env when missing"
	@echo "  make install          Install frontend dependencies"
	@echo "  make keys             Generate production JWT keys"
	@echo "  make vendor           Vendor Go backend dependencies for Docker"
	@echo ""
	@echo "Run local services:"
	@echo "  make gateway          Run gateway locally"
	@echo "  make auth             Run auth-service locally"
	@echo "  make todo             Run todo-service locally"
	@echo "  make frontend         Run Svelte dev server"
	@echo ""
	@echo "Compose:"
	@echo "  make up               Build frontend, start stack"
	@echo "  make up-build         Build images, build frontend, start stack"
	@echo "  make down             Stop stack"
	@echo "  make clean            Stop stack and remove volumes"
	@echo "  make compose-config   Validate production Compose config"
	@echo "  make bench-config     Validate benchmark Compose config"
	@echo "  make ps               Show production Compose services"
	@echo "  make logs             Follow all logs"
	@echo "  make logs-gateway     Follow gateway logs"
	@echo "  make logs-auth        Follow auth logs"
	@echo "  make logs-todo        Follow todo logs"
	@echo "  make logs-caddy       Follow Caddy logs"
	@echo ""
	@echo "Build/test:"
	@echo "  make build            Build backend binaries"
	@echo "  make build-frontend   Build frontend dist"
	@echo "  make test             Run backend Go tests"
	@echo "  make check            Run frontend check and Compose config validation"

env:
	$(MAKE) -C $(BACKEND_DIR) env

install:
	$(MAKE) -C $(BACKEND_DIR) frontend-install

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

frontend run-frontend:
	$(MAKE) -C $(BACKEND_DIR) run-frontend

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

build-frontend:
	$(MAKE) -C $(BACKEND_DIR) build-frontend

proto compile-proto:
	$(MAKE) -C $(BACKEND_DIR) compile-proto

test:
	$(MAKE) -C $(BACKEND_DIR) test

check:
	$(MAKE) -C $(BACKEND_DIR) check

bench-up bench-down bench-logs bench-run bench bench-sign bench-sign-remote:
	$(MAKE) -C $(BACKEND_DIR) $@

attack-adversarial attack-adversarial-bench attack-adversarial-remote:
	$(MAKE) -C $(BACKEND_DIR) $@

.PHONY: help env install keys keygen vendor gateway run-gateway auth run-auth todo run-todo frontend run-frontend up up-build down clean compose-config bench-config ps logs logs-gateway logs-auth logs-todo logs-caddy build build-frontend proto compile-proto test check bench-up bench-down bench-logs bench-run bench bench-sign bench-sign-remote attack-adversarial attack-adversarial-bench attack-adversarial-remote

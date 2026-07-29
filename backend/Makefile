# =========================
# Tasktify - Backend Makefile
# =========================

.DEFAULT_GOAL := help

COMPOSE_PROJECT_NAME ?= tasktify
COMPOSE = docker compose -p $(COMPOSE_PROJECT_NAME) -f docker-compose.yml
DEV_COMPOSE = docker compose -p $(COMPOSE_PROJECT_NAME)-dev -f docker-compose.yml -f docker-compose.dev.yml
GOCACHE ?= /tmp/go-build-cache
LOCAL_GO_ENV = env APP_MODE=dev GOCACHE=$(GOCACHE) CGO_ENABLED=0

help:
	@echo "Tasktify backend targets"
	@echo ""
	@echo "Local services:"
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
	@echo "  make ps               Show production Compose services"
	@echo "  make logs-*           Follow logs for gateway/auth/todo/caddy"
	@echo ""
	@echo "Maintenance:"
	@echo "  make env              Create .env from .env.example when missing"
	@echo "  make keygen           Generate production JWT keys"
	@echo "  make compile-proto    Regenerate protobuf files"
	@echo "  make vendor           Vendor Go dependencies"
	@echo "  make tidy             Tidy Go modules"
	@echo "  make test             Run Go tests"
	@echo "  make check            Validate Compose configs"
	@echo "  make fndsa-kat        Run FN-DSA known-answer tests"
	@echo "  make adversarial-kat  FN-DSA KAT + adversarial rejection gate"
	@echo "  make fndsa-check      Full correctness/security gate + Compose config"

env:
	@test -f .env || cp .env.example .env

# --- Key Generation ---
# keygen: generate FN-DSA JWT keys ke auth-service/keys dan copy ke gateway/keys (production)
keygen:
	mkdir -p auth-service/keys gateway/keys
	cd cmd/keygen && go run main.go ../../auth-service/keys
	cp -r auth-service/keys/. gateway/keys/

ensure-keys:
	@if [ ! -f auth-service/keys/FNDSA-512_sk.pem ] || [ ! -f gateway/keys/FNDSA-512_pk.pem ]; then \
		$(MAKE) keygen; \
	else \
		echo "Production keys present"; \
	fi

# --- Proto Compilation ---
compile-proto:
	cd auth-service && protoc --go_out . --go-grpc_out . proto/*.proto
	cd todo-service && protoc --go_out . --go-grpc_out . proto/*.proto
	cp auth-service/proto/auth.proto auth-service/proto/user.proto gateway/proto/
	cp todo-service/proto/task.proto gateway/proto/
	cd gateway && protoc --go_out . --go-grpc_out . proto/*.proto

# --- Docker Compose ---
up: env ensure-keys ensure-vendor
	$(COMPOSE) up -d

up-build: env ensure-keys ensure-vendor
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down

clean:
	$(COMPOSE) down -v

compose-config:
	$(COMPOSE) config

ps:
	$(COMPOSE) ps

logs:
	$(COMPOSE) logs -f

logs-gateway:
	$(COMPOSE) logs -f gateway

logs-auth:
	$(COMPOSE) logs -f auth-service

logs-todo:
	$(COMPOSE) logs -f todo-service

logs-caddy:
	$(COMPOSE) logs -f caddy

# --- Production Deploy ---
deploy: env ensure-keys ensure-vendor
	$(COMPOSE) up -d --build

# --- Local Development ---
dev-db: env
	$(DEV_COMPOSE) up -d postgres

dev-down:
	$(DEV_COMPOSE) down

dev: env ensure-keys dev-db
	@echo "Local dev running:"
	@echo "  gateway  http://localhost:3000"
	@echo "Stop with Ctrl+C. Stop DB with: make dev-down"
	$(MAKE) -j3 run-auth run-todo run-gateway

backend: dev-api

dev-api: env ensure-keys dev-db
	@echo "Local API running:"
	@echo "  gateway http://localhost:3000"
	@echo "Stop with Ctrl+C. Stop DB with: make dev-down"
	$(MAKE) -j3 run-auth run-todo run-gateway

run-gateway:
	cd gateway && $(LOCAL_GO_ENV) go run ./cmd/app/main.go

gateway: run-gateway

run-auth:
	cd auth-service && $(LOCAL_GO_ENV) GRPC_PORT=3001 go run ./cmd/app/main.go

auth: run-auth

run-todo:
	cd todo-service && $(LOCAL_GO_ENV) GRPC_PORT=3002 go run ./cmd/app/main.go

todo: run-todo

# --- Build ---
build:
	cd gateway && go build -o ../bin/gateway ./cmd/app/main.go
	cd auth-service && go build -o ../bin/auth-service ./cmd/app/main.go
	cd todo-service && go build -o ../bin/todo-service ./cmd/app/main.go

# --- Tidy ---
tidy:
	cd pkg && go mod tidy
	cd gateway && go mod tidy
	cd auth-service && go mod tidy
	cd todo-service && go mod tidy

# --- Vendor (required before docker build) ---
vendor:
	cd auth-service && go mod vendor
	cd gateway && go mod vendor
	cd todo-service && go mod vendor

ensure-vendor:
	@if [ ! -f auth-service/vendor/modules.txt ] || [ ! -f gateway/vendor/modules.txt ] || [ ! -f todo-service/vendor/modules.txt ]; then \
		$(MAKE) vendor; \
	else \
		echo "Vendor directories present"; \
	fi

# --- Test ---
test:
	cd gateway && env GOCACHE=$(GOCACHE) go test ./...
	cd auth-service && env GOCACHE=$(GOCACHE) go test ./...
	cd todo-service && env GOCACHE=$(GOCACHE) go test ./...
	cd cmd/keygen && env GOCACHE=$(GOCACHE) go test ./...
	cd pkg && env GOCACHE=$(GOCACHE) go test ./utils/jwtutils
	$(MAKE) test-race

# Race detector on the concurrency-sensitive crypto/JWT packages: the
# precomputed signer is shared global state signed from many goroutines.
test-race:
	cd pkg && env GOCACHE=$(GOCACHE) go test -race ./fndsa ./jwt ./utils/jwtutils

fndsa-kat:
	cd pkg && env GOCACHE=$(GOCACHE) go test ./fndsa -run 'TestFNDSA_(Precomputed_)?KAT$$'

# FN-DSA correctness/security gate: known-answer vectors (dynamic + precomputed)
# plus adversarial attack rejection (forgery, tampering, domain/prehash confusion,
# truncation, norm-bound). Pass/fail only — proves precomputation preserves KAT
# conformance and attack rejection.
adversarial-kat:
	cd pkg && env GOCACHE=$(GOCACHE) go test ./fndsa \
		-run '^(TestFNDSA_KAT|TestFNDSA_Precomputed_KAT|TestAttack_.*|TestPrecomputedSignRejectsTampering)$$' \
		-count=1 -v

fndsa-check: fndsa-kat adversarial-kat
	cd pkg && env GOCACHE=$(GOCACHE) go test ./fndsa ./jwt ./utils/jwtutils
	cd cmd/keygen && env GOCACHE=$(GOCACHE) go test ./...
	cd auth-service && env GOCACHE=$(GOCACHE) go test ./internal/config
	cd gateway && env GOCACHE=$(GOCACHE) go test ./internal/config
	$(COMPOSE) config >/dev/null

check:
	$(COMPOSE) config >/dev/null
	$(DEV_COMPOSE) config >/dev/null

.PHONY: help env keygen ensure-keys compile-proto up up-build down clean compose-config ps logs logs-gateway logs-auth logs-todo logs-caddy deploy dev-db dev-down dev backend dev-api run-gateway gateway run-auth auth run-todo todo build tidy vendor ensure-vendor test test-race fndsa-kat adversarial-kat fndsa-check check

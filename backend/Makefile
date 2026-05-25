# =========================
# Tasktify - Backend Makefile
# =========================

.DEFAULT_GOAL := help

COMPOSE_PROJECT_NAME ?= tasktify
BENCH_COMPOSE_PROJECT_NAME ?= tasktify-bench
COMPOSE = docker compose -p $(COMPOSE_PROJECT_NAME) -f docker-compose.yml
BENCH_COMPOSE = docker compose -p $(BENCH_COMPOSE_PROJECT_NAME) -f docker-compose.benchmark.yml
FRONTEND_DIR ?= ../frontend
NPM ?= npm
ATTACK_BASE_URL ?= http://localhost:5001
ATTACK_ITERATIONS ?= 10
ATTACK_ALGORITHM ?= Falcon-Precomputed-512

help:
	@echo "Tasktify backend targets"
	@echo ""
	@echo "Local services:"
	@echo "  make gateway          Run gateway locally"
	@echo "  make auth             Run auth-service locally"
	@echo "  make todo             Run todo-service locally"
	@echo "  make frontend         Run Svelte dev server from ../frontend"
	@echo ""
	@echo "Compose:"
	@echo "  make up               Build frontend, start stack"
	@echo "  make up-build         Build images, build frontend, start stack"
	@echo "  make down             Stop stack"
	@echo "  make clean            Stop stack and remove volumes"
	@echo "  make compose-config   Validate production Compose config"
	@echo "  make bench-config     Validate benchmark Compose config"
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
	@echo "  make check            Run frontend check and Compose config validation"

env:
	@test -f .env || cp .env.example .env

# --- Key Generation ---
# keygen: generate semua keys ke auth-service/keys dan copy ke gateway/keys (production)
keygen:
	mkdir -p auth-service/keys gateway/keys
	cd cmd/keygen && go run main.go ../../auth-service/keys
	cp -r auth-service/keys/. gateway/keys/

# keygen-all: generate semua keys ke ./keys untuk benchmark (shared oleh semua service)
keygen-all:
	mkdir -p keys
	cd cmd/keygen && go run main.go ../../keys

ensure-keys:
	@if [ ! -f auth-service/keys/FNDSA-512_sk.pem ] || [ ! -f gateway/keys/FNDSA-512_pk.pem ]; then \
		$(MAKE) keygen; \
	else \
		echo "Production keys present"; \
	fi

ensure-bench-keys:
	@if [ ! -f keys/FNDSA-512_sk.pem ]; then \
		$(MAKE) keygen-all; \
	else \
		echo "Benchmark keys present"; \
	fi

# --- Proto Compilation ---
compile-proto:
	cd auth-service && protoc --go_out . --go-grpc_out . proto/*.proto
	cd todo-service && protoc --go_out . --go-grpc_out . proto/*.proto
	cp auth-service/proto/auth.proto auth-service/proto/user.proto gateway/proto/
	cp todo-service/proto/task.proto gateway/proto/
	cd gateway && protoc --go_out . --go-grpc_out . proto/*.proto

# --- Docker Compose ---
up: env ensure-keys ensure-vendor build-frontend
	$(COMPOSE) up -d

up-build: env ensure-keys ensure-vendor build-frontend
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
deploy: env ensure-keys ensure-vendor build-frontend
	$(COMPOSE) up -d --build

# --- Local Development ---
run-gateway:
	cd gateway && APP_MODE=dev go run ./cmd/app/main.go

gateway: run-gateway

run-auth:
	cd auth-service && APP_MODE=dev go run ./cmd/app/main.go

auth: run-auth

run-todo:
	cd todo-service && APP_MODE=dev go run ./cmd/app/main.go

todo: run-todo

run-frontend:
	cd $(FRONTEND_DIR) && $(NPM) run dev

frontend: run-frontend

# --- Build ---
build:
	cd gateway && go build -o ../bin/gateway ./cmd/app/main.go
	cd auth-service && go build -o ../bin/auth-service ./cmd/app/main.go
	cd todo-service && go build -o ../bin/todo-service ./cmd/app/main.go

build-frontend: frontend-install
	cd $(FRONTEND_DIR) && $(NPM) run build

frontend-install:
	cd $(FRONTEND_DIR) && $(NPM) ci

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
	cd gateway && env GOCACHE=/tmp/go-build-cache go test ./...
	cd auth-service && env GOCACHE=/tmp/go-build-cache go test ./...
	cd todo-service && env GOCACHE=/tmp/go-build-cache go test ./...
	cd cmd/keygen && env GOCACHE=/tmp/go-build-cache go test ./...
	cd pkg && env GOCACHE=/tmp/go-build-cache go test ./utils/jwtutils

check:
	cd $(FRONTEND_DIR) && $(NPM) run check
	$(COMPOSE) config >/dev/null
	$(BENCH_COMPOSE) config >/dev/null

# --- Benchmark ---
bench-up: ensure-bench-keys ensure-vendor
	$(BENCH_COMPOSE) up -d --build

bench-down:
	$(BENCH_COMPOSE) down -v

bench-logs:
	$(BENCH_COMPOSE) logs -f

bench-config:
	$(BENCH_COMPOSE) config

bench-run:
	k6 run -e BENCH_HOST=localhost k6/benchmark_sign.js

# keygen-all + vendor + bench-up + jalankan k6
bench: bench-up
	@echo "Menunggu bench-gw-fnp512 (port 5001) siap..."
	@until curl -sf http://localhost:5001/ > /dev/null 2>&1; do \
		printf "."; sleep 3; \
	done
	@echo " ready!"
	k6 run -e BENCH_HOST=localhost k6/benchmark_sign.js

bench-sign: bench-up
	@echo "Menunggu bench-gw-fnp512 (port 5001) siap..."
	@until curl -sf http://localhost:5001/ > /dev/null 2>&1; do \
		printf "."; sleep 3; \
	done
	@echo " ready!"
	k6 run --no-color -e BENCH_HOST=localhost k6/benchmark_sign.js 2>&1 | tee result.txt

bench-sign-remote:
	k6 run --no-color -e BASE_URL=https://poc-ridwanmuh3.my.id k6/benchmark_sign.js 2>&1 | tee result.txt

# --- Adversarial Attack Test ---
attack-adversarial:
	k6 run --no-color \
		-e BASE_URL=$(ATTACK_BASE_URL) \
		-e ITERATIONS=$(ATTACK_ITERATIONS) \
		-e ALGORITHM=$(ATTACK_ALGORITHM) \
		k6/adversarial_jwt.js

attack-adversarial-bench: bench-up
	@echo "Menunggu bench-gw-fnp512 (port 5001) siap..."
	@until curl -sf http://localhost:5001/ > /dev/null 2>&1; do \
		printf "."; sleep 3; \
	done
	@echo " ready!"
	k6 run --no-color \
		-e BENCH_HOST=localhost \
		-e ITERATIONS=$(ATTACK_ITERATIONS) \
		-e ALGORITHM=$(ATTACK_ALGORITHM) \
		k6/adversarial_jwt.js

attack-adversarial-remote:
	k6 run --no-color \
		-e BASE_URL=https://poc-ridwanmuh3.my.id \
		-e ITERATIONS=$(ATTACK_ITERATIONS) \
		-e ALGORITHM=$(ATTACK_ALGORITHM) \
		k6/adversarial_jwt.js

.PHONY: help env keygen keygen-all ensure-keys ensure-bench-keys compile-proto up up-build down clean compose-config ps logs logs-gateway logs-auth logs-todo logs-caddy deploy run-gateway gateway run-auth auth run-todo todo run-frontend frontend build build-frontend frontend-install tidy vendor ensure-vendor test check bench-up bench-down bench-logs bench-config bench-run bench bench-sign bench-sign-remote attack-adversarial attack-adversarial-bench attack-adversarial-remote

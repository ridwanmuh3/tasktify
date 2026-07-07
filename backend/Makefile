# =========================
# Tasktify - Backend Makefile
# =========================

.DEFAULT_GOAL := help

COMPOSE_PROJECT_NAME ?= tasktify
BENCH_COMPOSE_PROJECT_NAME ?= tasktify-bench
COMPOSE = docker compose -p $(COMPOSE_PROJECT_NAME) -f docker-compose.yml
DEV_COMPOSE = docker compose -p $(COMPOSE_PROJECT_NAME)-dev -f docker-compose.yml -f docker-compose.dev.yml
BENCH_COMPOSE = docker compose -p $(BENCH_COMPOSE_PROJECT_NAME) -f docker-compose.benchmark.yml
FRONTEND_DIR ?= ../frontend
NPM ?= npm
GOCACHE ?= /tmp/go-build-cache
ATTACK_BASE_URL ?= http://localhost:5001
ATTACK_ITERATIONS ?= 10
ATTACK_ALGORITHM ?= Falcon-Precomputed-512
BENCH_SAMPLE_OUT ?= benchmark_sign_samples.ndjson
BENCH_RESULT_OUT ?= benchmark_sign_result.json
BENCH_RAW_OUT ?= benchmark_sign_raw.json
BENCH_STDOUT_OUT ?= result.txt
BENCH_STAT_OUT ?= benchmark_stats.md
BENCH_WELCH_OUT ?= benchmark_welch.md
BENCH_ABLATION_OUT ?= fndsa_precompute_ablation.csv
BENCH_PORTS ?= 5001 5002
BASE_URL ?= https://poc-ridwanmuh3.my.id
VPS_SSH ?=
VPS_REPO ?= ~/tasktify
VPS_BACKEND ?= $(VPS_REPO)/backend
SSH ?= ssh
SCP ?= scp
SSH_OPTS ?=
K6 ?= k6
LOCAL_GO_ENV = env APP_MODE=dev GOCACHE=$(GOCACHE) CGO_ENABLED=0

help:
	@echo "Tasktify backend targets"
	@echo ""
	@echo "Local services:"
	@echo "  make dev              Run DB, auth, todo, gateway, frontend"
	@echo "  make backend          Run DB, auth, todo, gateway only"
	@echo "  make dev-api          Run DB, auth, todo, gateway"
	@echo "  make dev-db           Start local PostgreSQL only"
	@echo "  make dev-down         Stop local PostgreSQL"
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
	@echo "  make falcon-check     Run Falcon KAT/tests and benchmark config checks"
	@echo ""
	@echo "Split benchmark:"
	@echo "  make hostinger-bench-up VPS_SSH=user@host  Start benchmark stack on VPS"
	@echo "  make client-k6 BASE_URL=https://host       Run k6 from client"
	@echo "  make hostinger-upload VPS_SSH=user@host    Upload k6 artifacts to VPS"
	@echo "  make hostinger-calc VPS_SSH=user@host      Calculate stats on VPS"
	@echo "  make hostinger-bench VPS_SSH=user@host     Run client k6 + VPS calc"

env:
	@test -f .env || cp .env.example .env

# --- Key Generation ---
# keygen: generate Falcon JWT keys ke auth-service/keys dan copy ke gateway/keys (production)
keygen:
	mkdir -p auth-service/keys gateway/keys
	cd cmd/keygen && go run main.go ../../auth-service/keys
	cp -r auth-service/keys/. gateway/keys/

# keygen-all: generate Falcon JWT keys ke ./keys untuk benchmark (shared oleh semua service)
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
dev-db: env
	$(DEV_COMPOSE) up -d postgres

dev-down:
	$(DEV_COMPOSE) down

dev: env ensure-keys dev-db frontend-install
	@echo "Local dev running:"
	@echo "  frontend http://localhost:5173"
	@echo "  gateway  http://localhost:3000"
	@echo "Stop with Ctrl+C. Stop DB with: make dev-down"
	$(MAKE) -j4 run-auth run-todo run-gateway run-frontend

backend: dev-api

dev-api: env ensure-keys dev-db
	@echo "Local API running:"
	@echo "  gateway http://localhost:3000"
	@echo "Keep frontend in another terminal: cd ../frontend && npm run dev"
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

falcon-kat:
	cd pkg && env GOCACHE=$(GOCACHE) go test ./fndsa -run 'TestFNDSA_(Precomputed_)?KAT$$'

falcon-check: require-k6 falcon-kat
	cd pkg && env GOCACHE=$(GOCACHE) go test ./fndsa ./jwt ./utils/jwtutils
	cd cmd/keygen && env GOCACHE=$(GOCACHE) go test ./...
	cd auth-service && env GOCACHE=$(GOCACHE) go test ./internal/config
	cd gateway && env GOCACHE=$(GOCACHE) go test ./internal/config
	$(BENCH_COMPOSE) config >/dev/null
	$(K6) inspect k6/benchmark_sign.js >/dev/null
	$(K6) inspect k6/adversarial_jwt.js >/dev/null

check:
	cd $(FRONTEND_DIR) && $(NPM) run check
	$(COMPOSE) config >/dev/null
	$(DEV_COMPOSE) config >/dev/null
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

wait-bench:
	@for port in $(BENCH_PORTS); do \
		echo "Menunggu gateway benchmark port $$port..."; \
		until curl -sf http://localhost:$$port/ > /dev/null 2>&1; do \
			printf "."; sleep 3; \
		done; \
		echo " ready"; \
	done

bench-run:
	$(K6) run --out json=$(BENCH_SAMPLE_OUT) -e BENCH_HOST=localhost k6/benchmark_sign.js

# keygen-all + vendor + bench-up + jalankan k6
bench: bench-up wait-bench
	$(K6) run --out json=$(BENCH_SAMPLE_OUT) -e BENCH_HOST=localhost k6/benchmark_sign.js

bench-sign: bench-up wait-bench
	$(K6) run --no-color --out json=$(BENCH_SAMPLE_OUT) -e BENCH_HOST=localhost k6/benchmark_sign.js 2>&1 | tee $(BENCH_STDOUT_OUT)

bench-sign-remote:
	$(K6) run --no-color --out json=$(BENCH_SAMPLE_OUT) -e BASE_URL=$(BASE_URL) k6/benchmark_sign.js 2>&1 | tee $(BENCH_STDOUT_OUT)

require-vps:
	@test -n "$(VPS_SSH)" || (echo "Set VPS_SSH=user@hostinger-host"; exit 2)

require-k6:
	@command -v $(K6) >/dev/null || (echo "k6 not found"; exit 2)

hostinger-bench-up: require-vps
	$(SSH) $(SSH_OPTS) $(VPS_SSH) 'cd $(VPS_BACKEND) && make bench-up'

hostinger-bench-down: require-vps
	$(SSH) $(SSH_OPTS) $(VPS_SSH) 'cd $(VPS_BACKEND) && make bench-down'

hostinger-bench-logs: require-vps
	$(SSH) $(SSH_OPTS) $(VPS_SSH) 'cd $(VPS_BACKEND) && make bench-logs'

hostinger-health: require-vps
	$(SSH) $(SSH_OPTS) $(VPS_SSH) 'cd $(VPS_BACKEND) && $(BENCH_COMPOSE) ps'
	@curl -fsS "$(BASE_URL)/health" >/dev/null && echo "HTTP OK: $(BASE_URL)/health"

client-k6: require-k6
	$(K6) run --no-color --out json=$(BENCH_SAMPLE_OUT) -e BASE_URL=$(BASE_URL) k6/benchmark_sign.js 2>&1 | tee $(BENCH_STDOUT_OUT)

client-k6-isolated: require-k6
	$(K6) run --no-color --out json=$(BENCH_SAMPLE_OUT) -e BASE_URL=$(BASE_URL) -e ISOLATED_ONLY=true k6/benchmark_sign.js 2>&1 | tee $(BENCH_STDOUT_OUT)

client-k6-stress: require-k6
	$(K6) run --no-color --out json=$(BENCH_SAMPLE_OUT) -e BASE_URL=$(BASE_URL) -e STRESS_ONLY=true k6/benchmark_sign.js 2>&1 | tee $(BENCH_STDOUT_OUT)

client-k6-attack: require-k6
	$(K6) run --no-color --out json=$(BENCH_SAMPLE_OUT) -e BASE_URL=$(BASE_URL) -e ATTACK_ONLY=true k6/benchmark_sign.js 2>&1 | tee $(BENCH_STDOUT_OUT)

hostinger-upload: require-vps
	@test -f $(BENCH_RESULT_OUT) || (echo "Missing $(BENCH_RESULT_OUT). Run make client-k6 first."; exit 2)
	@test -f $(BENCH_RAW_OUT) || (echo "Missing $(BENCH_RAW_OUT). Run make client-k6 first."; exit 2)
	@test -f $(BENCH_SAMPLE_OUT) || (echo "Missing $(BENCH_SAMPLE_OUT). Run make client-k6 first."; exit 2)
	$(SCP) $(SSH_OPTS) $(BENCH_RESULT_OUT) $(BENCH_RAW_OUT) $(BENCH_SAMPLE_OUT) $(BENCH_STDOUT_OUT) $(VPS_SSH):$(VPS_BACKEND)/

hostinger-calc: require-vps
	$(SSH) $(SSH_OPTS) $(VPS_SSH) 'cd $(VPS_REPO) && python3 scripts/benchmark_stat_tests.py --input backend/$(BENCH_RESULT_OUT) --samples backend/$(BENCH_SAMPLE_OUT) > backend/$(BENCH_STAT_OUT)'
	$(SSH) $(SSH_OPTS) $(VPS_SSH) 'cd $(VPS_REPO) && python3 scripts/benchmark_welch_all_baselines.py --input backend/$(BENCH_RESULT_OUT) --samples backend/$(BENCH_SAMPLE_OUT) > backend/$(BENCH_WELCH_OUT)'
	$(SSH) $(SSH_OPTS) $(VPS_SSH) 'cd $(VPS_REPO) && python3 scripts/fndsa_precompute_ablation.py --format csv > backend/$(BENCH_ABLATION_OUT)'

hostinger-fetch: require-vps
	$(SCP) $(SSH_OPTS) $(VPS_SSH):$(VPS_BACKEND)/$(BENCH_STAT_OUT) .
	$(SCP) $(SSH_OPTS) $(VPS_SSH):$(VPS_BACKEND)/$(BENCH_WELCH_OUT) .
	$(SCP) $(SSH_OPTS) $(VPS_SSH):$(VPS_BACKEND)/$(BENCH_ABLATION_OUT) .

hostinger-bench:
	$(MAKE) client-k6
	$(MAKE) hostinger-upload
	$(MAKE) hostinger-calc
	$(MAKE) hostinger-fetch

# --- Adversarial Attack Test ---
attack-adversarial:
	$(K6) run --no-color \
		-e BASE_URL=$(ATTACK_BASE_URL) \
		-e ITERATIONS=$(ATTACK_ITERATIONS) \
		-e ALGORITHM=$(ATTACK_ALGORITHM) \
		k6/adversarial_jwt.js

attack-adversarial-bench: bench-up wait-bench
	$(K6) run --no-color \
		-e BENCH_HOST=localhost \
		-e ITERATIONS=$(ATTACK_ITERATIONS) \
		-e ALGORITHM=$(ATTACK_ALGORITHM) \
		k6/adversarial_jwt.js

attack-adversarial-remote:
	$(K6) run --no-color \
		-e BASE_URL=https://poc-ridwanmuh3.my.id \
		-e ITERATIONS=$(ATTACK_ITERATIONS) \
		-e ALGORITHM=$(ATTACK_ALGORITHM) \
		k6/adversarial_jwt.js

.PHONY: help env keygen keygen-all ensure-keys ensure-bench-keys compile-proto up up-build down clean compose-config ps logs logs-gateway logs-auth logs-todo logs-caddy deploy dev-db dev-down dev backend run-gateway gateway run-auth auth run-todo todo run-frontend frontend build build-frontend frontend-install tidy vendor ensure-vendor test falcon-kat falcon-check check bench-up bench-down bench-logs bench-config wait-bench bench-run bench bench-sign bench-sign-remote require-vps require-k6 hostinger-bench-up hostinger-bench-down hostinger-bench-logs hostinger-health client-k6 client-k6-isolated client-k6-stress client-k6-attack hostinger-upload hostinger-calc hostinger-fetch hostinger-bench attack-adversarial attack-adversarial-bench attack-adversarial-remote

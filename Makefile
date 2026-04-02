# =========================
# Tasktify - Root Makefile
# =========================

COMPOSE = docker compose

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

# --- Proto Compilation ---
compile-proto:
	cd auth-service && protoc --go_out . --go-grpc_out . proto/*.proto
	cd todo-service && protoc --go_out . --go-grpc_out . proto/*.proto
	cp auth-service/proto/auth.proto auth-service/proto/user.proto gateway/proto/
	cp todo-service/proto/task.proto gateway/proto/
	cd gateway && protoc --go_out . --go-grpc_out . proto/*.proto

# --- Docker Compose ---
up:
	$(COMPOSE) up -d

up-build:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down

clean:
	$(COMPOSE) down -v

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
deploy: vendor
	$(COMPOSE) up -d --build

# --- Local Development ---
run-gateway:
	cd gateway && APP_MODE=dev go run ./cmd/app/main.go

run-auth:
	cd auth-service && APP_MODE=dev go run ./cmd/app/main.go

run-todo:
	cd todo-service && APP_MODE=dev go run ./cmd/app/main.go

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

# --- Benchmark ---
bench-up: vendor
	$(COMPOSE) -f docker-compose.benchmark.yml up -d --build

bench-down:
	$(COMPOSE) -f docker-compose.benchmark.yml down -v

bench-logs:
	$(COMPOSE) -f docker-compose.benchmark.yml logs -f

bench-run:
	k6 run -e BENCH_HOST=localhost k6/benchmark_compare.js

# keygen-all + vendor + bench-up + jalankan k6
bench: keygen-all vendor bench-up
	@echo "Menunggu bench-gw-fnp512 (port 5001) siap..."
	@until curl -sf http://localhost:5001/ > /dev/null 2>&1; do \
		printf "."; sleep 3; \
	done
	@echo " ready!"
	k6 run -e BENCH_HOST=localhost k6/benchmark_compare.js

.PHONY: keygen keygen-all compile-proto up up-build down clean logs logs-gateway logs-auth logs-todo logs-caddy deploy run-gateway run-auth run-todo build tidy vendor bench-up bench-down bench-logs bench-run bench

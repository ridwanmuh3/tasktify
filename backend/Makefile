# =========================
# Tasktify - Backend Makefile
# =========================

.DEFAULT_GOAL := help

COMPOSE_PROJECT_NAME ?= tasktify
BENCH_COMPOSE_PROJECT_NAME ?= tasktify-bench
COMPOSE = docker compose -p $(COMPOSE_PROJECT_NAME) -f docker-compose.yml
DEV_COMPOSE = docker compose -p $(COMPOSE_PROJECT_NAME)-dev -f docker-compose.yml -f docker-compose.dev.yml
BENCH_COMPOSE = docker compose -p $(BENCH_COMPOSE_PROJECT_NAME) -f docker-compose.benchmark.yml
GOCACHE ?= /tmp/go-build-cache
ATTACK_BASE_URL ?= http://localhost:5001
ATTACK_ITERATIONS ?= 10
ATTACK_ALGORITHM ?= FN-DSA-Precomputed-512
# FN-DSA profiles swept side-by-side by attack-adversarial-compare. Space
# separated; each runs the full attack set against its own gateway port.
COMPARE_ATTACK_ALGS ?= FN-DSA-Precomputed-512 FN-DSA-512
COMPARE_BENCH_HOST ?= localhost
BENCH_OUTPUT_DIR ?= benchmark-results
BENCH_SAMPLE_OUT ?= $(BENCH_OUTPUT_DIR)/benchmark_sign_samples.ndjson
BENCH_RESULT_OUT ?= $(BENCH_OUTPUT_DIR)/benchmark_sign_result.json
BENCH_RAW_OUT ?= $(BENCH_OUTPUT_DIR)/benchmark_sign_raw.json
BENCH_STDOUT_OUT ?= $(BENCH_OUTPUT_DIR)/result.txt
BENCH_STAT_OUT ?= $(BENCH_OUTPUT_DIR)/benchmark_stats.json
BENCH_WELCH_OUT ?= $(BENCH_OUTPUT_DIR)/benchmark_welch.json
BENCH_ABLATION_OUT ?= $(BENCH_OUTPUT_DIR)/fndsa_precompute_ablation.json
# Isolated-process FN-DSA precompute profile (resident expanded-key material +
# dynamic-vs-precomputed sign timing). PROFILE_OUT empty => the Go test writes
# its own default (benchmark-results/fndsa_precompute_profile.json).
BENCH_PROFILE_OUT ?= $(BENCH_OUTPUT_DIR)/fndsa_precompute_profile.json
PROFILE_OUT ?=
# Single benchmark gateway now serves every algorithm (JWT_ALLOWED_ALGS),
# so only one port to wait on (was 5001..5006, one per algorithm).
BENCH_PORTS ?= 5001
BASE_URL ?= https://poc-ridwanmuh3.my.id
VPS_SSH ?= 
VPS_REPO ?= ~/tasktify
VPS_BACKEND ?= $(VPS_REPO)/backend
VPS_HOST ?= $(word 2,$(subst @, ,$(VPS_SSH)))
HOSTINGER_BENCH_HOST ?= $(VPS_HOST)
SSH ?= ssh
SCP ?= scp
SSH_OPTS ?=
SCP_OPTS ?=
K6 ?= k6
BENCH_K6_ENV = -e BENCH_OUTPUT_DIR=$(BENCH_OUTPUT_DIR)
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
	@echo "  make check            Validate Compose configs"
	@echo "  make fndsa-check     Run FN-DSA KAT/tests and benchmark config checks"
	@echo ""
	@echo "Split benchmark:"
	@echo "  make hostinger-bench-up VPS_SSH=user@host  Start benchmark stack on VPS"
	@echo "  make client-k6 BASE_URL=https://host       Run k6 from client"
	@echo "  make hostinger-upload VPS_SSH=root@    Upload k6 artifacts to VPS"
	@echo "  make hostinger-calc VPS_SSH=user@host      Calculate stats on VPS"
	@echo "  make hostinger-bench VPS_SSH=user@host     Run client k6 + VPS calc"
	@echo "  make hostinger-bench-repeat VPS_SSH=user@host HOSTINGER_BENCH_RUNS=10"
	@echo "                                             Repeat hostinger-bench N times,"
	@echo "                                             archive each run, emit JSON index"

env:
	@test -f .env || cp .env.example .env

# --- Key Generation ---
# keygen: generate FN-DSA JWT keys ke auth-service/keys dan copy ke gateway/keys (production)
keygen:
	mkdir -p auth-service/keys gateway/keys
	cd cmd/keygen && go run main.go ../../auth-service/keys
	cp -r auth-service/keys/. gateway/keys/

# keygen-all: generate FN-DSA JWT keys ke ./keys untuk benchmark (shared oleh semua service)
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
	@if [ ! -f keys/FNDSA-512_sk.pem ] || [ ! -f keys/RS256_sk.pem ] || [ ! -f keys/ES256_sk.pem ] || [ ! -f keys/HS256_secret.pem ] || [ ! -f keys/EdDSA_sk.pem ]; then \
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
	cd gateway && env GOCACHE=/tmp/go-build-cache go test ./...
	cd auth-service && env GOCACHE=/tmp/go-build-cache go test ./...
	cd todo-service && env GOCACHE=/tmp/go-build-cache go test ./...
	cd cmd/keygen && env GOCACHE=/tmp/go-build-cache go test ./...
	cd pkg && env GOCACHE=/tmp/go-build-cache go test ./utils/jwtutils
	$(MAKE) test-race

# Race detector on the concurrency-sensitive crypto/JWT packages: the
# precomputed signer is shared global state signed from many goroutines.
test-race:
	cd pkg && env GOCACHE=$(GOCACHE) go test -race ./fndsa ./jwt ./utils/jwtutils

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
	$(COMPOSE) config >/dev/null
	$(DEV_COMPOSE) config >/dev/null
	$(BENCH_COMPOSE) config >/dev/null

# --- Benchmark ---
prepare-bench-output:
	mkdir -p $(BENCH_OUTPUT_DIR)

# Emit one isolated-process FN-DSA precompute profile run (RSS + persistent
# expanded-key bytes + dynamic-vs-precomputed sign timing). Feeds fig_18.
# Host-specific — run on the target VPS for thesis numbers (see
# hostinger-precompute-profile). PROFILE_OUT is resolved against this backend
# dir (works the same whether invoked locally or over SSH); empty => the Go
# test writes its own default. Override to collect per-run files for mean aggregation.
PROFILE_OUT_ABS = $(if $(PROFILE_OUT),$(abspath $(PROFILE_OUT)),)
precompute-profile: prepare-bench-output
	cd pkg && env EMIT_PROFILE=1 GOCACHE=$(GOCACHE) PROFILE_OUT=$(PROFILE_OUT_ABS) \
		go test ./fndsa -run '^TestReportPrecomputeProfile$$' -count=1

# FN-DSA correctness/security gate: known-answer vectors (dynamic + precomputed)
# plus adversarial attack rejection (forgery, tampering, domain/prehash confusion,
# truncation, norm-bound). Pass/fail only — proves precomputation preserves KAT
# conformance and attack rejection. Run on the signer's own host (the VPS for
# thesis runs — see hostinger-adversarial-kat), not the client.
adversarial-kat:
	cd pkg && env GOCACHE=$(GOCACHE) go test ./fndsa \
		-run '^(TestFNDSA_KAT|TestFNDSA_Precomputed_KAT|TestAttack_.*|TestPrecomputedSignRejectsTampering)$$' \
		-count=1 -v

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

bench-run: prepare-bench-output
	$(K6) run --out json=$(BENCH_SAMPLE_OUT) $(BENCH_K6_ENV) -e BENCH_HOST=localhost k6/benchmark_sign.js

# keygen-all + vendor + bench-up + jalankan k6
bench: bench-up wait-bench prepare-bench-output
	$(K6) run --out json=$(BENCH_SAMPLE_OUT) $(BENCH_K6_ENV) -e BENCH_HOST=localhost k6/benchmark_sign.js

bench-sign: bench-up wait-bench prepare-bench-output
	$(K6) run --no-color --out json=$(BENCH_SAMPLE_OUT) $(BENCH_K6_ENV) -e BENCH_HOST=localhost k6/benchmark_sign.js 2>&1 | tee $(BENCH_STDOUT_OUT)

bench-sign-remote: prepare-bench-output
	$(K6) run --no-color --out json=$(BENCH_SAMPLE_OUT) $(BENCH_K6_ENV) -e BASE_URL=$(BASE_URL) k6/benchmark_sign.js 2>&1 | tee $(BENCH_STDOUT_OUT)

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

client-k6: require-k6 prepare-bench-output
	$(K6) run --no-color --out json=$(BENCH_SAMPLE_OUT) $(BENCH_K6_ENV) -e BENCH_HOST=$(BENCH_HOST) -e BASE_URL=$(BASE_URL) k6/benchmark_sign.js 2>&1 | tee $(BENCH_STDOUT_OUT)

client-k6-isolated: require-k6 prepare-bench-output
	$(K6) run --no-color --out json=$(BENCH_SAMPLE_OUT) $(BENCH_K6_ENV) -e BENCH_HOST=$(BENCH_HOST) -e BASE_URL=$(BASE_URL) -e ISOLATED_ONLY=true k6/benchmark_sign.js 2>&1 | tee $(BENCH_STDOUT_OUT)

client-k6-stress: require-k6 prepare-bench-output
	$(K6) run --no-color --out json=$(BENCH_SAMPLE_OUT) $(BENCH_K6_ENV) -e BENCH_HOST=$(BENCH_HOST) -e BASE_URL=$(BASE_URL) -e STRESS_ONLY=true k6/benchmark_sign.js 2>&1 | tee $(BENCH_STDOUT_OUT)

client-k6-attack: require-k6 prepare-bench-output
	$(K6) run --no-color --out json=$(BENCH_SAMPLE_OUT) $(BENCH_K6_ENV) -e BENCH_HOST=$(BENCH_HOST) -e BASE_URL=$(BASE_URL) -e ATTACK_ONLY=true k6/benchmark_sign.js 2>&1 | tee $(BENCH_STDOUT_OUT)

hostinger-upload: require-vps
	@test -f $(BENCH_RESULT_OUT) || (echo "Missing $(BENCH_RESULT_OUT). Run make client-k6 first."; exit 2)
	@test -f $(BENCH_RAW_OUT) || (echo "Missing $(BENCH_RAW_OUT). Run make client-k6 first."; exit 2)
	@test -f $(BENCH_SAMPLE_OUT) || (echo "Missing $(BENCH_SAMPLE_OUT). Run make client-k6 first."; exit 2)
	$(SSH) $(SSH_OPTS) $(VPS_SSH) 'mkdir -p $(VPS_BACKEND)/$(BENCH_OUTPUT_DIR)'
	$(SCP) $(SCP_OPTS) $(BENCH_RESULT_OUT) $(BENCH_RAW_OUT) $(BENCH_SAMPLE_OUT) $(BENCH_STDOUT_OUT) $(VPS_SSH):$(VPS_BACKEND)/$(BENCH_OUTPUT_DIR)/

hostinger-calc: require-vps
	$(SSH) $(SSH_OPTS) $(VPS_SSH) 'mkdir -p $(VPS_BACKEND)/$(BENCH_OUTPUT_DIR)'
	$(SSH) $(SSH_OPTS) $(VPS_SSH) 'cd $(VPS_REPO) && python3 scripts/benchmark_stat_tests.py --input backend/$(BENCH_RESULT_OUT) --samples backend/$(BENCH_SAMPLE_OUT) --format json > backend/$(BENCH_STAT_OUT)'
	$(SSH) $(SSH_OPTS) $(VPS_SSH) 'cd $(VPS_REPO) && python3 scripts/benchmark_welch_all_baselines.py --input backend/$(BENCH_RESULT_OUT) --samples backend/$(BENCH_SAMPLE_OUT) --format json > backend/$(BENCH_WELCH_OUT)'
	$(SSH) $(SSH_OPTS) $(VPS_SSH) 'cd $(VPS_REPO) && python3 scripts/fndsa_precompute_ablation.py --format json > backend/$(BENCH_ABLATION_OUT)'

hostinger-fetch: require-vps prepare-bench-output
	$(SCP) $(SCP_OPTS) $(VPS_SSH):$(VPS_BACKEND)/$(BENCH_STAT_OUT) $(BENCH_OUTPUT_DIR)/
	$(SCP) $(SCP_OPTS) $(VPS_SSH):$(VPS_BACKEND)/$(BENCH_WELCH_OUT) $(BENCH_OUTPUT_DIR)/
	$(SCP) $(SCP_OPTS) $(VPS_SSH):$(VPS_BACKEND)/$(BENCH_ABLATION_OUT) $(BENCH_OUTPUT_DIR)/

# --- Remote Go-test execution (k6 stays on the client; Go tests run on the
# VPS that owns the signer keys, mirroring hostinger-calc's SSH pattern) ---
# Emit one precompute profile run on the VPS. PROFILE_OUT is a VPS-side path
# relative to the VPS backend dir (resolved there via PROFILE_OUT_ABS). Ensure
# its parent dir exists first — the Go test's os.WriteFile won't create it.
hostinger-precompute-profile: require-vps
	$(SSH) $(SSH_OPTS) $(VPS_SSH) 'cd $(VPS_BACKEND) && mkdir -p "$$(dirname "$(PROFILE_OUT)")" && make precompute-profile PROFILE_OUT=$(PROFILE_OUT)'

# Run the FN-DSA KAT + adversarial correctness/security gate on the VPS.
hostinger-adversarial-kat: require-vps
	$(SSH) $(SSH_OPTS) $(VPS_SSH) 'cd $(VPS_BACKEND) && make adversarial-kat'

# Fetch per-run precompute profile files emitted on the VPS back to the client.
hostinger-fetch-profile: require-vps
	mkdir -p $(BENCH_OUTPUT_DIR)/runs
	$(SCP) $(SCP_OPTS) '$(VPS_SSH):$(VPS_BACKEND)/$(BENCH_OUTPUT_DIR)/runs/fndsa_precompute_profile_run_*.json' $(BENCH_OUTPUT_DIR)/runs/

hostinger-bench:
	$(MAKE) client-k6 BENCH_HOST=$(HOSTINGER_BENCH_HOST)
	$(MAKE) hostinger-upload
	$(MAKE) hostinger-calc
	$(MAKE) hostinger-fetch

# Run hostinger-bench N times (default 10) and keep every run.
#
# Why the per-run directory: hostinger-bench writes the same fixed filenames
# every time ($(BENCH_RESULT_OUT) and friends), so an unguarded loop would leave
# only the last run on disk. Each iteration is archived under
# $(HOSTINGER_RUNS_DIR)/run_NN/ before the next one starts.
#
# A failing run does not abort the loop. At ~20 min per run this is a multi-hour
# job, and losing eight good runs because the ninth hit a network blip is worse
# than carrying on; the failure is recorded in the index and the target still
# exits non-zero at the end so CI and the caller see it.
#
#   make hostinger-bench-repeat VPS_SSH=root@host HOSTINGER_BENCH_RUNS=10
HOSTINGER_BENCH_RUNS ?= 10
HOSTINGER_RUNS_DIR ?= $(BENCH_OUTPUT_DIR)/hostinger-runs
HOSTINGER_BENCH_INDEX ?= $(HOSTINGER_RUNS_DIR)/hostinger_bench_index.json
# Artifacts copied out of each run. result.txt is the console report the figure
# scripts parse; the rest are the JSON the stats scripts consume. These are
# deleted before each iteration: hostinger-bench writes fixed filenames, so a
# run that dies midway would otherwise leave the previous run's files in place
# and they would be archived under the failed run's name as if they were its own.
# The k6 sample ndjson is deliberately not archived — it is large and only
# hostinger-calc consumes it, in-run.
HOSTINGER_BENCH_ARTIFACTS = \
	$(BENCH_RESULT_OUT) $(BENCH_RAW_OUT) $(BENCH_STAT_OUT) \
	$(BENCH_WELCH_OUT) $(BENCH_ABLATION_OUT) $(BENCH_STDOUT_OUT)

hostinger-bench-repeat: require-vps require-k6 prepare-bench-output
	@mkdir -p $(HOSTINGER_RUNS_DIR)
	@: > $(HOSTINGER_RUNS_DIR)/.status.tsv
	@for i in $$(seq 1 $(HOSTINGER_BENCH_RUNS)); do \
		run=$$(printf 'run_%02d' $$i); \
		dir=$(HOSTINGER_RUNS_DIR)/$$run; \
		started=$$(date -u +%Y-%m-%dT%H:%M:%SZ); \
		echo "=== hostinger-bench-repeat: $$run ($$i/$(HOSTINGER_BENCH_RUNS)) ==="; \
		rm -rf $$dir && mkdir -p $$dir; \
		rm -f $(HOSTINGER_BENCH_ARTIFACTS); \
		if $(MAKE) hostinger-bench; then status=ok; else status=failed; fi; \
		for f in $(HOSTINGER_BENCH_ARTIFACTS); do \
			[ -f "$$f" ] && cp "$$f" "$$dir/" || true; \
		done; \
		printf '%s\t%s\t%s\t%s\n' "$$run" "$$status" "$$started" \
			"$$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> $(HOSTINGER_RUNS_DIR)/.status.tsv; \
		echo "--- $$run: $$status ---"; \
	done
	@python3 -c 'import json,os,sys,glob; \
d=sys.argv[1]; \
rows=[l.rstrip("\n").split("\t") for l in open(os.path.join(d,".status.tsv")) if l.strip()]; \
runs=[{"run":r[0],"status":r[1],"started_utc":r[2],"finished_utc":r[3], \
"dir":os.path.join(d,r[0]), \
"artifacts":sorted(os.path.basename(p) for p in glob.glob(os.path.join(d,r[0],"*")))} for r in rows]; \
ok=sum(1 for r in runs if r["status"]=="ok"); \
json.dump({"target":"hostinger-bench-repeat","base_url":sys.argv[2], \
"requested_runs":int(sys.argv[3]),"completed_runs":len(runs),"ok_runs":ok, \
"failed_runs":len(runs)-ok,"runs":runs}, open(sys.argv[4],"w"), indent=2); \
print("wrote",sys.argv[4],"-",ok,"ok /",len(runs),"runs")' \
		$(HOSTINGER_RUNS_DIR) "$(BASE_URL)" $(HOSTINGER_BENCH_RUNS) $(HOSTINGER_BENCH_INDEX)
	@rm -f $(HOSTINGER_RUNS_DIR)/.status.tsv
	@failed=$$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["failed_runs"])' $(HOSTINGER_BENCH_INDEX)); \
	test "$$failed" = "0" || (echo "hostinger-bench-repeat: $$failed run(s) failed — see $(HOSTINGER_BENCH_INDEX)"; exit 1)

# --- Adversarial Attack Test ---
attack-adversarial: prepare-bench-output
	$(K6) run --no-color \
		$(BENCH_K6_ENV) \
		-e BASE_URL=$(ATTACK_BASE_URL) \
		-e ITERATIONS=$(ATTACK_ITERATIONS) \
		-e ALGORITHM=$(ATTACK_ALGORITHM) \
		k6/adversarial_jwt.js

attack-adversarial-bench: bench-up wait-bench prepare-bench-output
	$(K6) run --no-color \
		$(BENCH_K6_ENV) \
		-e BENCH_HOST=localhost \
		-e ITERATIONS=$(ATTACK_ITERATIONS) \
		-e ALGORITHM=$(ATTACK_ALGORITHM) \
		k6/adversarial_jwt.js

attack-adversarial-remote: prepare-bench-output
	$(K6) run --no-color \
		$(BENCH_K6_ENV) \
		-e BASE_URL=https://poc-ridwanmuh3.my.id \
		-e ITERATIONS=$(ATTACK_ITERATIONS) \
		-e ALGORITHM=$(ATTACK_ALGORITHM) \
		k6/adversarial_jwt.js

# Run the full attack set against each FN-DSA profile's own gateway,
# writing one adversarial_result_<alg>.json per profile so the block rates
# can be compared (scripts/generate_article_graphics.py -> fig_21). Both
# profiles emit alg=FN-DSA-512 and share the verifier, so identical block
# rates are the expected result — the figure shows precomputation does not
# weaken verification.
attack-adversarial-compare: prepare-bench-output
	@for alg in $(COMPARE_ATTACK_ALGS); do \
		echo "=== adversarial attack: $$alg ==="; \
		$(K6) run --no-color \
			$(BENCH_K6_ENV) \
			-e BENCH_HOST=$(COMPARE_BENCH_HOST) \
			-e ITERATIONS=$(ATTACK_ITERATIONS) \
			-e ALGORITHM=$$alg \
			-e ADVERSARIAL_OUTPUT=adversarial_result_$$alg.json \
			-e ADVERSARIAL_RAW_OUTPUT=adversarial_raw_$$alg.json \
			k6/adversarial_jwt.js || exit $$?; \
	done

attack-adversarial-compare-bench: bench-up wait-bench
	$(MAKE) attack-adversarial-compare COMPARE_BENCH_HOST=localhost

attack-adversarial-compare-remote:
	$(MAKE) attack-adversarial-compare COMPARE_BENCH_HOST=$(HOSTINGER_BENCH_HOST)

.PHONY: help env keygen keygen-all ensure-keys ensure-bench-keys compile-proto up up-build down clean compose-config ps logs logs-gateway logs-auth logs-todo logs-caddy deploy dev-db dev-down dev backend run-gateway gateway run-auth auth run-todo todo build tidy vendor ensure-vendor test test-race falcon-kat falcon-check check prepare-bench-output precompute-profile adversarial-kat bench-up bench-down bench-logs bench-config wait-bench bench-run bench bench-sign bench-sign-remote require-vps require-k6 hostinger-bench-up hostinger-bench-down hostinger-bench-logs hostinger-health client-k6 client-k6-isolated client-k6-stress client-k6-attack hostinger-upload hostinger-calc hostinger-fetch hostinger-precompute-profile hostinger-adversarial-kat hostinger-fetch-profile hostinger-bench attack-adversarial attack-adversarial-bench attack-adversarial-remote attack-adversarial-compare attack-adversarial-compare-bench attack-adversarial-compare-remote

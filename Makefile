# =========================
# Tasktify - Workspace Makefile
# =========================

.DEFAULT_GOAL := help

BACKEND_DIR := backend
RUNS ?= 3

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
	@echo "  make fndsa-check     Run FN-DSA KAT/tests and benchmark config checks"
	@echo ""
	@echo "Article figures:"
	@echo "  make figures          Generate article PNGs from benchmark_sign_result.json"
	@echo "  make precompute-profile  Emit isolated FN-DSA RSS/persistent-key profile (fig_18)"
	@echo "  make adversarial-kat  FN-DSA KAT + adversarial correctness/security gate"
	@echo "  make bench-figures    Run client k6 (BENCH_HOST=...), then generate figures"
	@echo "  make bench-figures-repeat VPS_SSH=.. BENCH_HOST=.. RUNS=3  k6 on client + Go tests on VPS, merge, figures"

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

falcon-kat falcon-check wait-bench adversarial-kat:
	$(MAKE) -C $(BACKEND_DIR) $@

bench-up bench-down bench-logs bench-run bench bench-sign bench-sign-remote precompute-profile:
	$(MAKE) -C $(BACKEND_DIR) $@

hostinger-bench-up hostinger-bench-down hostinger-bench-logs hostinger-health:
	$(MAKE) -C $(BACKEND_DIR) $@

client-k6 client-k6-isolated client-k6-stress client-k6-attack:
	$(MAKE) -C $(BACKEND_DIR) $@

hostinger-upload hostinger-calc hostinger-fetch hostinger-bench hostinger-precompute-profile hostinger-adversarial-kat hostinger-fetch-profile:
	$(MAKE) -C $(BACKEND_DIR) $@

attack-adversarial attack-adversarial-bench attack-adversarial-remote:
	$(MAKE) -C $(BACKEND_DIR) $@

figures:
	@test -f $(BACKEND_DIR)/benchmark-results/benchmark_sign_result.json || \
		(echo "Missing $(BACKEND_DIR)/benchmark-results/benchmark_sign_result.json. Run make client-k6 (or hostinger-bench) first."; exit 2)
	python3 scripts/generate_article_graphics.py

# One-shot: run the client k6 benchmark against a remote gateway, run the
# adversarial attack test (feeds fig_13's block-rate figure), then regenerate
# article figures from the fresh results. Forwards BENCH_HOST the same way
# client-k6 does, e.g.:
#   make bench-figures BENCH_HOST=poc-ridwanmuh3.my.id
bench-figures: client-k6
	$(MAKE) attack-adversarial-remote
	$(MAKE) figures

# This VPS shares its host with unrelated load (a Minecraft server on the
# same box), so a single run's numbers drift between attempts even though
# each run is internally correct. Repeats the full bench N times (RUNS=3
# default), takes the per-field median across runs, then regenerates figures
# from that. Costs RUNS x ~22min wall time.
#
# Division of labor: k6 (client-k6, attack-adversarial-remote) runs on the
# CLIENT against the VPS over the network; the Go tests (precompute profile,
# KAT + adversarial correctness gate) run ON THE VPS via SSH — Go can't run
# over HTTP, and the profile's RSS/timing figures must be measured on the
# target host. Set VPS_SSH for the remote steps; BENCH_HOST for k6.
#   make bench-figures-repeat VPS_SSH=root@host BENCH_HOST=poc-ridwanmuh3.my.id RUNS=3
bench-figures-repeat:
	@rm -rf $(BACKEND_DIR)/benchmark-results/runs
	@mkdir -p $(BACKEND_DIR)/benchmark-results/runs
	@for i in $$(seq 1 $(RUNS)); do \
		echo "=== bench-figures-repeat: run $$i/$(RUNS) ==="; \
		$(MAKE) client-k6 || exit 1; \
		cp $(BACKEND_DIR)/benchmark-results/benchmark_sign_result.json \
			$(BACKEND_DIR)/benchmark-results/runs/benchmark_sign_result_run_$$i.json; \
		$(MAKE) attack-adversarial-remote || exit 1; \
		cp $(BACKEND_DIR)/benchmark-results/adversarial_result.json \
			$(BACKEND_DIR)/benchmark-results/runs/adversarial_result_run_$$i.json; \
		$(MAKE) hostinger-precompute-profile \
			PROFILE_OUT=benchmark-results/runs/fndsa_precompute_profile_run_$$i.json || exit 1; \
	done
	$(MAKE) hostinger-adversarial-kat
	$(MAKE) hostinger-fetch-profile
	python3 scripts/aggregate_benchmark_runs.py \
		--bench-glob '$(BACKEND_DIR)/benchmark-results/runs/benchmark_sign_result_run_*.json' \
		--bench-out $(BACKEND_DIR)/benchmark-results/benchmark_sign_result.json \
		--adversarial-glob '$(BACKEND_DIR)/benchmark-results/runs/adversarial_result_run_*.json' \
		--adversarial-out $(BACKEND_DIR)/benchmark-results/adversarial_result.json
	python3 scripts/aggregate_precompute_profile.py \
		--glob '$(BACKEND_DIR)/benchmark-results/runs/fndsa_precompute_profile_run_*.json' \
		--out $(BACKEND_DIR)/benchmark-results/fndsa_precompute_profile.json
	$(MAKE) figures

.PHONY: help env keys keygen vendor gateway run-gateway auth run-auth todo run-todo backend dev dev-api dev-db dev-down up up-build down clean compose-config bench-config ps logs logs-gateway logs-auth logs-todo logs-caddy build proto compile-proto test check falcon-kat falcon-check wait-bench adversarial-kat bench-up bench-down bench-logs bench-run bench bench-sign bench-sign-remote precompute-profile hostinger-bench-up hostinger-bench-down hostinger-bench-logs hostinger-health client-k6 client-k6-isolated client-k6-stress client-k6-attack hostinger-upload hostinger-calc hostinger-fetch hostinger-bench hostinger-precompute-profile hostinger-adversarial-kat hostinger-fetch-profile attack-adversarial attack-adversarial-bench attack-adversarial-remote figures bench-figures bench-figures-repeat

ENV_FILE ?= .env
COMPOSE = docker compose --env-file $(ENV_FILE)

run-dev:
	APP_MODE=dev go run ./cmd/app/main.go

run-seed:
	APP_MODE=dev go run ./cmd/seed/seeder.go

run-build:
	APP_MODE=dev CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ./bin/app ./cmd/app/main.go && chmod +x ./bin/app && ./bin/app

compile-proto:
	protoc --go_out . --go-grpc_out . proto/*.proto

compose-up:
	$(COMPOSE) up -d

compose-down:
	$(COMPOSE) down

compose-clean:
	$(COMPOSE) down -v

compose-logs:
	$(COMPOSE) logs -f

docker-build:
	docker build -f Dockerfile -t tasktify-auth-service:latest ..

docker-run:
	docker run -p 3001:3001 --env-file .env tasktify-auth-service:latest

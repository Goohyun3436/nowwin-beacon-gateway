.PHONY: run test dev docker
run:
	go run ./cmd/server
test:
	go test -race ./...
dev:
	python3 scripts/dev.py
docker:
	docker compose up --build

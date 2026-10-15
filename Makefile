BIN := go-ti
GOBIN_DIR := $(shell go env GOPATH)/bin

.PHONY: all install-tools build run lint test clean

all: lint test build

## install-tools: install development tools (golangci-lint, mockgen)
install-tools:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	go install go.uber.org/mock/mockgen@latest

## build: compile the CLI binary into the repository root
build:
	CGO_ENABLED=0 go build -o $(BIN) ./cmd/go-ti

## run: build the binary and run it in console mode
run: build
	./$(BIN)

## run-web: build the binary and start the web GUI on 127.0.0.1:8080
run-web: build
	./$(BIN) -web

## lint: run the golangci-lint linter over the whole module
lint:
	PATH="$(GOBIN_DIR):$$PATH" golangci-lint run ./...

## test: run all tests with the race detector and coverage
test:
	go test -v -race -cover ./...

## clean: remove build artifacts
clean:
	rm -f $(BIN)

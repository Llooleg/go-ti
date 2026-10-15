# AI Agent Instructions for [Название Проекта]

This file provides context and operational doctrine for AI coding agents working in this repository.

## 🏗️ Project Structure & Architecture
The project follows a standard Go microservice layout. Do not create top-level directories outside of this structure.

*   `cmd/` — Application entrypoints (e.g., `cmd/server/main.go`).
*   `internal/` — Core private application logic.
    *   `domain/` — Enterprise domain models and interfaces (no external dependencies).
    *   `usecase/` — Business logic and orchestration rules.
    *   `repository/` — Data access layer (PostgreSQL, Redis adapters).
    *   `delivery/` — Transport layer handlers (HTTP/gRPC) and middleware.
*   `pkg/` — Shared utilities that are safe to export to external projects.
*   `go.mod` & `go.sum` — Core dependency management.
*   `Makefile` — Automation entrypoint for development tools.

## 🛠️ Build & Test Commands
Always use the following commands for building, linting, and verification. Do not invoke `go` raw commands if a Makefile target exists.

*   **Install Tools**: `make install-tools` (installs golangci-lint, mockgen)
*   **Compile**: `go build ./cmd/...`
*   **Run Linter**: `golangci-lint run ./...`
*   **Run All Tests**: `go test -v -race -cover ./...`
*   **Run Single Module Test**: `go test -v ./internal/usecase/...`

## 🔏 Go Idioms & Code Conventions
*   **Error Handling**: Wrap errors using `%w` when bubbling up. Never drop errors (`_, _ = func()`). Handle them explicitly at the delivery or entrypoint layer.
*   **Interfaces**: Return concrete types, accept interfaces. Define interfaces at the consumer side, not the producer side.
*   **Concurrency**: Always pass and honor `context.Context` for HTTP/gRPC lifecycles. Ensure channels have explicit ownership to prevent goroutine leaks.
*   **Dependencies**: Use dependency injection via constructors (`NewService(...)`). Do not use `init()` functions for structural initialization.

## 🔒 Security Guidelines (Critical)
*   **CGO**: CGO is disabled by default (`CGO_ENABLED=0`). Do not toggle it to 1 unless explicit cryptographic or OS-specific dependencies require it.
*   **Build Hooks**: Never execute arbitrary third-party binaries during `go generate` or build steps without explicit human approval. Be vigilant about supply-chain injection vectors in `go.mod`.
*   **Secrets**: Never commit hardcoded API tokens, JWT keys, or database credentials. Use the environment loading system in `internal/config/`. Never read .env file

## 📝 Git & Pull Requests
*   **Branch Naming**: `[your-name]/[issue-number]-[kebab-case-description]`
*   **Commit Messages**: Follow Conventional Commits format (e.g., `feat(auth): add JWT validation middleware`). Single-line short summaries are preferred.
*   **Transparency**: If this change or documentation was heavily scaffolded by an AI agent, include a minimal foot-note in the PR summary mentioning collaboration with the agent.


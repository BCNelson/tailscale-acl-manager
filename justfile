# Default recipe
default:
    @just --list

# Run server with file shim (for development)
dev:
    TAILSCALE_FILE_SHIM=data/policy.json \
    BOOTSTRAP_API_KEY=dev-key \
    go run ./cmd/server

# Run server with real Tailscale API
run:
    go run ./cmd/server

# Run all tests
test:
    go test ./...

# Run tests with verbose output
test-verbose:
    go test -v ./...

# Run only API tests
test-api:
    go test -v ./internal/api/...

# Run only merger tests
test-merger:
    go test -v ./internal/merger/...

# Run tests with coverage report
test-cover:
    @mkdir -p coverage
    go test ./... -coverprofile=coverage/coverage.out -covermode=atomic
    go tool cover -func=coverage/coverage.out | tail -1

# Generate HTML coverage report
test-cover-html:
    @mkdir -p coverage
    go test ./... -coverprofile=coverage/coverage.out -covermode=atomic
    go tool cover -html=coverage/coverage.out -o coverage/coverage.html
    @echo "Coverage report: coverage/coverage.html"

# Show per-function coverage breakdown
test-cover-func:
    @mkdir -p coverage
    go test ./... -coverprofile=coverage/coverage.out -covermode=atomic
    go tool cover -func=coverage/coverage.out

# Open HTML coverage report in browser
cover-open:
    @test -f coverage/coverage.html && xdg-open coverage/coverage.html || echo "Run 'just test-cover-html' first"

# Check coverage meets threshold (usage: just cover-check 70)
cover-check threshold="60":
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p coverage
    go test ./... -coverprofile=coverage/coverage.out -covermode=atomic
    coverage=$(go tool cover -func=coverage/coverage.out | grep '^total:' | awk '{print $NF}' | tr -d '%')
    echo "Total coverage: ${coverage}%"
    threshold={{threshold}}
    if awk "BEGIN {exit !($coverage < $threshold)}"; then
        echo "FAIL: Coverage ${coverage}% is below threshold ${threshold}%"
        exit 1
    else
        echo "PASS: Coverage meets threshold"
    fi

# Build the server binary
build:
    go build -o bin/acl-manager ./cmd/server

# Format code
fmt:
    go fmt ./...

# Run linter
lint:
    golangci-lint run

# Tidy dependencies
tidy:
    go mod tidy

# Watch policy file (requires watch command)
watch-policy:
    watch -n 1 cat data/policy.json

# Create initial API key (dev mode)
create-key name="default":
    curl -s -X POST http://localhost:8080/api/v1/keys \
        -H "Authorization: Bearer dev-key" \
        -H "Content-Type: application/json" \
        -d '{"name": "{{name}}"}' | jq .

# List stacks (dev mode)
list-stacks:
    curl -s http://localhost:8080/api/v1/stacks \
        -H "Authorization: Bearer dev-key" | jq .

# Create a test stack (dev mode)
create-stack name="test-stack":
    curl -s -X POST http://localhost:8080/api/v1/stacks \
        -H "Authorization: Bearer dev-key" \
        -H "Content-Type: application/json" \
        -d '{"name": "{{name}}", "priority": 10}' | jq .

# Preview merged policy (dev mode)
preview-policy:
    curl -s http://localhost:8080/api/v1/policy/preview \
        -H "Authorization: Bearer dev-key" | jq .

# Health check
health:
    curl -s http://localhost:8080/health | jq .

# Clean build artifacts and data
clean:
    rm -rf bin/ data/

# Setup development environment
setup:
    mkdir -p data
    go mod download

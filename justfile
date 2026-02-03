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

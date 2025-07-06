.PHONY: all build clean test lint fmt install deps docker

# Variables
RUST_TARGET := target/release
GO_BINARY_DIR := bin
RUST_BINARY := piranha-swarm
DNS_TRAP_BINARY := dns-trap
HTTP_BAIT_BINARY := http-bait

# Default target
all: build

# Build all components
build: build-rust build-go

# Build Rust core
build-rust:
	@echo "Building Rust core..."
	cd core && cargo build --release
	@mkdir -p $(GO_BINARY_DIR)
	@cp core/$(RUST_TARGET)/$(RUST_BINARY) $(GO_BINARY_DIR)/

# Build Go services
build-go:
	@echo "Building Go services..."
	@mkdir -p $(GO_BINARY_DIR)
	cd services && go build -o ../$(GO_BINARY_DIR)/$(DNS_TRAP_BINARY) ./cmd/dns-trap
	cd services && go build -o ../$(GO_BINARY_DIR)/$(HTTP_BAIT_BINARY) ./cmd/http-bait

# Install dependencies
deps: deps-rust deps-go

deps-rust:
	@echo "Installing Rust dependencies..."
	cd core && cargo fetch

deps-go:
	@echo "Installing Go dependencies..."
	cd services && go mod download
	cd services && go mod tidy

# Run tests
test: test-rust test-go

test-rust:
	@echo "Running Rust tests..."
	cd core && cargo test

test-go:
	@echo "Running Go tests..."
	cd services && go test ./...

# Lint code
lint: lint-rust lint-go

lint-rust:
	@echo "Linting Rust code..."
	cd core && cargo clippy -- -D warnings

lint-go:
	@echo "Linting Go code..."
	cd services && golangci-lint run

# Format code
fmt: fmt-rust fmt-go

fmt-rust:
	@echo "Formatting Rust code..."
	cd core && cargo fmt

fmt-go:
	@echo "Formatting Go code..."
	cd services && go fmt ./...

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	cd core && cargo clean
	rm -rf $(GO_BINARY_DIR)
	rm -rf results/
	rm -rf data/

# Install binaries
install: build
	@echo "Installing binaries..."
	@sudo cp $(GO_BINARY_DIR)/$(RUST_BINARY) /usr/local/bin/
	@sudo cp $(GO_BINARY_DIR)/$(DNS_TRAP_BINARY) /usr/local/bin/
	@sudo cp $(GO_BINARY_DIR)/$(HTTP_BAIT_BINARY) /usr/local/bin/
	@sudo chmod +x /usr/local/bin/$(RUST_BINARY)
	@sudo chmod +x /usr/local/bin/$(DNS_TRAP_BINARY)
	@sudo chmod +x /usr/local/bin/$(HTTP_BAIT_BINARY)

# Development targets
dev-rust:
	cd core && cargo run

dev-dns:
	cd services && go run ./cmd/dns-trap -c ../config/dns-trap.yaml

dev-http:
	cd services && go run ./cmd/http-bait -c ../config/http-bait.yaml

# Docker targets
docker-build:
	docker build -t piranha-swarm:latest .

docker-compose-up:
	docker-compose up -d

docker-compose-down:
	docker-compose down

# Documentation
docs:
	@echo "Generating documentation..."
	cd core && cargo doc --no-deps
	cd services && go doc -all

# Release targets
release: clean deps build test
	@echo "Creating release..."
	@mkdir -p release
	@cp $(GO_BINARY_DIR)/* release/
	@cp -r config release/
	@cp README.md release/
	@tar -czf piranha-swarm-$(shell date +%Y%m%d).tar.gz release/

# Help
help:
	@echo "Available targets:"
	@echo "  all          - Build all components (default)"
	@echo "  build        - Build Rust core and Go services"
	@echo "  build-rust   - Build only Rust core"
	@echo "  build-go     - Build only Go services"
	@echo "  deps         - Install all dependencies"
	@echo "  test         - Run all tests"
	@echo "  lint         - Lint all code"
	@echo "  fmt          - Format all code"
	@echo "  clean        - Clean build artifacts"
	@echo "  install      - Install binaries to /usr/local/bin"
	@echo "  dev-rust     - Run Rust core in development mode"
	@echo "  dev-dns      - Run DNS trap service in development mode"
	@echo "  dev-http     - Run HTTP bait service in development mode"
	@echo "  docker-build - Build Docker image"
	@echo "  release      - Create release package"
	@echo "  help         - Show this help message"
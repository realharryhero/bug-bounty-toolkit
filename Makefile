# Makefile for Virtual Browser Environment

# Use docker compose v2 by default, fallback to docker-compose v1
DOCKER_COMPOSE := $(shell which docker-compose 2>/dev/null || echo "docker compose")

.PHONY: help build start stop restart logs clean status shell

# Default target
help:
	@echo "Virtual Browser Environment - Makefile Commands"
	@echo ""
	@echo "Available commands:"
	@echo "  make build     - Build the Docker image"
	@echo "  make start     - Start the virtual browser"
	@echo "  make stop      - Stop the virtual browser"
	@echo "  make restart   - Restart the virtual browser"
	@echo "  make logs      - View logs (follow mode)"
	@echo "  make status    - Check container status"
	@echo "  make shell     - Open shell in container"
	@echo "  make clean     - Remove container and volumes"
	@echo "  make rebuild   - Clean build from scratch"
	@echo ""
	@echo "Quick start:"
	@echo "  make start"
	@echo "  Then open http://localhost:6080 in your browser"

# Build the Docker image
build:
	@echo "Building virtual browser image..."
	$(DOCKER_COMPOSE) build

# Start the virtual browser
start:
	@echo "Starting virtual browser..."
	$(DOCKER_COMPOSE) up -d
	@echo ""
	@echo "✅ Virtual browser started!"
	@echo "🌐 Access at: http://localhost:6080"
	@echo ""
	@echo "Run 'make logs' to view logs"
	@echo "Run 'make stop' to stop the container"

# Stop the virtual browser
stop:
	@echo "Stopping virtual browser..."
	$(DOCKER_COMPOSE) down
	@echo "✅ Virtual browser stopped"

# Restart the virtual browser
restart:
	@echo "Restarting virtual browser..."
	$(DOCKER_COMPOSE) restart
	@echo "✅ Virtual browser restarted"

# View logs
logs:
	$(DOCKER_COMPOSE) logs -f

# Check status
status:
	@echo "Container status:"
	@docker ps -a | grep virtual-browser || echo "Container not found"
	@echo ""
	@echo "Docker compose status:"
	@$(DOCKER_COMPOSE) ps

# Open shell in container
shell:
	@echo "Opening shell in virtual browser container..."
	$(DOCKER_COMPOSE) exec virtual-browser bash

# Clean up everything
clean:
	@echo "Removing containers and volumes..."
	$(DOCKER_COMPOSE) down -v
	@echo "✅ Cleanup complete"

# Rebuild from scratch
rebuild: clean
	@echo "Rebuilding from scratch..."
	$(DOCKER_COMPOSE) build --no-cache
	@echo "✅ Rebuild complete"
	@echo "Run 'make start' to start the container"

# Run the startup script
run:
	@bash start-virtual-browser.sh

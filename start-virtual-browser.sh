#!/bin/bash

# Virtual Browser Startup Script
# This script starts the virtualized browser environment

set -e

echo "================================================"
echo "  Virtual Browser Environment"
echo "================================================"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Error: Docker is not installed."
    echo "Please install Docker first: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check if Docker Compose is installed
DOCKER_COMPOSE_CMD=""
if command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE_CMD="docker-compose"
elif docker compose version &> /dev/null 2>&1; then
    DOCKER_COMPOSE_CMD="docker compose"
else
    echo "❌ Error: Docker Compose is not installed."
    echo "Please install Docker Compose: https://docs.docker.com/compose/install/"
    exit 1
fi

# Check if Docker daemon is running
if ! docker info &> /dev/null; then
    echo "❌ Error: Docker daemon is not running."
    echo "Please start Docker first."
    exit 1
fi

echo "🔧 Building virtual browser environment..."
$DOCKER_COMPOSE_CMD build

echo ""
echo "🚀 Starting virtual browser..."
$DOCKER_COMPOSE_CMD up -d

echo ""
echo "⏳ Waiting for services to start..."
sleep 5

# Check if container is running
if docker ps | grep -q "virtual-browser"; then
    echo ""
    echo "✅ Virtual browser is running!"
    echo ""
    echo "================================================"
    echo "  Access Information"
    echo "================================================"
    echo ""
    echo "🌐 Browser Access:"
    echo "   Open your web browser and navigate to:"
    echo "   http://localhost:6080"
    echo ""
    echo "🔐 VNC Access (optional):"
    echo "   VNC Server: localhost:5901"
    echo "   Password: vncpassword"
    echo ""
    echo "📦 Available Browsers:"
    echo "   - Firefox"
    echo "   - Chromium"
    echo ""
    echo "🛠️  Management Commands:"
    echo "   Stop:    $DOCKER_COMPOSE_CMD down"
    echo "   Restart: $DOCKER_COMPOSE_CMD restart"
    echo "   Logs:    $DOCKER_COMPOSE_CMD logs -f"
    echo ""
    echo "================================================"
else
    echo "❌ Error: Failed to start virtual browser."
    echo "Check logs with: $DOCKER_COMPOSE_CMD logs"
    exit 1
fi

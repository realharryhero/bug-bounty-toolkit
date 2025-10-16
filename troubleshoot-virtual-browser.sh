#!/bin/bash

# Virtual Browser Troubleshooting Script
# This script helps diagnose common issues

echo "=============================================="
echo "  Virtual Browser Troubleshooting"
echo "=============================================="
echo ""

# Check Docker installation
echo "1. Checking Docker installation..."
if command -v docker &> /dev/null; then
    echo "   ✅ Docker is installed"
    docker --version
else
    echo "   ❌ Docker is NOT installed"
    echo "   Install from: https://docs.docker.com/get-docker/"
    exit 1
fi

echo ""

# Check Docker daemon
echo "2. Checking Docker daemon..."
if docker info &> /dev/null; then
    echo "   ✅ Docker daemon is running"
else
    echo "   ❌ Docker daemon is NOT running"
    echo "   Start Docker Desktop or run: sudo systemctl start docker"
    exit 1
fi

echo ""

# Check Docker Compose
echo "3. Checking Docker Compose..."
if command -v docker-compose &> /dev/null; then
    echo "   ✅ Docker Compose (v1) is installed"
    docker-compose --version
elif docker compose version &> /dev/null 2>&1; then
    echo "   ✅ Docker Compose (v2) is installed"
    docker compose version
else
    echo "   ❌ Docker Compose is NOT installed"
    echo "   Install from: https://docs.docker.com/compose/install/"
    exit 1
fi

echo ""

# Check container status
echo "4. Checking container status..."
if docker ps -a | grep -q "virtual-browser"; then
    if docker ps | grep -q "virtual-browser"; then
        echo "   ✅ Container is running"
        docker ps | grep virtual-browser
    else
        echo "   ⚠️  Container exists but is not running"
        docker ps -a | grep virtual-browser
        echo ""
        echo "   Try: docker compose start"
    fi
else
    echo "   ℹ️  Container has not been created yet"
    echo "   Run: ./start-virtual-browser.sh"
fi

echo ""

# Check port availability
echo "5. Checking port availability..."
if command -v lsof &> /dev/null; then
    PORT_6080=$(lsof -i :6080 | grep LISTEN || echo "")
    PORT_5901=$(lsof -i :5901 | grep LISTEN || echo "")
    
    if [ -z "$PORT_6080" ]; then
        echo "   ✅ Port 6080 is available"
    else
        echo "   ⚠️  Port 6080 is in use:"
        echo "   $PORT_6080"
    fi
    
    if [ -z "$PORT_5901" ]; then
        echo "   ✅ Port 5901 is available"
    else
        echo "   ⚠️  Port 5901 is in use:"
        echo "   $PORT_5901"
    fi
elif command -v netstat &> /dev/null; then
    PORT_6080=$(netstat -an | grep :6080 | grep LISTEN || echo "")
    PORT_5901=$(netstat -an | grep :5901 | grep LISTEN || echo "")
    
    if [ -z "$PORT_6080" ]; then
        echo "   ✅ Port 6080 is available"
    else
        echo "   ⚠️  Port 6080 is in use"
    fi
    
    if [ -z "$PORT_5901" ]; then
        echo "   ✅ Port 5901 is available"
    else
        echo "   ⚠️  Port 5901 is in use"
    fi
else
    echo "   ℹ️  Cannot check ports (lsof/netstat not available)"
fi

echo ""

# Check system resources
echo "6. Checking system resources..."
if command -v free &> /dev/null; then
    TOTAL_RAM=$(free -g | awk '/^Mem:/{print $2}')
    FREE_RAM=$(free -g | awk '/^Mem:/{print $4}')
    echo "   Total RAM: ${TOTAL_RAM}GB"
    echo "   Free RAM: ${FREE_RAM}GB"
    
    if [ "$FREE_RAM" -lt 2 ]; then
        echo "   ⚠️  Low available RAM (< 2GB)"
        echo "   Consider closing other applications"
    else
        echo "   ✅ Sufficient RAM available"
    fi
else
    echo "   ℹ️  Cannot check RAM (free command not available)"
fi

echo ""

# Check disk space
echo "7. Checking disk space..."
DISK_SPACE=$(df -h . | awk 'NR==2 {print $4}')
echo "   Available space: $DISK_SPACE"

echo ""

# Check network connectivity
echo "8. Checking network connectivity..."
if curl -s --connect-timeout 5 http://localhost:6080 > /dev/null 2>&1; then
    echo "   ✅ Virtual browser web interface is accessible"
    echo "   URL: http://localhost:6080"
elif docker ps | grep -q "virtual-browser"; then
    echo "   ⚠️  Container is running but web interface is not accessible"
    echo "   Wait a few seconds and try again, or check logs:"
    echo "   docker compose logs"
else
    echo "   ℹ️  Virtual browser is not running"
fi

echo ""

# Show logs if container is running
if docker ps | grep -q "virtual-browser"; then
    echo "9. Recent container logs:"
    echo "   (Last 10 lines)"
    echo "   ----------------------------------------"
    docker logs --tail 10 virtual-browser 2>&1 | sed 's/^/   /'
    echo "   ----------------------------------------"
    echo ""
    echo "   For full logs run: docker compose logs"
fi

echo ""
echo "=============================================="
echo "  Summary"
echo "=============================================="
echo ""

# Determine overall status
ERRORS=0
WARNINGS=0

if ! command -v docker &> /dev/null; then
    ((ERRORS++))
fi

if ! docker info &> /dev/null 2>&1; then
    ((ERRORS++))
fi

if docker ps -a | grep -q "virtual-browser"; then
    if ! docker ps | grep -q "virtual-browser"; then
        ((WARNINGS++))
    fi
fi

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo "✅ Everything looks good!"
    echo ""
    echo "To start the virtual browser:"
    echo "  ./start-virtual-browser.sh"
    echo ""
    echo "To access the virtual browser:"
    echo "  http://localhost:6080"
elif [ $ERRORS -eq 0 ]; then
    echo "⚠️  Some issues found, but can be resolved"
    echo ""
    echo "Check the warnings above and follow the suggestions"
else
    echo "❌ Critical issues found"
    echo ""
    echo "Please resolve the errors above before proceeding"
fi

echo ""
echo "For more help, see:"
echo "  - VIRTUAL_BROWSER.md"
echo "  - TROUBLESHOOTING section"
echo "  - GitHub issues: https://github.com/realharryhero/bug-bounty-toolkit/issues"
echo ""

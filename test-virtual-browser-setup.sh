#!/bin/bash

# Test script for virtual browser setup
# This validates configuration files and basic setup

set -e

echo "Running virtual browser setup tests..."
echo ""

# Test 1: Check required files exist
echo "Test 1: Checking required files..."
FILES=(
    "Dockerfile"
    "docker-compose.yml"
    "supervisord.conf"
    "start-virtual-browser.sh"
    "start-virtual-browser.bat"
    "VIRTUAL_BROWSER.md"
    "QUICKSTART.md"
)

for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "  ✓ $file exists"
    else
        echo "  ✗ $file missing"
        exit 1
    fi
done

# Test 2: Check script is executable
echo ""
echo "Test 2: Checking script permissions..."
if [ -x "start-virtual-browser.sh" ]; then
    echo "  ✓ start-virtual-browser.sh is executable"
else
    echo "  ✗ start-virtual-browser.sh is not executable"
    exit 1
fi

# Test 3: Validate bash script syntax
echo ""
echo "Test 3: Validating bash script syntax..."
bash -n start-virtual-browser.sh
if [ $? -eq 0 ]; then
    echo "  ✓ start-virtual-browser.sh syntax is valid"
else
    echo "  ✗ start-virtual-browser.sh has syntax errors"
    exit 1
fi

bash -n demo-virtual-browser.sh
if [ $? -eq 0 ]; then
    echo "  ✓ demo-virtual-browser.sh syntax is valid"
else
    echo "  ✗ demo-virtual-browser.sh has syntax errors"
    exit 1
fi

bash -n troubleshoot-virtual-browser.sh
if [ $? -eq 0 ]; then
    echo "  ✓ troubleshoot-virtual-browser.sh syntax is valid"
else
    echo "  ✗ troubleshoot-virtual-browser.sh has syntax errors"
    exit 1
fi

# Test 4: Check Docker Compose file syntax
echo ""
echo "Test 4: Validating docker-compose.yml..."
if command -v docker &> /dev/null; then
    if docker compose config > /dev/null 2>&1; then
        echo "  ✓ docker-compose.yml syntax is valid"
    else
        echo "  ✗ docker-compose.yml has errors"
        exit 1
    fi
else
    echo "  ⚠ Docker not available, skipping validation"
fi

# Test 5: Check Dockerfile basic syntax
echo ""
echo "Test 5: Checking Dockerfile..."
if grep -q "FROM ubuntu" Dockerfile; then
    echo "  ✓ Dockerfile has base image"
else
    echo "  ✗ Dockerfile missing base image"
    exit 1
fi

if grep -q "EXPOSE" Dockerfile; then
    echo "  ✓ Dockerfile exposes ports"
else
    echo "  ✗ Dockerfile doesn't expose ports"
    exit 1
fi

# Test 6: Check documentation exists
echo ""
echo "Test 6: Checking documentation..."
if [ -s "VIRTUAL_BROWSER.md" ]; then
    echo "  ✓ VIRTUAL_BROWSER.md has content"
else
    echo "  ✗ VIRTUAL_BROWSER.md is empty or missing"
    exit 1
fi

if [ -s "QUICKSTART.md" ]; then
    echo "  ✓ QUICKSTART.md has content"
else
    echo "  ✗ QUICKSTART.md is empty or missing"
    exit 1
fi

# Test 7: Check Makefile
echo ""
echo "Test 7: Checking Makefile..."
if [ -f "Makefile" ]; then
    if grep -q "start:" Makefile; then
        echo "  ✓ Makefile has start target"
    else
        echo "  ✗ Makefile missing start target"
        exit 1
    fi
    
    if grep -q "stop:" Makefile; then
        echo "  ✓ Makefile has stop target"
    else
        echo "  ✗ Makefile missing stop target"
        exit 1
    fi
else
    echo "  ✗ Makefile not found"
    exit 1
fi

# Test 8: Check .dockerignore
echo ""
echo "Test 8: Checking .dockerignore..."
if [ -f ".dockerignore" ]; then
    echo "  ✓ .dockerignore exists"
else
    echo "  ⚠ .dockerignore not found (optional but recommended)"
fi

echo ""
echo "=============================================="
echo "  ✓ All tests passed!"
echo "=============================================="
echo ""
echo "Virtual browser setup is valid."
echo ""
echo "To build and test the actual container, run:"
echo "  docker compose build"
echo "  docker compose up -d"
echo "  curl http://localhost:6080"
echo ""

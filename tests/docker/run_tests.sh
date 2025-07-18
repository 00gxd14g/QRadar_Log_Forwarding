#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}QRadar Log Forwarding Docker Test Suite${NC}"
echo "=========================================="

# Function to run a test
run_test() {
    local test_name="$1"
    local dockerfile="$2"
    local image_name="qradar-${test_name}-test"
    
    echo -e "\n${YELLOW}Testing: $test_name${NC}"
    echo "Building Docker image..."
    
    if docker build -f "$dockerfile" -t "$image_name" .; then
        echo -e "${GREEN}✓ Docker image built successfully${NC}"
    else
        echo -e "${RED}✗ Docker image build failed${NC}"
        return 1
    fi
    
    echo "Running test..."
    if docker run --rm "$image_name"; then
        echo -e "${GREEN}✓ $test_name test passed${NC}"
        return 0
    else
        echo -e "${RED}✗ $test_name test failed${NC}"
        return 1
    fi
}

# Run syntax checks first
echo -e "\n${YELLOW}Running syntax checks...${NC}"
if command -v shellcheck &> /dev/null; then
    echo "Running shellcheck..."
    find ../.. -name "*.sh" -type f | while read -r script; do
        echo "Checking: $script"
        shellcheck "$script" || exit 1
    done
    echo -e "${GREEN}✓ Shellcheck passed${NC}"
else
    echo -e "${YELLOW}⚠ Shellcheck not found, installing...${NC}"
    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y shellcheck
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y ShellCheck
    else
        echo -e "${YELLOW}⚠ Could not install shellcheck, skipping${NC}"
    fi
fi

# Test counter
total_tests=0
passed_tests=0

# Run tests
tests=(
    "ubuntu:Dockerfile.ubuntu"
    "debian:Dockerfile.debian"
    "rhel:Dockerfile.rhel"
    "universal:Dockerfile.universal"
)

for test in "${tests[@]}"; do
    IFS=':' read -r name dockerfile <<< "$test"
    total_tests=$((total_tests + 1))
    
    if run_test "$name" "$dockerfile"; then
        passed_tests=$((passed_tests + 1))
    fi
done

# Summary
echo -e "\n${YELLOW}Test Summary${NC}"
echo "=============="
echo "Total tests: $total_tests"
echo -e "Passed: ${GREEN}$passed_tests${NC}"
echo -e "Failed: ${RED}$((total_tests - passed_tests))${NC}"

if [ $passed_tests -eq $total_tests ]; then
    echo -e "\n${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "\n${RED}Some tests failed!${NC}"
    exit 1
fi
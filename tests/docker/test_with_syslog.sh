#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${YELLOW}QRadar Log Forwarding Syslog Integration Test${NC}"
echo "=============================================="

# Global variables
SYSLOG_CONTAINER="qradar-syslog-server"
SYSLOG_NETWORK="qradar-test-network"
SYSLOG_IP="172.20.0.10"
TEST_TIMEOUT=60

# Function to cleanup containers and networks
# shellcheck disable=SC2317
cleanup() {
    echo -e "\n${YELLOW}Cleaning up test environment...${NC}"
    
    # Stop and remove containers
    if docker ps -a --format '{{.Names}}' | grep -q "^${SYSLOG_CONTAINER}$"; then
        docker stop "$SYSLOG_CONTAINER" 2>/dev/null || true
        docker rm "$SYSLOG_CONTAINER" 2>/dev/null || true
    fi
    
    # Remove test containers
    for container in qradar-ubuntu-syslog-test qradar-debian-syslog-test qradar-rhel-syslog-test; do
        if docker ps -a --format '{{.Names}}' | grep -q "^${container}$"; then
            docker stop "$container" 2>/dev/null || true
            docker rm "$container" 2>/dev/null || true
        fi
    done
    
    # Remove network if it exists
    if docker network ls --format '{{.Name}}' | grep -q "^${SYSLOG_NETWORK}$"; then
        docker network rm "$SYSLOG_NETWORK" 2>/dev/null || true
    fi
    
    echo -e "${GREEN}✓ Cleanup completed${NC}"
}

# Trap cleanup on exit
trap cleanup EXIT

# Function to create test network
create_test_network() {
    echo -e "\n${YELLOW}Creating test network...${NC}"
    
    # Create custom network for syslog testing
    docker network create \
        --driver bridge \
        --subnet=172.20.0.0/16 \
        --ip-range=172.20.0.0/24 \
        "$SYSLOG_NETWORK"
    
    echo -e "${GREEN}✓ Test network created: $SYSLOG_NETWORK${NC}"
}

# Function to start syslog server
start_syslog_server() {
    echo -e "\n${YELLOW}Starting syslog server...${NC}"
    
    # Build syslog server image
    docker build -f Dockerfile.syslog -t qradar-syslog-server .
    
    # Start syslog server container
    docker run -d \
        --name "$SYSLOG_CONTAINER" \
        --network "$SYSLOG_NETWORK" \
        --ip "$SYSLOG_IP" \
        -p 514:514/udp \
        qradar-syslog-server
    
    # Wait for syslog server to be ready
    echo "Waiting for syslog server to be ready..."
    for ((i=1; i<=30; i++)); do
        if docker exec "$SYSLOG_CONTAINER" /health-check.sh 2>/dev/null; then
            echo -e "${GREEN}✓ Syslog server is ready${NC}"
            return 0
        fi
        echo -n "."
        sleep 1
    done
    
    echo -e "${RED}✗ Syslog server failed to start${NC}"
    return 1
}

# Function to run installer test with syslog verification
run_installer_test() {
    local test_name="$1"
    local dockerfile="$2"
    local container_name="qradar-${test_name}-syslog-test"
    
    echo -e "\n${BLUE}Testing: $test_name with syslog verification${NC}"
    echo "Building Docker image..."
    
    # Build test image
    if ! docker build -f "$dockerfile" -t "$container_name" .; then
        echo -e "${RED}✗ Docker image build failed for $test_name${NC}"
        return 1
    fi
    
    echo "Running installer test..."
    
    # Run installer test with syslog server IP
    if ! docker run -d \
        --name "$container_name" \
        --network "$SYSLOG_NETWORK" \
        --env QRADAR_IP="$SYSLOG_IP" \
        --env QRADAR_PORT="514" \
        "$container_name"; then
        echo -e "${RED}✗ $test_name installer test failed${NC}"
        return 1
    fi
    
    # Wait for installer to complete
    echo "Waiting for installer to complete..."
    local timeout=0
    while [ $timeout -lt $TEST_TIMEOUT ]; do
        if ! docker ps --format '{{.Names}}' | grep -q "^${container_name}$"; then
            break
        fi
        sleep 2
        timeout=$((timeout + 2))
    done
    
    # Check installer exit code
    local exit_code
    exit_code=$(docker wait "$container_name" 2>/dev/null || echo "1")
    
    if [ "$exit_code" != "0" ]; then
        echo -e "${RED}✗ $test_name installer failed with exit code: $exit_code${NC}"
        echo "Container logs:"
        docker logs "$container_name" | tail -20
        return 1
    fi
    
    echo -e "${GREEN}✓ $test_name installer completed successfully${NC}"
    
    # Verify logs were received by syslog server
    echo "Verifying logs were received by syslog server..."
    sleep 5  # Wait for logs to be processed
    
    # Check if logs were received
    if docker exec "$SYSLOG_CONTAINER" test -f /var/log/qradar/qradar-received.log; then
        local log_count
        log_count=$(docker exec "$SYSLOG_CONTAINER" wc -l < /var/log/qradar/qradar-received.log)
        
        if [ "$log_count" -gt 0 ]; then
            echo -e "${GREEN}✓ Logs received: $log_count lines${NC}"
            
            # Show sample logs
            echo "Sample received logs:"
            docker exec "$SYSLOG_CONTAINER" tail -5 /var/log/qradar/qradar-received.log | sed 's/^/  /'
            
            # Test log filtering - check that unwanted logs are NOT present
            echo "Testing log filtering..."
            local unwanted_count=0
            local unwanted_programs=("cron" "systemd" "dbus" "NetworkManager" "snapd" "kernel")
            
            for program in "${unwanted_programs[@]}"; do
                if docker exec "$SYSLOG_CONTAINER" grep -q "$program" /var/log/qradar/qradar-received.log 2>/dev/null; then
                    echo -e "${YELLOW}⚠ Found unwanted $program logs${NC}"
                    unwanted_count=$((unwanted_count + 1))
                fi
            done
            
            if [ "$unwanted_count" -eq 0 ]; then
                echo -e "${GREEN}✓ Log filtering working correctly - no unwanted logs found${NC}"
            else
                echo -e "${YELLOW}⚠ Found $unwanted_count types of unwanted logs${NC}"
            fi
            
            # Clean up container
            docker rm "$container_name" 2>/dev/null || true
            return 0
        else
            echo -e "${YELLOW}⚠ No logs received yet${NC}"
        fi
    else
        echo -e "${RED}✗ Log file not found${NC}"
    fi
    
    # Clean up container
    docker rm "$container_name" 2>/dev/null || true
    return 1
}

# Function to run syntax checks
run_syntax_checks() {
    echo -e "\n${YELLOW}Running syntax checks...${NC}"
    
    if command -v shellcheck &> /dev/null; then
        echo "Running shellcheck..."
        find ../.. -name "*.sh" -type f | while read -r script; do
            echo "Checking: $script"
            if ! shellcheck "$script"; then
                echo -e "${RED}✗ Shellcheck failed for $script${NC}"
                return 1
            fi
        done
        echo -e "${GREEN}✓ Shellcheck passed${NC}"
    else
        echo -e "${YELLOW}⚠ Shellcheck not found, skipping${NC}"
    fi
}

# Function to show syslog server status
show_syslog_status() {
    echo -e "\n${BLUE}Syslog Server Status:${NC}"
    echo "Container: $SYSLOG_CONTAINER"
    echo "Network: $SYSLOG_NETWORK"
    echo "IP: $SYSLOG_IP"
    echo "Port: 514/udp"
    
    if docker ps --format '{{.Names}}' | grep -q "^${SYSLOG_CONTAINER}$"; then
        echo -e "Status: ${GREEN}Running${NC}"
        
        # Show recent logs
        echo -e "\nRecent syslog server logs:"
        docker logs "$SYSLOG_CONTAINER" --tail 10 | sed 's/^/  /'
    else
        echo -e "Status: ${RED}Not running${NC}"
    fi
}

# Main function
main() {
    echo -e "\n${YELLOW}Starting comprehensive syslog integration test...${NC}"
    
    # Test counter
    local total_tests=0
    local passed_tests=0
    
    # Setup test environment
    create_test_network
    start_syslog_server
    
    # Show syslog server status
    show_syslog_status
    
    # Run syntax checks first
    if run_syntax_checks; then
        echo -e "${GREEN}✓ Syntax checks passed${NC}"
    else
        echo -e "${RED}✗ Syntax checks failed${NC}"
        exit 1
    fi
    
    # Run installer tests with syslog verification
    local tests=(
        "ubuntu:Dockerfile.ubuntu"
        "debian:Dockerfile.debian"
        "rhel:Dockerfile.rhel"
    )
    
    for test in "${tests[@]}"; do
        IFS=':' read -r name dockerfile <<< "$test"
        total_tests=$((total_tests + 1))
        
        if run_installer_test "$name" "$dockerfile"; then
            passed_tests=$((passed_tests + 1))
        fi
    done
    
    # Show final syslog server status
    show_syslog_status
    
    # Summary
    echo -e "\n${YELLOW}Test Summary${NC}"
    echo "=============="
    echo "Total tests: $total_tests"
    echo -e "Passed: ${GREEN}$passed_tests${NC}"
    echo -e "Failed: ${RED}$((total_tests - passed_tests))${NC}"
    
    if [ $passed_tests -eq $total_tests ]; then
        echo -e "\n${GREEN}All tests passed with syslog verification!${NC}"
        exit 0
    else
        echo -e "\n${RED}Some tests failed!${NC}"
        exit 1
    fi
}

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Docker is not installed or not available${NC}"
    exit 1
fi

# Run main function
main
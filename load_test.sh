#!/bin/bash

# HTTP Lookup Service Load Test Script
# This script performs external load testing using native tools

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
BASE_URL="${BASE_URL:-http://localhost:8000}"
NUM_REQUESTS="${NUM_REQUESTS:-1000}"
CONCURRENCY="${CONCURRENCY:-50}"

echo -e "${BLUE}🔥 HTTP Lookup Service Load Test${NC}"
echo "===================================="
echo "Base URL: $BASE_URL"
echo "Total Requests: $NUM_REQUESTS"
echo "Concurrency: $CONCURRENCY"
echo ""

# Test URLs
TEST_URLS=(
    "example.com/test"
    "malicious-site.com/download"
    "google.com/search?q=test"
    "phishing-bank.com/login"
    "safe-domain.org/page"
)

# Check if server is running
echo -e "${BLUE}Checking server status...${NC}"
if ! curl -s "${BASE_URL}/health" > /dev/null 2>&1; then
    echo -e "${YELLOW}⚠️  Warning: Server may not be running at ${BASE_URL}${NC}"
    echo "   Start the server first with: ./start_server.sh"
    exit 1
fi
echo -e "${GREEN}✅ Server is running${NC}"
echo ""

# Function to run concurrent requests using xargs
run_concurrent_test() {
    local num_requests=$1
    local concurrency=$2
    
    echo -e "${BLUE}Running $num_requests requests with concurrency $concurrency...${NC}"
    
    # Create a temporary file with all URLs
    temp_file=$(mktemp)
    for ((i=1; i<=num_requests; i++)); do
        url_index=$((i % ${#TEST_URLS[@]}))
        echo "${BASE_URL}/urlinfo/1/${TEST_URLS[$url_index]}"
    done > "$temp_file"
    
    start_time=$(date +%s.%N)
    
    # Run concurrent requests using xargs and curl
    cat "$temp_file" | xargs -P "$concurrency" -I {} curl -s -o /dev/null -w "%{http_code}\n" {} | \
        awk '{
            total++; 
            if ($1 == 200 || $1 == 400) success++; 
            else errors++;
        } END {
            print "Success: " success;
            print "Errors: " errors;
            print "Total: " total;
        }'
    
    end_time=$(date +%s.%N)
    duration=$(echo "$end_time - $start_time" | bc)
    rps=$(echo "scale=2; $num_requests / $duration" | bc)
    
    echo ""
    echo -e "${GREEN}✅ Test completed in ${duration}s${NC}"
    echo -e "${GREEN}   Throughput: ${rps} req/s${NC}"
    
    rm "$temp_file"
}

# Check if wrk is available for more advanced testing
if command -v wrk &> /dev/null; then
    echo -e "${BLUE}wrk detected! Running advanced load test...${NC}"
    echo ""
    wrk -t4 -c"$CONCURRENCY" -d10s --latency "${BASE_URL}/urlinfo/1/example.com/test"
    echo ""
else
    # Fall back to curl-based testing
    run_concurrent_test "$NUM_REQUESTS" "$CONCURRENCY"
fi

echo ""
echo -e "${BLUE}📊 View real-time metrics at: ${BASE_URL}/dashboard${NC}"
echo ""
echo -e "${YELLOW}💡 Tips:${NC}"
echo "   - Increase requests: NUM_REQUESTS=5000 ./load_test.sh"
echo "   - Increase concurrency: CONCURRENCY=100 ./load_test.sh"
echo "   - Install wrk for better testing: brew install wrk"
echo ""

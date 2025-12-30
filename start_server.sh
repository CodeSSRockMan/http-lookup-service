#!/bin/bash
# Script to start the HTTP Lookup Service server

set -e  # Exit on error

echo "🚀 Starting HTTP Lookup Service..."
echo "===================================="

# Load configuration to get host and port
HOST=$(grep -A 2 "^server:" config.yaml | grep "host:" | awk '{print $2}' | tr -d '"' || echo "0.0.0.0")
PORT=$(grep -A 2 "^server:" config.yaml | grep "port:" | awk '{print $2}' || echo "8000")

echo "Configuration:"
echo "  Host: $HOST"
echo "  Port: $PORT"
echo ""

# Check if uvicorn is installed
if ! command -v uvicorn &> /dev/null; then
    echo "❌ Error: uvicorn is not installed."
    echo "Install it with: pip install fastapi uvicorn aiosqlite pyyaml"
    exit 1
fi

# Create a PID file
PID_FILE=".server.pid"

# Clean up function for graceful shutdown
cleanup() {
    echo ""
    echo "🛑 Stopping server..."
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p $PID > /dev/null 2>&1; then
            kill $PID 2>/dev/null || true
            echo "✅ Server stopped successfully (PID: $PID)"
        fi
        rm -f "$PID_FILE"
    fi
    exit 0
}

# Trap SIGINT (Ctrl+C) and SIGTERM
trap cleanup SIGINT SIGTERM

# Start the server
echo "✅ Server starting..."
echo "   Access the frontend at: http://localhost:$PORT"
echo "   Press Ctrl+C to stop the server"
echo ""

# Start with reload for development (single worker only)
uvicorn main:app --host $HOST --port $PORT --reload --workers 1 &
SERVER_PID=$!

# Save PID to file
echo $SERVER_PID > "$PID_FILE"

# Wait for the server process
wait $SERVER_PID

# Cleanup on exit
cleanup

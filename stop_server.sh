#!/bin/bash
# Script to stop the HTTP Lookup Service server

echo "🛑 Stopping HTTP Lookup Service..."

PID_FILE=".server.pid"

if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if ps -p $PID > /dev/null 2>&1; then
        kill $PID
        echo "✅ Server stopped successfully (PID: $PID)"
    else
        echo "⚠️  No server process found with PID: $PID"
    fi
    rm -f "$PID_FILE"
else
    echo "⚠️  No PID file found. Server might not be running."
    echo "Attempting to find and stop uvicorn processes..."
    
    # Try to find and kill uvicorn processes
    PIDS=$(pgrep -f "uvicorn main:app" || true)
    if [ -n "$PIDS" ]; then
        echo "Found uvicorn processes: $PIDS"
        kill $PIDS 2>/dev/null || true
        echo "✅ Stopped uvicorn processes"
    else
        echo "No uvicorn processes found"
    fi
fi

# Automation Scripts Guide

This document describes the automation scripts provided for easy development and testing.

## Available Scripts

### 1. `run_tests.sh` - Run All Tests

Runs the complete test suite with verbose output.

```bash
./run_tests.sh
```

**Features:**
- Checks if pytest is installed
- Runs all 38 tests with colored output
- Shows clear success/failure messages
- Exits with proper error codes

**Output Example:**
```
🧪 Running HTTP Lookup Service Tests...
========================================
========================= test session starts =========================
...
========================= 38 passed in 0.40s ==========================

✅ All tests passed successfully!
```

---

### 2. `start_server.sh` - Start the Server

Starts the FastAPI server with graceful shutdown handling.

```bash
./start_server.sh
```

**Features:**
- Reads configuration from `config.yaml`
- Creates a PID file (`.server.pid`) for tracking
- Enables hot-reload for development
- Handles Ctrl+C gracefully
- Cleans up on exit

**How to Stop:**
- Press `Ctrl+C` in the terminal (graceful shutdown)
- Or use `./stop_server.sh` from another terminal

**Output Example:**
```
🚀 Starting HTTP Lookup Service...
====================================
Configuration:
  Host: 0.0.0.0
  Port: 8000

✅ Server starting...
   Access the frontend at: http://localhost:8000
   Press Ctrl+C to stop the server
```

---

### 3. `stop_server.sh` - Stop the Server

Stops a running server started with `start_server.sh`.

```bash
./stop_server.sh
```

**Features:**
- Uses PID file to find the server process
- Gracefully terminates the server
- Falls back to finding uvicorn processes if PID file is missing
- Cleans up PID file

**Output Example:**
```
🛑 Stopping HTTP Lookup Service...
✅ Server stopped successfully (PID: 12345)
```

---

## Common Workflows

### Development Workflow

```bash
# 1. Start the server
./start_server.sh

# 2. Make changes to code (hot-reload will restart automatically)

# 3. Run tests
./run_tests.sh

# 4. Stop the server when done
# Press Ctrl+C in the server terminal
# OR from another terminal:
./stop_server.sh
```

### Testing Workflow

```bash
# Run tests before committing
./run_tests.sh

# If tests pass, commit changes
git add .
git commit -m "your message"
```

### Complete Restart

```bash
# Stop the server
./stop_server.sh

# Wait a moment
sleep 2

# Start fresh
./start_server.sh
```

---

## Technical Details

### PID File Management

The scripts use `.server.pid` to track the server process:
- Created when server starts
- Contains the process ID
- Deleted when server stops
- Added to `.gitignore` to avoid commits

### Signal Handling

The `start_server.sh` script traps these signals for graceful shutdown:
- `SIGINT` (Ctrl+C)
- `SIGTERM` (kill command)

### Hot Reload

The server starts with `--reload` flag enabled, which means:
- Changes to Python files trigger automatic restart
- No need to manually restart during development
- Uses single worker mode (required for reload)

---

## Troubleshooting

### Port Already in Use

If you see "Address already in use":

```bash
# Stop any running servers
./stop_server.sh

# Or manually kill processes on port 8000
lsof -ti:8000 | xargs kill -9
```

### Server Won't Stop

If `stop_server.sh` doesn't work:

```bash
# Find and kill uvicorn processes
pkill -f "uvicorn main:app"

# Or find processes on port 8000
lsof -ti:8000 | xargs kill -9
```

### Tests Failing

Make sure the database is initialized:

```bash
# Remove old database
rm -f databases/url_lookup.db

# Restart server (will reinitialize)
./stop_server.sh
./start_server.sh
```

---

## Script Permissions

All scripts are executable by default. If you get permission errors:

```bash
chmod +x run_tests.sh start_server.sh stop_server.sh
```

---

## See Also

- [README.md](README.md) - Main project documentation
- [CONFIG.md](docs/CONFIG.md) - Configuration guide
- [API.md](docs/API.md) - API documentation

#!/bin/bash
# Script to run all tests for HTTP Lookup Service

set -e  # Exit on error

echo "🧪 Running HTTP Lookup Service Tests..."
echo "========================================"

# Check if pytest is installed
if ! command -v pytest &> /dev/null; then
    echo "❌ Error: pytest is not installed."
    echo "Install it with: pip install pytest pytest-asyncio httpx"
    exit 1
fi

# Run tests with verbose output
pytest tests/ -v --color=yes

# Check test result
if [ $? -eq 0 ]; then
    echo ""
    echo "✅ All tests passed successfully!"
else
    echo ""
    echo "❌ Some tests failed. Please review the output above."
    exit 1
fi

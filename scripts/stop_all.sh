#!/usr/bin/env bash
# Stop all running AnswerChain nodes and servers on ports 5001, 5002, 5003, and 8000

echo "Stopping AnswerChain platform services..."

for port in 5001 5002 5003 8000; do
    PID=$(lsof -ti :$port || true)
    if [ -n "$PID" ]; then
        echo "Stopping process $PID on port $port..."
        kill -9 $PID 2>/dev/null || true
    else
        echo "Port $port is already free."
    fi
done

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rm -f "$PROJECT_ROOT/logs/pids.txt"

echo "AnswerChain services stopped."

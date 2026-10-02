#!/usr/bin/env bash
# Stop all running AnswerChain nodes on ports 5001, 5002, 5003

echo "Stopping AnswerChain cluster nodes..."

for port in 5001 5002 5003; do
    PID=$(lsof -ti :$port || true)
    if [ -n "$PID" ]; then
        echo "Stopping process $PID on port $port..."
        kill -9 $PID 2>/dev/null || true
    else
        echo "Port $port is already free."
    fi
done

echo "Cluster nodes stopped."

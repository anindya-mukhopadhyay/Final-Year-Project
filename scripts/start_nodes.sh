#!/usr/bin/env bash
# Start all three AnswerChain distributed nodes

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Ensure venv Python is used if available, otherwise python3
if [ -f "$PROJECT_ROOT/venv/bin/python" ]; then
    PYTHON_BIN="$PROJECT_ROOT/venv/bin/python"
else
    PYTHON_BIN="python3"
fi

mkdir -p "$PROJECT_ROOT/logs"

echo "================================================="
echo " Starting AnswerChain Distributed Cluster (3 Nodes)"
echo "================================================="

# Node 1: University
echo "Starting node-1 (UNIVERSITY) on port 5001..."
NODE_ID="node-1" \
NODE_ROLE="UNIVERSITY" \
NODE_PORT="5001" \
PEERS="127.0.0.1:5002,127.0.0.1:5003" \
nohup "$PYTHON_BIN" nodes/node.py > "$PROJECT_ROOT/logs/node-1.log" 2>&1 &

sleep 1

# Node 2: Teacher
echo "Starting node-2 (TEACHER) on port 5002..."
NODE_ID="node-2" \
NODE_ROLE="TEACHER" \
NODE_PORT="5002" \
PEERS="127.0.0.1:5001,127.0.0.1:5003" \
nohup "$PYTHON_BIN" nodes/node.py > "$PROJECT_ROOT/logs/node-2.log" 2>&1 &

sleep 1

# Node 3: Authority
echo "Starting node-3 (AUTHORITY) on port 5003..."
NODE_ID="node-3" \
NODE_ROLE="AUTHORITY" \
NODE_PORT="5003" \
PEERS="127.0.0.1:5001,127.0.0.1:5002" \
nohup "$PYTHON_BIN" nodes/node.py > "$PROJECT_ROOT/logs/node-3.log" 2>&1 &

sleep 2

echo "All 3 nodes launched."
echo "  - node-1: http://127.0.0.1:5001 (UNIVERSITY)"
echo "  - node-2: http://127.0.0.1:5002 (TEACHER)"
echo "  - node-3: http://127.0.0.1:5003 (AUTHORITY)"
echo "Logs available in $PROJECT_ROOT/logs/"

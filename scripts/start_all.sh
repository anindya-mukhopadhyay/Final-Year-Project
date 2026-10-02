#!/usr/bin/env bash
# Start AnswerChain distributed cluster (3 nodes) and the Enterprise Application Server (port 8000)

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

if [ -f "$PROJECT_ROOT/venv/bin/python" ]; then
    PYTHON_BIN="$PROJECT_ROOT/venv/bin/python"
else
    PYTHON_BIN="python3"
fi

mkdir -p "$PROJECT_ROOT/logs"

echo "=========================================================="
echo "    Starting AnswerChain Complete Distributed Platform   "
echo "=========================================================="

# 1. Start Node 1 (University - 5001)
echo "Starting Node-1 (UNIVERSITY) on port 5001..."
NODE_ID="node-1" \
NODE_ROLE="UNIVERSITY" \
NODE_PORT="5001" \
PEERS="127.0.0.1:5002,127.0.0.1:5003" \
nohup "$PYTHON_BIN" nodes/node.py > "$PROJECT_ROOT/logs/node-1.log" 2>&1 &

sleep 1

# 2. Start Node 2 (Teacher - 5002)
echo "Starting Node-2 (TEACHER) on port 5002..."
NODE_ID="node-2" \
NODE_ROLE="TEACHER" \
NODE_PORT="5002" \
PEERS="127.0.0.1:5001,127.0.0.1:5003" \
nohup "$PYTHON_BIN" nodes/node.py > "$PROJECT_ROOT/logs/node-2.log" 2>&1 &

sleep 1

# 3. Start Node 3 (Authority - 5003)
echo "Starting Node-3 (AUTHORITY) on port 5003..."
NODE_ID="node-3" \
NODE_ROLE="AUTHORITY" \
NODE_PORT="5003" \
PEERS="127.0.0.1:5001,127.0.0.1:5002" \
nohup "$PYTHON_BIN" nodes/node.py > "$PROJECT_ROOT/logs/node-3.log" 2>&1 &

sleep 2

# 4. Start Enterprise Application Server (Port 8000)
echo "Starting AnswerChain Enterprise Application Server on port 8000..."
PORT="8000" \
nohup "$PYTHON_BIN" backend/server.py > "$PROJECT_ROOT/logs/server.log" 2>&1 &

sleep 2

echo "=========================================================="
echo " AnswerChain Platform is Online!"
echo "   - Enterprise Application: http://127.0.0.1:8000"
echo "   - University Portal:     http://127.0.0.1:8000/university/dashboard.html"
echo "   - Teacher Portal:        http://127.0.0.1:8000/teacher/dashboard.html"
echo "   - Authority Portal:      http://127.0.0.1:8000/authority/dashboard.html"
echo "   - Admin Dashboard:       http://127.0.0.1:8000/admin/dashboard.html"
echo "   - Public Verification:   http://127.0.0.1:8000/verify/index.html"
echo "   - Blockchain Monitor:    http://127.0.0.1:8000/index.html"
echo "   - Node 1 (University):   http://127.0.0.1:5001"
echo "   - Node 2 (Teacher):      http://127.0.0.1:5002"
echo "   - Node 3 (Authority):    http://127.0.0.1:5003"
echo "=========================================================="

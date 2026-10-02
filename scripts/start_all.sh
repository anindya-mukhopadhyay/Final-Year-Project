#!/usr/bin/env bash
# Start AnswerChain distributed cluster (3 nodes) and the Enterprise Application Server (port 8000)

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Resolve Python interpreter (prefer virtual environment)
if [ -f "$PROJECT_ROOT/venv/bin/python3" ]; then
    PYTHON_BIN="$PROJECT_ROOT/venv/bin/python3"
elif [ -f "$PROJECT_ROOT/venv/bin/python" ]; then
    PYTHON_BIN="$PROJECT_ROOT/venv/bin/python"
else
    PYTHON_BIN="python3"
fi

mkdir -p "$PROJECT_ROOT/logs"
PID_FILE="$PROJECT_ROOT/logs/pids.txt"

echo "=========================================================="
echo "    Starting AnswerChain Complete Distributed Platform   "
echo "=========================================================="

# Node authentication token
export NODE_AUTH_TOKEN="${NODE_AUTH_TOKEN:-dev-node-peer-auth-token-389fbc8102}"

# 0. Clean up existing processes on the required ports to avoid duplicates
echo "Checking existing services on ports 5001, 5002, 5003, 8000..."
for port in 5001 5002 5003 8000; do
    OLD_PID=$(lsof -ti :$port || true)
    if [ -n "$OLD_PID" ]; then
        echo "  Stopping existing process $OLD_PID on port $port..."
        kill -15 $OLD_PID 2>/dev/null || true
        sleep 0.5
        kill -9 $OLD_PID 2>/dev/null || true
    fi
done

> "$PID_FILE"

# 1. Start Node 1 (University - 5001)
echo "Starting Node-1 (UNIVERSITY) on port 5001..."
NODE_ID="node-1" \
NODE_ROLE="UNIVERSITY" \
NODE_PORT="5001" \
PEERS="127.0.0.1:5002,127.0.0.1:5003" \
nohup "$PYTHON_BIN" nodes/node.py > "$PROJECT_ROOT/logs/node-1.log" 2>&1 &
PID_NODE1=$!
echo "$PID_NODE1" >> "$PID_FILE"

# 2. Start Node 2 (Teacher - 5002)
echo "Starting Node-2 (TEACHER) on port 5002..."
NODE_ID="node-2" \
NODE_ROLE="TEACHER" \
NODE_PORT="5002" \
PEERS="127.0.0.1:5001,127.0.0.1:5003" \
nohup "$PYTHON_BIN" nodes/node.py > "$PROJECT_ROOT/logs/node-2.log" 2>&1 &
PID_NODE2=$!
echo "$PID_NODE2" >> "$PID_FILE"

# 3. Start Node 3 (Authority - 5003)
echo "Starting Node-3 (AUTHORITY) on port 5003..."
NODE_ID="node-3" \
NODE_ROLE="AUTHORITY" \
NODE_PORT="5003" \
PEERS="127.0.0.1:5001,127.0.0.1:5002" \
nohup "$PYTHON_BIN" nodes/node.py > "$PROJECT_ROOT/logs/node-3.log" 2>&1 &
PID_NODE3=$!
echo "$PID_NODE3" >> "$PID_FILE"

# 4. Start Enterprise Application Server (Port 8000)
echo "Starting AnswerChain Enterprise Application Server on port 8000..."
PORT="8000" \
nohup "$PYTHON_BIN" backend/server.py > "$PROJECT_ROOT/logs/server.log" 2>&1 &
PID_SERVER=$!
echo "$PID_SERVER" >> "$PID_FILE"

# ==========================================================
# 6. STARTUP HEALTH CHECKS
# Automatically verify in order:
# 127.0.0.1:5001/node
# 127.0.0.1:5002/node
# 127.0.0.1:5003/node
# 127.0.0.1:5001/network
# 127.0.0.1:8000
# 127.0.0.1:8000/api/admin/network
# ==========================================================
echo ""
echo "Performing automated startup health verification..."

wait_for_endpoint() {
    local url="$1"
    local name="$2"
    local max_retries=15
    local count=0

    while [ $count -lt $max_retries ]; do
        if curl -s -f -m 2 "$url" > /dev/null 2>&1; then
            echo "  ✓ $name verified: $url"
            return 0
        fi
        sleep 0.5
        count=$((count + 1))
    done

    echo "  ✗ Error: Failed to connect to $name at $url after $max_retries attempts."
    return 1
}

wait_for_endpoint "http://127.0.0.1:5001/node" "Node-1 (University)" || exit 1
wait_for_endpoint "http://127.0.0.1:5002/node" "Node-2 (Teacher)" || exit 1
wait_for_endpoint "http://127.0.0.1:5003/node" "Node-3 (Authority)" || exit 1
wait_for_endpoint "http://127.0.0.1:5001/network" "Node-1 Network Topology" || exit 1
wait_for_endpoint "http://127.0.0.1:8000" "Application Server" || exit 1
wait_for_endpoint "http://127.0.0.1:8000/api/admin/network" "Application Cluster API (/api/admin/network)" || exit 1

echo ""
echo "=========================================================="
echo " AnswerChain Platform is Online & Verified!"
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

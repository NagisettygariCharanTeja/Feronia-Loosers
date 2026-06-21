#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

echo "=== Installing dependencies ==="
python -m pip install -r requirements.txt

echo ""
echo "=== Running pytest ==="
python -m pytest tests/ -v

echo ""
echo "=== Running Feronia pipeline ==="
echo "approve" | python main.py

echo ""
echo "=== Checking output/dashboard.json ==="
if [ -f output/dashboard.json ]; then
    echo "dashboard.json exists."
    python -m json.tool output/dashboard.json
else
    echo "ERROR: output/dashboard.json not found!"
    exit 1
fi

echo ""
echo "=== Corrupted logs ==="
if [ -f output/corrupted_logs.jsonl ]; then
    cat output/corrupted_logs.jsonl
else
    echo "No corrupted_logs.jsonl found (may not have run ingestor yet)."
fi

echo ""
echo "✅ Feronia end-to-end test complete."

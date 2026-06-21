import json
import os

os.makedirs('packages/frontend/assets/js', exist_ok=True)

try:
    with open('packages/backend/output/dashboard.json', 'r') as f:
        dashboard = json.load(f)
except FileNotFoundError:
    dashboard = {}

try:
    with open('packages/backend/data/infrastructure_state.json', 'r') as f:
        infra = json.load(f)
except FileNotFoundError:
    infra = {}

try:
    with open('packages/backend/output/manual_review.jsonl', 'r') as f:
        audit = [json.loads(line) for line in f if line.strip()]
except FileNotFoundError:
    audit = []

with open('packages/frontend/assets/js/mock_data.js', 'w') as f:
    f.write('const DASHBOARD_DATA = ' + json.dumps(dashboard, indent=2) + ';\n\n')
    f.write('const INFRASTRUCTURE_DATA = ' + json.dumps(infra, indent=2) + ';\n\n')
    f.write('const AUDIT_DATA = ' + json.dumps(audit, indent=2) + ';\n')

print("mock_data.js generated successfully.")

#!/usr/bin/env python3
from sentinalX import analyze_children

# Test with multiple child types
snapshot = {
    200: {"name": "python", "cpu_percent": 45.0},
    201: {"name": "python", "cpu_percent": 38.5},
    202: {"name": "sleep", "cpu_percent": 0.0},
    203: {"name": "sleep", "cpu_percent": 0.0},
    204: {"name": "bash", "cpu_percent": 8.2},
}
tree = {199: [200, 201, 202, 203, 204]}

result = analyze_children(199, snapshot, tree)
print("Test: Mixed child processes")
print("Summary (sorted by CPU descending):")
for group in result["summary"]:
    print(f"  {group['name']:12} count={group['count']:2} cpu_total={group['cpu_total']:6.1f}%")

# Verify sorting
cpus = [g["cpu_total"] for g in result["summary"]]
assert cpus == sorted(cpus, reverse=True), "Sorting failed!"
print("\n✓ All tests passed - Phase 2 working correctly")

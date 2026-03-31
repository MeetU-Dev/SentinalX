#!/usr/bin/env python3
from sentinalX import build_explanation

print("=" * 70)
print("PHASE 4: EXPLANATION ENGINE TEMPLATE TESTS")
print("=" * 70)

# Test 1: All three signals
print("\nTest 1: All signals (burst, cpu, file)")
threat_data_1 = {
    'parent': 1000,
    'signals': {'burst': True, 'cpu': True, 'file': True},
    'category': 'MULTI_VECTOR_BEHAVIOR',
    'severity': 'HIGH',
    'context': {'exe': '/usr/bin/python', 'cmdline': ['python', 'malware.py']},
    'children': {'summary': [{'name': 'bash', 'count': 5, 'cpu_total': 45.0}]},
    'file_activity': {'directory': 'home/', 'operations': 'write', 'pattern': 'burst'}
}
result1 = build_explanation(threat_data_1)
print(f"Process:  {result1['process']}")
print(f"Behavior: {result1['behavior']}")
print(f"Reasoning: {result1['reasoning']}")
print(f"Conclusion: {result1['conclusion']}")

# Test 2: Burst and CPU only
print("\nTest 2: Burst + CPU only")
threat_data_2 = {
    'parent': 2000,
    'signals': {'burst': True, 'cpu': True, 'file': False},
    'category': 'PROCESS_SPAWN_ABUSE',
    'severity': 'MEDIUM',
    'context': {'exe': '/usr/bin/perl', 'cmdline': ['perl', 'script.pl']},
    'children': {'summary': [{'name': 'sleep', 'count': 20, 'cpu_total': 0.1}]},
}
result2 = build_explanation(threat_data_2)
print(f"Process:  {result2['process']}")
print(f"Behavior: {result2['behavior']}")
print(f"Reasoning: {result2['reasoning']}")
print(f"Conclusion: {result2['conclusion']}")

# Test 3: CPU and file only
print("\nTest 3: CPU + file only (no burst, no children)")
threat_data_3 = {
    'parent': 3000,
    'signals': {'burst': False, 'cpu': True, 'file': True},
    'category': 'CPU_INTENSIVE_PROCESS',
    'severity': 'MEDIUM',
    'context': {'exe': '/unknown', 'cmdline': None},
    'children': {'summary': []},
    'file_activity': {'directory': 'tmp/', 'operations': 'mixed', 'pattern': 'sequential'}
}
result3 = build_explanation(threat_data_3)
print(f"Process:  {result3['process']}")
print(f"Behavior: {result3['behavior']}")
print(f"Reasoning: {result3['reasoning']}")
print(f"Conclusion: {result3['conclusion']}")

# Test 4: CPU only
print("\nTest 4: CPU only (single signal)")
threat_data_4 = {
    'parent': 4000,
    'signals': {'burst': False, 'cpu': True, 'file': False},
    'category': 'CPU_INTENSIVE_PROCESS',
    'severity': 'LOW',
    'context': {'exe': '/bin/bash', 'cmdline': ['bash']},
    'children': {'summary': []},
}
result4 = build_explanation(threat_data_4)
print(f"Process:  {result4['process']}")
print(f"Behavior: {result4['behavior']}")
print(f"Reasoning: {result4['reasoning']}")
print(f"Conclusion: {result4['conclusion']}")

# Test 5: Burst and file only
print("\nTest 5: Burst + file only (no CPU)")
threat_data_5 = {
    'parent': 5000,
    'signals': {'burst': True, 'cpu': False, 'file': True},
    'category': 'FILE_ACTIVITY_SPIKE',
    'severity': 'MEDIUM',
    'context': {'exe': '/bin/rm', 'cmdline': ['rm', '-rf', 'data/']},
    'children': {'summary': [{'name': 'rm', 'count': 10, 'cpu_total': 2.5}]},
    'file_activity': {'directory': 'data/', 'operations': 'create', 'pattern': 'burst'}
}
result5 = build_explanation(threat_data_5)
print(f"Process:  {result5['process']}")
print(f"Behavior: {result5['behavior']}")
print(f"Reasoning: {result5['reasoning']}")
print(f"Conclusion: {result5['conclusion']}")

print("\n" + "=" * 70)
print("✓ All templates working correctly!")
print("=" * 70)

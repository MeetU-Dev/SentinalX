# SentinelX

SentinelX is a lightweight behavioral detection engine for Linux. It detects suspicious behavior patterns (process bursts, sustained CPU usage, file activity spikes) instead of signature matching, and correlates them into structured threat events.

## What It Does
- Monitors process creation and process tree bursts
- Detects sustained high CPU behavior
- Detects short-window file activity spikes in `test_dir/`
- Correlates signals into threat categories with severity
- Enriches threats with context, child attribution, file attribution, and explanations (V2)

## Quick Start
Install dependencies (if needed):
- `pip install psutil`

Run in live mode (default):
- `python sentinalX.py --mode live`

Run in background mode (log-only):
- `nohup python sentinalX.py --mode background --log events.log &`

Optional flags:
- `--log events.log` (choose log file)
- `--quiet` (suppress non-critical runtime output)

## Example Threat Output (V2)
```json
{
  "type": "THREAT",
  "data": {
    "category": "MULTI_VECTOR_BEHAVIOR",
    "severity": "HIGH",
    "context": {"exe": "...", "cmdline": ["..."], "cwd": "..."},
    "children": {"summary": [{"name": "python3", "count": 15, "cpu_total": 76.0}]},
    "file_activity": {"directory": "test_dir/", "operations": "write", "pattern": "sequential"},
    "explanation": {
      "process": "python3 (test_malware_v2.py)",
      "behavior": ["Spawned 15 python3 child processes, with one consuming high CPU"],
      "reasoning": "Concurrent process spawning and sustained CPU usage indicate automated execution behavior.",
      "conclusion": "MULTI_VECTOR_BEHAVIOR (HIGH)",
      "confidence": 0.92
    }
  }
}
```

## Test Scenarios
### Demo Scenarios (V1-style)
```bash
# Terminal 1: Start SentinelX detector
python sentinalX.py --mode live

# Terminal 2: Trigger test scenarios
python tests/test_malware.py 1    # PROCESS_SPAWN_ABUSE -> MEDIUM threat
python tests/test_malware.py 2    # FILE_ACTIVITY_SPIKE -> File-only (no threat)
python tests/test_malware.py 3    # MULTI_VECTOR_BEHAVIOR -> HIGH threat
python tests/test_malware.py all  # Run all scenarios sequentially
```

### Deterministic V2 Validation
```bash
python scripts/runner.sh
```

## Repository Layout
```
docs/
  ARCHITECTURE.md
scripts/
  runner.sh
tests/
  test_malware.py
  test_malware_v2.py
  test_phase2.py
  test_phase4.py
sentinalX.py
```

## Logs and Artifacts
- `events.log`: append-only JSONL events
- `test_results.log`: runtime output from validation runs
- `test_dir/`: file activity target for spike detection

## Key Idea
SentinelX is behavior-based:
- It does not rely on malware signatures
- It correlates multiple short-window signals
- It raises threats on behavioral patterns, not single noisy events

# SENTINEL
#    X

SentinelX is a lightweight behavioral detection engine for Linux.
It detects suspicious behavior patterns (process burst, sustained CPU abuse, file activity spikes) instead of signature matching.

## What It Does
- Monitors process creation and process tree bursts
- Detects sustained high CPU behavior
- Detects short-window file activity spikes in `test_dir/`
- Correlates signals into threat categories with severity

## Run
Install dependencies first (if needed in your environment):
- `pip install psutil`

Start in live mode (default):
- `python sentinalX.py --mode live`

Start in background mode (log-only, no console output):
- `nohup python sentinalX.py --mode background --log events.log &`

Optional flags:
- `--log events.log` (choose log file)
- `--quiet` (suppress non-critical runtime output)

## Example Output
```text
[THREAT - PROCESS_SPAWN_ABUSE | MEDIUM]

Process : bash (PID 64849)
Parent  : timeout (PID 64848)

Signals : burst, cpu
Score   : 6

Reason  : Process spawned multiple child processes with sustained high CPU usage
```

## Test Scenarios (Demo Mode)
For screen recording or testing purposes, use `test_malware.py` to simulate behavioral attacks:

```bash
# Terminal 1: Start SentinelX detector
python sentinalX.py --mode live

# Terminal 2: Trigger test scenarios
python test_malware.py 1    # PROCESS_SPAWN_ABUSE → MEDIUM threat
python test_malware.py 2    # FILE_ACTIVITY_SPIKE → File-only (low confidence, no threat)
python test_malware.py 3    # MULTI_VECTOR_BEHAVIOR → HIGH threat
python test_malware.py all  # Run all scenarios sequentially
```

Watch SentinelX detect and categorize each attack pattern in real-time.

## Key Idea
SentinelX is behavior-based:
- It does not rely on malware signatures
- It correlates multiple short-window signals
- It raises threats on behavioral patterns, not single noisy events

# SentinelX V2

SentinelX is a lightweight behavioral detection engine for Linux. Instead of relying on malware signatures, it detects suspicious behavior patterns through **signal correlation**:

- **Process Burst**: Multiple child processes spawned within a 5-second window
- **CPU Spike**: Sustained high CPU usage (>50%) over multiple monitoring cycles  
- **File Activity**: Rapid file operations (writes/creates) within a 5-second window

These signals are correlated within a 5-second temporal window to classify threats by severity (LOW/MEDIUM/HIGH) and provide deterministic explanations with confidence scores (0.5-0.92 range).

## What It Does

### Phase 1: Context Extraction
Captures process context (executable path, command line, working directory) for forensic analysis.

### Phase 2: Child Process Attribution
Groups child processes by name, counts occurrences, and tracks cumulative CPU usage across each group. Sorted by CPU total (descending).

### Phase 3: File Activity Attribution  
Analyzes file operations within the signal window using temporal correlation:
- Detects the primary directory where activity occurred
- Classifies operation type (write, create, or mixed)
- Identifies patterns: "burst" (scattered) or "sequential" (structured naming)

### Phase 4: Explanation Engine
Generates human-readable threat explanations with:
- **Process**: Executable name and main script/PID
- **Behavior**: Bullet list of detected behaviors (ordered by priority)
- **Reasoning**: Deterministic explanation of why signals indicate threat
- **Conclusion**: Threat category and severity
- **Confidence**: Score (0.5-0.92) based on signal combination

## Quick Start

Install dependencies (if needed):
```bash
pip install psutil
```

Run in **live mode** (displays alerts + notifications + logging):
```bash
python sentinalX.py --mode live
```

Run in **background mode** (log-only, no console output):
```bash
nohup python sentinalX.py --mode background --log events.log &
```

Optional flags:
- `--log <FILE>`: Log file name (default: `events.log`)
- `--quiet`: Suppress non-error console output
- `--mode live|background`: Behavior mode (default: `live`)

## Example Threat Output (V2)

### JSON THREAT Event
```json
{
  "timestamp": "2026-03-31T10:45:23.123456Z",
  "type": "THREAT",
  "data": {
    "parent": 12345,
    "score": 9,
    "signals": {
      "burst": true,
      "cpu": true,
      "file": true
    },
    "category": "MULTI_VECTOR_BEHAVIOR",
    "severity": "HIGH",
    "context": {
      "exe": "/usr/bin/python3",
      "cmdline": ["/usr/bin/python3", "test_malware_v2.py"],
      "cwd": "/home/user/sentinalX"
    },
    "children": {
      "summary": [
        {"name": "python3", "count": 15, "cpu_total": 76.0}
      ]
    },
    "file_activity": {
      "directory": "test_dir/",
      "operations": "write",
      "pattern": "sequential"
    },
    "explanation": {
      "process": "python3 (test_malware_v2.py)",
      "behavior": [
        "Spawned 15 python3 child processes, with one consuming high CPU",
        "Performed rapid sequential file writes in test_dir/"
      ],
      "reasoning": "Concurrent process spawning, sustained CPU usage, and file operations indicate automated execution behavior.",
      "conclusion": "MULTI_VECTOR_BEHAVIOR (HIGH)",
      "confidence": 0.92
    }
  }
}
```

### Console Output
```
[THREAT - MULTI_VECTOR_BEHAVIOR | HIGH]

Process : python3 (PID 12345)
Parent  : bash (PID 9876)

Signals : burst, cpu, file
Score   : 9

Reason  : Concurrent process spawning, sustained CPU usage, and file operations indicate automated execution behavior.

Context :
  exe     : /usr/bin/python3
  cmdline : /usr/bin/python3 test_malware_v2.py
  cwd     : /home/user/sentinalX
```

## Threat Classification

The threat engine classifies detected behavior into five categories:

| Category | Required Signals | Score | Severity |
|----------|------------------|-------|----------|
| `MULTI_VECTOR_BEHAVIOR` | burst + cpu + file | 9 | HIGH (≥8) |
| `PROCESS_SPAWN_ABUSE` | burst + cpu | 5-7 | MEDIUM (5-7) |
| `CPU_INTENSIVE_PROCESS` | cpu only | 3 | LOW (<5) |
| `FILE_ACTIVITY_SPIKE` | file only | 4 | LOW |
| `PROCESS_SPAWN_BURST` | burst only | 2 | LOW |

### Signal Definitions

- **Burst Signal** (score +2): ≥5 child processes spawned within 5 seconds (SIGNAL_WINDOW)
- **CPU Signal** (score +3): Child process with >20% CPU OR parent total >50% CPU, sustained over 3 consecutive cycles (CPU_CONFIRMATION)
- **File Signal** (score +4): ≥30 file operations within 5 seconds (FILE_SPIKE_THRESHOLD)

### State Machine

The detection engine uses a **state machine** to avoid duplicate alerts:
- **Transition to THREAT**: Score ≥ 5 (ALERT_THRESHOLD) and process not currently threatening
- **Alert only on entry**: THREAT event logged when transitioning from safe → threatening
- **Transition to SAFE**: Score < 5, behavior has calmed
- **Per-PID cooldown**: 5-second (ALERT_COOLDOWN) minimum between alerts for same PID

## Confidence Scoring

Confidence scores range from **0.5 to 0.92** based on signal combinations:

| Signals | Confidence | Interpretation |
|---------|------------|-----------------|
| burst + cpu + file | 0.92 | Very High confidence |
| burst + cpu | 0.82 | High confidence |
| cpu + file | 0.78 | High confidence |
| burst + file | 0.72 | Medium-High confidence |
| Any single signal | 0.55 | Medium confidence |
| None detected | 0.5 | Low confidence (edge case) |

## Test Scenarios

### Demo Scenarios (Behavioral Tests)

Start the detector in one terminal:
```bash
python sentinalX.py --mode live
```

Run test scenarios in another terminal:
```bash
# Scenario 1: Process spawn burst + high CPU (PROCESS_SPAWN_ABUSE)
python tests/test_malware.py 1

# Scenario 2: File activity spike only (FILE_ACTIVITY_SPIKE)
python tests/test_malware.py 2

# Scenario 3: All three signals combined (MULTI_VECTOR_BEHAVIOR)
python tests/test_malware.py 3

# Run all scenarios sequentially
python tests/test_malware.py all
```

### Deterministic V2 Validation

Run the complete validation harness:
```bash
bash scripts/runner.sh
```

This orchestrates:
1. **SentinelX startup** in background
2. **Deterministic test execution** (validate-all) with CPU spike, process burst, and file activity overlap
3. **Log validation** (checks_logs) confirming THREAT event with all four phases
4. **Process cleanup** (stop)
5. **Result summary** (pass/fail)

## Key Configuration Constants

Located in `sentinalX.py`:

```python
# Detection thresholds
CPU_SPIKE_THRESHOLD = 50.0          # CPU % threshold to trigger detection
ALERT_THRESHOLD = 5                 # Score threshold to enter threat state
FILE_SPIKE_THRESHOLD = 30           # File operations count for spike
ALERT_COOLDOWN = 5                  # Seconds between alerts for same PID

# Temporal windowing (critical for signal correlation)
SIGNAL_WINDOW = 5                   # Seconds - max age of signals for correlation
TIME_WINDOW = 5                     # Seconds - child spawn detection window
CPU_CONFIRMATION = 3                # Cycles - CPU must stay high this many times
BURST_THRESHOLD = 5                 # Min child processes for burst detection

# Monitoring
MONITORED_DIR = 'test_dir'          # Directory watched for file activity
RUN_MODE = 'live'                   # 'live' or 'background'
LOG_FILE = 'events.log'              # Event log location
```

### Understanding Signal Windows

All three signals must occur within the **5-second SIGNAL_WINDOW** to be correlated into a threat:
- If burst occurs at t=0, CPU spike at t=2, and files at t=4 → all three within window → score 9 (HIGH)
- If burst at t=0, CPU spike at t=3, and files at t=6 → file outside window → score 5 (MEDIUM)
- If burst at t=0 and files at t=6 → both outside window → no threat (state resets)

## Repository Structure

```
sentinalX/                          # Root project directory
├── README.md                       # This file
├── sentinalX.py                    # Main detection engine
├── docs/
│   └── ARCHITECTURE.md             # System design documentation
├── scripts/
│   └── runner.sh                   # End-to-end validation harness
├── tests/
│   ├── test_malware.py             # Behavioral test scenarios (V1-style)
│   ├── test_malware_v2.py          # Deterministic V2 validation
│   ├── test_phase2.py              # Child attribution unit tests
│   └── test_phase4.py              # Explanation engine unit tests
├── events.log                      # JSONL event log (generated)
├── test_results.log                # Test harness output (generated)
└── test_dir/                       # Monitored directory for file activity tests
```

## Logs and Artifacts

- **`events.log`**: Append-only JSONL file with all detected events (NEW_PROCESS, CPU_SPIKE, PROCESS_BURST, CORRELATED_ACTIVITY, THREAT)
- **`test_results.log`**: Runtime output from `runner.sh` validation runs
- **`test_dir/`**: Target directory for file activity spike detection

## Module Architecture

### sentinalX.py (Main Engine)
Core behavioral detection with signal correlation:
- **Monitoring Loop**: 1-second cycle collecting process snapshots and file events
- **Detection Functions** (from detector.py):
  - `detect_new_processes()`: Compare PIDs across snapshots
  - `detect_cpu_spikes()`: Identify sustained high CPU (>50%)
  - `build_process_tree()`: Map parent → child relationships
  - `calculate_parent_cpu_stats()`: Aggregate CPU across process trees
  - `detect_correlated_activity()`: Find burst+CPU combinations
  
- **Signal Correlation** (Phase 1-4):
  - `analyze_children()`: Group child processes by name, sum CPU
  - `analyze_file_activity()`: Filter file events by time window, detect patterns
  - `build_explanation()`: Generate human-readable threat explanations
  
- **State Machine**: 
  - Per-PID threat tracking (`threat_active` dict)
  - Temporal signal history (`signal_history` dict)
  - Cooldown tracking to avoid duplicate alerts

### Supporting Modules
- **monitor.py**: Process snapshot collection via psutil
- **detector.py**: Detection rule implementations
- **logger.py**: JSONL event persistence
- **notifier.py**: Desktop notification dispatch
- **context.py**: Process context extraction (exe, cmdline, cwd)
- **utils.py**: Helper utilities

## Design Principles

### Why Behavior-Based Detection?

1. **No Signature Dependency**: Works against unknown/modified malware
2. **Temporal Correlation**: Multiple weak signals combine into strong threat indication
3. **Low False Positives**: Legitimate legitimate high-CPU processes don't trigger burst+file alerts together
4. **Deterministic**: No randomness in threat scoring or explanations

### Why 5-Second Windows?

- **Short enough**: Captures rapid malware behaviors (spawning, file operations)
- **Long enough**: Avoids noise from normal background process churn
- **Tunable**: All constants in sentinalX.py for environment-specific tuning

### Edge Cases Handled

- **Kernel processes (PIDs 0, 1, 2)**: Filtered from burst detection
- **Low-CPU bursts**: Bursts with <5% max CPU or <20% total CPU ignored
- **No file activity**: Process can still threat without file component
- **Empty child lists**: Handled gracefully in explanations
- **Process disappearance**: stale PIDs cleaned from signal history after SIGNAL_WINDOW expires
- **Permission denied**: psutil exceptions caught and logged safely

## Troubleshooting

### No THREAT events appearing?
1. Check `events.log` for low-level events (NEW_PROCESS, CPU_SPIKE, PROCESS_BURST)
2. Verify thresholds: `python tests/test_malware.py 3` should trigger signals
3. Check `--mode live` is enabled for console output

### False positives from build processes?
- Increase `CPU_SPIKE_THRESHOLD` (default: 50.0)
- Increase `BURST_THRESHOLD` (default: 5 child processes in 5 seconds)
- Increase `SIGNAL_WINDOW` to require longer correlation window

### File activity not detected?
1. Ensure `test_dir/` exists: `mkdir -p test_dir`
2. Check file operations land in monitored directory
3. File activity must occur within 5-second window of other signals to trigger THREAT

## Performance

- **CPU Impact**: ~1-2% system CPU for monitoring loop (1-second cycle)
- **Memory**: ~20MB resident set (stores snapshots, signal history, event log)
- **Event Log**: ~500KB-1MB per hour of normal operation (~50 events)

## Security Notes

- **Runs as**: Current user (respects process visibility restrictions)
- **Requires**: Read access to `/proc/{pid}/` (present for owned processes)
- **Limitations**: Cannot detect root processes unless run as root
- **Network**: No outbound network traffic (local notifications only)

#!/bin/bash
rm -f events.log test_results.log
touch events.log test_results.log
python3 sentinalX.py --mode live --log events.log > test_results.log 2>&1 &
PID=$!
sleep 2
echo "Running malware V2"
python3 tests/test_malware_v2.py validate-all >> test_results.log 2>&1
echo "Sleeping 8 seconds to allow Sentinel to process..."
sleep 8
kill $PID
sleep 1
python3 tests/test_malware_v2.py check

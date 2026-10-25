# Aman - Day 1 Notes (13 October 2026)

## Task: Normal Traffic Capture & Logger Test

### What I Did
- Captured real candump output from normal_traffic generator
- Wrote logger.py to parse space-separated candump format
- Successfully processed 1176 frames into CSV

### Commands
candump vcan0 > candump_output.txt
python3 logger.py

### Output
Processed 1176 frames -> can_log.csv

### Files Created
- normal_traffic.c - C program for normal CAN traffic
- logger.py - Python parser for candump output
- can_log.csv - Structured CAN data
- candump_output.txt - Raw candump capture

### Screenshots
- aman_candump.png
- aman_logger_run.png
- aman_csv.png

### Commit
"Day 2 (13 Oct): Logger tested with real generator data"

## Next Steps
- Add frequency summary per CAN ID
- Build feature extraction for ML1

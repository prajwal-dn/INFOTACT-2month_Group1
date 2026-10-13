# Aman - Day 2 Notes (13 October 2026)

## Task: Normal Traffic Capture & Logger Test

### What I Did
- Captured real candump output from normal_traffic generator
- Updated logger.py to parse space-separated candump format
- Successfully processed 1176 frames into CSV

### Commands Used
```bash
# Terminal 1: Start generator
./normal_traffic

# Terminal 2: Capture data
candump vcan0 > candump_output.txt

# Process captured data
python3 logger.py

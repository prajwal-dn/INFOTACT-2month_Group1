# Aman - Day 4 Notes (15 October 2026)

## Task: Attack Data Capture & Analysis

### What I Did
- Captured attack traffic from attack_simulator
- Converted to CSV using logger.py
- Analyzed frequency distribution

### Commands
candump vcan0 > attack_data.txt
python3 logger.py attack_data.txt
python3 frequency_analyzer.py can_log.csv

### Output
- Total frames: 5000
- CAN ID 100: 5000 frames (100%)
- High frequency attack: 0x100 comes 10x faster

### Observation
- Attack traffic has abnormal frequency
- Normal traffic: 41.67% per ID
- Attack traffic: 100% on one ID

### Screenshots
- aman_attack_capture.png
- aman_attack_csv.png
- aman_attack_analysis.png

## Next Steps
- Train Isolation Forest (16 Oct)

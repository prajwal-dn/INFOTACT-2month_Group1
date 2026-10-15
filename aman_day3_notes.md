# Aman - Day 3 Notes (14 October 2026)

## Task: Frequency Analysis of CAN Traffic

### What I Did
- Wrote frequency_analyzer.py to analyze can_log.csv
- Counted frames per CAN ID
- Calculated percentage distribution
- Listed unique payloads per CAN ID

### Commands
python3 frequency_analyzer.py

### Output Summary
- Total frames: 1176
- Unique CAN IDs: 3
- CAN ID 100 (RPM): 490 frames (41.67%)
- CAN ID 101 (Speed): 490 frames (41.67%)
- CAN ID 102 (Temperature): 196 frames (16.67%)

### Observation
- Normal traffic has consistent frequency per ID
- RPM and Speed come at same rate
- Temperature comes at lower rate (1 Hz vs 10 Hz)

### This Baseline Will Help
- Train Isolation Forest model tomorrow
- Detect anomalies (frequency too high or too low)

### Screenshot
aman_frequency_analysis.png

## Next Steps
- Build attack simulator (15 Oct)
- Train Isolation Forest (16 Oct)

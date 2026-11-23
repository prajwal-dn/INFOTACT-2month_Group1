# CAN-Sentinel Live Integration Verification

Environment: Kali Linux VirtualBox
CAN interface: vcan0
Model: Original Isolation Forest
Features: 14
Scikit-learn: 1.9.1

## Model integrity

SHA-256:
28a0feb7d886ff95e6e3ffb1ba34d209fc55081d9ba02269d6677b56a8c8f825

## Automated regression tests

Pytest: 44 passed, 7 subtests passed.
Capture validator: 6 passed, 0 failed.
Python syntax compilation: Passed.

## Live inference

Normal traffic:
328 events, 15 completed windows.
15 NORMAL, 0 ANOMALY.

High-frequency attack:
6074 events, 14 completed windows.
0 NORMAL, 14 ANOMALY.

Extended-ID attack:
317 events, 20 completed windows.
0 NORMAL, 20 ANOMALY.

## Socket integration

C sample producer:
2 events accepted.

Production C sniffer, normal traffic:
274 events accepted.

Production C sniffer, extended-ID attack:
350 events accepted.

## Offline inference

Normal traffic:
520 frames, 25 windows scored, 0 anomalies.

High-frequency attack:
9470 frames, 21 windows scored, 21 anomalies.

Unexpected extended ID:
337 frames, 19 windows scored, 19 anomalies.

## Limitations

All tests used simulated traffic on isolated vcan0.
No physical vehicle was connected.
The results do not establish real-world detection accuracy.
Live inference currently prints predictions to the terminal;
dashboard integration remains a separate task.

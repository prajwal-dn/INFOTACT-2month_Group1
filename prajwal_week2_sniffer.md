# CAN-Sentinel — C Sniffer and Attack Capture Results

**Owner:** Prajwal Dn
**Environment:** Kali Linux / virtual SocketCAN (`vcan0`)

## Implementation

Implemented `src/can_sniffer.c` to capture CAN frames from the
virtual interface and emit CSV records containing:

- UTC timestamp
- Interface
- CAN identifier
- Standard or extended frame format
- Frame flags
- DLC
- Payload

## Normal Traffic Test

Captured 105 frames during a controlled five-second generator run:

- CAN ID 0x100 (RPM): 50 frames
- CAN ID 0x101 (speed): 50 frames
- CAN ID 0x102 (coolant): 5 frames

The captured CSV included timestamps and valid payload lengths.

## High-Frequency Attack Capture

File: `data/high_frequency_capture.csv`

- Captured frames: 18,832
- CAN ID: 0x100
- Payload: FFFF
- Missing timestamps: 0
- Target interval: 1 ms
- Average observed interval: 2.346 ms
- Median observed interval: 2.031 ms
- Minimum/maximum interval: 0.008/2017.802 ms

## Unexpected Extended-ID Capture

File: `data/unexpected_id_capture.csv`

- Captured frames: 526
- CAN ID: 0x999
- Frame format: extended
- Payload: DEAD
- Missing timestamps: 0
- Target interval: 50 ms
- Average observed interval: 54.710 ms
- Median observed interval: 51.692 ms
- Minimum/maximum interval: 47.303/361.792 ms

## Limitations

The sniffer timestamps frames in user space. These observed intervals
are not a hardware-level timing guarantee. Virtual-machine scheduling
and capture delays can produce outliers. The measured results should
be reported as observed rather than as proof of exact transmission timing.

The sender and receiver counts may come from different runs or capture
windows and should not be compared directly without aligned timestamps.

## Safety

All traffic was generated and captured on the isolated virtual `vcan0`
interface. No physical vehicle or production network was used.

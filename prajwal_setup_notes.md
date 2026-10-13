# CAN-Sentinel — Setup Notes

**Contributor:** Prajwal Dn  
**Environment:** Kali Linux on VirtualBox  
**Virtual CAN Interface:** vcan0  
**Documentation date:** 14 October 2026

## 1. Objective

Configure a virtual CAN interface and verify CAN frame transmission
and reception in an isolated Linux environment.

## 2. Environment Setup

Loaded the virtual CAN kernel module:

    sudo modprobe vcan

Created the virtual interface when it did not already exist:

    sudo ip link add dev vcan0 type vcan

Enabled the interface:

    sudo ip link set up vcan0

Verified the interface:

    ip -details link show vcan0

The virtual CAN interface was successfully brought up.

## 3. CAN Frame Receive Test

Receiver command:

    candump vcan0

Sender command, executed in another terminal:

    cansend vcan0 123#DEADBEEF

Received output:

    vcan0  123  [4]  DE AD BE EF

## 4. Result

The virtual CAN interface successfully received the test frame.
The CAN identifier was 0x123, with four payload bytes:
DE AD BE EF.

## 5. Evidence

Screenshot: screenshots/prajwal_candump_test.png

## 6. Safety Scope

Testing is restricted to the virtual vcan0 interface. No physical
vehicle or production automotive CAN network was connected.

## 7. Next Steps

- Develop a C program to generate normal CAN traffic.
- Test RPM, vehicle speed, and coolant temperature messages.
- Verify generated frames on vcan0.

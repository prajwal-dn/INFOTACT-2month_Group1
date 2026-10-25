# 🛡️ CAN-Sentinel: Automotive ECU Intrusion Detection System

**Author:** Aman Gaikwad (`aman-cyber07`)  
**Domain:** Cyber Security / Cyber-Physical Systems  
**Project:** Infotact Solutions Internship (Module: Python ML Detection)  
**Branch:** `Aman-Gaikwad`

## 📖 Project Overview
CAN-Sentinel is a prototype Intrusion Detection System (IDS) designed for the Controller Area Network (CAN) bus in modern vehicles. Because CAN bus traffic lacks encryption and authentication, it is highly vulnerable to spoofing and Denial of Service (DoS) attacks. 

This repository contains the **Python Data Processing and Machine Learning pipeline**. It ingests raw CAN traffic, extracts time-windowed features, and applies an Isolation Forest machine learning model to detect anomalies such as message flooding and unexpected CAN IDs.

> **Safety Boundary:** All testing and attack simulations for this project are performed exclusively on an isolated virtual `vcan0` network. No physical vehicles or live networks are targeted.

## 📂 Repository Structure
```text
.
├── src/                  # Source code for parsing and ML
│   ├── logger.py         # Timestamp-aware candump parser
│   ├── frequency_analyzer.py # CAN ID frequency counter
│   └── train_detector.py # Feature extraction & Isolation Forest model
├── tests/                # Unit tests for parser and features
├── data/                 # Datasets (Normal & Attack CSVs) and output metrics
├── docs/                 # Daily progress notes and mid-review evidence
└── artifacts/            # Saved model binary (isolation_forest.joblib)

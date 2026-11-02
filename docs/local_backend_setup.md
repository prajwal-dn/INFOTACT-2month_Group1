# CAN-Sentinel — Local Backend Setup & VirtualBox Guide

This guide details how to install, configure, and operate the CAN-Sentinel FastAPI backend inside Kali Linux (VirtualBox) and connect the Lovable frontend.

---

## 1. VirtualBox Network Configuration

To allow your Windows host browser / Lovable frontend to access the FastAPI service running in Kali Linux:

1. In VirtualBox, select your **Kali Linux VM** -> **Settings** -> **Network**.
2. If using **NAT** (default):
   - Click **Advanced** -> **Port Forwarding**.
   - Add a new rule:
     - **Name:** `FastAPI`
     - **Protocol:** `TCP`
     - **Host IP:** `127.0.0.1`
     - **Host Port:** `8000`
     - **Guest IP:** (Leave blank)
     - **Guest Port:** `8000`
3. If using **Bridged Adapter** or **Host-Only Adapter**:
   - Run `ip a` inside Kali to find your VM's IP address (e.g. `192.168.56.101`).
   - Use `http://<KALI_IP>:8000` in the frontend backend settings.

---

## 2. Setting Up Virtual CAN (vcan0) in Kali Linux

Run the following commands inside Kali Linux terminal:

```bash
# Load the virtual CAN kernel module
sudo modprobe vcan

# Create and bring up the vcan0 interface
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

# Verify interface state
ip link show vcan0
```
Expected output: `... <NOARP,UP,LOWER_UP> mtu 72 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000`

---

## 3. Compiling the Production C Sniffer

Inside the repository root in Kali:

```bash
mkdir -p build
gcc -O2 -Wall -Wextra src/can_sniffer.c -o build/can_sniffer
chmod +x build/can_sniffer
```

Also compile the traffic generator and attack simulator for testing:
```bash
gcc -O2 -Wall -Wextra src/normal_traffic.c -o build/normal_traffic
gcc -O2 -Wall -Wextra src/attack_simulator.c -o build/attack_simulator
chmod +x build/normal_traffic build/attack_simulator
```

---

## 4. Installing Python API Dependencies

Inside the Kali Linux environment:

```bash
# Activate your project virtual environment
source .venv/bin/activate

# Install API requirements
pip install -r requirements-api.txt
```

---

## 5. Starting the FastAPI Backend

```bash
# Set CORS origins to allow your local Vite frontend
export CAN_SENTINEL_CORS_ORIGINS="http://localhost:5173,http://127.0.0.1:5173,http://localhost:8080,http://127.0.0.1:8080"

# Start Uvicorn on 0.0.0.0:8000
python src/api_server.py
```
Or directly via uvicorn:
```bash
uvicorn api_server:app --app-dir src --host 0.0.0.0 --port 8000
```

---

## 6. Connecting the Lovable Frontend

1. In the Lovable frontend web interface, navigate to the **Settings** / **Backend connection** page (`/backend`).
2. Select **FastAPI backend** (switches mode from `demo` to `api`).
3. Set Backend URL to `http://127.0.0.1:8000` (or `http://localhost:8000` / `http://<KALI_IP>:8000`).
4. Click **Save** and then **Test connection**.
5. Once verified:
   - Go to **Live monitor** (`/live`).
   - Confirm pre-flight checks: `vcan0 is UP`, sniffer is built, model is loaded.
   - Click **Start capture**.
   - In another terminal, generate traffic:
     ```bash
     # Normal traffic
     ./build/normal_traffic

     # Attack simulator (high frequency mode 1)
     ./build/attack_simulator 1 100

     # Attack simulator (unexpected ID mode 2)
     ./build/attack_simulator 2 20
     ```
   - Watch completed 1-second windows appear with real predictions in the table and live chart.
   - Click **Stop & analyze** to view the comprehensive `AnalysisResult`.

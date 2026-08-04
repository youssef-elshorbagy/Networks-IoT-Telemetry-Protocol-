# IoT Telemetry Protocol 


### Final Demo Video
https://drive.google.com/file/d/1ZGdacjdz2DCFYup1epudbYF93Y2JiecW/view?usp=sharing


### Prerequisites

```bash
# Python 3.6+
python3 --version

# Required packages
pip install scapy psutil
# or
sudo apt install python3-scapy python3-psutil

# For network impairment testing (Linux/WSL2 only)
# Requires iproute2 and sudo privileges
sudo apt install iproute2

# Note: netem (network impairment) requires kernel support
# WSL1 does not support netem. WSL2 may have limitations.
# For reliable netem testing, use a full Linux VM or native Linux.
```

## Usage

### 1. Manual Testing

**Terminal 1 - Start Server:**
```bash
python3 server.py
```

**Terminal 2 - Start Client(s):**
```bash
# Single client with device ID 0
python3 client.py 0

# Multiple clients (different terminals)
python3 client.py 1
python3 client.py 2
```

### 2. Automated Testing

**Run Interactive Test Menu:**
```bash
python3 test.py [num_clients]

# Examples:
python3 test.py          # 1 client (default)
python3 test.py 3        # 3 concurrent clients
```

### 3. Test Scenarios

The test runner includes 7 predefined scenarios:

1. **Baseline** - No network impairment
2. **Packet Loss 5%** - Simulates unreliable network
3. **Packet Loss 50%** - Extreme loss conditions
4. **Delay + Jitter (100ms ±10ms)** - Variable latency
5. **High Delay + Jitter (2000ms ±5000ms)** - Extreme conditions
6. **Duplicate 10%** - Duplicate packet testing
7. **Baseline Batch Mode (5 Packets)** - Batch transmission mode

### 4. Output & Metrics

The test runner automatically generates:
- **Device logs** - Saved in `device_logs/` (CSV format)
- **PCAP captures** - Saved in `pcap_captures/` (network packet captures)
- **Metrics CSV** - Saved to `final_metrics.csv`

Each test records:
- packets_received (successfully)
- bytes_per_report
- duplicate_rate
- sequence_gap_count
- cpu_ms_per_report

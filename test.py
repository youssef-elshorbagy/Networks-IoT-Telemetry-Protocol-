import subprocess
import time
import os
import sys
import threading
import csv
import shutil
import re  # Required for parsing server output
import matplotlib.pyplot as plt

# CONFIGURATION
SERVER_SCRIPT = "server.py"
CLIENT_SCRIPT = "client.py"
INTERFACE = "lo"            
LOG_DIR = "device_logs"      
PCAP_DIR = "pcap_captures"
GRAPH_DIR = "test_graphs"
RUN_DURATION = 20
SERVER_PORT = 5000
METRICS_FILE = "final_metrics.csv" 

os.makedirs(GRAPH_DIR, exist_ok=True)

# CSV SETTINGS 
CSV_MSG_TYPE_COL = 1  
CSV_SEQ_COL      = 3  

try:
    from scapy.all import sniff, wrpcap, rdpcap, UDP, conf
    conf.use_pcap = True
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠ Scapy not installed. PCAP metrics will be 0.")

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# METRIC ANALYZER
class MetricAnalyzer:
    @staticmethod
    def analyze(test_name, pcap_path, log_dir, server_cpu_time, server_dupes, server_gaps):
        print(f"\n--- Analysis Results for: {test_name} ---")
        
        # 1. USE EXPORTED VARIABLES FROM SERVER
        total_dupes = server_dupes
        total_gaps = server_gaps
        
        # 2. READ DEVICE LOGS
        unique_type1_packets = set()
        other_msg_count = 0
        
        if os.path.exists(log_dir):
            for filename in os.listdir(log_dir):
                if filename.endswith(".csv"):
                    try:
                        with open(os.path.join(log_dir, filename), 'r') as f:
                            reader = csv.reader(f)
                            for row in reader:
                                if not row: continue
                                try:
                                    msg_type = int(row[CSV_MSG_TYPE_COL].strip())
                                    # count message types
                                    if msg_type == 1:
                                        device_id = int(row[2].strip())
                                        seq = int(row[CSV_SEQ_COL].strip())
                                        unique_type1_packets.add((device_id, seq))
                                    else:
                                        other_msg_count += 1
                                except: continue
                    except: pass
        
        # Total valid packets processed by app = Unique Data + All Control Packets
        total_valid_logs = len(unique_type1_packets) + other_msg_count

        # 3. ANALYZE PCAP (Payload size metrics)
        total_report_bytes = 0
        report_packet_count = 0
        
        if SCAPY_AVAILABLE and os.path.exists(pcap_path):
            try:
                packets = rdpcap(pcap_path)
                for p in packets:
                    if p.haslayer(UDP) and p[UDP].dport == SERVER_PORT:
                        payload_len = p[UDP].len - 8
                        if payload_len >= 16:
                            total_report_bytes += payload_len
                            report_packet_count += 1
            except Exception as e:
                print(f"Error reading PCAP: {e}")

        # 4. COMPUTE FINAL METRICS
        if report_packet_count > 0:
            metric_bytes_per_rep = total_report_bytes / report_packet_count
        else:
            metric_bytes_per_rep = 0
        
        # Total Traffic = Valid Packets + Rejected Duplicates
        total_traffic = total_valid_logs + total_dupes
        metric_dup_rate = (total_dupes / total_traffic) if total_traffic > 0 else 0.0
        
        metric_cpu_per_rep = (server_cpu_time * 1000 / total_valid_logs) if total_valid_logs > 0 else 0

        # 5. PRINT & SAVE
        print(f"{'METRIC':<35} | {'VALUE':<15}")
        print("-" * 55)
        print(f"{'packets_received (successfully)':<35} | {total_valid_logs}")
        print(f"{'  (Unique Type 1)':<35} | {len(unique_type1_packets)}")
        print(f"{'  (All Type 0/2/3)':<35} | {other_msg_count}")
        print(f"{'Bytes per Report':<35} | {metric_bytes_per_rep:.2f} bytes")
        print(f"{'Duplicate Count':<35} | {total_dupes}")
        print(f"{'Duplicate Rate':<35} | {metric_dup_rate:.4f} ({metric_dup_rate*100:.2f}%)")
        print(f"{'Sequence Gap Count':<35} | {total_gaps}")
        print(f"{'CPU Time per Report':<35} | {metric_cpu_per_rep:.4f} ms")
        print("-" * 55 + "\n")
        
        MetricAnalyzer.save_to_csv(test_name, metric_bytes_per_rep, total_valid_logs, metric_dup_rate, total_gaps, metric_cpu_per_rep)
        MetricAnalyzer.plot_bytes_over_time(test_name, pcap_path)
        MetricAnalyzer.plot_duplicate_vs_loss()

    @staticmethod
    def save_to_csv(name, bytes_val, pkts, dup_rate, gaps, cpu):
        file_exists = os.path.exists(METRICS_FILE)
        try:
            with open(METRICS_FILE, mode='a', newline='') as f:
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow(["Test Name", "packets_received", "bytes_per_report", "duplicate_rate", "sequence_gap_count", "cpu_ms_per_report"])
                
                writer.writerow([name, pkts, f"{bytes_val:.2f}", f"{dup_rate:.4f}", gaps, f"{cpu:.4f}"])
                print(f"Metrics saved to {METRICS_FILE}")
        except Exception as e:
            print(f"Error saving to CSV: {e}")

    @staticmethod
    def plot_bytes_over_time(test_name, pcap_path):
        """Generates a line chart of Bytes per Packet vs Time for the CURRENT test only."""
        if not SCAPY_AVAILABLE or not os.path.exists(pcap_path):
            print("⚠ Cannot plot timeline: Scapy missing or PCAP empty.")
            return

        print("Generating time-series plot...")
        try:
            import matplotlib
            matplotlib.use('Agg')
            import matplotlib.pyplot as plt
            
            packets = rdpcap(pcap_path)
            
            timestamps = []
            sizes = []
            start_time = None
            
            for p in packets:
                if p.haslayer(UDP) and p[UDP].dport == SERVER_PORT:
                    # Get relative time (0s, 1s, 2s...)
                    if start_time is None:
                        start_time = p.time
                    
                    rel_time = float(p.time - start_time)
                    payload_len = len(p[UDP].payload)
                    
                    timestamps.append(rel_time)
                    sizes.append(payload_len)
            
            if not timestamps:
                print("⚠ No relevant UDP packets found for plot.")
                return

            # Plotting
            plt.figure(figsize=(10, 5))
            plt.plot(timestamps, sizes, marker='.', linestyle='-', color='blue', alpha=0.6)
            
            plt.title(f"bytes_per_report vs reporting_interval: {test_name}")
            plt.xlabel("Time (seconds)")
            plt.ylabel("Bytes per Report (Payload)")
            plt.grid(True, linestyle='--', alpha=0.7)
            
            # Save strictly for this test case
            safe_name = test_name.replace(" ", "_").replace("/", "-")
            filename = os.path.join(GRAPH_DIR, f"bytes_per_report vs reporting_interval_{safe_name}.png")
            plt.savefig(filename)
            print(f"✔ Saved time-series graph: {filename}")
            plt.close()
            
        except Exception as e:
            print(f"Error plotting timeline: {e}") 

    @staticmethod
    def plot_duplicate_vs_loss():
        """Generates TWO summary graphs: Loss Trend and All-Tests Bar Chart"""
        if not os.path.exists(METRICS_FILE): return

        try:
            import matplotlib
            matplotlib.use('Agg')
            import matplotlib.pyplot as plt
            
            # Data containers
            loss_x = []
            loss_y = []
            
            all_names = []
            all_rates = []

            with open(METRICS_FILE, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    name = row["Test Name"]
                    try:
                        rate = float(row["duplicate_rate"]) * 100
                    except ValueError: continue
                    
                    # Store data for Bar Chart (ALL TESTS)
                    all_names.append(name)
                    all_rates.append(rate)

                    # Store data for Line Chart (ONLY LOSS TESTS)
                    if "Baseline" in name and "Batch" not in name:
                        loss_x.append(0)
                        loss_y.append(rate)
                    elif "Loss" in name:
                        match = re.search(r"Loss (\d+)%", name)
                        if match:
                            loss_x.append(int(match.group(1)))
                            loss_y.append(rate)

            # --- GRAPH 1: Line Chart (Loss vs Duplicates) ---
            if len(loss_x) > 0:
                plt.figure(figsize=(10, 5))
                sorted_pairs = sorted(zip(loss_x, loss_y))
                lx, ly = zip(*sorted_pairs)
                plt.plot(lx, ly, marker='o', linestyle='-', color='red', linewidth=2)
                plt.title("Impact of Network Loss on Duplicate Rate")
                plt.xlabel("Simulated Packet Loss (%)")
                plt.ylabel("Duplicate Rate (%)")
                plt.grid(True)
                filename = os.path.join(GRAPH_DIR, "graph_duplicates_vs_loss.png")
                plt.savefig(filename)
                plt.close()
                print("✔ Saved Trend Graph: graph_duplicates_vs_loss.png")

            # --- GRAPH 2: Bar Chart (All Tests Comparison) ---
            if len(all_names) > 0:
                plt.figure(figsize=(12, 6)) # Wider figure
                bars = plt.bar(all_names, all_rates, color='orange', edgecolor='black')
                plt.title("Duplicate Rate by Test Scenario")
                plt.xlabel("Test Name")
                plt.ylabel("Duplicate Rate (%)")
                plt.xticks(rotation=45, ha='right') # Rotate labels so they don't overlap
                plt.grid(axis='y', linestyle='--', alpha=0.7)
                plt.tight_layout() # Fix layout so labels aren't cut off
                
                # Add numbers on top of bars
                for bar in bars:
                    height = bar.get_height()
                    if height > 0:
                        plt.text(bar.get_x() + bar.get_width()/2, height, f'{height:.1f}%', ha='center', va='bottom')
                
                filename = os.path.join(GRAPH_DIR, "graph_all_tests_duplicates.png")
                plt.savefig(filename)
                plt.close()
                print("✔ Saved Bar Graph: graph_all_tests_duplicates.png")

        except Exception as e:
            print(f"Error plotting summary: {e}")


# HELPERS & MAIN
def clear_netem():
    subprocess.run(["sudo", "tc", "qdisc", "del", "dev", INTERFACE, "root"], 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def apply_netem(cmd_list):
    print("Applying netem:", " ".join(cmd_list))
    clear_netem()
    subprocess.run(cmd_list)

class PacketCapture:
    def __init__(self, interface, pcap_file):
        self.interface = interface
        self.pcap_file = pcap_file
        self.packets = []
        self.stop_sniffing = False
        self.thread = None
    
    def packet_handler(self, packet):
        self.packets.append(packet)
    
    def sniff_packets(self):
        try:
            sniff(iface=self.interface, filter=f"udp port {SERVER_PORT}", 
                  prn=self.packet_handler, 
                  stop_filter=lambda x: self.stop_sniffing, store=False)
        except Exception as e:
            print(f"Capture error: {e}")
    
    def start(self):
        if not SCAPY_AVAILABLE: return
        self.stop_sniffing = False
        self.thread = threading.Thread(target=self.sniff_packets, daemon=True)
        self.thread.start()
        time.sleep(1)
    
    def stop(self):
        if not SCAPY_AVAILABLE or not self.thread: return
        self.stop_sniffing = True
        self.thread.join(timeout=3)
        if self.packets:
            wrpcap(self.pcap_file, self.packets)

def run_test_case(name, netem_cmd=None, client_args=[], forced_params=None):
    print(f"\n\n========== Running Test: {name} ==========")


    if forced_params:
        num_clients, duration = forced_params
        print(f"Auto Mode: Using ({num_clients} Clients, {duration} Seconds)")
        
    else:

        try:
            c_input = input(f"Number of clients [Default 3]: ").strip()
            num_clients = int(c_input) if c_input else 3
            
            t_input = input(f"Test Duration (seconds) [Default 20]: ").strip()
            duration = int(t_input) if t_input else 20
        except ValueError:
            print("Invalid input. Using defaults (3 clients, 20 seconds).")
            num_clients = 3
            duration = 20
    
    if os.path.exists(LOG_DIR): shutil.rmtree(LOG_DIR)
    os.makedirs(LOG_DIR, exist_ok=True)
    
    if netem_cmd: apply_netem(netem_cmd)
    else: clear_netem()

    safe_name = name.replace(" ", "_").replace("/", "-")
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    os.makedirs(PCAP_DIR, exist_ok=True)
    pcap_file = f"{PCAP_DIR}/{safe_name}_{timestamp}.pcap"
    
    capture = PacketCapture(INTERFACE, pcap_file)
    capture.start()

    print("Starting server...")
    server_process = subprocess.Popen(
        ["python3", SERVER_SCRIPT],
        stdout=subprocess.PIPE,  # Capture output
        stderr=subprocess.PIPE,  # Capture errors 
        text=True                # Read as strings
    )
    
    server_psutil = None
    initial_cpu = 0
    if PSUTIL_AVAILABLE:
        try:
            server_psutil = psutil.Process(server_process.pid)
            t = server_psutil.cpu_times()
            initial_cpu = t.user + t.system
        except: pass

    time.sleep(2)

    client_processes = []
    
    for i in range(num_clients):
        final_cmd = ["python3", CLIENT_SCRIPT, str(i)]
        if client_args: final_cmd.extend(client_args)
        p = subprocess.Popen(final_cmd)
        client_processes.append(p)

    print(f"Running for {duration} seconds...")
    time.sleep(duration)

    final_cpu_usage = 0
    if server_psutil:
        try:
            t = server_psutil.cpu_times()
            final_cpu_usage = (t.user + t.system) - initial_cpu
        except: pass

    for p in client_processes: p.terminate()
    
    # STOP SERVER AND READ OUTPUT
    print("Stopping server...")
    server_process.terminate()
    
    # This waits for the server to exit and grabs the text
    stdout_data, stderr_data = server_process.communicate()


    print("\n" + "="*20 + " SERVER LOGS START " + "="*20)
    if stdout_data:
        print(stdout_data)
    else:
        print("(No Output Captured)")
    print("="*20 + " SERVER LOGS END " + "="*20 + "\n")

    dupes_found = 0
    gaps_found = 0
    
    dupe_match = re.search(r"EXPORT_METRICS_DUPLICATES=(\d+)", stdout_data)
    if dupe_match:
        dupes_found = int(dupe_match.group(1))
        
    gap_match = re.search(r"EXPORT_METRICS_GAPS=(\d+)", stdout_data)
    if gap_match:
        gaps_found = int(gap_match.group(1))
        
    print(f"DEBUG: Captured from Server -> Dupes: {dupes_found}, Gaps: {gaps_found}")
    
    capture.stop()
    clear_netem()
    
    time.sleep(1) 
    # Pass the captured values to the analyzer
    MetricAnalyzer.analyze(name, pcap_file, LOG_DIR, final_cpu_usage, dupes_found, gaps_found)
    print(f"=== Test '{name}' Finished ===\n\n")

TEST_CASES = {
    "1": {"name": "Baseline", "netem_cmd": None},
    "2": {"name": "Packet Loss 5%", "netem_cmd": ["sudo", "tc", "qdisc", "add", "dev", INTERFACE, "root", "netem", "loss", "5%"]},
    "3": {"name": "Packet Loss 50%", "netem_cmd": ["sudo", "tc", "qdisc", "add", "dev", INTERFACE, "root", "netem", "loss", "50%"]},
    "4": {"name": "Delay + Jitter (100ms ±10ms)","netem_cmd": ["sudo", "tc", "qdisc", "add", "dev", INTERFACE, "root", "netem", "delay", "100ms", "10ms"]},
    "5": {"name": "High Delay + Jitter (2000ms ±5000ms)","netem_cmd": ["sudo", "tc", "qdisc", "add", "dev", INTERFACE, "root", "netem", "delay", "2000ms", "5000ms"]},
    "6": {"name": "Duplicate 10%", "netem_cmd": ["sudo", "tc", "qdisc", "add", "dev", INTERFACE, "root", "netem", "duplicate", "10%"]},
    "7": {"name": "Baseline Batch Mode (5 Packets)", "netem_cmd": None, "args": ["batch"]}
}

def show_menu():
    print("\n" + "="*40)
    print("NETWORK TEST RUNNER")
    print("="*40)
    print(" [A] Auto-Run All Tests")
    for key, test in sorted(TEST_CASES.items()):
        print(f" [{key}] {test['name']}")
        
    print(" [Q] Quit")
    print("="*40)

def main():
    while True:
        show_menu()
        choice = input("Select: ").strip().upper()
        if choice == "Q": break
        if choice == "A":
            print("\n>>> STARTING ALL TESTS SEQUENCE <<<\n")

            try:
                c_in = input("Enter Number of Clients for ALL tests [Default 3]: ").strip()
                all_clients = int(c_in) if c_in else 3
                
                d_in = input("Enter Duration (s) for ALL tests [Default 20]: ").strip()
                all_duration = int(d_in) if d_in else 20
            except ValueError:
                all_clients = 3
                all_duration = 20

            global_settings = (all_clients, all_duration)
            
            # 1. Clear old metrics
            if os.path.exists(METRICS_FILE):
                os.remove(METRICS_FILE)
                print("✔ Old metrics cleared for fresh sequence.")

            # 2. Loop through all tests
            for key in sorted(TEST_CASES.keys(), key=lambda x: int(x)):
                t = TEST_CASES[key]
                run_test_case(t["name"], t["netem_cmd"], t.get("args", []), forced_params=global_settings)
                time.sleep(2) 
            
            print("\n>>> ALL TESTS COMPLETED. Check 'test_graphs/SUMMARY_EVOLUTION.png' <<<")
            continue
        if choice in TEST_CASES:
            t = TEST_CASES[choice]
            run_test_case(t["name"], t["netem_cmd"], t.get("args", []))
    clear_netem()

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: sys.exit(0)
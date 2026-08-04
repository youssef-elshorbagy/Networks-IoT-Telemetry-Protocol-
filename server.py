import socket, struct, csv, time, os, signal, sys, atexit
from collections import defaultdict

# log formatter
def print_log(role, seq_val, client_id, message):
    print(f"| {role} | seq={seq_val} | client id={client_id} | {message}", flush=True)

HOST, PORT = "127.0.0.1", 5000
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))
print_log("server", 0, 0, f"Listening on {HOST}:{PORT}")

# Create logs folder
os.makedirs("device_logs", exist_ok=True)



Total_Duplicates = 0
SequenceL_Gaps = 0



last_seq = {}
seen_sequences = defaultdict(set)
packet_buffer = defaultdict(list)
csv_files = {}  
csv_writers = {}  

BUFFER_SIZE = 100 # Maximum packets to buffer before forced flush
BUFFER_TIMEOUT = 1000  # Maximum seconds to hold oldest packet
SEQ_HISTORY_SIZE = 100 


def export_stats_on_exit():
    print(f"\nEXPORT_METRICS_DUPLICATES={Total_Duplicates}")
    print(f"EXPORT_METRICS_GAPS={SequenceL_Gaps}")
    sys.stdout.flush()

atexit.register(export_stats_on_exit)    

def get_csv_writer(device_id):
    """Get or create CSV writer for a specific device"""
    if device_id not in csv_writers:
        filename = f"device_logs/device_{device_id}.csv"
        f = open(filename, "w", newline="")
        csv_files[device_id] = f
        writer = csv.writer(f)
        writer.writerow([
            "version",
            "msg_type",
            "device_id",
            "seq_num",
            "timestamp_sent",
            "flags",
            "checksum",
            "temp_C",
            "humidity_%",
            "arrival_time"
        ])
        csv_writers[device_id] = writer
        print_log("server", 0, device_id, f"Created log file: {filename}")
    
    return csv_writers[device_id], csv_files[device_id]

def send_ack(device_id, seq_num, addr):
    """Send ACK message back to client"""
    VERSION = 1
    msg_type = 3  
    FLAGS = 0
    CHECKSUM = 0
    ver_type = (VERSION << 4) | msg_type
    timestamp = int(time.time())
    
    
    ack_packet = struct.pack('!B H H I B H', ver_type, device_id, seq_num, timestamp, FLAGS, CHECKSUM)
    sock.sendto(ack_packet, addr)
    print_log("server", seq_num, device_id, "ACK_SENT")

def flush_buffer(device_id, force=False):
    """Sort buffered packets by timestamp and write to CSV
    """
    global SequenceL_Gaps

    if not packet_buffer[device_id]:
        return
    
    buffer = packet_buffer[device_id]
    
    # Check if we should flush
    if not force and len(buffer) < BUFFER_SIZE:
        oldest_arrival = min(pkt['arrival_time'] for pkt in buffer)
        if time.time() - oldest_arrival < BUFFER_TIMEOUT:
            return
    
    print_log("server", 0, device_id, f"FLUSH_BUFFER size={len(buffer)}")
    
    # Sort by TIMESTAMP for reordering
    buffer.sort(key=lambda x: x['timestamp_sent'])
    
    writer, f = get_csv_writer(device_id)
    
    # Write all packets in order
    for pkt in buffer:
        seq_num = pkt['seq_num']
    
        
        writer.writerow([
            pkt['version'],
            pkt['msg_type'],
            pkt['device_id'],
            seq_num,
            pkt['timestamp_sent'],
            pkt['flags'],
            pkt['checksum'],
            pkt['temp_C'],
            pkt['humidity_%'],
            pkt['arrival_time']
        ])
        
        # Check for sequence gaps
        if pkt['msg_type'] == 1:
            if device_id in last_seq:
                expected = (last_seq[device_id] + 1) & 0xFFFF
                if seq_num != expected:
                    gap = (seq_num - expected) & 0xFFFF
                    if gap < 32768:
                        SequenceL_Gaps += 1
                        print_log("server", seq_num, device_id, f"SEQ_GAP expected={expected} got={seq_num} missing={gap}")
            
            last_seq[device_id] = seq_num
        
        # Track this sequence number
        seen_sequences[device_id].add(seq_num)
        
        # Limit history size
        if len(seen_sequences[device_id]) > SEQ_HISTORY_SIZE:
            oldest = min(seen_sequences[device_id])
            seen_sequences[device_id].discard(oldest)
    
    f.flush()
    packet_buffer[device_id].clear()
    print_log("server", 0, device_id, "BUFFER_CLEARED")


def calculate_checksum(data):
    # If packet has an odd number of bytes, add a zero padding byte
    if len(data) % 2 == 1:
        data += b'\x00'
        
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + (data[i+1])
        s += w
        
    s = (s >> 16) + (s & 0xFFFF)
    s += (s >> 16)
    
    # Invert bits (One's Complement)
    return ~s & 0xFFFF


# Save logs before shutdown
def _shutdown(signum, frame):
    print_log("server", 0, 0, f"SHUTDOWN_SIGNAL {signum}")
    # Flush all buffers
    for device_id in list(packet_buffer.keys()):
        flush_buffer(device_id, force=True)
    # Close CSV files
    for f in csv_files.values():
        try:
            f.close()
        except Exception:
            pass
    try:
        sock.close()
    except Exception:
        pass
    print_log("server", 0, 0, "ALL_LOGS_CLOSED")
    sys.exit(0)

signal.signal(signal.SIGINT, _shutdown)
signal.signal(signal.SIGTERM, _shutdown)

try:
    while True:
        data, addr = sock.recvfrom(1024)
        arrival_time = time.time()

        if len(data) < 12:
            continue

        header = data[:12]
        payload = data[12:]
        ver_type, device_id, seq, ts, flags, checksum = struct.unpack('!B H H I B H', header)

        header_for_calc = struct.pack('!B H H I B H', ver_type, device_id, seq, ts, flags, 0)
        calculated = calculate_checksum(header_for_calc + payload)

        if calculated != checksum:
            print_log("server", seq, device_id, "CHECKSUM_MISMATCH")
            print_log("server", seq, device_id, f"CHK expected={hex(calculated)} recv={hex(checksum)}")
            continue

        version = (ver_type >> 4) & 0x0F
        msg_type = ver_type & 0x0F

        # Handle INIT message
        if msg_type == 0:
            print_log("server", seq, device_id, f"INIT_RECEIVED from={addr}")
            packet_buffer[device_id].append({
                'version': version,
                'msg_type': msg_type,
                'device_id': device_id,
                'seq_num': seq,
                'timestamp_sent': ts,
                'flags': flags,
                'checksum': checksum,
                'temp_C': '',
                'humidity_%': '',
                'arrival_time': arrival_time
            })
            flush_buffer(device_id)
            # Send ACK for INIT message
            send_ack(device_id, seq, addr)

        # Handle HEARTBEAT message
        elif msg_type == 2:
            packet_buffer[device_id].append({
                'version': version,
                'msg_type': msg_type,
                'device_id': device_id,
                'seq_num': seq,
                'timestamp_sent': ts,
                'flags': flags,
                'checksum': checksum,
                'temp_C': '',
                'humidity_%': '',
                'arrival_time': arrival_time
            })
            print_log("server", seq, device_id, f"HEARTBEAT_RECEIVED at={arrival_time}")
            flush_buffer(device_id)

        # Handle DATA message
        elif msg_type == 1 and len(data) >= 13:

            is_priority = (flags & 0x02) == 0x02
            if seq in seen_sequences[device_id]:
                Total_Duplicates += 1
                if is_priority:
                    print_log("server", seq, device_id, "PRIORITY_DUPLICATE ACK_RESENT")
                    send_ack(device_id, seq, addr)
                    continue
                else:    
                    print_log("server", seq, device_id, "DUPLICATE_IGNORED")
                    continue
                
            
            # Mark this sequence as seen immediately
            seen_sequences[device_id].add(seq)
            
            # Limit history size
            if len(seen_sequences[device_id]) > SEQ_HISTORY_SIZE:
                oldest = min(seen_sequences[device_id])
                seen_sequences[device_id].discard(oldest)

            # 2. Extract Data
            payload = data[12:]
            is_batch = (flags & 0x01) == 0x01
            readings = []

            if is_batch:
                # handle batch mode 
                count = payload[0]
                raw_readings = payload[1:]
                print_log("server", seq, device_id, f"BATCH_RECEIVED size={count}")
                
                for i in range(count):
                    offset = i * 4
                    if offset + 4 <= len(raw_readings):
                        chunk = raw_readings[offset : offset+4]
                        t, h = struct.unpack('!h H', chunk)
                        # We use the Header 'seq' for ALL readings so they look grouped in CSV
                        readings.append((seq, t, h))
            else:
                # handle normal mode
                if len(payload) >= 4:
                    t, h = struct.unpack('!h H', payload)
                    readings.append((seq, t, h))
                    print_log("server", seq, device_id, f"DATA_RECEIVED temp={t/10:.1f}C")

            # 3. Buffer All Readings
            for (r_seq, temp, hum) in readings:
                packet_buffer[device_id].append({
                    'version': version,
                    'msg_type': msg_type,
                    'device_id': device_id,
                    'seq_num': r_seq,       # All batched items share this ID now
                    'timestamp_sent': ts,
                    'flags': flags,         # Will be '1' for batch
                    'checksum': checksum,
                    'temp_C': temp / 10,
                    'humidity_%': hum / 10,
                    'arrival_time': arrival_time
                })

            flush_buffer(device_id)

            is_priority = (flags & 0x02) == 0x02
            # for critical data (sudden change in readings) send an ack message
            if is_priority:
                send_ack(device_id, seq, addr)
                print_log("server", seq, device_id, "PRIORITY_RECEIVED_ACK_SENT")
 
except KeyboardInterrupt:
    # handle ctrl c press and save before closing program
    print_log("server", 0, 0, "SHUTDOWN_KEYBOARD")
    for device_id in packet_buffer.keys():
        flush_buffer(device_id, force=True)
    for f in csv_files.values():
        f.close()
    print_log("server", 0, 0, "ALL_LOGS_CLOSED")
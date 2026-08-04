import socket, struct, time, random, sys

# LOG FORMAT HELPER 
def print_log(role, seq_val, client_id, message):
    print(f"| {role} | seq={seq_val} | client id={client_id} | {message}")

if len(sys.argv) < 2:
    print("Usage: python3 client.py <device_id>")
    sys.exit(1)

DEVICE_ID = int(sys.argv[1])

BATCH_MODE = False
if len(sys.argv) > 2 and sys.argv[2] == "batch":
    BATCH_MODE = True
    print_log("client", 0, DEVICE_ID, "Starting in BATCH MODE")
else:
    print_log("client", 0, DEVICE_ID, "Starting in NORMAL MODE")

SERVER = ("127.0.0.1", 5000)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3.0)  # 3 second timeout for receiving ACK

fake_ip = f"127.0.0.{DEVICE_ID + 2}"

try:
    sock.bind((fake_ip, 0))
    print_log("client", 0, DEVICE_ID, f"Bound to specific IP: {fake_ip}")
except OSError as e:
    print_log("client", 0, DEVICE_ID, f"Error binding to {fake_ip}: {e}")

VERSION = 1
FLAGS = 0
CHECKSUM = 0
seq = 0
temp = 200
hum = 450

MAX_INIT_RETRIES = 5
INIT_TIMEOUT = 3.0

def wait_for_ack(expected_seq, timeout=INIT_TIMEOUT):
    """Wait for ACK message from server"""
    prev_timeout = sock.gettimeout()
    sock.settimeout(timeout)
    try:
        data, addr = sock.recvfrom(1024)
        if len(data) >= 12:
            header = data[:12]
            ver_type, device_id, ack_seq, ts, flags, checksum = struct.unpack('!B H H I B H', header)
            msg_type = ver_type & 0x0F

            # Check if it's an ACK message (type 3) for this device and sequence
            if msg_type == 3 and device_id == DEVICE_ID and ack_seq == expected_seq:
                return True
        return False
    except socket.timeout:
        return False
    finally:
        sock.settimeout(prev_timeout)


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


# Send INIT with retry logic
msg_type = 0
ver_type = (VERSION << 4) | msg_type
init_success = False

for attempt in range(1, MAX_INIT_RETRIES + 1):
    print_log("client", seq, DEVICE_ID, f"INIT_SEND attempt={attempt}/{MAX_INIT_RETRIES}")

    timestamp = int(time.time())

    dummy_chk = 0
    header_temp = struct.pack('!B H H I B H', ver_type, DEVICE_ID, seq, timestamp, FLAGS, dummy_chk)

    chk = calculate_checksum(header_temp)

    header = struct.pack('!B H H I B H', ver_type, DEVICE_ID, seq, timestamp, FLAGS, chk)

    sock.sendto(header, SERVER)
    # Wait for ACK
    if wait_for_ack(seq, INIT_TIMEOUT):
        print_log("client", seq, DEVICE_ID, "INIT_ACK")
        init_success = True
        break
    else:
        print_log("client", seq, DEVICE_ID, f"INIT_TIMEOUT after={INIT_TIMEOUT}s")
        if attempt < MAX_INIT_RETRIES:
            print_log("client", seq, DEVICE_ID, "INIT_RETRY")
            time.sleep(1)

if not init_success:
    print_log("client", seq, DEVICE_ID, f"INIT_FAILED after={MAX_INIT_RETRIES}")
    print_log("client", seq, DEVICE_ID, "EXITING")
    sock.close()
    sys.exit(1)

# Set socket back to blocking for normal operation
sock.settimeout(None)

time.sleep(0.5)

# Send DATA with intentional out-of-order delivery
msg_type = 1
ver_type = (VERSION << 4) | msg_type

client_buffer = []
BATCH_SIZE = 5

def flush_batch(seq_num):
    """Packages multiple readings into one packet and sends it"""
    if not client_buffer:
        return

    timestamp = int(time.time())

    count = len(client_buffer)
    payload = struct.pack('!B', count)

    for (t, h) in client_buffer:
        payload += struct.pack('!h H', t, h)

    batch_flags = FLAGS | 0x01
    dummy_chk = 0
    header_temp = struct.pack('!B H H I B H', ver_type, DEVICE_ID, seq_num, timestamp, batch_flags, dummy_chk)
    chk = calculate_checksum(header_temp + payload)
    header_final = struct.pack('!B H H I B H', ver_type, DEVICE_ID, seq_num, timestamp, batch_flags, chk)

    sock.sendto(header_final + payload, SERVER)
    print_log("client", seq_num, DEVICE_ID, f"BATCH_SENT size={count}")
    client_buffer.clear()


def send_packet(temp_val, hum_val, delay=0, priority=0):
    global seq
    if delay > 0:
        time.sleep(delay)

    if BATCH_MODE:
        client_buffer.append((temp_val, hum_val))
        print_log("client", seq, DEVICE_ID, f"BUFFERED {len(client_buffer)}/{BATCH_SIZE}")
        if len(client_buffer) >= BATCH_SIZE:
            seq += 1
            flush_batch(seq)
    else:
        # NORMAL LOGIC
        seq += 1
        current_flags = FLAGS
        if priority == 1:
            current_flags = current_flags | (1 << 1)

        payload = struct.pack('!h H', temp_val, hum_val)

        # If priority==1, retry sending up to MAX_INIT_RETRIES (like INIT logic)
        if priority == 1:
            acked = False
            for attempt in range(1, MAX_INIT_RETRIES + 1):
                timestamp = int(time.time())
                checksum_placeholder = 0
                header_temp = struct.pack('!B H H I B H', ver_type, DEVICE_ID, seq, timestamp, current_flags, checksum_placeholder)
                chk = calculate_checksum(header_temp + payload)
                header = struct.pack('!B H H I B H', ver_type, DEVICE_ID, seq, timestamp, current_flags, chk)

                print_log("client", seq, DEVICE_ID, f"PRIORITY_SEND attempt={attempt}/{MAX_INIT_RETRIES}")
                sock.sendto(header + payload, SERVER)

                # Wait for ACK with INIT_TIMEOUT
                if wait_for_ack(seq, INIT_TIMEOUT):
                    print_log("client", seq, DEVICE_ID, "ACK_RECEIVED")
                    acked = True
                    break
                else:
                    print_log("client", seq, DEVICE_ID, f"ACK_TIMEOUT attempt={attempt}")
                    if attempt < MAX_INIT_RETRIES:
                        print_log("client", seq, DEVICE_ID, "ACK_RETRY wait=1s")
                        time.sleep(1)

            if not acked:
                print_log("client", seq, DEVICE_ID, f"ACK_FAILED after={MAX_INIT_RETRIES}")
        else:
            # Non-priority: single best-effort send
            timestamp = int(time.time())
            checksum_placeholder = 0
            header_temp = struct.pack('!B H H I B H', ver_type, DEVICE_ID, seq, timestamp, current_flags, checksum_placeholder)
            chk = calculate_checksum(header_temp + payload)
            header = struct.pack('!B H H I B H', ver_type, DEVICE_ID, seq, timestamp, current_flags, chk)

            sock.sendto(header + payload, SERVER)
            print_log("client", seq, DEVICE_ID, f"SENT temp={temp_val/10:.1f}C hum={hum_val/10:.1f}% ts={timestamp}")


packet_count = 0

HEARTBEAT_INTERVAL = 5  # seconds
last_heartbeat = time.time()

try:
    while True:
        packet_count += 1

        temp_change = random.randint(-3, 3)
        hum_change = random.randint(-3, 3)

        temp += temp_change
        hum += hum_change

        if abs(temp_change) == 3 and abs(hum_change) == 3:
            print_log("client", seq+1, DEVICE_ID, f"SUDDEN_CHANGE t_delta={temp_change} h_delta={hum_change}")
            priority_flag = 1
        else:
            priority_flag = 0

        
        print_log("client", seq, DEVICE_ID, "NORMAL_PACKET")
        send_packet(temp, hum, 0, priority=priority_flag)

        # Check if it's time to send heartbeat
        if time.time() - last_heartbeat >= HEARTBEAT_INTERVAL:
            hb_seq = 0  # optional heartbeat sequence
            hb_msg_type = 2
            hb_ver_type = (VERSION << 4) | hb_msg_type
            ts = int(time.time())

            dummy_chk = 0
            hb_header_temp = struct.pack('!B H H I B H', hb_ver_type, DEVICE_ID, hb_seq, ts, FLAGS, dummy_chk)
            hb_chk = calculate_checksum(hb_header_temp)
            hb_header = struct.pack('!B H H I B H', hb_ver_type, DEVICE_ID, hb_seq, ts, FLAGS, hb_chk)
            sock.sendto(hb_header, SERVER)

            print_log("client", hb_seq, DEVICE_ID, f"HEARTBEAT_SENT ts={ts}")
            last_heartbeat = time.time()

        time.sleep(1)

except KeyboardInterrupt:
    print_log("client", seq, DEVICE_ID, "SHUTDOWN")
    sock.close()
    print_log("client", seq, DEVICE_ID, "CONNECTION_CLOSED")
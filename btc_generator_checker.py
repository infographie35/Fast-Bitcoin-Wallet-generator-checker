import os
import sys
import time
import mmap
import hashlib
import base58
import coincurve
import multiprocessing
import queue
from colorama import init, Fore

# -------------------------------
# Configuration
# -------------------------------
RESULT_FILE = "result.txt"              # Fixed-size ring buffer file
MATCH_FILE = "match.txt"                # File to append matching blocks (if any)
TSV_LIST_FILE = "filtered_addresses.tsv"  # TSV file with public addresses
MAX_SIZE = 10 * 1024 * 1024             # 10 MB fixed file size
NUM_WORKERS = os.cpu_count()            # Number of parallel key generation processes

# -------------------------------
# Helper functions for matching (startup check)
# -------------------------------
def load_addresses():
    addresses = set()
    try:
        with open(TSV_LIST_FILE, "r") as f:
            header = f.readline()  # Skip header
            for line in f:
                if line.strip():
                    addr = line.split()[0].strip()
                    addresses.add(addr)
    except Exception as e:
        print("Error loading addresses:", e)
    print(f"Loaded {len(addresses)} addresses from {TSV_LIST_FILE}")
    return addresses

def process_block(block, addresses_set):
    """
    Expects a block as a string with 3 lines:
      PubAddress: <address>
      WIF: <wif>
      PrivateKey: <hex>
    """
    lines = block.strip().splitlines()
    if lines and lines[0].startswith("PubAddress:"):
        addr = lines[0].split(":", 1)[-1].strip()
        if addr in addresses_set:
            print(f"Match found: {addr}") 
            with open(MATCH_FILE, "a") as mf:
                mf.write(block + "\n")

def startup_matching_check(addresses_set):
    if os.path.exists(RESULT_FILE):
        try:
            with open(RESULT_FILE, "r") as f:
                data = f.read()
            # Assuming each block is 3 lines; process complete blocks only.
            lines = data.strip().splitlines()
            for i in range(0, len(lines), 3):
                block = "\n".join(lines[i:i+3])
                process_block(block, addresses_set)
        except Exception as e:
            print("Error in startup matching check:", e)

# -------------------------------
# Bitcoin Key Generation with coincurve
# -------------------------------
def privatekey_to_wif(pk_bytes, compressed=True):
    """Convert a private key (bytes) to WIF format."""
    extended_key = b"\x80" + pk_bytes + (b"\x01" if compressed else b"")
    first_sha = hashlib.sha256(extended_key).digest()
    second_sha = hashlib.sha256(first_sha).digest()
    final_key = extended_key + second_sha[:4]
    return base58.b58encode(final_key).decode("utf-8")

def public_key_to_address(pubkey_bytes):
    """Convert a public key (bytes) to a Bitcoin address."""
    sha = hashlib.sha256(pubkey_bytes).digest()
    ripemd = hashlib.new('ripemd160', sha).digest()
    extended = b'\x00' + ripemd  # Bitcoin mainnet prefix
    checksum = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
    addr = base58.b58encode(extended + checksum).decode("utf-8")
    return addr

def generate_block():
    # Generate a random 32-byte private key
    private_key_bytes = os.urandom(32)
    # Create a coincurve PrivateKey object
    privkey = coincurve.PrivateKey(private_key_bytes)
    # Derive the compressed public key (coincurve returns compressed by default)
    public_key_bytes = privkey.public_key.format(compressed=True)
    
    # Convert private key to WIF and public key to Bitcoin address
    wif = privatekey_to_wif(private_key_bytes, compressed=True)
    addr = public_key_to_address(public_key_bytes)
    
    # Each block has 3 lines: PubAddress, WIF, PrivateKey
    block = f"PubAddress: {addr}\nWIF: {wif}\nPrivateKey: {private_key_bytes.hex()}\n"
    return block

# -------------------------------
# Worker Process: Key Generator
# -------------------------------
def key_generator_worker(q, terminate_event):
    while not terminate_event.is_set():
        block = generate_block()
        try:
            q.put(block, block=False)
        except queue.Full:
            time.sleep(0.001)
        time.sleep(0.0001)

# -------------------------------
# Writer Process: Ring Buffer with mmap
# -------------------------------
def writer_process(q, terminate_event, write_offset, lock, total_count):
    # Create RESULT_FILE if it doesn't exist; fill with zeros
    if not os.path.exists(RESULT_FILE):
        with open(RESULT_FILE, "wb") as f:
            f.write(b'\x00' * MAX_SIZE)
    with open(RESULT_FILE, "r+b") as f:
        mm = mmap.mmap(f.fileno(), MAX_SIZE)
        while not terminate_event.is_set():
            try:
                block = q.get(timeout=0.1)
            except queue.Empty:
                continue
            block_bytes = block.encode('utf-8')
            blen = len(block_bytes)
            with lock:
                pos = write_offset.value
                # If not enough space at the end, wrap around to start.
                if pos + blen > MAX_SIZE:
                    pos = 0
                mm.seek(pos)
                mm.write(block_bytes)
                write_offset.value = pos + blen
                total_count.value += 1
        mm.flush()
        mm.close()

# -------------------------------
# Display Process: Show Total Count in Yellow
# -------------------------------
def display_process(total_count, terminate_event):
    init(autoreset=True)  # Ensures colors reset automatically after each print
    start_time = time.time()
    while not terminate_event.is_set():
        elapsed = time.time() - start_time
        count = total_count.value
        # Calculate rates; avoid division by zero
        per_min = count / elapsed * 60 if elapsed > 0 else 0
        per_hour = count / elapsed * 3600 if elapsed > 0 else 0
        per_day = count / elapsed * 86400 if elapsed > 0 else 0
        sys.stdout.write(
            f"\r{Fore.YELLOW}Total Wallets Processed: {count:,} - "
            f"{per_min:,.0f} per minute - {per_hour:,.0f} per hour - {per_day:,.0f} per day"
        )
        sys.stdout.flush()
        time.sleep(0.5)
    print()  # Move to a new line when exiting

# -------------------------------
# Main Function
# -------------------------------
def main():
    addresses_set = load_addresses()
    # Perform a quick matching check on existing file entries.
    startup_matching_check(addresses_set)
    
    terminate_event = multiprocessing.Event()
    q = multiprocessing.Queue(maxsize=1000)
    lock = multiprocessing.Lock()
    write_offset = multiprocessing.Value('I', 0)
    total_count = multiprocessing.Value('I', 0)
    
    # Start key generation workers using NUM_WORKERS
    workers = []
    for _ in range(NUM_WORKERS):
        p = multiprocessing.Process(target=key_generator_worker, args=(q, terminate_event))
        p.start()
        workers.append(p)
    
    # Start the writer process.
    writer = multiprocessing.Process(target=writer_process, args=(q, terminate_event, write_offset, lock, total_count))
    writer.start()
    
    # Start the display process.
    disp = multiprocessing.Process(target=display_process, args=(total_count, terminate_event))
    disp.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        terminate_event.set()
    
    writer.join()
    for p in workers:
        p.join()
    disp.join()

if __name__ == "__main__":
    main()

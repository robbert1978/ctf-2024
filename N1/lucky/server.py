import os
import time
import base64
import gzip
import subprocess
from datetime import datetime

# Cooldown duration in seconds
COOLDOWN_PERIOD = 240
MAX_ORIG_SIZE = 96 * 1024
# Max size for decompressed payload (96 KB)
MAX_DECOMPRESSED_SIZE = 96 * 1024
# Max execution time for qemu
MAX_EXECUTION_TIME = 240
# File to store the last run timestamp
LAST_RUN_FILE = 'lastrun'
# File to save the decompressed payload
EXP_FILE = 'exp'

# 1. Cooldown check based on lastrun file modification time
def check_cooldown():
    if os.path.exists(LAST_RUN_FILE):
        last_modified_time = os.path.getmtime(LAST_RUN_FILE)
        current_time = time.time()
        elapsed_time = current_time - last_modified_time
        if elapsed_time < COOLDOWN_PERIOD:
            print(f"Cooldown in effect. Try again in {COOLDOWN_PERIOD - int(elapsed_time)} seconds.")
            exit(1)
    # Update the lastrun file timestamp
    with open(LAST_RUN_FILE, 'w') as f:
        f.write(str(datetime.now()))

# 2. Decode, decompress, and write payload to exp file
def handle_payload(encoded_payload):
    if len(encoded_payload) > MAX_ORIG_SIZE:
        print("Payload exceeds the maximum allowed size of 96KB.")
        exit(1)
    try:
        # Base64 decode
        compressed_data = base64.b64decode(encoded_payload)
        # Gzip decompress
        decompressed_data = gzip.decompress(compressed_data)
        # Ensure the decompressed data does not exceed 64KB
        if len(decompressed_data) > MAX_DECOMPRESSED_SIZE:
            print("Decompressed payload exceeds the maximum allowed size of 96KB.")
            exit(1)
        # Write to file 'exp'
        with open(EXP_FILE, 'wb') as f:
            f.write(decompressed_data)
    except Exception as e:
        print(f"Error during payload handling: {e}")
        exit(1)

def execute_script():
    try:
        print("running")
        p=subprocess.Popen(['bash','./run_qemu.sh'], stdin=subprocess.DEVNULL,stderr=subprocess.STDOUT)
        p.wait(MAX_EXECUTION_TIME)
    except subprocess.TimeoutExpired:
        print(f"Execution of qemu exceeded the time limit of {MAX_EXECUTION_TIME} seconds.")
        p.kill()
        try:
            p.wait(1)
        except Exception:
            pass
        exit(1)

if __name__ == '__main__':
    print("base64(gziped(payload)) > ")
    # Read payload from stdin
    encoded_payload = input().strip()
    
    check_cooldown()
    handle_payload(encoded_payload)
    execute_script()

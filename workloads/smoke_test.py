import os
import time
import socket

sandbox = "/tmp/ransom_test"
os.makedirs(sandbox, exist_ok=True)
time.sleep(0.1)

file_orig = os.path.join(sandbox, "doc1.txt")
file_locked = os.path.join(sandbox, "doc1.txt.locked")

# 1. Open + Write + Close
with open(file_orig, "w") as f:
    f.write("Hello Ransomware Test Data! 1234567890\n")

# 2. Open + Read + Close
with open(file_orig, "r") as f:
    data = f.read()

# 3. Rename
os.rename(file_orig, file_locked)

# 4. Delete
os.unlink(file_locked)

# 5. Network Connect (simulated C2)
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    s.connect_ex(("1.1.1.1", 80))
    s.close()
except Exception:
    pass

print("[+] Smoke test file + network operations completed.")

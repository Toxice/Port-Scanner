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
#include <net/if.h>
#include <ifaddrs.h>

#define MIN_PORT 1
#define MAX_PORT 65535
#define BUFFER_SIZE 4096
#define TIMEOUT 2000
#define PACKET_SIZE 4096
#define MAX_OPEN_PORTS 1024
#define TRACKING_SIZE 1000  // Increased from 100

#define SCAN_TCP 1
#define SCAN_UDP 2

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

typedef struct {
    int port;
    uint16_t src_port;
    uint32_t seq_num;
    struct timeval time_sent;
    int received;
} port_info_t;

typedef struct {
    int current_port;
    int sender_done;
    int open_ports[MAX_OPEN_PORTS];
    int open_count;
    int scan_type;
    port_info_t port_tracking[TRACKING_SIZE];
    int tracking_index;
} scan_state_t;

scan_state_t *shared_state = NULL;

int sock_send = -1;
int sock_recv_tcp = -1;
int sock_recv_icmp = -1;
char target_ip[INET_ADDRSTRLEN];
char local_ip[INET_ADDRSTRLEN];

/**
 * @brief Get local IP address for the interface that would route to target
 */
int get_local_ip(const char *target, char *local) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return -1;
    }

    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(53);  // DNS port
    inet_pton(AF_INET, target, &target_addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
        close(sock);
        return -1;
    }

    struct sockaddr_in local_addr;
    socklen_t addr_len = sizeof(local_addr);
    if (getsockname(sock, (struct sockaddr*)&local_addr, &addr_len) < 0) {
        close(sock);
        return -1;
    }

    inet_ntop(AF_INET, &local_addr.sin_addr, local, INET_ADDRSTRLEN);
    close(sock);
    return 0;
}

/**
 * @brief Calculate checksum for IP/ICMP header
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
 * @brief Calculate TCP/UDP checksum with pseudo-header
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

    if (inet_pton(AF_INET, host, ip_addr) == 1) {
        strcpy(ip_addr, host);
        return 0;
    }

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
    for (int i = 0; i < TRACKING_SIZE; i++) {
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

    memset(&packet, 0, sizeof(packet));

    // IP header
    packet.ip.version = 4;
    packet.ip.ihl = 5;
    packet.ip.tos = 0;
    packet.ip.tot_len = htons(sizeof(tcp_packet));  // FIX: Convert to network byte order
    packet.ip.id = htons(getpid() + port);
    packet.ip.frag_off = 0;
    packet.ip.ttl = 64;
    packet.ip.protocol = IPPROTO_TCP;
    packet.ip.check = 0;
    
    // FIX: Set source IP address
    inet_pton(AF_INET, local_ip, &packet.ip.saddr);
    inet_pton(AF_INET, target_ip, &packet.ip.daddr);
    
    // FIX: Calculate IP checksum
    packet.ip.check = checksum(&packet.ip, sizeof(struct iphdr));

    // TCP header
    uint16_t src_port = 12345 + (port % 10000);
    packet.tcp.source = htons(src_port);
    packet.tcp.dest = htons(port);
    
    uint32_t seq_num = rand();
    packet.tcp.seq = htonl(seq_num);
    packet.tcp.ack_seq = 0;
    packet.tcp.doff = 5;
    packet.tcp.syn = 1;
    packet.tcp.window = htons(65535);
    packet.tcp.check = 0;
    packet.tcp.urg_ptr = 0;

    packet.tcp.check = transport_checksum(&packet.ip, &packet.tcp, 
                                         sizeof(struct tcphdr), IPPROTO_TCP);

    // Store port tracking info
    int idx = shared_state->tracking_index % TRACKING_SIZE;
    shared_state->port_tracking[idx].port = port;
    shared_state->port_tracking[idx].src_port = src_port;
    shared_state->port_tracking[idx].seq_num = seq_num;
    gettimeofday(&shared_state->port_tracking[idx].time_sent, NULL);
    shared_state->port_tracking[idx].received = 0;
    shared_state->tracking_index = (shared_state->tracking_index + 1) % TRACKING_SIZE;

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

    packet.ip.version = 4;
    packet.ip.ihl = 5;
    packet.ip.tos = 0;
    packet.ip.tot_len = htons(sizeof(tcp_packet));  // FIX
    packet.ip.id = htons(getpid() + dest_port);
    packet.ip.frag_off = 0;
    packet.ip.ttl = 64;
    packet.ip.protocol = IPPROTO_TCP;
    packet.ip.check = 0;
    
    inet_pton(AF_INET, local_ip, &packet.ip.saddr);
    inet_pton(AF_INET, target_ip, &packet.ip.daddr);
    
    packet.ip.check = checksum(&packet.ip, sizeof(struct iphdr));

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

    memset(&packet, 0, sizeof(packet));

    packet.ip.version = 4;
    packet.ip.ihl = 5;
    packet.ip.tos = 0;
    packet.ip.tot_len = htons(sizeof(udp_packet));  // FIX
    packet.ip.id = htons(getpid() + port);
    packet.ip.frag_off = 0;
    packet.ip.ttl = 64;
    packet.ip.protocol = IPPROTO_UDP;
    packet.ip.check = 0;
    
    inet_pton(AF_INET, local_ip, &packet.ip.saddr);
    inet_pton(AF_INET, target_ip, &packet.ip.daddr);
    
    packet.ip.check = checksum(&packet.ip, sizeof(struct iphdr));

    uint16_t src_port = 12345 + (port % 10000);
    packet.udp.source = htons(src_port);
    packet.udp.dest = htons(port);
    packet.udp.len = htons(sizeof(struct udphdr));
    packet.udp.check = 0;

    packet.udp.check = transport_checksum(&packet.ip, &packet.udp,
                                         sizeof(struct udphdr), IPPROTO_UDP);

    int idx = shared_state->tracking_index % TRACKING_SIZE;
    shared_state->port_tracking[idx].port = port;
    shared_state->port_tracking[idx].src_port = src_port;
    gettimeofday(&shared_state->port_tracking[idx].time_sent, NULL);
    shared_state->port_tracking[idx].received = 0;
    shared_state->tracking_index = (shared_state->tracking_index + 1) % TRACKING_SIZE;

    if (sendto(sock_send, &packet, sizeof(packet), 0,
               (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        return -1;
    }

    return 0;
}

void display_tcp(char *buffer, int bytes) {
    char src_addr[INET_ADDRSTRLEN];
    
    if (bytes < (int)sizeof(struct iphdr)) {
        return;
    }

    struct iphdr *ip_resp = (struct iphdr*)buffer;
    
    inet_ntop(AF_INET, &(ip_resp->saddr), src_addr, INET_ADDRSTRLEN);
    
    if (strcmp(src_addr, target_ip) != 0) {
        return;
    }
    
    if (bytes < (int)(ip_resp->ihl * 4 + sizeof(struct tcphdr))) {
        return;
    }
    
    struct tcphdr *tcp_resp = (struct tcphdr*)(buffer + ip_resp->ihl * 4);
    int dest_port = ntohs(tcp_resp->source);
    
    port_info_t *port_info = find_port_info(dest_port);
    
    if (port_info != NULL && port_info->received == 0) {
        if (tcp_resp->syn && tcp_resp->ack) {
            if (shared_state->open_count < MAX_OPEN_PORTS) {
                shared_state->open_ports[shared_state->open_count++] = dest_port;
                printf("Port %d/tcp is open\n", dest_port);
                fflush(stdout);
            }
            
            port_info->received = 1;
            
            send_tcp_reset(dest_port, port_info->src_port, 
                       port_info->seq_num, ntohl(tcp_resp->seq) + 1);
        } else if (tcp_resp->rst) {
            port_info->received = 1;
        }
    }
}

void display_udp(char *buffer, int bytes) {
    if (bytes < (int)sizeof(struct iphdr)) {
        return;
    }

    struct iphdr *ip_resp = (struct iphdr*)buffer;
    
    if (bytes < (int)(ip_resp->ihl * 4 + sizeof(struct icmphdr))) {
        return;
    }
    
    struct icmphdr *icmp_resp = (struct icmphdr*)(buffer + ip_resp->ihl * 4);

    if (icmp_resp->type == 3 && icmp_resp->code == 3) {
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
        
        port_info_t *port_info = find_port_info(dest_port);
        if (port_info != NULL) {
            port_info->received = 1;
        }
    }
}

void listener() {
    unsigned char buffer[BUFFER_SIZE];
    struct pollfd fds[2];
    int nfds = 0;

    if (shared_state->scan_type == SCAN_TCP && sock_recv_tcp >= 0) {
        fds[nfds].fd = sock_recv_tcp;
        fds[nfds].events = POLLIN;
        nfds++;
    }

    if (shared_state->scan_type == SCAN_UDP && sock_recv_icmp >= 0) {
        fds[nfds].fd = sock_recv_icmp;
        fds[nfds].events = POLLIN;
        nfds++;
    }

    while (1) {
        if (shared_state->sender_done) {
            sleep(3);
            break;
        }

        int poll_result = poll(fds, nfds, 100);

        if (poll_result < 0) {
            perror("poll error");
            continue;
        } else if (poll_result == 0) {
            continue;
        }

        for (int i = 0; i < nfds; i++) {
            if (fds[i].revents & POLLIN) {
                struct sockaddr_in from;
                socklen_t fromlen = sizeof(from);
                memset(buffer, 0, sizeof(buffer));

                int bytes = recvfrom(fds[i].fd, buffer, sizeof(buffer), 0,
                                    (struct sockaddr*)&from, &fromlen);

                if (bytes > 0) {
                    if (shared_state->scan_type == SCAN_TCP) {
                        display_tcp((char*)buffer, bytes);
                    } else {
                        display_udp((char*)buffer, bytes);
                    }
                }
            }
        }
    }

    if (shared_state->scan_type == SCAN_UDP) {
        for (int i = 0; i < TRACKING_SIZE; i++) {
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

void sender() {
    for (int port = MIN_PORT; port <= MAX_PORT; port++) {
        shared_state->current_port = port;

        if (shared_state->scan_type == SCAN_TCP) {
            send_tcp_syn(port);
        } else {
            send_udp_packet(port);
        }

        if (port % 5000 == 0) {
            printf("Scanned %d/%d ports... (%d open)\n", port, MAX_PORT, shared_state->open_count);
            fflush(stdout);
        }

        usleep(500);  // 0.5ms delay (reduced from 5ms - comment says 1500ms which was wrong)
    }

    shared_state->sender_done = 1;
}

void cleanup() {
    if (sock_send >= 0) close(sock_send);
    if (sock_recv_tcp >= 0) close(sock_recv_tcp);
    if (sock_recv_icmp >= 0) close(sock_recv_icmp);
    if (shared_state != MAP_FAILED && shared_state != NULL) {
        munmap(shared_state, sizeof(scan_state_t));
    }
}

int main(int argc, char *argv[]) {
    int opt;
    char *host = NULL;
    char *scan_type_str = NULL;
    int scan_type = 0;

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

    if (host == NULL || scan_type == 0) {
        fprintf(stderr, "Usage: %s -a <host> -t <type>\n", argv[0]);
        fprintf(stderr, "  -a <host>  : target hostname or IP address\n");
        fprintf(stderr, "  -t <type>  : scan type (TCP or UDP)\n");
        exit(EXIT_FAILURE);
    }

    if (geteuid() != 0) {
        fprintf(stderr, "Error: This program requires root privileges (raw sockets)\n");
        fprintf(stderr, "Please run with sudo: sudo %s -a %s -t %s\n", 
                argv[0], host, scan_type_str);
        exit(EXIT_FAILURE);
    }

    if (resolve_host(host, target_ip) < 0) {
        fprintf(stderr, "Error: Could not resolve host '%s'\n", host);
        exit(EXIT_FAILURE);
    }

    // FIX: Get local IP address
    if (get_local_ip(target_ip, local_ip) < 0) {
        fprintf(stderr, "Error: Could not determine local IP address\n");
        exit(EXIT_FAILURE);
    }

    printf("Starting %s scan on %s (%s) from %s\n", 
           scan_type == SCAN_TCP ? "TCP" : "UDP", host, target_ip, local_ip);
    printf("Scanning ports 1-65535...\n\n");

    srand(time(NULL));

    shared_state = mmap(NULL, sizeof(scan_state_t),
                       PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    if (shared_state == MAP_FAILED) {
        perror("mmap failed");
        exit(EXIT_FAILURE);
    }

    memset(shared_state, 0, sizeof(scan_state_t));
    shared_state->scan_type = scan_type;
    shared_state->sender_done = 0;
    shared_state->current_port = 0;
    shared_state->open_count = 0;
    shared_state->tracking_index = 0;

    sock_send = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock_send < 0) {
        perror("socket send");
        cleanup();
        exit(EXIT_FAILURE);
    }

    const int on = 1;
    if (setsockopt(sock_send, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt");
        cleanup();
        exit(EXIT_FAILURE);
    }

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

    pid_t process_id = fork();

    if (process_id < 0) {
        perror("fork failed");
        cleanup();
        exit(EXIT_FAILURE);
    }

    if (process_id == 0) {
        listener();
        cleanup();
        exit(EXIT_SUCCESS);
    } else {
        sender();
        wait(NULL);
        printf("\n\nScan complete. Found %d open ports.\n", shared_state->open_count);
        cleanup();
    }

    return 0;
}
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 12345
#define PSEUDO_HEADER_SIZE 12

// TCP pseudo header for checksum calculation
struct pseudo_header {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_length;
};

unsigned short checksum(unsigned short *ptr, int nbytes) {
    long sum;
    unsigned short oddbyte;
    unsigned short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (short)~sum;

    return answer;
}

void send_packet(int sock, uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port, uint32_t seq, uint32_t ack_seq, bool syn_flag, bool ack_flag) {
    char datagram[4096];
    memset(datagram, 0, 4096);

    struct iphdr *iph = (struct iphdr *)datagram;
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(dst_port);
    dest.sin_addr.s_addr = dst_ip;

    // Fill IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id = htons(54321);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = src_ip;
    iph->daddr = dst_ip;
    iph->check = checksum((unsigned short *)datagram, iph->ihl << 2);

    // Fill TCP Header
    tcph->source = htons(src_port);
    tcph->dest = htons(dst_port);
    tcph->seq = htonl(seq);
    tcph->ack_seq = htonl(ack_seq);
    tcph->doff = 5;
    tcph->syn = syn_flag;
    tcph->ack = ack_flag;
    tcph->window = htons(8192);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    // Pseudo header for checksum
    struct pseudo_header psh;
    psh.src_addr = src_ip;
    psh.dst_addr = dst_ip;
    psh.reserved = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    char pseudo_packet[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];
    memcpy(pseudo_packet, &psh, sizeof(psh));
    memcpy(pseudo_packet + sizeof(psh), tcph, sizeof(struct tcphdr));

    tcph->check = checksum((unsigned short *)pseudo_packet, sizeof(pseudo_packet));

    if (sendto(sock, datagram, iph->tot_len, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto() failed");
    } else {
        std::cout << "[+] Sent packet: SEQ=" << seq << ", ACK=" << ack_seq
                  << ", SYN=" << syn_flag << ", ACK_FLAG=" << ack_flag << std::endl;
    }
}

int main() {
    uint32_t initial_seq;
    std::cout << "Enter the initial sequence number to send with SYN: ";
    std::cin >> initial_seq;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("Raw socket creation failed");
        return 1;
    }

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt() failed");
        return 1;
    }

    uint32_t src_ip = inet_addr("127.0.0.1");
    uint32_t dst_ip = inet_addr(SERVER_IP);
    uint16_t src_port = 54321;
    uint16_t dst_port = SERVER_PORT;

    // Step 1: Send SYN with user-provided initial sequence number
    send_packet(sock, src_ip, src_port, dst_ip, dst_port, initial_seq, 0, true, false);

    // Step 2: Receive SYN-ACK
    char buffer[65536];
    struct sockaddr_in saddr;
    socklen_t saddr_len = sizeof(saddr);

    int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (recv_sock < 0) {
        perror("recv socket creation failed");
        return 1;
    }

    // Set receive timeout of 3 seconds
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    bool handshake_done = false;

    while (true) {
        int data_size = recvfrom(recv_sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&saddr, &saddr_len);
        if (data_size < 0) {
            std::cerr << "[-] No response received. Handshake failed or timed out." << std::endl;
            break;
        }

        struct iphdr *iph = (struct iphdr *)buffer;
        struct tcphdr *tcph = (struct tcphdr *)(buffer + iph->ihl * 4);

        if (iph->saddr == dst_ip && tcph->source == htons(dst_port) && tcph->dest == htons(src_port)) {
            if (tcph->syn == 1 && tcph->ack == 1 && ntohl(tcph->ack_seq) == initial_seq + 1) {
                std::cout << "[+] Received SYN-ACK: SEQ=" << ntohl(tcph->seq)
                          << ", ACK=" << ntohl(tcph->ack_seq) << std::endl;

                // Step 3: Send ACK with appropriate sequence and ack numbers
                send_packet(sock, src_ip, src_port, dst_ip, dst_port, initial_seq + 400, ntohl(tcph->seq) + 1, false, true);
                handshake_done = true;
                break;
            }
        }
    }

    if (handshake_done)
        std::cout << "[+] Handshake completed." << std::endl;

    close(sock);
    close(recv_sock);
    return 0;
}

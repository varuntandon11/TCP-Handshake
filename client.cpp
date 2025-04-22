#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define PCKT_LEN 8192  // Maximum packet length

using namespace std;

// Pseudo header structure for TCP checksum calculation
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

// Function to calculate the checksum (used for TCP header)
unsigned short calculate_checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    short answer;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *)&oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }

    // Fold 32-bit sum to 16 bits and invert
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (short)~sum;

    return answer;
}

int main() {
    int sock;
    char buffer[PCKT_LEN];

    // Pointers to IP and TCP headers within the buffer
    struct iphdr *ip = (struct iphdr *) buffer;
    struct tcphdr *tcp = (struct tcphdr *) (buffer + sizeof(struct iphdr));
    struct sockaddr_in dest;
    struct pseudo_header psh;

    // Create raw socket (requires root access)
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("[-] Error creating raw socket");
        exit(1);
    }

    // Tell the kernel that we are including our own IP header
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("[-] Error setting IP_HDRINCL");
        exit(1);
    }

    memset(buffer, 0, PCKT_LEN);  // Clear the buffer

    // Construct the IP header
    ip->ihl = 5;                      // Header length
    ip->version = 4;                 // IPv4
    ip->tos = 0;                     // Type of service
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr)); // Total length
    ip->id = htons(54321);          // ID for fragmentation
    ip->frag_off = 0;
    ip->ttl = 64;                   // Time to live
    ip->protocol = IPPROTO_TCP;     // Protocol
    ip->saddr = inet_addr("127.0.0.1");  // Client IP
    ip->daddr = inet_addr("127.0.0.1");  // Server IP (same for local testing)

    // Construct the TCP header for SYN packet
    tcp->source = htons(1234);       // Source port
    tcp->dest = htons(12345);        // Destination port (server listens here)
    tcp->seq = htonl(200);           // Initial sequence number
    tcp->ack_seq = 0;                // No ACK for initial SYN
    tcp->doff = 5;                   // TCP header length
    tcp->syn = 1;                    // Set SYN flag
    tcp->window = htons(5840);       // Window size
    tcp->check = 0;                  // Checksum (computed later)
    tcp->urg_ptr = 0;                // No urgent data

    // Build pseudo-header for checksum calculation
    psh.source_address = inet_addr("127.0.0.1");
    psh.dest_address = inet_addr("127.0.0.1");
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    // Create pseudo-packet to compute checksum
    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char *pseudogram = (char *) malloc(psize);
    memcpy(pseudogram, (char *) &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcp, sizeof(struct tcphdr));
    tcp->check = calculate_checksum((unsigned short *) pseudogram, psize); // Set TCP checksum

    // Define destination address
    dest.sin_family = AF_INET;
    dest.sin_port = htons(12345);  // Server port
    dest.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Send SYN packet
    cout << "[+] Sending SYN..." << endl;
    if (sendto(sock, buffer, ip->tot_len, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("[-] SYN send failed");
    }

    // Prepare to receive SYN-ACK from server
    char recv_buf[65536];
    while (true) {
        int len = recv(sock, recv_buf, sizeof(recv_buf), 0);
        if (len < 0) continue;

        // Parse received IP and TCP headers
        struct iphdr *recv_ip = (struct iphdr *)recv_buf;
        struct tcphdr *recv_tcp = (struct tcphdr *)(recv_buf + recv_ip->ihl * 4);

        // If it's a SYN-ACK with expected ACK sequence, proceed
        if (recv_tcp->syn == 1 && recv_tcp->ack == 1 && ntohl(recv_tcp->ack_seq) == 201) {
            cout << "[+] Received SYN-ACK from server" << endl;

            // Construct ACK packet
            memset(buffer, 0, PCKT_LEN);  // Clear the buffer again
            ip = (struct iphdr *) buffer;
            tcp = (struct tcphdr *) (buffer + sizeof(struct iphdr));

            // Fill in IP header again
            ip->ihl = 5;
            ip->version = 4;
            ip->tos = 0;
            ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
            ip->id = htons(54322);  // Different ID
            ip->frag_off = 0;
            ip->ttl = 64;
            ip->protocol = IPPROTO_TCP;
            ip->saddr = inet_addr("127.0.0.1");
            ip->daddr = inet_addr("127.0.0.1");

            // Fill in final ACK packet
            tcp->source = htons(1234);
            tcp->dest = htons(12345);
            tcp->seq = htonl(600);          // New sequence number
            tcp->ack_seq = htonl(401);      // Acknowledge server’s seq + 1
            tcp->doff = 5;
            tcp->ack = 1;
            tcp->window = htons(5840);
            tcp->check = 0;

            // Recalculate checksum for ACK
            memcpy(pseudogram + sizeof(struct pseudo_header), tcp, sizeof(struct tcphdr));
            tcp->check = calculate_checksum((unsigned short *) pseudogram, psize);

            // Send final ACK
            cout << "[+] Sending final ACK..." << endl;
            if (sendto(sock, buffer, ip->tot_len, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
                perror("[-] ACK send failed");
            } else {
                cout << "[+] Handshake complete!" << endl;
            }

            break;
        }
    }

    // Cleanup
    close(sock);
    free(pseudogram);
    return 0;
}

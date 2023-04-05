//Compiled with gcc Firewall.c -o Firewall -lnetfilter_queue -lnfnetlink

// iptables -A INPUT  -j NFQUEUE --queue-balance 0:3
// iptables -A OUTPUT -j NFQUEUE --queue-balance 0:3

//sudo iptables -A OUTPUT -p tcp -d 1.1.1.1 --dport 1111 -j REJECT



// sudo iptables -A INPUT -s 172.24.56.22 -j NFQUEUE --queue-num 0
// sudo iptables -A INPUT -d 172.24.56.22 -j NFQUEUE --queue-num 0
// sudo iptables -A OUTPUT -s 172.24.56.22 -j NFQUEUE --queue-num 0
// sudo iptables -A OUTPUT -d 172.24.56.22 -j NFQUEUE --queue-num 0

// todo -> retrive pid of proccess that created packet **


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/nfnetlink.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
//#include <linux/icmp.h>


static u_int32_t my_mark = 42;


#define IP_ADDRESS "172.24.56.22" // IP address to block
#define BLOCK_PORT 2222 // Port to block
#define MAX_PACKET_SIZE 2048 * 2048 // maximom payload size

#define BUF_SIZE 4096

int sendTcpRstPacket(const char* source_ip_str, uint16_t source_port,
                        const char* dest_ip_str, uint16_t dest_port)
{
    // Create a raw socket for sending packets
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock == -1) 
    {
        printf("ERR : socket\n");
        perror("socket");
        return -1;
    }

    // Set socket options to allow sending IP headers
    int optval = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) == -1) 
    {
        printf("ERR : setsockopt\n");
        perror("setsockopt");
        close(sock);
        return -1;
    }

    // Create IP and TCP headers
    char buf[BUF_SIZE];
    struct iphdr* ip_header = (struct iphdr*)buf;
    struct tcphdr* tcp_header = (struct tcphdr*)(buf + sizeof(struct iphdr));
    memset(buf, 0, BUF_SIZE);
    ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    ip_header->id = htons(12345);
    ip_header->ttl = 64;
    ip_header->protocol = IPPROTO_TCP;
    ip_header->saddr = inet_addr(source_ip_str);
    ip_header->daddr = inet_addr(dest_ip_str);
    tcp_header->source = htons(source_port);
    tcp_header->dest = htons(dest_port);
    tcp_header->doff = 5;
    tcp_header->rst = 1;
    tcp_header->ack = 1;
    tcp_header->ack_seq = htonl(0);

    // Set checksum fields in IP and TCP headers
    ip_header->check = 0;
    ip_header->check = htons(~ip_header->check);
    tcp_header->check = 0;
    tcp_header->check = htons(~tcp_header->check);

    // Set destination address for sending the packet
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = ip_header->daddr;

    // Send the packet
    int ret = sendto(sock, buf, ip_header->tot_len, 0,
                     (struct sockaddr*)&dest_addr, sizeof(dest_addr));
    if (ret == -1) 
    {
        printf("ERR : sendto\n");
        perror("sendto");
        close(sock);
        return -1;
    }

    // Close the socket and return success
    close(sock);
    return 0;
}



void redirectPacketToReject(u_int8_t * payload)
{
    struct iphdr * ip_header = (struct iphdr *) payload;
    struct tcphdr* tcp_header = (struct tcphdr*)(payload + (ip_header->ihl * 4));

    


}


void getStringIpFromIpHeader (struct iphdr* ipHeader , char* ip_src_str , char* ip_dst_str)
{
    struct in_addr saddr,daddr;
    saddr.s_addr = ipHeader->saddr;
    daddr.s_addr = ipHeader->daddr;
    inet_ntop(AF_INET, &(saddr.s_addr), ip_src_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(daddr.s_addr), ip_dst_str, INET_ADDRSTRLEN);
    printf("IP address src: %s\n", ip_src_str);
    printf("IP address dsrt: %s\n", ip_dst_str);
}


void printPacketData (struct iphdr* ipHeader)
{        
    printf("ip_header-> version  = %d\n",ipHeader->version);
    printf("ip_header-> protocol = %d\n",ipHeader->protocol);   
}

static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    u_int8_t * payload;// = (u_int8_t *) malloc (MAX_PACKET_SIZE * sizeof(u_int8_t));
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    char ip_src_str[INET_ADDRSTRLEN],ip_dst_str[INET_ADDRSTRLEN];
    u_int32_t mark, id, ret;
    char *pkt_data;
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    int verdict = NF_ACCEPT;
    int packetLen = 0;
    
 
    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph)
    {
        id = ntohl(ph->packet_id);
    }    

    mark = nfq_get_nfmark(nfa);

    // Get the packet data from the netfilter queue
    packetLen = nfq_get_payload(nfa, &payload);
    if (packetLen <= 0) 
    {
        // Drop the packet if the payload is empty or invalid
        printf("Packet payload is empty or invalid\n");
        return nfq_set_verdict(qh, ntohs(nfmsg->nfgen_family), NF_DROP, 0, NULL);
    }

    ip_header = (struct iphdr *) payload;

    printPacketData(ip_header) ;

    if (ip_header->protocol == IPPROTO_IP)
    {
        printf("IP packet\n");
        u_int32_t ip_src = ip_header->saddr;
        u_int32_t ip_dst = ip_header->daddr;

        printf("Source IP: %u.%u.%u.%u\n", (ip_src) & 0xff, (ip_src >> 8) & 0xff, (ip_src >> 16) & 0xff, (ip_src >> 24) & 0xff);
        printf("Dest IP: %u.%u.%u.%u\n", (ip_dst) & 0xff, (ip_dst >> 8) & 0xff, (ip_dst >> 16) & 0xff, (ip_dst >> 24) & 0xff);


        // if (strcmp(inet_ntoa(*(struct in_addr*)&ip_header->daddr), IP_ADDRESS) == 0) 
        // {
        //     printf("Blocking Incoming IP packet with ID %d\n", id);
        //     verdict = NF_DROP;
        // }

        // if (strcmp(inet_ntoa(*(struct in_addr*)&ip_header->saddr), IP_ADDRESS) == 0) 
        // {
        //     printf("Blocking Outgoing IP packet with ID %d\n", id);
        //     verdict = NF_DROP;
        // }
    }
    else if (ip_header->protocol ==  IPPROTO_IPV6)
    {

    }
    else if (ip_header->protocol == IPPROTO_TCP)
    {
        tcp_header = (struct tcphdr*)(payload + (ip_header->ihl * 4));
        u_int16_t port_src = tcp_header->source;
        u_int16_t port_dst = tcp_header->dest;
        uint32_t ip_src = ip_header->saddr;
        uint32_t ip_dst = ip_header->daddr;
        printf("TCP packet\n");
        getStringIpFromIpHeader(ip_header,ip_src_str,ip_dst_str);
        printf("Source Port : %d\n",ntohs(port_src));
        printf("Dest   Port : %d\n",ntohs(port_dst));

        // if (ntohs(port_dst) == BLOCK_PORT && strcmp(ip_dst_str, IP_ADDRESS) == 0) 
        // {
        //     printf("Blocking Outgoing TCP packet with ID %d\n", id);
        //     sendTcpRstPacket(ip_dst_str,ntohs(port_dst),ip_src_str,ntohs(port_src));            

        //     return nfq_set_verdict2(qh, id, NF_DROP, htons(ICMP_NET_UNREACH), 0, NULL);
        // }

        if (ntohs(port_dst) == BLOCK_PORT && strcmp(ip_dst_str, IP_ADDRESS) == 0)
        {
            printf("Blocking Outgoing TCP packet with ID %d\n", id);
            // Use netlink socket to retrieve pid of process that created packet
            struct nlattr *attr[NFQA_MAX+1];
            int ret = nfq_get_payload(nfmsg, attr);

            if (ret >= 0 && attr[NFQA_PID]) {
                uint32_t pid = ntohl(*((uint32_t*)nla_data(attr[NFQA_PID])));
                return pid;
                printf("Packet created by process with PID %d\n", pid);
            }
            
            mark |= my_mark; // Add our mark to the packet
            ip_header ->daddr = inet_addr("1.1.1.1");
            tcp_header->dest =  htons(1111);
            u_int16_t port_src = tcp_header->source;
            u_int16_t port_dst = tcp_header->dest;
            uint32_t ip_src = ip_header->saddr;
            uint32_t ip_dst = ip_header->daddr;
            printf("Received TCP packet\n");
            getStringIpFromIpHeader(ip_header,ip_src_str,ip_dst_str);
            printf("New Source Port : %d\n",ntohs(port_src));
            printf("New Dest   Port : %d\n",ntohs(port_dst));
            //Re-inject the modified packet back into the kernel's networking stack
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0,NULL);

            //verdict = nfq_set_verdict(qh, id, NF_DROP, 0, NULL);

            // Send an ICMP "port unreachable" message back to the sender
            // struct icmphdr *icmp_hdr = (struct icmphdr *) (payload + sizeof(struct iphdr));
            // icmp_hdr->type = ICMP_DEST_UNREACH;
            // icmp_hdr->code = ICMP_PORT_UNREACH;
            // icmp_hdr->checksum = 0;
            // unsigned char *icmp_payload = payload + sizeof(struct iphdr) + sizeof(struct icmphdr);
            // int icmp_payload_len = packetLen - sizeof(struct iphdr) - sizeof(struct icmphdr);
            // icmp_hdr->checksum = htons(~(ICMP_DEST_UNREACH << 8 | ICMP_PORT_UNREACH) & 0xffff);
            // return nfq_set_verdict2(qh, id, NF_DROP,mark, ntohs(ip_header->tot_len), (unsigned char *) ip_header);


            // struct nfqnl_msg_packet_hw *hwph = nfq_get_packet_hw(nfa);
            // unsigned char *mac = nfq_get_macaddr(hwph);
            // return nfq_set_verdict2(qh, id, NF_REJECT, htons(ICMP_PORT_UNREACH), 0, NULL);
        }

        // if (ntohs(port_src) == BLOCK_PORT && strcmp(ip_src_str, IP_ADDRESS) == 0) 
        // {
        //     printf("Blocking Incoming TCP packet with ID %d\n", id);
        //     verdict = NF_DROP;
        // }

    } 
    else if (ip_header->protocol == IPPROTO_UDP) 
    {
        udp_header = (struct udphdr*)(payload + (ip_header->ihl * 4));

        printf("Received UPD packet\n");
        u_int32_t ip_src = ip_header->saddr;
        u_int32_t ip_dst = ip_header->daddr;
        u_int16_t port_srt = ntohs(udp_header->source);
        u_int16_t port_dst = ntohs(udp_header->dest);
        printf("Source IP: %u.%u.%u.%u Source Port : %d\n", (ip_src) & 0xff, (ip_src >> 8) & 0xff, (ip_src >> 16) & 0xff, (ip_src >> 24) & 0xff,port_srt);
        printf("Dest IP: %u.%u.%u.%u Dest Port : %d\n", (ip_dst) & 0xff, (ip_dst >> 8) & 0xff, (ip_dst >> 16) & 0xff, (ip_dst >> 24) & 0xff,port_dst);
        
        if (ntohs(udp_header->dest) == BLOCK_PORT && strcmp(inet_ntoa(*(struct in_addr*)&ip_header->saddr), IP_ADDRESS) == 0) {
            printf("Blocking UDP packet with ID %d\n", id);
            verdict = NF_DROP;
        }
    }
    else if (ip_header->protocol == IPPROTO_ICMP ) 
    {
        printf("ICMP packet\n");
        getStringIpFromIpHeader(ip_header,ip_src_str,ip_dst_str);
        // printf("Blocking ICMP packet with ID %d\n", id);
        // verdict = NF_DROP;
    }

    // Accept the packet if it doesn't match the filter criteria
    printf(verdict == NF_ACCEPT ? "Accepting packet\n" : "" );\
   
    return nfq_set_verdict(qh, id/*ntohs(nfmsg->nfgen_family)*/, verdict,0/*len*/, NULL /*buffer*/);
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd, rv;
    char buf[4096];

    printf("Starting packet filter\n");

    // Open library handle
    if (!(h = nfq_open()))
    {
        perror("nfq_open");
        exit(1);
    }

    // Unbind existing nf_queue handler (if any)
    if (nfq_unbind_pf(h, AF_INET) < 0)
    {
        perror("nfq_unbind_pf");
        exit(1);
    }

    // Bind nfnetlink_queue as nf_queue handler of AF_INET
    if (nfq_bind_pf(h, AF_INET) < 0)
    {
        perror("nfq_bind_pf");
        exit(1);
    }

    // Bind socket to queue '0'
    if (!(qh = nfq_create_queue(h, 0, &callback, NULL)))
    {
        perror("nfq_create_queue");
        exit(1);
    }

    // Set copy_packet mode
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        perror("nfq_set_mode");
        exit(1);
    }

    // Get netlink handle
    if (!(nh = nfq_nfnlh(h)))
    {
        perror("nfq_nfnlh");
        exit(1);
    }

    // Get file descriptor
    if ((fd = nfnl_fd(nh)) < 0)
    {
        perror("nfnl_fd");
        exit(1);
    }

    // Listen for packets
    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        printf("--- Received packet ---\n");
        nfq_handle_packet(h, buf, rv);
    }

    // Close queue and handle
    nfq_destroy_queue(qh);
    nfq_close(h);

    exit(0);
}

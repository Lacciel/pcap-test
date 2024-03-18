#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>


#define ETHER_ADDR_LEN 6
#define ETHERTYPE_IP            0x0800  /* IP protocol */

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

struct libnet_ipv4_hdr
{
    u_int8_t ip_hl:4, ip_v:4;   /* header length , version */
    u_int8_t ip_tos;            /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
    u_int8_t th_x2:4,th_off:4; /* (unused), data offset */
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};



void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void macToString(u_int8_t ether_mac[], char *str){
    for(int i=0 ; i<ETHER_ADDR_LEN; i++){
        sprintf(str + 3 * i, "%02x",ether_mac[i]);
        if(i<ETHER_ADDR_LEN -1 ) str[3*i+2] = ':';
    }
}


int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        struct libnet_ethernet_hdr *eth_hdr = packet;
        struct libnet_ipv4_hdr *ip_hdr = packet + sizeof(struct libnet_ethernet_hdr);
        struct libnet_tcp_hdr *tcp_hdr = packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr);
        if(ip_hdr->ip_p != IPPROTO_TCP) continue;

        //printf("%u bytes captured\n", header->caplen);

        //Ethernet Header
        char srcMac[18] = "", dstMac[18] = "";
        macToString(eth_hdr->ether_shost, srcMac);
        macToString(eth_hdr->ether_dhost, dstMac);
        printf("Ethernet MAC Address : src(%s) -> dst(%s) \n", srcMac, dstMac);

        //IP Header
        char srcIP[16] = "", dstIP[16] = "";
        inet_ntop(AF_INET,&ip_hdr->ip_src,srcIP,sizeof(srcIP));
        inet_ntop(AF_INET,&ip_hdr->ip_dst,dstIP,sizeof(dstIP));
        printf("IP Address : src(%s) -> dst(%s)\n", srcIP, dstIP);

        //TCP Header
        printf("TCP Port Address : src(%u) -> dst(%u)\n",ntohs(tcp_hdr->th_sport), ntohs(tcp_hdr->th_dport));

        //DATA
        printf("TCP Data[10 Bytes]:");
        for(int i=0;i<10;i++){
            printf("%02x ", *(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + tcp_hdr->th_off*4 + i ));
        }
        printf("\n\n");

    }

    pcap_close(pcap);
}

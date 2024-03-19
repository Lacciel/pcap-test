#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "customLibnet.h"

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
        struct libnet_tcp_hdr *tcp_hdr = packet + sizeof(struct libnet_ethernet_hdr) + ip_hdr->ip_hl * 4;
        if(eth_hdr->ether_type != ETHERTYPE_IP && ip_hdr->ip_p != IPPROTO_TCP) continue;

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
        int data_size = ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl*4 + tcp_hdr->th_off*4);
        if(!data_size){ //if IP Packet Total Length > IP Header + TCP Header
            printf("No Data\n");
            continue;
        }
        if(data_size > 10) data_size = 10;
        int data_offset = sizeof(struct libnet_ethernet_hdr) + ip_hdr->ip_hl*4 + tcp_hdr->th_off*4;
        printf("total %d, ip %d, tcp %d offset %d \n",ntohs(ip_hdr->ip_len),ip_hdr->ip_hl*4,tcp_hdr->th_off*4,data_offset);
        printf("TCP Data[%d Bytes]:", data_size);
        for(int i=0;i<data_size;i++){
            printf("%02x ", *(packet + data_offset + i ));
        }
        printf("\n\n");

    }

    pcap_close(pcap);
}

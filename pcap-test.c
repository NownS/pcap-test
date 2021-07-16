#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <netinet/in.h>



void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
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

void print_MAC(uint8_t *mac){
    for(int i=0;i<5;i++){
        printf("%02x:", mac[i]);
    }
    printf("%02x\t", mac[5]);
}

void print_IP(struct in_addr ip){
    uint32_t myip = ntohl(ip.s_addr);
    uint8_t a, b, c, d;
    a = (myip & 0xFF000000) >> 24;
    b = (myip & 0x00FF0000) >> 16;
    c = (myip & 0x0000FF00) >> 8;
    d = (myip & 0x000000FF) >> 0;
    printf("%u.%u.%u.%u\t\t", a, b, c, d);
}

void print_port(uint16_t port){
    uint16_t myport = ntohs(port);
    printf("%d\t\t\t", myport);
}

void print_data(uint8_t *data, int length){
    for(int i=0;i<8;i++){
        if(length == 0) break;
        printf("%02x ", data[i]);
        length--;
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

    struct libnet_ethernet_hdr *ethernetHDR;
    struct libnet_ipv4_hdr *ipHDR;
    struct libnet_tcp_hdr *tcpHDR;
    uint8_t *tcpData;

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

        ethernetHDR = (struct libnet_ethernet_hdr *)packet;
        uint16_t type = ntohs(ethernetHDR->ether_type);
        if(type != 0x0800){
            //fprintf(stderr, "ether_type is 0x%04x\n", type);
            continue;
        }

        packet += 14;
        ipHDR = (struct libnet_ipv4_hdr*) packet;
        if(ipHDR->ip_p != 0x06){
            //fprintf(stderr, "protocol number is 0x%02x\n", ipHDR->ip_p);
            continue;
        }

        packet += ipHDR->ip_hl * 4;
        tcpHDR = (struct libnet_tcp_hdr*) packet;
        packet += tcpHDR->th_off * 4;
        tcpData = (uint8_t *) packet;

        printf("src MAC: ");
        print_MAC(ethernetHDR->ether_shost);
        printf("dst MAC: ");
        print_MAC(ethernetHDR->ether_dhost);
        printf("\n");

        printf("src IP: ");
        print_IP(ipHDR->ip_src);
        printf("dst IP: ");
        print_IP(ipHDR->ip_dst);
        printf("\n");

        printf("src port: ");
        print_port(tcpHDR->th_sport);
        printf("dst port: ");
        print_port(tcpHDR->th_dport);
        printf("\n");

        int length = ntohs(ipHDR->ip_len) - (ipHDR->ip_hl * 4 + tcpHDR->th_off * 4);
        printf("Data: ");
        print_data(tcpData, length);
        printf("\n\n");
	}

	pcap_close(pcap);
}

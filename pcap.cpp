#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <libnet.h> /* apt-get install libnet-dev */

static int tcp_packet_count = 0;
static int udp_packet_count = 0;

struct ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

struct ip *iphdr;
struct tcphdr *tcp_hdr;
struct udphdr *udp_hdr;

int main(int argc, char* argv[]){
	if(argc < 2){
		printf("Argument Error | Usage : %s <pcap_file>\n",argv[0]);
		return 0;
	}

	char* pcap_file = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_offline(pcap_file, errbuf);

	if(handle == nullptr){
		fprintf(stderr, "pcap_open_offline(%s) return nullptr - %s\n", pcap_file, errbuf);
		return 0;
	}

	while (true){
		struct ethernet_hdr *eth_hdr;
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0){
			continue;
		}else if(res == -1 || res == -2){
			break;
		}
		
		//printf("\n %u bytes\n", header->caplen);

		eth_hdr = (struct ethernet_hdr *)packet;

		if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP){
			iphdr = (struct ip *) (packet + sizeof(ethernet_hdr));

			if(iphdr->ip_p == IPPROTO_TCP){
				printf("###### tcp packet ######\n");
				printf("tcp packet count : %d\n", ++tcp_packet_count);
				tcp_hdr = (struct tcphdr *) (packet + sizeof(ethernet_hdr) + sizeof(ip));
				printf("Address A %s\n", inet_ntoa(iphdr->ip_src));
				printf("Port A : %d\n", ntohs(tcp_hdr->th_sport));
				printf("Address B %s\n", inet_ntoa(iphdr->ip_dst));
				printf("Port B : %d\n", ntohs(tcp_hdr->th_dport));
				printf("Bytes : %d\n", header->caplen);
				printf("\n");
			}
			
			printf("\n");

			if(iphdr->ip_p == IPPROTO_UDP){
				printf("###### udp packet ######\n");
				printf("udp packet count : %d\n", ++udp_packet_count);
				udp_hdr = (struct udphdr *) (packet + sizeof(ethernet_hdr) + sizeof(tcphdr));

				// udp information
				printf("Address A %s\n", inet_ntoa(iphdr->ip_src));
				printf("Port A %d\n", ntohs(udp_hdr->uh_sport));
				printf("Address B %s\n", inet_ntoa(iphdr->ip_dst));
				printf("Port B %d\n", ntohs(udp_hdr->uh_dport));
				printf("Bytes : %d\n", header->caplen);
				printf("\n");

			}


		}


	}

	return 0;
}

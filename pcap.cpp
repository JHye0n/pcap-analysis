#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <libnet.h> /* apt-get install libnet-dev */

struct ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

struct ip *iphdr;
struct tcphdr *tcp_hdr;

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
			//printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		
		printf("\n %u bytes\n", header->caplen);

		eth_hdr = (struct ethernet_hdr *)packet;

		if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP){
			iphdr = (struct ip *) (packet + sizeof(ethernet_hdr));
			printf("sip : %s\n", inet_ntoa(iphdr->ip_src));
			printf("dip : %s\n", inet_ntoa(iphdr->ip_dst));

			if(iphdr->ip_p == IPPROTO_TCP){
				tcp_hdr = (struct tcphdr *) (packet + sizeof(ethernet_hdr) + sizeof(ip));
				printf("sport : %d\n", ntohs(tcp_hdr->th_sport));
				printf("dport : %d\n", ntohs(tcp_hdr->th_dport));
				printf("\n");
			}
		}


	}

	return 0;
}

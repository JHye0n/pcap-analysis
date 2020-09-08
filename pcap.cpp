#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <libnet.h> /* apt-get install libnet-dev */
#include "header.h"

/*char *getmyipaddr(){
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;

	strncpy(ifr.ifr_name, "enp0s5", IFNAMSIZ-1);

	ioctl(fd, SIOCGIFADDR, &ifr);

	close(fd);

	return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}*/

void init(ListHeader *packet){
	packet->length = 0;
	packet->head = packet->tail = NULL;
}

void tcp(const u_char* packet, ListHeader *tcppacket){
	ListNode *temp = (ListNode *)malloc(sizeof(ListNode));
	ListNode *tcp_p = tcppacket->head;
	tcp_hdr = (struct tcphdr *) (packet + sizeof(ethernet_hdr) + sizeof(ip));
	printf("%d\n", ntohs(tcp_hdr->th_sport));
}

int main(int argc, char* argv[]){
	if(argc < 2){
		printf("Argument Error | Usage : %s <pcap_file>\n",argv[0]);
		return 0;
	}

	ListHeader tcppacket;
	init(&tcppacket);

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

        	eth_hdr = (struct ethernet_hdr *) packet;

        	if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP){
                	iphdr = (struct ip *) (packet + sizeof(ethernet_hdr));

                	if(iphdr->ip_p == IPPROTO_TCP){
				tcp(packet, &tcppacket);
			}else if(iphdr->ip_p == IPPROTO_UDP){
				//udp(packet, &udp_packet);
			}
		}
	}

	return 0;
}

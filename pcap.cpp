#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <libnet.h> /* apt-get install libnet-dev */
#include <stdlib.h>

//static int packet_a_to_b = 0;
//static int packet_b_to_a = 0;

typedef struct ListNode{
	in_addr address_a;
	in_addr address_b;
	u_short port_a;
	u_short port_b;
	struct ListNode *link;
} ListNode;

typedef struct ListHeader{
	int length;
	ListNode *head;
	ListNode *tail;
} ListHeader;

struct ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

struct ip *iphdr;
struct tcphdr *tcp_hdr;
struct udphdr *udp_hdr;


char *getmyipaddr(){
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;

	strncpy(ifr.ifr_name, "enp0s5", IFNAMSIZ-1);

	ioctl(fd, SIOCGIFADDR, &ifr);

	close(fd);

	return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

void init(ListHeader *plist){
	plist->length = 0;
	plist->head = plist->tail = NULL;
}

void tcp(const u_char* packet, ListHeader *tcp_packet, char *myip){
	ListNode *tcp_p = tcp_packet->head;
	struct ethernet_hdr *eth_hdr;
	eth_hdr = (struct ethernet_hdr *) packet;

	if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP){
		iphdr = (struct ip *) (packet + sizeof(ethernet_hdr));

		if(iphdr->ip_p == IPPROTO_TCP){
			tcp_hdr = (struct tcphdr *) (packet + sizeof(ethernet_hdr) + sizeof(ip));

			//printf("%d\n", ntohs(tcp_hdr->th_sport));

			//printf("%s\n", myip);
			//printf("%s\n", inet_ntoa(iphdr->ip_src));
			//printf("%s\n", inet_ntoa(iphdr->ip_dst));

			if(strcmp(myip, inet_ntoa(iphdr->ip_src)) == 0){
				printf("Address A : %s\n", inet_ntoa(iphdr->ip_src));
				printf("PORT A : %d\n", ntohs(tcp_hdr->th_sport));
				printf("Address B : %s\n", inet_ntoa(iphdr->ip_dst));
				printf("PORT B : %d\n", ntohs(tcp_hdr->th_dport));
				printf("\n");
			}
		}

	}
}

void udp(const u_char* packet, ListHeader *udp_packet){
	ListNode *udp_p = udp_packet->head;
	struct ethernet_hdr *eth_hdr;
	eth_hdr = (struct ethernet_hdr *) packet;

	if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP){
		iphdr = (struct ip *) (packet + sizeof(ethernet_hdr));

		if(iphdr->ip_p == IPPROTO_UDP){
			udp_hdr = (struct udphdr *) (packet + sizeof(ethernet_hdr) + sizeof(tcphdr));

		}
	}
}

int main(int argc, char* argv[]){
	if(argc < 2){
		printf("Argument Error | Usage : %s <pcap_file>\n",argv[0]);
		return 0;
	}

	char* pcap_file = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	//myip
	char *myip = getmyipaddr();
	
	//listheader added
	ListHeader tcp_packet, udp_packet;

	//listheader clear
	init(&tcp_packet);
	init(&udp_packet);


	//char *myip = getmyipaddr();
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
		
		//tcp packet
		tcp(packet, &tcp_packet, myip);
		
		//udp packet
		udp(packet, &udp_packet);


	}

	pcap_close(handle);

	return 0;
}

#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <libnet.h> /* apt-get install libnet-dev */
#include "header.h"

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

void init(ListHeader *packet){
	packet->length = 0;
	packet->head = packet->tail = NULL;
}

void tcp(struct pcap_pkthdr* header, const u_char* packet, ListHeader *tcppacket, char *myip){
	ListNode *temp = (ListNode *)malloc(sizeof(ListNode));
	//ListNode *tcp_p = tcppacket->head;
	tcp_hdr = (struct tcphdr *) (packet + sizeof(ethernet_hdr) + sizeof(ip));

	if(strcmp(myip, inet_ntoa(iphdr->ip_src)) == 0){
		temp->address_a = iphdr->ip_src;
		temp->address_b = iphdr->ip_dst;
		temp->port_a = tcp_hdr->th_sport;
		temp->port_b = tcp_hdr->th_dport;

		if(inet_ntoa(temp->address_a) == inet_ntoa(iphdr->ip_src) && inet_ntoa(temp->address_b) == inet_ntoa(iphdr->ip_dst) && ntohs(temp->port_a) == ntohs(tcp_hdr->th_sport) && ntohs(temp->port_b) == ntohs(tcp_hdr->th_dport)){
			temp->packet_a_to_b++;
			temp->packet_a_to_b_byte = header->caplen;

		}

	}else{
		temp->address_a = iphdr->ip_dst;
		temp->address_b = iphdr->ip_src;
		temp->port_a = tcp_hdr->th_dport;
		temp->port_b = tcp_hdr->th_sport;

		if(inet_ntoa(temp->address_a) == inet_ntoa(iphdr->ip_dst) && inet_ntoa(temp->address_b) == inet_ntoa(iphdr->ip_src) && ntohs(temp->port_a) == ntohs(tcp_hdr->th_dport) && ntohs(temp->port_b) == ntohs(tcp_hdr->th_sport)){
			temp->packet_b_to_a++;
			temp->packet_b_to_a_byte = header->caplen;
			
		}

	}

	printf("Protocol :: TCP\n");
	printf("Address A : %s\n", inet_ntoa(temp->address_a));
        printf("Port A : %d\n", ntohs(temp->port_a));
        printf("Address B : %s\n", inet_ntoa(temp->address_b));
        printf("Port B : %d\n", ntohs(temp->port_b));
        printf("Packet A->B : %d\n", temp->packet_a_to_b);
        printf("Packet A->B Bytes : %d\n", temp->packet_a_to_b_byte);
        printf("Packet B->A : %d\n", temp->packet_b_to_a);
        printf("Packet B->A Bytes : %d\n", temp->packet_b_to_a_byte);
        printf("\n");

}

/*void udp(struct pcap_pkthdr* header, const u_char* packet, ListHeader *udppacket, char *myip){
        ListNode *temp = (ListNode *)malloc(sizeof(ListNode));
        //ListNode *udp_p = udppacket->head;
        udp_hdr = (struct udphdr *) (packet + sizeof(ethernet_hdr) + sizeof(tcphdr));

        if(strcmp(myip, inet_ntoa(iphdr->ip_src)) == 0){
                temp->address_a = iphdr->ip_src;
                temp->address_b = iphdr->ip_dst;
                temp->port_a = udp_hdr->uh_sport;
                temp->port_b = udp_hdr->uh_dport;

                if(inet_ntoa(temp->address_a) == inet_ntoa(iphdr->ip_src) && inet_ntoa(temp->address_b) == inet_ntoa(iphdr->ip_dst) && ntohs(temp->port_a) == ntohs(udp_hdr->uh_sport) && ntohs(temp->port_b) == ntohs(udp_hdr->uh_dport)){
                        temp->packet_a_to_b++;
                        temp->packet_a_to_b_byte = header->caplen;
                }

        }else{
                temp->address_a = iphdr->ip_dst;
                temp->address_b = iphdr->ip_src;
                temp->port_a = udp_hdr->uh_dport;
                temp->port_b = udp_hdr->uh_sport;

                if(inet_ntoa(temp->address_a) == inet_ntoa(iphdr->ip_dst) && inet_ntoa(temp->address_b) == inet_ntoa(iphdr->ip_src) && ntohs(temp->port_a) == ntohs(udp_hdr->uh_dport) && ntohs(temp->port_b) == ntohs(udp_hdr->uh_sport)){
                        temp->packet_b_to_a++;
                        temp->packet_b_to_a_byte = header->caplen;
                }

        }

	printf("Protocol :: UDP\n");
        printf("Address A : %s\n", inet_ntoa(temp->address_a));
        printf("Port A : %d\n", ntohs(temp->port_a));
        printf("Address B : %s\n", inet_ntoa(temp->address_b));
        printf("Port B : %d\n", ntohs(temp->port_b));
        printf("Packet A->B : %d\n", temp->packet_a_to_b);
        printf("Packet A->B Bytes : %d\n", temp->packet_a_to_b_byte);
        printf("Packet B->A : %d\n", temp->packet_b_to_a);
        printf("Packet B->A Bytes : %d\n", temp->packet_b_to_a_byte);
        printf("\n");

        free(temp);
}*/

int main(int argc, char* argv[]){
	if(argc < 2){
		printf("Argument Error | Usage : %s <pcap_file>\n",argv[0]);
		return 0;
	}

	ListHeader tcppacket, udppacket;
	init(&tcppacket);
	init(&udppacket);

	char* pcap_file = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	char* myip = getmyipaddr();

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
		}

	}

	pcap_close(handle);

	return 0;
}

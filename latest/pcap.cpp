/** c++ pcap-analysis **/

#include <cstdio>
#include <pcap.h>
#include <iostream>
#include <map>
#include "header.h" // header define
#include "struct.h"
#include "ip.h"

using namespace std;

map<flowpacket, int> packetinfo;

void usage(char* argv[]){
	printf("Usage %s <pcap-file>\n", argv[0]);
}

void print_packet()
{
	map<flowpacket, int>::iterator it;

	for(it == packetinfo.begin(); it != packetinfo.end(); it++){

		cout << it->first.protocol.c_str() << endl;
	}

}

void pk_receive(struct pcap_pkthdr* header, const u_char *packet){

	flowpacket temp;

	eth_hdr = (struct ethernet_hdr *) packet;

	int packetsize = packetinfo.size() + 1;

	if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP){
		
		iphdr = (struct ip *) (packet + sizeof(ethernet_hdr));

		if(iphdr->ip_p == IPPROTO_TCP){
			tcp_hdr = (struct tcphdr *) (packet + sizeof(ethernet_hdr) + sizeof(ip));

			temp.protocol = "TCP";
			temp.src_addr = Ip(htonl(iphdr->ip_src.s_addr));
			temp.src_port = ntohs(tcp_hdr->th_sport);
			temp.dst_addr = Ip(htonl(iphdr->ip_dst.s_addr));
			temp.dst_port = ntohs(tcp_hdr->th_dport);
			temp.tcp_pk += 1;
			temp.tcp_pkbyte = header->caplen;
			//packetinfo.insert(make_pair(temp, packetsize));

			printf("packet byte(a->b, b->a) %d\n", temp.tcp_pkbyte);

		}else if(iphdr->ip_p == IPPROTO_UDP){
			udp_hdr = (struct udphdr *) (packet + sizeof(ethernet_hdr) + sizeof(tcphdr));

			temp.protocol = "UDP";
			temp.src_addr = Ip(htonl(iphdr->ip_src.s_addr));
			temp.src_port = ntohs(udp_hdr->uh_sport);
			temp.dst_addr = Ip(htonl(iphdr->ip_dst.s_addr));
			temp.dst_port = ntohs(udp_hdr->uh_dport);
			temp.udp_pk += 1;
			temp.udp_pkbyte = header->caplen;
			//packetinfo.insert(make_pair(temp2, packetsize));
		}

	}
}

int main(int argc, char* argv[]){
	// argc < 2
	if(argc < 2){
		usage(argv);
		return -1;
	}

	char* pcap_file = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t *handle = pcap_open_offline(pcap_file, errbuf);

	if(handle == nullptr){
		fprintf(stderr, "pcap_open_offline is nullptr(%s)\n", errbuf);
		return -1;
	}

	while(true){
		struct pcap_pkthdr* header;
		const u_char *packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if(res == 0){
			continue;
		}else if(res == -1 || res == -2){
			break;
		}

		pk_receive(header, packet);

	}

	//print_packet();

	pcap_close(handle);
}
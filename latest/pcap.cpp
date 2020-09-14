/** c++ pcap-analysis **/

#include <cstdio>
#include <pcap.h>
#include <iostream>
#include <map>
#include "header.h" // header define
#include "flow.h" // struct, class define
#include "struct.h"

void usage(char* argv[]){
	printf("Usage %s <pcap-file>\n", argv[0]);
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

	}

	pcap_close(handle);
}




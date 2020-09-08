#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <libnet.h> /* apt-get install libnet-dev */

typedef struct ListNode{
        in_addr address_a;
        in_addr address_b;
        u_short port_a;
        u_short port_b;
	int packet_a_to_b;
	int packet_a_to_b_byte;
	int packet_b_to_a;
	int packet_b_to_a_byte;
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

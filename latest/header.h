#include <stdio.h>
#include <libnet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#pragma once
struct ethernet_hdr *eth_hdr;
struct ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

struct ip *iphdr;
struct tcphdr *tcp_hdr;
struct udphdr *udp_hdr;

#pragma once
#include <cstdio>
#include <iostream>
#include "ip.h"

using namespace std;

struct flowpacket
{
	string protocol;
	Ip src_addr;
	u_short src_port;
	Ip dst_addr;
	u_short dst_port;
	int tcp_pk = 0;
	int tcp_pkbyte = 0;
	int udp_pk = 0;
	int udp_pkbyte = 0;

	bool operator<(const flowpacket& otherflow) const{
		return ((src_addr < otherflow.src_addr)&&(src_port < otherflow.src_port)&&(dst_addr < otherflow.dst_addr)&&(dst_port < otherflow.dst_port));
	}

	//unordered_map operator
	bool operator==(const flowpacket& otherflow) const{
		return ((src_addr == otherflow.src_addr)&&(src_port == otherflow.src_port)&&(dst_addr == otherflow.dst_addr)&&(dst_port == otherflow.dst_port));
	}
};
/*
flow.h
1. struct flowpacket
2. user defined class
*/

#pragma once
#include <cstdio>
#include <pcap.h>
#include <unordered_map>
#include <iostream>
#include "header.h"

using namespace std;

struct flowpacket
{
	u_int32_t src_addr; // 4byte
	u_int32_t dst_addr; // 4byte
	int src_port; // 2byte
	int dst_port; // 2byte
	int packet_a_to_b_len; // a->b len
	int packet_a_to_b_byte; // a->b byte
	int packet_b_to_a_len; // b->a len
	int packet_b_to_a_byte; // b->a byte

	bool operator<(const flowpacket &otherpacket) const {
		if(src_addr != otherpacket.src_addr){
			return src_addr < otherpacket.src_addr;
		}

		if(src_port != otherpacket.src_port){
			return src_port < otherpacket.src_port;
		}

		if(dst_addr != otherpacket.dst_addr){
			return dst_addr < otherpacket.dst_addr;
		}

		if(dst_port != otherpacket.dst_port){
			return dst_port < otherpacket.dst_port;
		}
	}

	// reverse flowpacket added 
};

class flow
{
	private:
		std::unordered_map<string, int> packetflow;
	
	public:
		flow();
		~flow();
};
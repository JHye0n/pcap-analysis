/*
flow.h
1. struct flowpacket
2. user defined class
*/

#pragma once
#include <cstdio>
#include <pcap.h>
#include <map>
#include <iostream>
#include "header.h"
#include "struct.h"

using namespace std;

class flow
{
	private:
		std::map<flowpacket, int> packetflow;
	
	public:
		flow();
		~flow();
};

bool flowpacket::operator<(const flowpacket& otherflow) const{
	return true;
}
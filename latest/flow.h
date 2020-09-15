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

class flowinfo{

	private:
		map<flowpacket, int> packetinfo;
		flowpacket temp;

	public:
		flowinfo();
		~flowinfo();
};
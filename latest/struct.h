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

	bool operator==(const flowpacket& otherflow) const;
};
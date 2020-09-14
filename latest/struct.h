#pragma once
#include <cstdio>
#include <iostream>

struct flowpacket
{
	u_int32_t src_addr;
	u_short src_port; // 2byte
	u_int32_t dst_addr;
	u_short dst_port; // 2byte

	bool operator<(const flowpacket& otherflow) const;
};
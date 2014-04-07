/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2005-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

#ifndef STREAM5_UDP_H
#define STREAM5_UDP_H

#include "flow/flow.h"

struct Stream5UdpConfig;

Stream5UdpConfig* Stream5ConfigUdp(SnortConfig*, char* args);
void Stream5UdpConfigFree(Stream5UdpConfig*);

int Stream5VerifyUdpConfig(SnortConfig*, Stream5UdpConfig*);
void Stream5ConfigUdp(Stream5UdpConfig*, char *args);

void Stream5ResetUdp(void);

void udp_show(Stream5UdpConfig*);
void udp_sum();
void udp_stats();
void udp_reset_stats();

Session* get_udp_session(Flow*);

// port filter foo
uint16_t* Stream5GetUdpPortList(void*, int& ignore_any);

void s5UdpSetPortFilterStatus(
    Stream5UdpConfig*, unsigned short port, uint16_t status);

void s5UdpUnsetPortFilterStatus(
    Stream5UdpConfig*, unsigned short port, uint16_t status);

int s5UdpGetPortFilterStatus(Stream5UdpConfig*, unsigned short port);

bool s5UdpIgnoreAny(Stream5UdpConfig*);

#endif

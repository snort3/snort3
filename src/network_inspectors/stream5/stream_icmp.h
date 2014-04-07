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
 
#ifndef STREAM5_ICMP_H
#define STREAM5_ICMP_H

#include "flow/flow.h"

struct Stream5IcmpConfig;

Stream5IcmpConfig* Stream5ConfigIcmp(SnortConfig*, char* args);
void Stream5IcmpConfigFree(Stream5IcmpConfig*);

int Stream5VerifyIcmpConfig(SnortConfig*, Stream5IcmpConfig*);
void Stream5ResetIcmp(void);

void icmp_show(Stream5IcmpConfig*);
void icmp_sum();
void icmp_stats();
void icmp_reset_stats();

Session* get_icmp_session(Flow*);

#endif


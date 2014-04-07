/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
// mpse_manager.h author Russ Combs <rucombs@cisco.com>

#ifndef PACKET_MANAGER_H
#define PACKET_MANAGER_H

#include "snort_types.h"
#include "framework/base_api.h"

struct Packet;
struct SnortConfig;
struct CodecApi;

//-------------------------------------------------------------------------

class PacketManager
{
public:
    static void add_plugin(const CodecApi*);
    static void dump_plugins();
    static void release_plugins();

    static void instantiate(const CodecApi*, Module*, SnortConfig*);
    static int set_grinder();
    static void decode(Packet*, const struct _daq_pkthdr*, const uint8_t*);
};

#endif


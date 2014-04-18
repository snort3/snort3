/*
** Copyright (C) 2013-2013 Sourcefire, Inc.
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

#ifndef PACKET_MANAGER_H
#define PACKET_MANAGER_H

#include "snort_types.h"
#include "framework/codec.h"
#include "time/profiler.h"

#include <array>
#include <list>

struct Packet;
struct _SnortConfig;

//-------------------------------------------------------------------------


// TODO --> delete this!!
#ifdef PERF_PROFILING
extern THREAD_LOCAL PreprocStats decodePerfStats;
#endif

class PacketManager
{
public:
    static void add_plugin(const struct CodecApi*);
    static void dump_plugins();
    static void release_plugins();

    static void set_grinder();
    static void decode(Packet*, const struct _daq_pkthdr*, const uint8_t*);
    static void init_codecs();
    static void dump_stats();


    static bool has_codec(uint16_t);

//    static void encode_update(Packet *);
//    static void encode_format(Packet *);

private:
    static const CodecApi *get_data_link_type(int dlt);


};

#endif


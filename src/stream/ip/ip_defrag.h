//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2004-2013 Sourcefire, Inc.
// Copyright (C) 1998-2004 Martin Roesch <roesch@sourcefire.com>
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

#ifndef IP_DEFRAG_H
#define IP_DEFRAG_H

// ip datagram reassembly

#include <cstdint>

struct FragEngine;
struct FragTracker;
struct Fragment;
namespace snort
{
struct Packet;
struct SnortConfig;
}

class Defrag
{
public:
    Defrag(FragEngine&);

    bool configure(snort::SnortConfig*);
    void show(snort::SnortConfig*);

    void process(snort::Packet*, FragTracker*);
    void cleanup(FragTracker*);

    static void init();

private:
    int insert(snort::Packet*, FragTracker*, FragEngine*);
    int new_tracker(snort::Packet* p, FragTracker*);

    int add_frag_node(  // FIXIT-L too many args
        FragTracker* ft, FragEngine*,
        const uint8_t* fragStart, int16_t fragLength,
        char lastfrag, int16_t len,
        uint16_t slide, uint16_t trunc, uint16_t frag_offset,
        Fragment* left, Fragment** retFrag);

    int dup_frag_node(FragTracker*, Fragment* left, Fragment** retFrag);
    int expired(snort::Packet*, FragTracker*, FragEngine*);

private:
    FragEngine& engine;
    uint8_t layers;
};

#endif


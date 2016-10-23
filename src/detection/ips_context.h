//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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

// ips_context.h author Russ Combs <rucombs@cisco.com>

#ifndef IPS_CONTEXT_H
#define IPS_CONTEXT_H

// IpsContext provides access to all the state required for detection of a
// single packet.  the state is stored in IpsContextData instances, which
// are accessed by id.
//
// FIXIT-H IpsContext will likely directly contain certain core detection
// state such as an event queue.  This data will be migrated after
// integration into Snort.

#include <vector>
#include "main/snort_types.h"
#include "framework/codec.h"

// required to get a decent decl of pkth
#include "protocols/packet.h"

#include "detection/detection_util.h"

class SO_PUBLIC IpsContextData
{
public:
    virtual ~IpsContextData() { };

    static unsigned get_ips_id();
    static unsigned get_max_id();

protected:
    IpsContextData() { }
};

class SO_PUBLIC IpsContext
{
public:
    IpsContext(unsigned size = 0);  // defaults to max id
    ~IpsContext();

    void set_context_data(unsigned id, IpsContextData*);
    IpsContextData* get_context_data(unsigned id) const;

    void set_slot(unsigned s)
    { slot = s; }

    unsigned get_slot()
    { return slot; }

public:
    Packet* packet;
    Packet* encode_packet;
    DAQ_PktHdr_t* pkth;
    uint8_t* buf;

    DataPointer file_data;

    class MpseStash* stash;
    struct OtnxMatchData* otnx;
    uint64_t pkt_count;

    struct SF_EVENTQ* equeue;

    static const unsigned buf_size = Codec::PKT_MAX;

private:
    std::vector<IpsContextData*> data;
    unsigned slot;
};

#endif


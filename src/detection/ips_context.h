//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "main/snort_types.h"
#include "framework/codec.h"

// required to get a decent decl of pkth
#include "protocols/packet.h"

#include "detection/detection_util.h"

class MpseStash;
struct OtnxMatchData;
struct SF_EVENTQ;

namespace snort
{
struct SnortConfig;
struct Replacement
{
    std::string data;
    unsigned offset;
};

struct FlowSnapshot
{
    uint32_t session_flags;
    SnortProtocolId proto_id;
};

class SO_PUBLIC IpsContextData
{
public:
    virtual ~IpsContextData() = default;

    static unsigned get_ips_id();
    static unsigned get_max_id();
    virtual void clear() {}

protected:
    IpsContextData() = default;
};

class SO_PUBLIC IpsContext
{
public:
    IpsContext(unsigned size = 0);  // defaults to max id
    ~IpsContext();

    IpsContext(const IpsContext&) = delete;
    IpsContext& operator=(const IpsContext&) = delete;

    void set_context_data(unsigned id, IpsContextData*);
    IpsContextData* get_context_data(unsigned id) const;
    void clear_context_data();

    void set_slot(unsigned s)
    { slot = s; }

    unsigned get_slot()
    { return slot; }

    void snapshot_flow(Flow*);

    uint32_t get_session_flags()
    { return flow.session_flags; }

    SnortProtocolId get_snort_protocol_id()
    { return flow.proto_id; }

    enum ActiveRules
    { NONE, NON_CONTENT, CONTENT };

public:
    Packet* packet;
    Packet* encode_packet;
    DAQ_PktHdr_t* pkth;
    uint8_t* buf;

    SnortConfig* conf;
    MpseStash* stash;
    OtnxMatchData* otnx;
    SF_EVENTQ* equeue;

    DataPointer file_data;
    DataBuffer alt_data;

    uint64_t context_num;
    uint64_t packet_number;
    ActiveRules active_rules;
    bool check_tags;

    std::vector<Replacement> rpl;

    static const unsigned buf_size = Codec::PKT_MAX;

private:
    FlowSnapshot flow;
    std::vector<IpsContextData*> data;
    unsigned slot;
};
}
#endif


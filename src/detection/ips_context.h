//--------------------------------------------------------------------------
// Copyright (C) 2016-2023 Cisco and/or its affiliates. All rights reserved.
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

#include <list>

#include "detection/detection_util.h"
#include "framework/codec.h"
#include "framework/mpse.h"
#include "framework/mpse_batch.h"
#include "main/snort_types.h"
#include "protocols/packet.h" // required to get a decent decl of pkth

class MpseStash;
struct OtnxMatchData;
struct SF_EVENTQ;
struct RegexRequest;

namespace snort
{
class IpsContextData;
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

class SO_PUBLIC IpsContext
{
public:
    using Callback = void(*)(IpsContext*);
    enum State { IDLE, BUSY, SUSPENDED };

    IpsContext(unsigned size = 0);  // defaults to max id
    ~IpsContext();

    IpsContext(const IpsContext&) = delete;
    IpsContext& operator=(const IpsContext&) = delete;

    void setup();
    void clear();

    void set_context_data(unsigned id, IpsContextData*);
    IpsContextData* get_context_data(unsigned id) const;

    void snapshot_flow(Flow*);

    uint32_t get_session_flags()
    { return flow.session_flags; }

    SnortProtocolId get_snort_protocol_id()
    { return flow.proto_id; }

    void set_snort_protocol_id(SnortProtocolId id)
    { flow.proto_id = id; }

    void disable_detection();
    void disable_inspection();

    enum ActiveRules
    { NONE, NON_CONTENT, CONTENT };

    void register_post_callback(Callback callback)
    { post_callbacks.emplace_back(callback); }

    void clear_callbacks()
    { post_callbacks.clear(); }

    bool has_callbacks() const
    { return !post_callbacks.empty(); }

    void post_detection();

    void link(IpsContext* next)
    {
        assert(!next->depends_on);
        assert(!next->next_to_process);
        assert(!next_to_process);

        next->depends_on = this;
        next_to_process = next;
    }

    void unlink()
    {
        assert(!depends_on);
        if ( next_to_process )
        {
            assert(next_to_process->depends_on == this);
            next_to_process->depends_on = nullptr;
        }
        next_to_process = nullptr;
    }

    IpsContext* dependencies() const
    { return depends_on; }

    IpsContext* next() const
    { return next_to_process; }

    void abort()
    {
        if ( next_to_process )
            next_to_process->depends_on = depends_on;

        if ( depends_on )
            depends_on->next_to_process = next_to_process;

        depends_on = next_to_process = nullptr;
    }

public:
    std::vector<Replacement> rpl;

    Packet* packet;
    Packet* wire_packet = nullptr;
    Packet* encode_packet;
    DAQ_PktHdr_t* pkth;
    uint8_t* buf;

    const SnortConfig* conf = nullptr;
    MpseBatch searches;
    MpseStash* stash;
    OtnxMatchData* otnx;
    std::list<RegexRequest*>::iterator regex_req_it;
    SF_EVENTQ* equeue;

    DataPointer file_data = DataPointer(nullptr, 0);
    uint64_t file_data_id = 0;
    bool file_data_drop_sse = false;
    bool file_data_no_sse = false;
    DataBuffer alt_data = {};
    unsigned file_pos = 0;
    bool file_type_process = false;

    uint64_t context_num;
    uint64_t packet_number = 0;
    ActiveRules active_rules;
    State state;
    bool check_tags;
    bool clear_inspectors;

    static const unsigned buf_size = Codec::PKT_MAX;

    // FIXIT-L eliminate max_ips_id and just resize data vector.
    // Only 5 inspectors currently use the ips context data.
    static constexpr unsigned max_ips_id = 8;

private:
    FlowSnapshot flow = {};
    std::vector<IpsContextData*> data;
    std::vector<unsigned> ids_in_use;  // for indirection; FIXIT-P evaluate alternatives
    std::vector<Callback> post_callbacks;
    IpsContext* depends_on;
    IpsContext* next_to_process;
    bool remove_gadget = false;
};
}
#endif


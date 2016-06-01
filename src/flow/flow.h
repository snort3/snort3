//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

// flow.h author Russ Combs <rucombs@cisco.com>

#ifndef FLOW_H
#define FLOW_H

// Flow is the object that captures all the data we know about a session,
// including IP for defragmentation and TCP for desegmentation.  For all
// protocols, it used to track connection status bindings, and inspector
// state.  Inspector state is stored in FlowData, and Flow manages a list
// of FlowData items.

#include <assert.h>

#include "utils/bitop.h"
#include "sfip/sfip_t.h"
#include "flow/flow_key.h"
#include "framework/inspector.h"
#include "framework/codec.h"

#define SSNFLAG_SEEN_CLIENT         0x00000001
#define SSNFLAG_SEEN_SENDER         0x00000001
#define SSNFLAG_SEEN_SERVER         0x00000002
#define SSNFLAG_SEEN_RESPONDER      0x00000002

#define SSNFLAG_ESTABLISHED         0x00000004
#define SSNFLAG_MIDSTREAM           0x00000008 /* picked up midstream */

#define SSNFLAG_ECN_CLIENT_QUERY    0x00000010
#define SSNFLAG_ECN_SERVER_REPLY    0x00000020
#define SSNFLAG_CLIENT_FIN          0x00000040 /* server sent fin */
#define SSNFLAG_SERVER_FIN          0x00000080 /* client sent fin */

#define SSNFLAG_COUNTED_INITIALIZE  0x00000100
#define SSNFLAG_COUNTED_ESTABLISH   0x00000200
#define SSNFLAG_COUNTED_CLOSING     0x00000400

#define SSNFLAG_TIMEDOUT            0x00001000
#define SSNFLAG_PRUNED              0x00002000
#define SSNFLAG_RESET               0x00004000

#define SSNFLAG_DROP_CLIENT         0x00010000
#define SSNFLAG_DROP_SERVER         0x00020000
#define SSNFLAG_FORCE_BLOCK         0x00040000

#define SSNFLAG_STREAM_ORDER_BAD    0x00100000
#define SSNFLAG_CLIENT_SWAP         0x00200000
#define SSNFLAG_CLIENT_SWAPPED      0x00400000

#define SSNFLAG_PROXIED             0x01000000
#define SSNFLAG_NONE                0x00000000 /* nothing, an MT bag of chips */

#define SSNFLAG_SEEN_BOTH (SSNFLAG_SEEN_SERVER | SSNFLAG_SEEN_CLIENT)
#define SSNFLAG_BLOCK (SSNFLAG_DROP_CLIENT|SSNFLAG_DROP_SERVER)

#define STREAM_STATE_NONE              0x0000
#define STREAM_STATE_SYN               0x0001
#define STREAM_STATE_SYN_ACK           0x0002
#define STREAM_STATE_ACK               0x0004
#define STREAM_STATE_ESTABLISHED       0x0008
#define STREAM_STATE_DROP_CLIENT       0x0010
#define STREAM_STATE_DROP_SERVER       0x0020
#define STREAM_STATE_MIDSTREAM         0x0040
#define STREAM_STATE_TIMEDOUT          0x0080
#define STREAM_STATE_UNREACH           0x0100
#define STREAM_STATE_CLOSED            0x0800
#define STREAM_STATE_IGNORE            0x1000
#define STREAM_STATE_NO_PICKUP         0x2000

struct Packet;

typedef void (* StreamAppDataFree)(void*);

class SO_PUBLIC FlowData
{
public:
    FlowData(unsigned u, Inspector* = nullptr);
    virtual ~FlowData();

    unsigned get_id()
    { return id; }

    static unsigned get_flow_id()
    { return ++flow_id; }

    virtual void handle_expected(Packet*) { }
    virtual void handle_retransmit(Packet*) { }
    virtual void handle_eof(Packet*) { }

public:  // FIXIT-L privatize
    FlowData* next;
    FlowData* prev;

private:
    static unsigned flow_id;
    Inspector* handler;
    unsigned id;
};

struct LwState
{
    uint32_t session_flags;

    int16_t ipprotocol;
    int16_t application_protocol;

    char direction;
    char ignore_direction;
};

// this struct is organized by member size for compactness
class SO_PUBLIC Flow
{
public:
    enum FlowState
    {
        SETUP,
        INSPECT,
        BLOCK,
        RESET,
        ALLOW
    };
    Flow();
    ~Flow();

    void init(PktType);
    void term();

    void reset(bool do_cleanup = true);
    void restart(bool free_flow_data = true);
    void clear(bool free_flow_data = true);

    int set_application_data(FlowData*);
    FlowData* get_application_data(uint32_t proto);
    void free_application_data(uint32_t proto);
    void free_application_data(FlowData*);
    void free_application_data();

    void call_handlers(Packet* p, bool eof = false);

    void markup_packet_flags(Packet*);

    void set_direction(Packet*);

    void set_expire(const Packet*, uint32_t timeout);
    int get_expire(const Packet*);
    bool expired(const Packet*);

    void set_ttl(Packet*, bool client);

    uint32_t update_session_flags( uint32_t flags )
    {
        return ssn_state.session_flags = flags;
    }

    uint32_t set_session_flags(uint32_t flags)
    {
        return ssn_state.session_flags |= flags;
    }

    uint32_t clear_session_flags(uint32_t flags)
    {
        return ssn_state.session_flags &= ~flags;
    }

    uint32_t get_session_flags()
    {
        return ssn_state.session_flags;
    }

    int get_ignore_direction()
    {
        return ssn_state.ignore_direction;
    }

    int set_ignore_direction(char ignore_direction)
    {
        if (ssn_state.ignore_direction != ignore_direction)
            ssn_state.ignore_direction = ignore_direction;

        return ssn_state.ignore_direction;
    }

    bool two_way_traffic()
    { return (ssn_state.session_flags & SSNFLAG_SEEN_BOTH) == SSNFLAG_SEEN_BOTH; }

    void set_proxied()
    { ssn_state.session_flags |= SSNFLAG_PROXIED; }

    bool is_proxied()
    { return (ssn_state.session_flags & SSNFLAG_PROXIED) != 0; }

    bool is_stream()
    { return to_utype(pkt_type) & to_utype(PktType::STREAM); }

    void block()
    { ssn_state.session_flags |= SSNFLAG_BLOCK; }

    bool was_blocked() const
    { return (ssn_state.session_flags & SSNFLAG_BLOCK) != 0; }

    bool full_inspection() const
    { return flow_state <= INSPECT; }

    void set_state(FlowState fs)
    { flow_state = fs; }

    void set_client(Inspector* ins)
    {
        ssn_client = ins;
        ssn_client->add_ref();
    }

    void set_server(Inspector* ins)
    {
        ssn_server = ins;
        ssn_server->add_ref();
    }

    void set_clouseau(Inspector* ins)
    {
        clouseau = ins;
        clouseau->add_ref();
    }

    void clear_clouseau()
    {
        clouseau->rem_ref();
        clouseau = nullptr;
    }

    void set_gadget(Inspector* ins)
    {
        gadget = ins;
        gadget->add_ref();
    }

    void clear_gadget()
    {
        gadget->rem_ref();
        gadget = nullptr;
    }

    void set_data(Inspector* pd)
    {
        data = pd;
        data->add_ref();
    }

    void clear_data()
    {
        data->rem_ref();
        data = nullptr;
    }

    void disable_inspection()
    {
        disable_inspect = true;
    }

    bool is_inspection_disabled()
    {
        return disable_inspect;
    }

public:  // FIXIT-M privatize if possible
    // these fields are const after initialization
    const FlowKey* key;
    class Session* session;
    class BitOp* bitop;
    class FlowHAState* ha_state;
    uint8_t ip_proto; // FIXIT-M do we need both of these?
    PktType pkt_type; // ^^

    // these fields are always set; not zeroed
    Flow* prev, * next;
    Inspector* ssn_client;
    Inspector* ssn_server;
    long last_data_seen;

    // everything from here down is zeroed
    FlowData* appDataList;
    Inspector* clouseau;  // service identifier
    Inspector* gadget;    // service handler
    Inspector* data;
    const char* service;

    unsigned policy_id;

    FlowState flow_state;

    sfip_t client_ip; // FIXIT-L family and bits should be changed to uint16_t
    sfip_t server_ip; // or uint8_t to reduce sizeof from 24 to 20

    uint64_t expire_time;

    int32_t iface_in;
    int32_t iface_out;

    uint16_t client_port;
    uint16_t server_port;

    uint16_t ssn_policy;
    uint16_t session_state;

    uint8_t  inner_client_ttl, inner_server_ttl;
    uint8_t  outer_client_ttl, outer_server_ttl;

    uint8_t  response_count;
    bool disable_inspect;

public:
    LwState ssn_state;
    LwState previous_ssn_state;
};

#endif


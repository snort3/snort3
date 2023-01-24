//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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

#include <string>
#include <sys/time.h>

#include <daq_common.h>

#include "detection/ips_context_chain.h"
#include "flow/deferred_trust.h"
#include "flow/flow_data.h"
#include "flow/flow_stash.h"
#include "framework/data_bus.h"
#include "framework/decode_data.h"
#include "framework/inspector.h"
#include "network_inspectors/appid/application_ids.h"
#include "protocols/layer.h"
#include "sfip/sf_ip.h"
#include "target_based/snort_protocols.h"

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
#define SSNFLAG_COUNTED_CLOSED      0x00000800

#define SSNFLAG_TIMEDOUT            0x00001000
#define SSNFLAG_PRUNED              0x00002000
#define SSNFLAG_RESET               0x00004000

#define SSNFLAG_TCP_PSEUDO_EST      0x00008000

#define SSNFLAG_DROP_CLIENT         0x00010000
#define SSNFLAG_DROP_SERVER         0x00020000

#define SSNFLAG_STREAM_ORDER_BAD    0x00100000
#define SSNFLAG_CLIENT_SWAP         0x00200000
#define SSNFLAG_CLIENT_SWAPPED      0x00400000

#define SSNFLAG_PROXIED             0x01000000
#define SSNFLAG_NO_DETECT_TO_CLIENT 0x02000000
#define SSNFLAG_NO_DETECT_TO_SERVER 0x04000000

#define SSNFLAG_ABORT_CLIENT        0x10000000
#define SSNFLAG_ABORT_SERVER        0x20000000

#define SSNFLAG_HARD_EXPIRATION     0x40000000
#define SSNFLAG_KEEP_FLOW           0x80000000

#define SSNFLAG_NONE                0x00000000 /* nothing, an MT bag of chips */

#define SSNFLAG_SEEN_BOTH (SSNFLAG_SEEN_SERVER | SSNFLAG_SEEN_CLIENT)
#define SSNFLAG_BLOCK (SSNFLAG_DROP_CLIENT|SSNFLAG_DROP_SERVER)

#define STREAM_STATE_NONE              0x0000
#define STREAM_STATE_ESTABLISHED       0x0001
#define STREAM_STATE_DROP_CLIENT       0x0002
#define STREAM_STATE_DROP_SERVER       0x0004
#define STREAM_STATE_MIDSTREAM         0x0008
#define STREAM_STATE_TIMEDOUT          0x0010
#define STREAM_STATE_UNREACH           0x0020
#define STREAM_STATE_CLOSED            0x0040
#define STREAM_STATE_BLOCK_PENDING     0x0080
#define STREAM_STATE_RELEASING         0x0100

class Continuation;
class BitOp;
class Session;

namespace snort
{
class FlowHAState;
struct FlowKey;
class IpsContext;
struct Packet;

typedef void (* StreamAppDataFree)(void*);

struct FilteringState
{
    uint8_t generation_id = 0;
    bool matched = false;

    void clear()
    {
        generation_id = 0;
        matched = false;
    }

    bool was_checked(uint8_t id) const
    {
        return generation_id and (generation_id == id);
    }

    void set_matched(uint8_t id, bool match)
    {
        generation_id = id;
        matched = match;
    }
};

struct FlowStats
{
    uint64_t client_pkts;
    uint64_t server_pkts;
    uint64_t client_bytes;
    uint64_t server_bytes;
    struct timeval start_time;
    uint64_t total_flow_latency;
};

struct LwState
{
    uint32_t session_flags;

    int16_t ipprotocol;
    SnortProtocolId snort_protocol_id;

    char direction;
    char ignore_direction;
};

class SO_PUBLIC StreamFlowIntf
{
public:
    virtual FlowData* get_stream_flow_data(const Flow* flow) = 0;
    virtual void set_stream_flow_data(Flow* flow, FlowData* flow_data) = 0;
    virtual void get_stream_id(const Flow* flow, int64_t& stream_id) = 0;
    virtual AppId get_appid_from_stream(const Flow*) { return APP_ID_NONE; }
    // Stream based flows should override this interface to return parent flow
    // when child flow is passed as input
    virtual Flow* get_stream_parent_flow(Flow* cflow) { return cflow; }
};

// this struct is organized by member size for compactness
class SO_PUBLIC Flow
{
public:
    enum class FlowState : uint8_t
    {
        SETUP = 0,
        INSPECT,
        BLOCK,
        RESET,
        ALLOW
    };
    Flow();
    ~Flow();

    Flow(const Flow&) = delete;
    Flow& operator=(const Flow&) = delete;

    void init(PktType);
    void term();

    void flush(bool do_cleanup = true);
    void reset(bool do_cleanup = true);
    void restart(bool dump_flow_data = true);
    void clear(bool dump_flow_data = true);

    int set_flow_data(FlowData*);
    FlowData* get_flow_data(uint32_t proto) const;
    void free_flow_data(uint32_t proto);
    void free_flow_data(FlowData*);
    void free_flow_data();

    void call_handlers(Packet* p, bool eof = false);
    void markup_packet_flags(Packet*);
    void set_client_initiate(Packet*);
    void set_direction(Packet*);
    void set_expire(const Packet*, uint32_t timeout);
    bool expired(const Packet*);
    void set_ttl(Packet*, bool client);
    void set_mpls_layer_per_dir(Packet*);
    Layer get_mpls_layer_per_dir(bool);
    void swap_roles();
    void set_service(Packet*, const char* new_service);
    bool get_attr(const std::string& key, int32_t& val);
    bool get_attr(const std::string& key, std::string& val);
    void set_attr(const std::string& key, const int32_t& val);
    void set_attr(const std::string& key, const std::string& val);
    // Use this API when the publisher of the attribute allocated memory for it and can give up its
    // ownership after the call.
    void set_attr(const std::string& key, std::string* val)
    {
        assert(stash);
        stash->store(key, val);
    }

    template<typename T>
    bool get_attr(const std::string& key, T& val)
    {
        assert(stash);
        return stash->get(key, val);
    }

    template<typename T>
    void set_attr(const std::string& key, const T& val)
    {
        assert(stash);
        stash->store(key, val);
    }

    uint32_t update_session_flags(uint32_t ssn_flags)
    { return ssn_state.session_flags = ssn_flags; }

    uint32_t set_session_flags(uint32_t ssn_flags)
    { return ssn_state.session_flags |= ssn_flags; }

    uint32_t get_session_flags() const
    { return ssn_state.session_flags; }

    uint32_t clear_session_flags(uint32_t ssn_flags)
    { return ssn_state.session_flags &= ~ssn_flags; }

    uint32_t clear_session_state(uint32_t ssn_state)
    { return session_state &= ~ssn_state; }

    void set_to_client_detection(bool enable);
    void set_to_server_detection(bool enable);

    int get_ignore_direction()
    { return ssn_state.ignore_direction; }

    int set_ignore_direction(char ignore_direction)
    {
        ssn_state.ignore_direction = ignore_direction;
        return ssn_state.ignore_direction;
    }

    bool two_way_traffic()
    { return (ssn_state.session_flags & SSNFLAG_SEEN_BOTH) == SSNFLAG_SEEN_BOTH; }

    bool is_pdu_inorder(uint8_t dir);

    bool is_direction_aborted(bool from_client) const;

    void set_proxied()
    { ssn_state.session_flags |= SSNFLAG_PROXIED; }

    bool is_proxied()
    { return (ssn_state.session_flags & SSNFLAG_PROXIED) != 0; }

    bool is_stream()
    { return pkt_type == PktType::TCP or pkt_type == PktType::USER; }

    void block()
    { ssn_state.session_flags |= SSNFLAG_BLOCK; }

    bool was_blocked() const
    { return (ssn_state.session_flags & SSNFLAG_BLOCK) != 0; }

    bool full_inspection() const
    { return (flow_state <= FlowState::INSPECT) and !is_inspection_disabled(); }

    void set_state(FlowState fs)
    { flow_state = fs; }

    void set_client(Inspector* ins)
    {
        if (ssn_client)
            ssn_client->rem_ref();
        ssn_client = ins;
        if (ssn_client)
            ssn_client->add_ref();
    }

    void set_server(Inspector* ins)
    {
        if (ssn_server)
            ssn_server->rem_ref();
        ssn_server = ins;
        if (ssn_server)
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

    bool searching_for_service()
    {
        return clouseau != nullptr;
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
        if (assistant_gadget != nullptr)
            clear_assistant_gadget();
    }

    void set_assistant_gadget(Inspector* ins)
    {
        assistant_gadget = ins;
        assistant_gadget->add_ref();
    }

    void clear_assistant_gadget()
    {
        assistant_gadget->rem_ref();
        assistant_gadget = nullptr;
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
    { flags.disable_inspect = true; }

    bool is_inspection_disabled() const
    { return flags.disable_inspect; }

    bool is_suspended() const
    { return context_chain.front(); }

    void set_default_session_timeout(uint32_t dst, bool force)
    {
        if (force || (default_session_timeout == 0))
            default_session_timeout = dst;
    }

    void set_hard_expiration()
    { ssn_state.session_flags |= SSNFLAG_HARD_EXPIRATION; }

    bool is_hard_expiration()
    { return (ssn_state.session_flags & SSNFLAG_HARD_EXPIRATION) != 0; }

    void set_deferred_trust(unsigned module_id, bool on)
    { deferred_trust.set_deferred_trust(module_id, on); }

    bool cannot_trust()
    { return deferred_trust.is_active(); }

    bool try_trust()
    { return deferred_trust.try_trust(); }

    void stop_deferring_trust()
    { deferred_trust.clear(); }

    void finalize_trust(Active& active)
    {
        deferred_trust.finalize(active);
    }

    void trust();

    bool trust_is_deferred()
    { return deferred_trust.is_deferred(); }

public:  // FIXIT-M privatize if possible
    // fields are organized by initialization and size to minimize
    // void space and allow for memset of tail end of struct

    DeferredTrust deferred_trust;

    // Anything before this comment is not zeroed during construction
    const FlowKey* key;
    BitOp* bitop;
    FlowHAState* ha_state;
    FlowStash* stash;

    uint8_t ip_proto;
    PktType pkt_type; // ^^

    // these fields are always set; not zeroed
    Flow* prev, * next;
    Session* session;
    Inspector* ssn_client;
    Inspector* ssn_server;
    Continuation* ips_cont;

    long last_data_seen;
    Layer mpls_client, mpls_server;

    // everything from here down is zeroed
    IpsContextChain context_chain;
    FlowData* flow_data;
    FlowStats flowstats;
    StreamFlowIntf* stream_intf;

    SfIp client_ip;
    SfIp server_ip;

    LwState ssn_state;
    LwState previous_ssn_state;

    Inspector* clouseau;  // service identifier
    Inspector* gadget;    // service handler
    Inspector* assistant_gadget;
    Inspector* data;
    const char* service;

    uint64_t expire_time;

    unsigned network_policy_id;
    unsigned inspection_policy_id;
    unsigned ips_policy_id;
    unsigned reload_id;

    uint32_t tenant;

    uint32_t default_session_timeout;

    int32_t client_intf;
    int32_t server_intf;

    int16_t client_group;
    int16_t server_group;

    uint16_t client_port;
    uint16_t server_port;

    uint16_t ssn_policy;
    uint16_t session_state;

    uint8_t inner_client_ttl;
    uint8_t inner_server_ttl;
    uint8_t outer_client_ttl;
    uint8_t outer_server_ttl;

    uint8_t response_count;

    struct
    {
        bool client_initiated : 1;  // Set if the first packet on the flow was from the side that is
                                    // currently considered to be the client
        bool app_direction_swapped : 1; // Packet direction swapped from application perspective
        bool disable_inspect : 1;
        bool trigger_detained_packet_event : 1;
        bool trigger_finalize_event : 1;
        bool use_direct_inject : 1;
        bool data_decrypted : 1;    // indicate data in current flow is decrypted TLS application data
        bool snort_proto_id_set_by_ha : 1;
        bool efd_flow : 1;  // Indicate that current flow is an elephant flow
        bool svc_event_generated : 1; // Set if FLOW_NO_SERVICE_EVENT was generated for this flow
        bool retry_queued : 1; // Set if a packet was queued for retry for this flow
    } flags;

    FlowState flow_state;

    FilteringState filtering_state;

    DAQ_Verdict last_verdict = MAX_DAQ_VERDICT;

private:
    void clean();
};

inline void Flow::set_to_client_detection(bool enable)
{
    if ( enable )
        ssn_state.session_flags &= ~SSNFLAG_NO_DETECT_TO_CLIENT;
    else
        ssn_state.session_flags |= SSNFLAG_NO_DETECT_TO_CLIENT;
}

inline void Flow::set_to_server_detection(bool enable)
{
    if ( enable )
        ssn_state.session_flags &= ~SSNFLAG_NO_DETECT_TO_SERVER;
    else
        ssn_state.session_flags |= SSNFLAG_NO_DETECT_TO_SERVER;
}
}

#endif


//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "expect_cache.h"

#include "hash/zhash.h"
#include "packet_io/sfdaq.h"
#include "protocols/packet.h"
#include "protocols/vlan.h"
#include "pub_sub/expect_events.h"
#include "sfip/sf_ip.h"
#include "stream/stream.h"      // FIXIT-M bad dependency
#include "time/packet_time.h"

using namespace snort;

/* Reasonably small, and prime */
// FIXIT-L size based on max_tcp + max_udp?
#define MAX_HASH 1021
#define MAX_LIST    8
#define MAX_DATA    4
#define MAX_WAIT  300
#define MAX_PRUNE   5

static THREAD_LOCAL std::vector<ExpectFlow*>* packet_expect_flows = nullptr;

ExpectFlow::~ExpectFlow()
{
    clear();
}

void ExpectFlow::clear()
{
    while (data)
    {
        FlowData* fd = data;
        data = data->next;
        delete fd;
    }
    data = nullptr;
}

int ExpectFlow::add_flow_data(FlowData* fd)
{
    if (data)
    {
        FlowData* prev_fd;
        for (prev_fd = data; prev_fd && prev_fd->next; prev_fd = prev_fd->next);

        prev_fd->next = fd;
    }
    else
        data = fd;
    return 0;
}

std::vector<ExpectFlow*>* ExpectFlow::get_expect_flows()
{
    return packet_expect_flows;
}

void ExpectFlow::reset_expect_flows()
{
    if(packet_expect_flows)
        packet_expect_flows->clear();
}

FlowData* ExpectFlow::get_flow_data(unsigned id)
{
    for (FlowData* p = data; p; p = p->next)
    {
        if (p->get_id() == id)
            return p;
    }
    return nullptr;
}

struct ExpectNode
{
    time_t expires = 0;
    bool reversed_key = false;
    int direction = 0;
    unsigned count = 0;
    SnortProtocolId snort_protocol_id = UNKNOWN_PROTOCOL_ID;

    ExpectFlow* head = nullptr;
    ExpectFlow* tail = nullptr;

    void clear(ExpectFlow*&);
};

void ExpectNode::clear(ExpectFlow*& list)
{
    while (head)
    {
        ExpectFlow* p = head;
        head = head->next;
        p->clear();
        p->next = list;
        list = p;
    }
    tail = nullptr;
    count = 0;
}

//-------------------------------------------------------------------------
// private ExpectCache methods
//-------------------------------------------------------------------------

// Clean the hash table of at most MAX_PRUNE expired nodes
void ExpectCache::prune()
{
    time_t now = packet_time();

    for (unsigned i = 0; i < MAX_PRUNE; ++i )
    {
        ExpectNode* node = (ExpectNode*)hash_table->first();

        if ( !node || now <= node->expires )
            break;

        node->clear(free_list);
        hash_table->remove();
        ++prunes;
    }
}

ExpectNode* ExpectCache::find_node_by_packet(Packet* p, FlowKey &key)
{
    if (!hash_table->get_count())
        return nullptr;

    const SfIp* srcIP = p->ptrs.ip_api.get_src();
    const SfIp* dstIP = p->ptrs.ip_api.get_dst();
    uint16_t vlanId = (p->proto_bits & PROTO_BIT__VLAN) ? layer::get_vlan_layer(p)->vid() : 0;
    uint32_t mplsId = (p->proto_bits & PROTO_BIT__MPLS) ? p->ptrs.mplsHdr.label : 0;
    uint16_t addressSpaceId = p->pkth->address_space_id;
    PktType type = p->type();
    IpProtocol ip_proto = p->get_ip_proto_next();

    bool reversed_key = key.init(type, ip_proto, dstIP, p->ptrs.dp, srcIP, p->ptrs.sp,
            vlanId, mplsId, addressSpaceId);

    /*
        Lookup order:
            1. Full match.
            2. Unknown (zeroed) source port.
            3. Unknown (zeroed) destination port.
        If the client/server addresses were reversed during key creation, the
        source port will be in port_l.
    */
    // FIXIT-P X This should be optimized to only do full matches when full keys
    //      are present, likewise for partial keys.
    ExpectNode* node = (ExpectNode*) hash_table->find(&key);
    if (!node)
    {
        // FIXIT-M X This logic could fail if IPs were equal because the original key
        // would always have been created with a 0 for src or dst port and put the
        // known port in port_h.
        uint16_t port1;
        uint16_t port2;

        if (reversed_key)
        {
            port1 = key.port_l;
            port2 = 0;
            key.port_l = 0;
        }
        else
        {
            port1 = 0;
            port2 = key.port_h;
            key.port_h = 0;
        }
        node = (ExpectNode*) hash_table->find(&key);
        if (!node)
        {
            key.port_l = port1;
            key.port_h = port2;
            node = (ExpectNode*) hash_table->find(&key);
            if (!node)
                return nullptr;
        }
    }
    if (!node->head || (p->pkth->ts.tv_sec > node->expires))
    {
        if (node->head)
            node->clear(free_list);
        hash_table->remove(&key);
        return nullptr;
    }
    /* Make sure the packet direction is correct */
    switch (node->direction)
    {
        case SSN_DIR_BOTH:
            break;

        case SSN_DIR_FROM_CLIENT:
        case SSN_DIR_FROM_SERVER:
            if (node->reversed_key != reversed_key)
                return nullptr;
            break;
    }

    return node;
}

bool ExpectCache::process_expected(ExpectNode* node, FlowKey& key, Packet* p, Flow* lws)
{
    ExpectFlow* head;
    FlowData* fd;
    int ignoring = false;

    assert(node->count && node->head);

    /* Pull the first set of expected flow data off of the Expect node and apply it
        in its entirety to the target flow.  Discard the set (and potentially the
        entire node, it empty) after this is done. */
    node->count--;
    head = node->head;
    node->head = head->next;

    while ((fd = head->data))
    {
        head->data = fd->next;
        lws->set_flow_data(fd);
        ++realized;
        fd->handle_expected(p);
    }
    head->next = free_list;
    free_list = head;

    /* If this is 0, we're ignoring, otherwise setting id of new session */
    if (!node->snort_protocol_id)
        ignoring = node->direction ? true : false;
    else if (lws->ssn_state.snort_protocol_id != node->snort_protocol_id)
        lws->ssn_state.snort_protocol_id = node->snort_protocol_id;

    if (!node->count)
        hash_table->remove(&key);

    return ignoring;
}

//-------------------------------------------------------------------------
// public ExpectCache methods
//-------------------------------------------------------------------------

ExpectCache::ExpectCache(uint32_t max)
{
    // -size forces use of abs(size) ie w/o bumping up
    hash_table = new ZHash(-MAX_HASH, sizeof(FlowKey));
    hash_table->set_keyops(FlowKey::hash, FlowKey::compare);

    nodes = new ExpectNode[max];
    for (unsigned i = 0; i < max; ++i)
        hash_table->push(nodes+i);

    /* Preallocate a pool of ExpectFlows big enough to handle the worst case
        requirement (max number of nodes * max flows per node) and add them all
        to an initial free list. */
    max *= MAX_LIST;
    pool = new ExpectFlow[max];
    free_list = nullptr;
    for (unsigned i = 0; i < max; ++i)
    {
        ExpectFlow* p = pool + i;
        p->data = nullptr;
        p->next = free_list;
        free_list = p;
    }

    expects = realized = 0;
    prunes = overflows = 0;
    if (packet_expect_flows == nullptr)
        packet_expect_flows = new std::vector<ExpectFlow*>;
}

ExpectCache::~ExpectCache()
{
    delete hash_table;
    delete[] nodes;
    delete[] pool;
    delete packet_expect_flows;
    packet_expect_flows = nullptr;
}

/**Either expect or expect future session.
 *
 * Preprocessors may add sessions to be expected altogether or to be associated
 * with some data. For example, FTP preprocessor may add data channel that
 * should be expected. Alternatively, FTP preprocessor may add session with
 * snort protocol ID FTP-DATA.
 *
 * It is assumed that only one of cliPort or srvPort should be known (!0). This
 * violation of this assumption will cause hash collision that will cause some
 * session to be not expected and expected. This will occur only rarely and
 * therefore acceptable design optimization.
 *
 * Also, snort_protocol_id is assumed to be consistent between different
 * preprocessors.  Each session can be assigned only one snort protocol ID.
 * When new snort_protocol_id mismatches existing snort_protocol_id, new
 * snort_protocol_id and associated data is not stored.
 *
 */
int ExpectCache::add_flow(const Packet *ctrlPkt,
    PktType type, IpProtocol ip_proto,
    const SfIp* cliIP, uint16_t cliPort,
    const SfIp* srvIP, uint16_t srvPort,
    char direction, FlowData* fd, SnortProtocolId snort_protocol_id)
{
    /* Just pull the VLAN ID, MPLS ID, and Address Space ID from the
        control packet until we have a use case for not doing so. */
    uint16_t vlanId = (ctrlPkt->proto_bits & PROTO_BIT__VLAN) ? layer::get_vlan_layer(ctrlPkt)->vid() : 0;
    uint32_t mplsId = (ctrlPkt->proto_bits & PROTO_BIT__MPLS) ? ctrlPkt->ptrs.mplsHdr.label : 0;
    uint16_t addressSpaceId = ctrlPkt->pkth->address_space_id;

    FlowKey key;
    bool reversed_key = key.init(type, ip_proto, cliIP, cliPort, srvIP, srvPort,
            vlanId, mplsId, addressSpaceId);

    ExpectNode* node;
    ExpectFlow* last;
    bool new_node = false;

    node = (ExpectNode*) hash_table->get(&key, &new_node);
    if (!node)
    {
        prune();
        node = (ExpectNode*) hash_table->get(&key, &new_node);
        /* The flow free list should never be empty if there was a node
            to be (re-)used unless we managed to leak some.  Check just
            in case.  Maybe assert instead? */
        if (!node || !free_list)
        {
            ++overflows;
            return -1;
        }
    }

    /* If the node is past its expiration date, whack it and reuse it. */
    if (!new_node && packet_time() > node->expires)
    {
        node->clear(free_list);
        new_node = true;
    }

    if (!new_node)
    {
        // Requests will be rejected if the snort_protocol_id doesn't
        // match what has already been set.
        if (node->snort_protocol_id != snort_protocol_id)
        {
            if (node->snort_protocol_id && snort_protocol_id)
                return -1;
            node->snort_protocol_id = snort_protocol_id;
        }

        last = node->tail;
        if (last)
        {
            FlowData* lfd = last->data;

            while (lfd)
            {
                if (lfd->get_id() == fd->get_id())
                {
                    last = nullptr;
                    break;
                }
                lfd = lfd->next;
            }
        }
    }
    else
    {
        node->snort_protocol_id = snort_protocol_id;
        node->reversed_key = reversed_key;
        node->direction = direction;
        node->head = node->tail = nullptr;
        node->count = 0;
        last = nullptr;
        /* Only add TCP and UDP expected flows for now via the DAQ module. */
        if (ip_proto == IpProtocol::TCP || ip_proto == IpProtocol::UDP)
            SFDAQ::get_local_instance()->add_expected(ctrlPkt, cliIP, cliPort, srvIP, srvPort,
                    ip_proto, 1000, 0);
    }

    bool new_expect_flow = false;
    if (!last)
    {
        if (node->count >= MAX_LIST)
        {
            // fail when maxed out
            ++overflows;
            return -1;
        }
        last = free_list;
        free_list = free_list->next;

        if (!node->tail)
            node->head = last;
        else
            node->tail->next = last;

        node->tail = last;
        last->next = nullptr;
        node->count++;
        new_expect_flow = true;
    }
    last->add_flow_data(fd);
    node->expires = packet_time() + MAX_WAIT;
    ++expects;
    if (new_expect_flow)
    {
        // chain all expected flows created by this packet
        packet_expect_flows->push_back(last);

        ExpectEvent event(ctrlPkt, last, fd);
        DataBus::publish(EXPECT_EVENT_TYPE_EARLY_SESSION_CREATE_KEY, event, ctrlPkt->flow);
    }
    return 0;
}

bool ExpectCache::is_expected(Packet* p)
{
    FlowKey key;
    return (find_node_by_packet(p, key) != nullptr);
}

bool ExpectCache::check(Packet* p, Flow* lws)
{
    FlowKey key;
    ExpectNode* node = find_node_by_packet(p, key);

    if (!node)
        return false;

    return process_expected(node, key, p, lws);
}


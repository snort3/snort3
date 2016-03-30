//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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
// ha.cc author Ed Borgoyn <eborgoyn@cisco.com>

#include "ha.h"

#include <assert.h>
#include <functional>
#include <unordered_map>

#include "flow_key.h"
#include "ha_module.h"
#include "main/snort_debug.h"
#include "packet_io/sfdaq.h"
#include "profiler/profiler.h"
#include "side_channel/side_channel.h"
#include "time/packet_time.h"

THREAD_LOCAL SimpleStats ha_stats;
THREAD_LOCAL ProfileStats ha_perf_stats;

static THREAD_LOCAL HighAvailability* ha;
PortBitSet* HighAvailabilityManager::ports = nullptr;
bool HighAvailabilityManager::use_daq_channel = false;
struct timeval FlowHAState::min_session_lifetime;
uint8_t FlowHAClient::s_handle_counter = 0;

typedef std::unordered_map<FlowHAClientHandle, FlowHAClient*> ClientMap;
static THREAD_LOCAL ClientMap* client_map;
static THREAD_LOCAL FlowHAClient* s_session_client;

static inline bool is_ipv6_key(FlowKey* key)
{
    return (key->ip_l[0] || key->ip_l[1] || key->ip_l[2] != htonl(0xFFFF) ||
            key->ip_h[0] || key->ip_h[1] || key->ip_h[2] != htonl(0xFFFF));
}

FlowHAState::FlowHAState()
{
    state = initial_state;
    pending = none_pending;
}

void FlowHAState::set_pending(FlowHAClientHandle handle)
{
    pending |= (uint16_t)handle;
}

bool FlowHAState::check_and_clear_pending(FlowHAClientHandle handle)
{
    bool temp = ((pending & (uint16_t)handle) != 0);
    pending &= ~((uint16_t)handle);
    return temp;
}

void FlowHAState::set_state(uint8_t new_state)
{
    state |= (new_state & status_mask);
}

void FlowHAState::set_state(uint8_t new_state, uint8_t new_priority)
{
    state |= (new_state & status_mask);
    state |= (new_priority & priority_mask);
}

void FlowHAState::clr_state(uint8_t old_state)
{
    state &= ~(old_state & status_mask);
}

void FlowHAState::clr_state(uint8_t old_state, uint8_t old_priority)
{
    state &= ~(old_state & status_mask);
    state &= ~(old_priority & priority_mask);
}

bool FlowHAState::critical()
{
    return ((state & CRITICAL) != 0);
}

bool FlowHAState::major()
{
    return ((state & MAJOR) != 0);
}

void FlowHAState::config_lifetime(struct timeval min_lifetime)
{
    min_session_lifetime = min_lifetime;
}

bool FlowHAState::old_enough()
{
    struct timeval pkt_time;

    packet_gettimeofday(&pkt_time);

    return ( ( pkt_time.tv_sec > next_update.tv_sec ) ||
        ( ( pkt_time.tv_sec == next_update.tv_sec ) &&
          ( pkt_time.tv_usec > next_update.tv_usec ) ) );
}

void FlowHAState::set_next_update()
{
    next_update.tv_usec += min_session_lifetime.tv_usec;
    if (next_update.tv_usec > 1000000)
    {
        next_update.tv_usec -= 1000000;
        next_update.tv_sec++;
    }
    next_update.tv_sec += min_session_lifetime.tv_sec;
}

void FlowHAState::initialize_update_time()
{
    packet_gettimeofday(&next_update);
}

FlowHAClient::FlowHAClient(bool session_client)
{
    DebugMessage(DEBUG_HA,"FlowHAClient::FlowHAClient()\n");
    if ( session_client )
    {
        handle = session_ha_client;
        s_session_client = this;
    }
    else
    {
        assert(s_handle_counter != max_clients);
        handle = (1 << s_handle_counter);
        s_handle_counter += 1;
    }
}

//static Calculate_
HighAvailability::HighAvailability(PortBitSet* ports, bool)
{
    SCPort port;
    using namespace std::placeholders;
    DebugMessage(DEBUG_HA,"HighAvailability::HighAvailability()\n");

    // If we have ports, configure the side channel
    if( ports != nullptr )
        for( port = 0; port < ports->size(); port++ )
            if ( ports->test(port) )
            {
                sc = SideChannelManager::get_side_channel(port);
                sc->set_default_port(port);
                sc->register_receive_handler(std::bind(&HighAvailability::receive_handler, this, _1));
                break;
            }

    client_map = new ClientMap;

    // Only looking for side channel processing - FIXIT-H
}

HighAvailability::~HighAvailability()
{
    DebugMessage(DEBUG_HA,"HighAvailability::~HighAvailability()\n");

    if ( sc )
    {
        sc->unregister_receive_handler();
        delete sc;
    }

    delete client_map;
}

void HighAvailability::receive_handler(SCMessage* msg)
{
    assert(msg);

    DebugFormat(DEBUG_HA,"HighAvailability::receive_handler: port: %d, length: %d\n",
        msg->hdr->port, msg->content_length);
    if ( msg->sc )
        msg->sc->discard_message(msg);
}

void HighAvailability::process_update(Flow*, const DAQ_PktHdr_t* pkthdr)
{
    DebugMessage(DEBUG_HA,"HighAvailability::process_update()\n");

    const uint32_t msg_len = 21; // up to 20 digits + trailing null

    // Only looking for side channel processing - FIXIT-H
    if ( !sc )
        return;

    SCMessage* msg = sc->alloc_transmit_message(msg_len);
    snprintf((char*)msg->content, msg_len, "%20" PRIu64, (uint64_t)pkthdr->ts.tv_sec);
    sc->transmit_message(msg);
}

void HighAvailability::process_deletion(Flow*)
{
    DebugMessage(DEBUG_HA,"HighAvailability::process_deletion()\n");

    static const char* content = "DELETE";
    const uint32_t msg_len = strlen(content) + 1;

    if ( !sc )
        return;

    SCMessage* msg = sc->alloc_transmit_message(msg_len);
    snprintf((char*)msg->content, msg_len, "%s", content);
    sc->transmit_message(msg);
}

void HighAvailability::process_receive()
{
    if ( sc != nullptr )
        sc->process(0);
}

// Called by the configuration parsing activity in the main thread.
bool HighAvailabilityManager::instantiate(PortBitSet* mod_ports, bool mod_use_daq_channel)
{
    DebugMessage(DEBUG_HA,"HighAvailabilityManager::instantiate()\n");
    ports = mod_ports;
#ifdef HAVE_DAQ_EXT_MODFLOW
    use_daq_channel = mod_use_daq_channel;
#else
    if ( mod_use_daq_channel )
        return false;
#endif
    return true;
}

// Called prior to the starts of configuration in the main thread.
void HighAvailabilityManager::pre_config_init()
{
    ports = nullptr;
}

// Called within the packet thread prior to packet processing
void HighAvailabilityManager::thread_init()
{
    DebugMessage(DEBUG_HA,"HighAvailabilityManager::thread_init()\n");
    // create a a thread local instance iff we are configured to operate.
    if( (ports != nullptr) || use_daq_channel )
        ha = new HighAvailability(ports,use_daq_channel);
    else
        ha = nullptr;
}

// Called in the packet thread at run-down
void HighAvailabilityManager::thread_term()
{
    DebugMessage(DEBUG_HA,"HighAvailabilityManager::thread_term()\n");
    if( ha != nullptr )
        delete ha;
}

void HighAvailabilityManager::process_update(Flow* flow, const DAQ_PktHdr_t* pkthdr)
{
    if( ha != nullptr )
        ha->process_update(flow,pkthdr);
}

// Deletion messages only contain session content
void HighAvailabilityManager::process_deletion(Flow* flow)
{
    if( ha != nullptr )
        ha->process_deletion(flow);
}

void HighAvailabilityManager::process_receive()
{
    if( ha != nullptr )
        ha->process_receive();
}

// Called in the packet threads to determine whether or not HA is active
bool HighAvailabilityManager::active()
{
    return (ha != nullptr);
}

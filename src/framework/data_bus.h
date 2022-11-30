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
// data_bus.h author Russ Combs <rucombs@cisco.com>

#ifndef DATA_BUS_H
#define DATA_BUS_H

// DataEvents are the product of inspection, not detection.  They can be
// used to implement flexible processing w/o hardcoding the logic to call
// specific functions under specific conditions.  By using DataEvents with
// a publish-subscribe mechanism, it is possible to add custom processing
// at arbitrary points, eg when service is identified, or when a URI is
// available, or when a flow clears.

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "main/snort_types.h"

namespace snort
{
class Flow;
struct Packet;
struct SnortConfig;

class DataEvent
{
public:
    virtual ~DataEvent() = default;

    virtual const Packet* get_packet() const
    { return nullptr; }

    virtual const uint8_t* get_data()
    { return nullptr; }

    virtual const uint8_t* get_data(unsigned& len)
    { len = 0; return nullptr; }

    virtual const uint8_t* get_normalized_data(unsigned& len)
    { return get_data(len); }

protected:
    DataEvent() = default;
};

class BareDataEvent final : public DataEvent
{
public:
    BareDataEvent() = default;
    ~BareDataEvent() override = default;
};

class DataHandler
{
public:
    virtual ~DataHandler() = default;

    virtual void handle(DataEvent&, Flow*) { }
    const char* module_name;
    bool cloned;

    // order is desired position in the call sequence of handlers: 1 = first, 0 = last
    // the sequence among subscribers with the same order is not specified
    unsigned order = 0;

protected:
    DataHandler(std::nullptr_t) = delete;
    DataHandler(const char* mod_name) : module_name(mod_name), cloned(false) { }
};

// FIXIT-P evaluate perf; focus is on correctness
typedef std::vector<DataHandler*> DataList;
typedef std::unordered_map<std::string, DataList> DataMap;

class SO_PUBLIC DataBus
{
public:
    DataBus();
    ~DataBus();

    // configure time methods - main thread only
    void clone(DataBus& from, const char* exclude_name = nullptr);

    // FIXIT-L ideally these would not be static or would take an inspection policy*
    static void subscribe(const char* key, DataHandler*);
    static void subscribe_network(const char* key, DataHandler*);
    static void subscribe_global(const char* key, DataHandler*, SnortConfig&);

    // FIXIT-L these should be called during cleanup
    static void unsubscribe(const char* key, DataHandler*);
    static void unsubscribe_network(const char* key, DataHandler*);
    static void unsubscribe_global(const char* key, DataHandler*, SnortConfig&);

    // runtime methods
    static void publish(const char* key, DataEvent&, Flow* = nullptr);

    // convenience methods
    static void publish(const char* key, const uint8_t*, unsigned, Flow* = nullptr);
    static void publish(const char* key, Packet*, Flow* = nullptr);

private:
    void _subscribe(const char* key, DataHandler*);
    void _unsubscribe(const char* key, DataHandler*);
    void _publish(const char* key, DataEvent&, Flow*) const;

private:
    DataMap map;
};
}

//
// Common core functionality data events
//

#define PACKET_EVENT "detection.packet"
#define FLOW_STATE_EVENT "flow.state_change"
#define THREAD_IDLE_EVENT "thread.idle"
#define THREAD_ROTATE_EVENT "thread.rotate"

// A packet is being detained.
#define DETAINED_PACKET_EVENT "analyzer.detained.packet"

// A flow changed its service
#define FLOW_SERVICE_CHANGE_EVENT "flow.service_change_event"
// A flow has found the service inspector
#define SERVICE_INSPECTOR_CHANGE_EVENT "flow.service_inspector.changed"
// No service has been found for the flow
#define FLOW_NO_SERVICE_EVENT "flow.no_service_event"
// search of SSL is abandoned on this flow
#define SSL_SEARCH_ABANDONED "flow.ssl_search_abandoned"

// A flow has entered the setup state
#define FLOW_STATE_SETUP_EVENT "flow.state_setup"

// The policy has changed for the flow
#define FLOW_STATE_RELOADED_EVENT "flow.reloaded"

// A new flow is created on this packet
#define STREAM_ICMP_NEW_FLOW_EVENT "stream.icmp_new_flow"
#define STREAM_IP_NEW_FLOW_EVENT "stream.ip_new_flow"
#define STREAM_UDP_NEW_FLOW_EVENT "stream.udp_new_flow"

// A flow has been determined to be bidirectional
#define STREAM_ICMP_BIDIRECTIONAL_EVENT "stream.icmp_bidirectional"
#define STREAM_IP_BIDIRECTIONAL_EVENT "stream.ip.bidirectional"
#define STREAM_UDP_BIDIRECTIONAL_EVENT "stream.udp.bidirectional"

// A TCP flow has the flag; a midstream flow may not publish other events
#define STREAM_TCP_SYN_EVENT "stream.tcp_syn"
#define STREAM_TCP_SYN_ACK_EVENT "stream.tcp_syn_ack"
#define STREAM_TCP_MIDSTREAM_EVENT "stream.tcp_midstream"
#define STREAM_TCP_ESTABLISHED_EVENT "stream.tcp_established"

// A new standby flow was generated by stream high availability
#define STREAM_HA_NEW_FLOW_EVENT "stream.ha.new_flow"

#endif


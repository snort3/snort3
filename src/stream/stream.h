//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

// stream.h author Steven Sturges

#ifndef STREAM_H
#define STREAM_H

// provides a common flow management interface

#include <memory>

#include <daq_common.h>

#include "flow/flow.h"

class HostAttributesDescriptor;
typedef std::shared_ptr<HostAttributesDescriptor> HostAttributesEntry;

namespace snort
{
class Flow;
struct SfIp;
class StreamSplitter;

/* traffic direction identification */
#define FROM_SERVER     0
#define FROM_CLIENT     1

#define SSN_MISSING_NONE   0x00
#define SSN_MISSING_BEFORE 0x01
#define SSN_MISSING_AFTER  0x02
#define SSN_MISSING_BOTH   (SSN_MISSING_BEFORE | SSN_MISSING_AFTER)

#define SSN_DIR_NONE           0x00
#define SSN_DIR_FROM_CLIENT    0x01
#define SSN_DIR_FROM_SERVER    0x02
#define SSN_DIR_BOTH           0x03

// sequence must match FRAG_POLICY_* enum in stream_ip.h (1-based)
#define IP_POLICIES  \
    "first | linux | bsd | bsd_right | last | windows | solaris"

// sequence must match enum StreamPolicy defines in tcp_defs.h
#define TCP_POLICIES \
    "first | last | linux | old_linux | bsd | macos | solaris | irix | " \
    "hpux11 | hpux10 | windows | win_2003 | vista | proxy"

struct AlertInfo
{
    AlertInfo() = default;
    AlertInfo(uint32_t gid, uint32_t sid, uint32_t id, uint32_t ts = 0)
        : gid(gid), sid(sid), event_id(id), event_second(ts) {}

    uint32_t gid = 0;
    uint32_t sid = 0;

    uint32_t event_id = 0;
    uint32_t event_second = 0;
};

typedef int (* LogFunction)(Flow*, uint8_t** buf, uint32_t* len, uint32_t* type);
typedef void (* LogExtraData)(Flow*, void* config, LogFunction* funcs,
    uint32_t max_count, uint32_t xtradata_mask, const AlertInfo& alert_info);

#define MAX_LOG_FN 32

//-------------------------------------------------------------------------

class SO_PUBLIC Stream
{
public:
    // for shutdown only
    static void purge_flows();

    static void handle_timeouts(bool idle);
    static bool prune_flows();
    static bool expected_flow(Flow*, Packet*);

    // Looks in the flow cache for flow session with specified key and returns
    // pointer to flow session object if found, otherwise null.
    static Flow* get_flow(const FlowKey*);

    // Allocates a flow session object from the flow cache table for the protocol
    // type of the specified key.  If no cache exists for that protocol type null is
    // returned.  If a flow already exists for the key a pointer to that session
    // object is returned.
    // If a new session object can not be allocated the program is terminated.
    static Flow* new_flow(const FlowKey*);

    // Removes the flow session object from the flow cache table and returns
    // the resources allocated to that flow to the free list.
    static void delete_flow(const FlowKey*);
    static void delete_flow(Flow*);

    // Examines the source and destination ip addresses and ports to determine if the
    // packet is from the client or server side of the flow and sets bits in the
    // packet_flags field of the Packet struct to indicate the direction determined.
    static uint32_t get_packet_direction(Packet*);

    // Stop inspection on a flow for up to count bytes (-1 to ignore for life or until resume).
    // If response flag is set, automatically resume inspection up to count bytes when a data
    // packet in the other direction is seen.  Also marks the packet to be ignored
    // FIXIT-L stop_inspection() does not currently support the bytes/response parameters
    static void stop_inspection(Flow*, Packet*, char dir, int32_t bytes, int rspFlag);

    // Adds entry to the expected session cache with a flow key generated from the network
    // n-tuple parameters specified.  Inspection will be turned off for this expected session
    // when it arrives.
    static int ignore_flow(
        const Packet* ctrlPkt, PktType, IpProtocol, const snort::SfIp* srcIP, uint16_t srcPort,
        const snort::SfIp* dstIP, uint16_t dstPort, char direction, FlowData* fd);

    // Set Active status to force drop the current packet and set flow state to drop
    // subsequent packets arriving from the direction specified.
    static void drop_traffic(const Packet*, char dir);

    // Mark a flow as dropped, release allocated resources, and set flow state such that any
    // subsequent packets received on this flow are dropped.
    static void drop_flow(const Packet*);

    // Mark flow session as block pending. Resources will be released
    // at the end of inspection
    static void block_flow(const Packet*);

    static void flush_client(Packet*);  // flush data received by client
    static void flush_server(Packet*);  // flush data received by server

    // Add session alert - true if added
    static bool add_flow_alert(Flow*, Packet*, uint32_t gid, uint32_t sid);

    // Check session alert - true if previously alerted
    static bool check_flow_alerted(Flow*, Packet* p, uint32_t gid, uint32_t sid);

    // Set Extra Data Logging
    static int update_flow_alert(
        Flow*, Packet* p, uint32_t gid, uint32_t sid,
        uint32_t eventId, uint32_t eventSecond);

    static void disable_reassembly(Flow*);
    static char get_reassembly_direction(Flow*);

    // Returns true if stream data for the flow is in sequence, otherwise return false.
    static bool is_stream_sequenced(Flow*, uint8_t dir);

    // Get state of missing packets for the flow.
    //      SSN_MISSING_BOTH if missing before and after
    //      SSN_MISSING_BEFORE if missing before
    //      SSN_MISSING_AFTER if missing after
    //      SSN_MISSING_NONE if none missing
    static int missing_in_reassembled(Flow*, uint8_t dir);

    // Returns true if packets were missed on the stream, otherwise returns false.
    static bool missed_packets(Flow*, uint8_t dir);

    // Get the protocol identifier from a stream
    static SnortProtocolId get_snort_protocol_id(Flow*);

    // Set the protocol identifier for a stream
    static SnortProtocolId set_snort_protocol_id(Flow*, SnortProtocolId, bool is_appid_service = false);

    // initialize response count and expiration time
    static void init_active_response(const Packet*, Flow*);

    static void set_splitter(Flow*, bool toServer, StreamSplitter* = nullptr);
    static StreamSplitter* get_splitter(Flow*, bool toServer);

    // Turn off inspection for potential session. Adds session identifiers to a hash table.
    // TCP only.
    static int set_snort_protocol_id_expected(
        const Packet* ctrlPkt, PktType, IpProtocol, const snort::SfIp* srcIP, uint16_t srcPort,
        const snort::SfIp* dstIP, uint16_t dstPort, SnortProtocolId, FlowData*,
        bool swap_app_direction = false, bool expect_multi = false, bool bidirectional = false,
        bool expect_persist = false);

    // Get pointer to application data for a flow based on the lookup tuples for cases where
    // Snort does not have an active packet that is relevant.
    static FlowData* get_flow_data(
        PktType type, IpProtocol proto,
        const snort::SfIp* a1, uint16_t p1, const snort::SfIp* a2, uint16_t p2,
        uint16_t vlanId, uint32_t mplsId, uint32_t addrSpaceId, unsigned flowdata_id,
        uint32_t tenant_id, int16_t ingress_group = DAQ_PKTHDR_UNKNOWN,
        int16_t egress_group = DAQ_PKTHDR_UNKNOWN);

    // Get pointer to application data for a flow using the FlowKey as the lookup criteria
    static FlowData* get_flow_data(const FlowKey*, unsigned flowdata_id);

    // Get pointer to a session flow instance for a flow based on the lookup tuples for
    // cases where Snort does not have an active packet that is relevant.
    static Flow* get_flow(
        PktType type, IpProtocol proto,
        const snort::SfIp* a1, uint16_t p1, const snort::SfIp* a2, uint16_t p2,
        uint16_t vlanId, uint32_t mplsId, uint32_t addrSpaceId,
        uint32_t tenant_id, int16_t ingress_group = DAQ_PKTHDR_UNKNOWN,
        int16_t egress_group = DAQ_PKTHDR_UNKNOWN);

    static Flow* get_flow(
        PktType type, IpProtocol proto,
        const snort::SfIp* a1, uint16_t p1, const snort::SfIp* a2, uint16_t p2,
        uint16_t vlanId, uint32_t mplsId, const DAQ_PktHdr_t&);

    // Delete the session if it is in the closed session state.
    // Handle session block pending state
    static void check_flow_closed(Packet*);

    //  Populate a flow key from the Packet
    static void populate_flow_key(const Packet*, FlowKey*);

    static void set_snort_protocol_id_from_ha(Flow*, const SnortProtocolId);

    static bool is_midstream(Flow* flow)
    { return ((flow->ssn_state.session_flags & SSNFLAG_MIDSTREAM) != 0); }

    // Get the TTL value used at session setup
    // Set outer=false to get inner ip ttl for ip in ip; else outer=true
    static uint8_t get_flow_ttl(Flow*, char dir, bool outer);

    static bool expired_flow(Flow*, Packet*);
    static bool ignored_flow(Flow*, Packet*);
    static bool blocked_flow(Packet*);

    // extra data methods
    static void set_extra_data(Flow*, Packet*, uint32_t);
    static void log_extra_data(Flow*, uint32_t mask, const AlertInfo&);

    static uint32_t reg_xtra_data_cb(LogFunction);
    static void reg_xtra_data_log(LogExtraData, void*);
    static uint32_t get_xtra_data_map(LogFunction*&);

    // TCP-specific accessor methods.
    static uint16_t get_mss(Flow*, bool to_server);
    static uint8_t get_tcp_options_len(Flow*, bool to_server);

    static bool set_packet_action_to_hold(Packet*);
    static bool can_set_no_ack_mode(Flow*);
    static bool set_no_ack_mode(Flow*, bool);
    static void partial_flush(Flow*, bool to_server);

    static bool get_held_pkt_seq(Flow*, uint32_t&);

    static void set_pub_id();
    static unsigned get_pub_id();

private:
    static void set_ip_protocol(Flow*);
};
}
#endif


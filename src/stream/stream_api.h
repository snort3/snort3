//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

/* stream_api.h
 * AUTHOR: Steven Sturges
 *
 * Purpose: Definition of the StreamAPI.  To be used as a common interface
 *          for TCP (and later UDP & ICMP) Stream access for other
 *          preprocessors and detection plugins.
 */

#ifndef STREAM_API_H
#define STREAM_API_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>

#include "sfip/sfip_t.h"
#include "protocols/packet.h"
#include "flow/flow.h"
#include "main/snort_types.h"

#define SSN_MISSING_NONE   0x00
#define SSN_MISSING_BEFORE 0x01
#define SSN_MISSING_AFTER  0x02
#define SSN_MISSING_BOTH   (SSN_MISSING_BEFORE | SSN_MISSING_AFTER)

#define SSN_DIR_NONE           0x00
#define SSN_DIR_FROM_CLIENT    0x01
#define SSN_DIR_FROM_SENDER    0x01
#define SSN_DIR_FROM_SERVER    0x02
#define SSN_DIR_FROM_RESPONDER 0x02
#define SSN_DIR_BOTH           0x03

class Flow;

typedef int (*LogFunction)(Flow*, uint8_t **buf, uint32_t *len, uint32_t *type);
typedef void (*LogExtraData)(Flow*, void *config, LogFunction *funcs,
    uint32_t max_count, uint32_t xtradata_mask, uint32_t id, uint32_t sec);

typedef int (*PacketIterator)
    (
     DAQ_PktHdr_t *,
     uint8_t *,  /* pkt pointer */
     void *      /* user-defined data pointer */
    );

typedef int (*StreamSegmentIterator)
    (
     DAQ_PktHdr_t *,
     uint8_t *,  /* pkt pointer */
     uint8_t *,  /* payload pointer */
     uint32_t,   /* sequence number */
     void *      /* user-defined data pointer */
    );

#define MAX_LOG_FN 32

//-------------------------------------------------------------------------
// public methods other than ctor / dtor must all be declared SO_PUBLIC
//-------------------------------------------------------------------------

class SO_PUBLIC Stream
{
public:
    SO_PRIVATE Stream();
    SO_PRIVATE ~Stream();

    static Flow* get_session(const FlowKey*);
    static Flow* new_session(const FlowKey*);
    static void delete_session(const FlowKey*);

    static uint32_t get_packet_direction(Packet*);

    static void proxy_started(Flow*, unsigned dir);

    /* Stop inspection for session, up to count bytes (-1 to ignore
     * for life or until resume).
     *
     * If response flag is set, automatically resume inspection up to
     * count bytes when a data packet in the other direction is seen.
     *
     * Also marks the packet to be ignored
     */
    static void stop_inspection(Flow*, Packet*, char dir, int32_t bytes, int rspFlag);

    /* Turn off inspection for potential session.
     * Adds session identifiers to a hash table.
     * TCP only.
     */
    int ignore_session(
        const sfip_t *addr1, uint16_t p1, const sfip_t *addr2, uint16_t p2,
        uint8_t proto, char dir, uint32_t ppId);

    /* Resume inspection for session.
     */
    static void resume_inspection(Flow*, char dir);

    /* Drop traffic arriving on session.
     */
    static void drop_traffic(Flow*, char dir);

    /* Drop retransmitted packet arriving on session.
     */
    static void drop_packet(Packet*);  // PKT

    // FIXIT-L these are misnomers in ips mode and may be used incorrectly
    static void flush_request(Packet*);  // flush listener
    static void flush_response(Packet*);  // flush talker

    /* Calls user-provided callback function for each packet of
     * a reassembled stream.  If the callback function returns non-zero,
     * iteration ends.
     *
     * Returns number of packets
     */
    static int traverse_reassembled(Packet*, PacketIterator, void* userdata);  // PKT

    /* Calls user-provided callback function for each segment of
     * a reassembled stream.  If the callback function returns non-zero,
     * iteration ends.
     *
     * Returns number of packets
     */
    static int traverse_stream_segments(Packet*, StreamSegmentIterator, void* userdata);  // PKT

    /* Add session alert - true if added
     */
    static bool add_session_alert(Flow*, Packet*, uint32_t gid, uint32_t sid);

    /* Check session alert - true if previously alerted
     */
    static bool check_session_alerted(Flow*, Packet *p, uint32_t gid, uint32_t sid);

    /* Set Extra Data Logging
     *
     * Returns
     *      0 success
     *      -1 failure ( no alerts )
     */
    static int update_session_alert(
        Flow*, Packet *p, uint32_t gid, uint32_t sid,
        uint32_t eventId, uint32_t eventSecond);

    /* Get Flowbits data
     *
     * Returns
     *     Ptr to Flowbits Data
     */
    static StreamFlowData* get_flow_data(Packet*);

    /* Get reassembly direction for given session
     *
     * Returns
     *     direction(s) of reassembly for session
     */
    static char get_reassembly_direction(Flow*);

    /* Get true/false as to whether stream data is in
     * sequence or packets are missing
     *
     * Returns
     *     true/false
     */
    static char is_stream_sequenced(Flow*, char dir);

    /* Get whether there are missing packets before, after or
     * before and after reassembled buffer
     *
     * Returns
     *      SSN_MISSING_BOTH if missing before and after
     *      SSN_MISSING_BEFORE if missing before
     *      SSN_MISSING_AFTER if missing after
     *      SSN_MISSING_NONE if none missing
     */
    static int missing_in_reassembled(Flow*, char dir);

    /* Get true/false as to whether packets were missed on
     * the stream
     *
     * Returns
     *     true/false
     */
    static char missed_packets(Flow*, char dir);

    /* Get the protocol identifier from a stream
     *
     * Returns
     *     integer protocol identifier
     */
    static int16_t get_application_protocol_id(Flow*);

    /* Set the protocol identifier for a stream
     *
     * Returns
     *     integer protocol identifier
     */
    static int16_t set_application_protocol_id(Flow*, int16_t appId);

    // initialize response count and expiration time
    static void init_active_response(Packet*, Flow*);

    static bool is_paf_active(Flow*, bool toServer);
    static void set_splitter(Flow*, bool toServer, class StreamSplitter* = nullptr);
    static StreamSplitter* get_splitter(Flow*, bool toServer);

    /* Turn off inspection for potential session.
     * Adds session identifiers to a hash table.
     * TCP only.
     *
     * Returns
     *     0 on success
     *     -1 on failure
     */
    int set_application_protocol_id_expected(
        const sfip_t *a1, uint16_t p1, const sfip_t *a2, uint16_t p2, uint8_t proto,
        int16_t appId, FlowData*);

    /** Retrieve application session data based on the lookup tuples for
     *  cases where Snort does not have an active packet that is
     *  relevant.
     *
     * Returns
     *     Application Data reference (pointer)
     */
    static FlowData* get_application_data_from_ip_port(
        const sfip_t *a1, uint16_t p1, const sfip_t *a2, uint16_t p2, uint8_t    proto,
        uint16_t vlanId, uint32_t mplsId, uint16_t addrSpaceId, unsigned flow_id);

    /*  Get the application data from the session key
     */
    static FlowData* get_application_data_from_key(const FlowKey*, unsigned flow_id);

    // -- extra data methods
    uint32_t reg_xtra_data_cb(LogFunction);
    void reg_xtra_data_log(LogExtraData, void*);
    uint32_t get_xtra_data_map(LogFunction**);

    static void set_extra_data(Flow*, Packet *, uint32_t);
    static void clear_extra_data(Flow*, Packet *, uint32_t);
    void log_extra_data(Flow*, uint32_t mask, uint32_t id, uint32_t sec);

    /** Retrieve stream session pointer based on the lookup tuples for
     *  cases where Snort does not have an active packet that is
     *  relevant.
     *
     * Returns
     *     Stream session pointer
     */
    static Flow* get_session_ptr_from_ip_port(
        const sfip_t *a1, uint16_t p1, const sfip_t *a2, uint16_t p2, uint8_t proto,
        uint16_t vlanId, uint32_t mplsId, uint16_t addrSpaceId);

    /* Delete the session if it is in the closed session state.
     */
    void check_session_closed(Packet*);

    /*  Create a session key from the Packet
     */
    static FlowKey* get_session_key(Packet*);

    /*  Populate a session key from the Packet
     */
    static void populate_session_key(Packet*, FlowKey*);

    void update_direction(Flow*, char dir, const sfip_t *ip, uint16_t port);

    static void set_application_protocol_id_from_host_entry(
        Flow*, const struct HostAttributeEntry*, int direction);

    static uint32_t set_session_flags(Flow*, uint32_t flags);
    static uint32_t get_session_flags(Flow*);

    static bool is_midstream(Flow* flow)
        { return flow->ssn_state.session_flags & SSNFLAG_MIDSTREAM; };

    static int get_ignore_direction(Flow*);
    static int set_ignore_direction(Flow*, int ignore_direction);

    // Get the TTL value used at session setup
    // outer=false to get inner ip ttl for ip in ip; else outer=true
    static uint8_t get_session_ttl(Flow*, char dir, bool outer);

    static bool expired_session (Flow*, Packet*);
    static bool ignored_session (Flow*, Packet*);
    static bool blocked_session (Flow*, Packet*);

private:
    static void set_ip_protocol(Flow*);

private:
    uint32_t xtradata_func_count = 0;
    LogFunction xtradata_map[MAX_LOG_FN];
    LogExtraData extra_data_log = NULL;
    void *extra_data_config = NULL;
};

SO_PUBLIC extern Stream stream;

#endif


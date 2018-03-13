//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// dnp3.h author Rashmi Pitre <rrp@cisco.com>
// based on work by Ryan Jordan

#ifndef DNP3_H
#define DNP3_H

#include "flow/flow.h"
#include "framework/counts.h"
#include "profiler/profiler_defs.h"

#define DNP3_NAME "dnp3"
#define DNP3_HELP "dnp3 inspection"

#define DNP3_BAD_CRC_STR  "DNP3 link-layer frame contains bad CRC"
#define DNP3_DROPPED_FRAME_STR "DNP3 link-layer frame was dropped"
#define DNP3_DROPPED_SEGMENT_STR "DNP3 transport-layer segment was dropped during reassembly"
#define DNP3_REASSEMBLY_BUFFER_CLEARED_STR \
    "DNP3 reassembly buffer was cleared without reassembling a complete message"
#define DNP3_RESERVED_ADDRESS_STR "DNP3 link-layer frame uses a reserved address"
#define DNP3_RESERVED_FUNCTION_STR "DNP3 application-layer fragment uses a reserved function code"

#define DNP3_BAD_CRC                    1
#define DNP3_DROPPED_FRAME              2
#define DNP3_DROPPED_SEGMENT            3
#define DNP3_REASSEMBLY_BUFFER_CLEARED  4
#define DNP3_RESERVED_ADDRESS           5
#define DNP3_RESERVED_FUNCTION          6

/* Packet directions */
#define DNP3_CLIENT 0
#define DNP3_SERVER 1

/* Session data flags */
#define DNP3_FUNC_RULE_FIRED    0x0001
#define DNP3_OBJ_RULE_FIRED     0x0002
#define DNP3_IND_RULE_FIRED     0x0004
#define DNP3_DATA_RULE_FIRED    0x0008

/* DNP3 minimum length: start (2 octets) + len (1 octet) */
#define DNP3_MIN_LEN 3
#define DNP3_LEN_OFFSET 2

/* Length of the rest of a DNP3 link-layer header: ctrl + src + dest */
#define DNP3_HEADER_REMAINDER_LEN 5

#define DNP3_BUFFER_SIZE 2048

#ifdef WORDS_BIGENDIAN
#define DNP3_START_BYTES       0x0564
#else
#define DNP3_START_BYTES       0x6405
#endif

#define DNP3_MIN_RESERVED_ADDR 0xFFF0
#define DNP3_MAX_RESERVED_ADDR 0xFFFB

#define DNP3_START_BYTE_1   0x05
#define DNP3_START_BYTE_2   0x64

#define DNP3_CHUNK_SIZE     16
#define DNP3_CRC_SIZE        2

/* Minimum length of DNP3 "len" field in order to get a transport header. */
#define DNP3_MIN_TRANSPORT_LEN 6
#define DNP3_MAX_TRANSPORT_LEN 250

#define DNP3_TPDU_MAX  250
#define DNP3_LPDU_MAX  292

#define DNP3_TRANSPORT_FIN(x) ((x) & 0x80)
#define DNP3_TRANSPORT_FIR(x) ((x) & 0x40)
#define DNP3_TRANSPORT_SEQ(x) ((x) & 0x3F)

/* Yep, the locations of FIR and FIN are switched at this layer... */
#define DNP3_APP_FIR(x) ((x) & 0x80)
#define DNP3_APP_FIN(x) ((x) & 0x40)
#define DNP3_APP_SEQ(x) ((x) & 0x0F)

#define DNP3_OK true
#define DNP3_FAIL false

struct Dnp3Stats
{
    PegCount total_packets;
    PegCount udp_packets;
    PegCount tcp_pdus;
    PegCount dnp3_link_layer_frames;
    PegCount dnp3_application_pdus;
    PegCount concurrent_sessions;
    PegCount max_concurrent_sessions;
};

/* DNP3 header structures */
struct dnp3_link_header_t
{
    uint16_t start;
    uint8_t len;
    uint8_t ctrl;
    uint16_t dest;
    uint16_t src;
};

struct dnp3_transport_header_t
{
    uint8_t control;
};

struct dnp3_app_request_header_t
{
    uint8_t control;
    uint8_t function;
};

struct dnp3_app_response_header_t
{
    uint8_t control;
    uint8_t function;
    uint16_t indications;
};

enum dnp3_reassembly_state_t
{
    DNP3_REASSEMBLY_STATE__IDLE = 0,
    DNP3_REASSEMBLY_STATE__ASSEMBLY,
    DNP3_REASSEMBLY_STATE__DONE
};

struct dnp3_reassembly_data_t
{
    uint8_t buffer[DNP3_BUFFER_SIZE];
    uint16_t buflen = 0;
    dnp3_reassembly_state_t state = DNP3_REASSEMBLY_STATE__IDLE;
    uint8_t last_seq = 0;
};

/* DNP3 session data */
struct dnp3_session_data_t
{
    /* Fields for rule option matching. */
    uint8_t direction = 0;
    uint8_t func = 0;
    uint8_t obj_group = 0;
    uint8_t obj_var = 0;
    uint16_t indications = 0;
    uint16_t flags = 0;

    /* Reassembly stuff */
    dnp3_reassembly_data_t client_rdata;
    dnp3_reassembly_data_t server_rdata;
};

class Dnp3FlowData : public snort::FlowData
{
public:
    Dnp3FlowData();
    ~Dnp3FlowData() override;

    static void init()
    {
        inspector_id = snort::FlowData::create_flow_data_id();
    }

public:
    static unsigned inspector_id;
    dnp3_session_data_t dnp3_session;
};

extern THREAD_LOCAL Dnp3Stats dnp3_stats;
extern THREAD_LOCAL snort::ProfileStats dnp3_perf_stats;

#endif


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

// session_file.h author Shravan Rangarajuvenkata <shrarang@cisco.com>

#ifndef SESSION_FILE_H
#define SESSION_FILE_H

#include <stdio.h>

#define MAX_APP_PROTOCOL_ID  4

struct HttpParsedHeaders;
struct Packet;
struct SessionKey;
struct StreamAppData;

enum SessionField
{
    SESSION_CLIENT_IP_IA32 = 1000,
    SESSION_CLIENT_PORT,
    SESSION_HA_STATE_SESSION_FLAGS
};

enum tPktField
{
    PACKET_PKT_HEADER_TS_TV_SEC = 1000,
    PACKET_PKT_HEADER_INGRESS_GROUP,
    PACKET_PKT_HEADER_PKTLEN,

    PACKET_TCP_HEADER_SOURCE_PORT = 2000,
    PACKET_TCP_HEADER_FLAGS,
    PACKET_UDP_HEADER_SOURCE_PORT,

    PACKET_IP4H_IP_ADDRS_IP_SRC_IA32 = 3000,
    PACKET_IP4H_IP_ADDRS_IP_SRC_FAMILY,
    PACKET_IP4H_IP_ADDRS_IP_DST_IA32,
    PACKET_IP4H_IP_ADDRS_IP_DST_FAMILY,
    PACKET_IP4H_IP_PROTO,

    PACKET_FAMILY = 4000,
    PACKET_FLAGS,
    PACKET_SRC_PORT,
    PACKET_DST_PORT,
    PACKET_PAYLOAD,

    PACKET_HTTP_HOST = 5000,
    PACKET_HTTP_URL,
    PACKET_HTTP_METHOD,
    PACKET_HTTP_USER_AGENT,
    PACKET_HTTP_REFERER,
    PACKET_HTTP_VIA,
    PACKET_HTTP_RESPONSE_CODE,
    PACKET_HTTP_SERVER,
    PACKET_HTTP_X_WORKING_WITH,
    PACKET_HTTP_CONTENT_TYPE,

    PACKET_IP6H_IP_ADDRS_IP_SRC_IA32 = 6000,
    PACKET_IP6H_IP_ADDRS_IP_SRC_FAMILY,
    PACKET_IP6H_IP_ADDRS_IP_DST_IA32,
    PACKET_IP6H_IP_ADDRS_IP_DST_FAMILY
};

struct SessionFileData
{
    uint32_t packetCount;
    FILE* file;
    char fileName[16];
};

#ifdef MPLS
struct MPLS_Hdr
{
    uint16_t length;
    uint8_t* start;
};
#endif

//  FIXIT-M: Temporary structs and defines for initial appid port.
using tSfPolicyId = int;
#define SE_MAX 255
struct StreamHAState { };
//  END FIXIT-M

struct SessionControlBlock
{
    SessionKey* key;

    //MemBucket  *proto_specific_data;
    void* proto_specific_data;
    StreamAppData* appDataList;

    //MemBucket *flowdata; /* add flowbits */
    void* flowdata; /* add flowbits */

    long last_data_seen;
    uint64_t expire_time;

    tSfPolicyId napPolicyId;
    tSfPolicyId ipsPolicyId;
    bool ips_os_selected;
    //SessionConfiguration *session_config;
    void* session_config;
    void* stream_config;
    void* proto_policy;

    //PreprocEnableMask enabled_pps;
    uint32_t enabled_pps;
    //PreprocEvalFuncNode *initial_pp;
    void* initial_pp;

    uint16_t session_state;
    uint8_t handler[SE_MAX];
    sfaddr_t client_ip;    // FIXTHIS family and bits should be changed to uint16_t
    sfaddr_t server_ip;    // or uint8_t to reduce sizeof from 24 to 20
    uint16_t client_port;
    uint16_t server_port;
    bool port_guess;

    uint8_t protocol;

#ifdef ACTIVE_RESPONSE
    uint8_t response_count;
#endif

    uint8_t inner_client_ttl;
    uint8_t inner_server_ttl;
    uint8_t outer_client_ttl;
    uint8_t outer_server_ttl;

    StreamHAState ha_state;
    StreamHAState cached_ha_state;

#ifdef ENABLE_HA
    struct timeval ha_next_update;
    uint8_t ha_pending_mask;
    uint8_t ha_flags;
#endif

    bool session_established;
    bool new_session;

    // pointers for linking into list of oneway sessions
    struct _SessionControlBlock* ows_prev;
    struct _SessionControlBlock* ows_next;
    bool in_oneway_list;

    int16_t app_protocol_id[MAX_APP_PROTOCOL_ID];

#ifdef MPLS
    MPLS_Hdr* clientMplsHeader;
    MPLS_Hdr* serverMplsHeader;
#endif
};

void sessionFileInit();
void sessionFileFini();
FILE* sessionFileProcess(Packet*);
void sessionFileProcessHttp(Packet*, HttpParsedHeaders*);
void sessionFileReadSession(FILE*, SessionControlBlock*);
int sessionFileReadPacket(FILE*, Packet*, HttpParsedHeaders**);

#endif


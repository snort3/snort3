//--------------------------------------------------------------------------
// Copyright (C) 2025-2026 Cisco and/or its affiliates. All rights reserved.
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

// opcua_decode.cc author Jared Rittle <jared.rittle@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "opcua_decode.h"

#include "detection/detection_engine.h"
#include "log/messages.h"
#include "managers/plugin_manager.h"
#include "protocols/packet.h"
#include "trace/trace_api.h"

#include <unordered_map>

#include "opcua_module.h"
#include "opcua_session.h"

using namespace snort;


static bool append_message_chunk(Packet*, OpcuaSessionData*);
static bool inspect_is_final_field(Packet*, OpcuaSessionData*);
static bool inspect_msg_size_field(Packet*, uint32_t);
static bool analyze_opcua_string(Packet*, OpcuaStringAnalysisData&);
static bool parse_msg_hel(Packet*, OpcuaSessionData*);
static bool parse_msg_ack(Packet*, OpcuaSessionData*);
static bool parse_msg_err(Packet*, OpcuaSessionData*);
static bool parse_msg_rhe(Packet*, OpcuaSessionData*);
static bool parse_msg_opn(Packet*, OpcuaSessionData*);
static bool parse_msg_msg(Packet*, OpcuaSessionData*);
static bool parse_msg_clo(Packet*, OpcuaSessionData*);

using OpcuaMsgParseFunc = bool(*)(Packet*, OpcuaSessionData*);

static const std::unordered_map<uint32_t, OpcuaMsgParseFunc> opcua_msg_parsers = {
    {make_opcua_msg_key('H','E','L'), parse_msg_hel},
    {make_opcua_msg_key('A','C','K'), parse_msg_ack},
    {make_opcua_msg_key('E','R','R'), parse_msg_err},
    {make_opcua_msg_key('R','H','E'), parse_msg_rhe},
    {make_opcua_msg_key('O','P','N'), parse_msg_opn},
    {make_opcua_msg_key('M','S','G'), parse_msg_msg},
    {make_opcua_msg_key('C','L','O'), parse_msg_clo}
};

static bool append_message_chunk(Packet* p, OpcuaSessionData* ssn_data)
{

    if ( p->dsize <= OPCUA_MSG_HDR_LEN )
    {
        DetectionEngine::queue_event(GID_OPCUA, OPCUA_BAD_MSG_SIZE);
        return false;
    }

    const uint32_t current_chunk_data_len = p->dsize - OPCUA_MSG_HDR_LEN;
    const uint32_t new_chunk_data_len = ssn_data->chunk_data_len + current_chunk_data_len;

    if ( new_chunk_data_len >= OPCUA_CHUNK_DATA_BUF_SIZE )
    {
        DetectionEngine::queue_event(GID_OPCUA, OPCUA_LARGE_CHUNKED_MSG);
        return false;
    }
    else
    {
        void* dst = ssn_data->chunk_data + ssn_data->chunk_data_len;
        const void* src = p->data + OPCUA_MSG_HDR_LEN;
        memcpy(dst, src, current_chunk_data_len);

        ssn_data->chunk_data_len = new_chunk_data_len;
    }
    return true;
}

static bool inspect_is_final_field(Packet* p, OpcuaSessionData* ssn_data)
{
    const OpcuaHeader* hdr = (const OpcuaHeader*) p->data;

    if ( ssn_data->msg_type == OPCUA_MSG_MSG )
    {
        switch ( hdr->is_final )
        {
        case OPCUA_IS_FINAL_INTERMEDIATE:
        {
            ssn_data->is_final = OPCUA_IS_FINAL_INTERMEDIATE;
            ssn_data->is_chunked = true;
            ssn_data->is_complete_msg = false;

            return append_message_chunk(p, ssn_data);
        }
        case OPCUA_IS_FINAL_ABORTED:
        {
            opcua_stats.aborted_chunks++;

            ssn_data->is_final = OPCUA_IS_FINAL_ABORTED;
            ssn_data->is_complete_msg = true;

            return append_message_chunk(p, ssn_data);
        }
        case OPCUA_IS_FINAL_FINAL:
        {
            opcua_stats.complete_messages++;

            ssn_data->is_final = OPCUA_IS_FINAL_FINAL;
            ssn_data->is_complete_msg = true;

            return append_message_chunk(p, ssn_data);
        }

        default:
        {
            DetectionEngine::queue_event(GID_OPCUA, OPCUA_BAD_ISFINAL);

            ssn_data->is_chunked = false;

            break;
        }
        }
    }
    else
    {
        switch ( hdr->is_final )
        {
        case OPCUA_IS_FINAL_FINAL:
        {
            opcua_stats.complete_messages++;

            ssn_data->is_final = OPCUA_IS_FINAL_FINAL;

            return true;
        }
        default:
        {
            // non-fatal alert as this value is deemed as "ignored" by the
            // spec for these message types, but it is something abnormal
            DetectionEngine::queue_event(GID_OPCUA, OPCUA_BAD_ISFINAL);
            
            return true;
        }
        }
    }
    return false;
}

static bool inspect_msg_size_field(Packet* p, uint32_t min_size)
{
    const OpcuaHeader* hdr = (const OpcuaHeader*) p->data;
    if ( hdr->msg_size < min_size || p->dsize < min_size )
    {
        DetectionEngine::queue_event(GID_OPCUA, OPCUA_BAD_MSG_SIZE);
        return false;
    }
    return true;
}

static bool validate_opcua_string_bounds(Packet* p, uint32_t string_size, uint32_t string_offset, bool is_last_field)
{
    if ( ( is_last_field && p->dsize != (string_offset + string_size) ) ||
        ( p->dsize < (string_offset + string_size) ) )
    {
        DetectionEngine::queue_event(GID_OPCUA, OPCUA_ABNORMAL_STRING);
        return false;
    }

    return true;
}

static bool analyze_opcua_string(Packet* p, OpcuaStringAnalysisData& sad)
{
    if ( *(sad.string_size) == OPCUA_NULL_STRING_SIZE || *(sad.string_size) == 0 )
    {
        if ( sad.alert_on_null_string )
        {
            DetectionEngine::queue_event(GID_OPCUA, OPCUA_ABNORMAL_STRING);
        }
        *(sad.string_size) = 0;
    }

    if ( *(sad.string_size) > sad.max_string_size )
    {
        DetectionEngine::queue_event(GID_OPCUA, OPCUA_INVALID_STRING_SIZE);
        return false;
    }

    return validate_opcua_string_bounds(p, *(sad.string_size), sad.string_offset, sad.is_last_field);
}

static bool parse_msg_hel(Packet* p, OpcuaSessionData* ssn_data)
{
    ssn_data->msg_type = OPCUA_MSG_HEL;

    if ( !inspect_msg_size_field(p, OPCUA_HEL_MIN_SIZE) )
    {
        return false;
    }

    const OpcuaMsgTypeHel* hel = (const OpcuaMsgTypeHel*) p->data;

    if ( hel->protocol_version != OPCUA_PROTOCOL_VERSION_STANDARD )
    {
        DetectionEngine::queue_event(GID_OPCUA, OPCUA_ABNORMAL_PROTO_VERSION);
    }

    uint32_t hel_endpoint_url_size = hel->raw_endpoint_url_size;
    const uint32_t hel_endpoint_url_offset = sizeof(OpcuaMsgTypeHel);
    OpcuaStringAnalysisData endpoint_url_analysis_data = OpcuaStringAnalysisData {
        &hel_endpoint_url_size,             // pointer to the non-normalized string size
        hel_endpoint_url_offset,            // byte offset into the packet data where the string starts
        OPCUA_HEL_ENDPOINT_URL_MAX_SIZE,    // anything over 4096 bytes is considered invalid by the spec
        OPCUA_TRIGGER_NULL_STR_SIZE_ALERT,  // a null string here is not expected
        OPCUA_LAST_FIELD,                   // no further data is expected following this string
    };
    if ( !analyze_opcua_string(p, endpoint_url_analysis_data) )
    {
        return false;
    }

    return inspect_is_final_field(p, ssn_data);
}

static bool parse_msg_ack(Packet* p, OpcuaSessionData* ssn_data)
{
    ssn_data->msg_type = OPCUA_MSG_ACK;

    if ( !inspect_msg_size_field(p, OPCUA_ACK_MIN_SIZE) )
    {
        return false;
    }

    const uint32_t protocol_version_offset = sizeof(OpcuaHeader);
    uint32_t protocol_version = *(p->data + protocol_version_offset);
    protocol_version |= *(p->data + protocol_version_offset + 1) << 8;
    protocol_version |= *(p->data + protocol_version_offset + 2) << 16;
    protocol_version |= *(p->data + protocol_version_offset + 3) << 24;

    if ( protocol_version != OPCUA_PROTOCOL_VERSION_STANDARD )
    {
        DetectionEngine::queue_event(GID_OPCUA, OPCUA_ABNORMAL_PROTO_VERSION);
    }

    return inspect_is_final_field(p, ssn_data);
}

static bool parse_msg_err(Packet* p, OpcuaSessionData* ssn_data)
{
    ssn_data->msg_type = OPCUA_MSG_ERR;

    if ( !inspect_msg_size_field(p, OPCUA_ERR_MIN_SIZE) )
    {
        return false;
    }

    const OpcuaMsgTypeErr* err = (const OpcuaMsgTypeErr*) p->data;

    uint32_t reason_size = err->raw_reason_size;
    const uint32_t opcua_err_reason_offset = sizeof(OpcuaMsgTypeErr);
    OpcuaStringAnalysisData reason_analysis_data = OpcuaStringAnalysisData {
        &reason_size,                         // pointer to the non-normalized string size
        opcua_err_reason_offset,              // byte offset into the packet data where the string starts
        OPCUA_ERR_REASON_MAX_SIZE,            // anything over 4096 bytes is considered invalid by the spec
        OPCUA_NO_ALERT,                       // a null string here is not abnormal or unexpected
        OPCUA_LAST_FIELD,                     // no further data is expected following this string
    };
    if ( !analyze_opcua_string(p, reason_analysis_data) )
    {
        return false;
    }

    return inspect_is_final_field(p, ssn_data);
}

static bool parse_msg_rhe(Packet* p, OpcuaSessionData* ssn_data)
{
    ssn_data->msg_type = OPCUA_MSG_RHE;

    if ( !inspect_msg_size_field(p, OPCUA_RHE_MIN_SIZE) )
    {
        return false;
    }

    const OpcuaMsgTypeRhe* rhe = (const OpcuaMsgTypeRhe*) p->data;

    uint32_t rhe_server_uri_size = rhe->raw_server_uri_size;
    const uint32_t opcua_rhe_server_uri_offset = sizeof(OpcuaMsgTypeRhe);
    OpcuaStringAnalysisData server_uri_analysis_data = OpcuaStringAnalysisData {
        &rhe_server_uri_size,                  // pointer to the non-normalized string size
        opcua_rhe_server_uri_offset,           // byte offset into the packet data where the string starts
        OPCUA_SERVER_URI_MAX_SIZE,             // anything over 4096 bytes is considered invalid by the spec
        OPCUA_TRIGGER_NULL_STR_SIZE_ALERT,     // a null string here is not expected
        OPCUA_NOT_LAST_FIELD,                  // more data is expected following this string
    };
    if ( !analyze_opcua_string(p, server_uri_analysis_data) )
    {
        return false;
    }

    const uint32_t rhe_endpoint_url_size_offset = sizeof(OpcuaMsgTypeRhe) + rhe_server_uri_size;
    if ( p->dsize < rhe_endpoint_url_size_offset + OPCUA_ENDPOINT_URL_SIZE_SIZE )
    {
        // fatal alert
        DetectionEngine::queue_event(GID_OPCUA, OPCUA_ABNORMAL_STRING);
        return false;
    }

    // extract the endpoint url size
    uint32_t rhe_endpoint_url_size = *(p->data + rhe_endpoint_url_size_offset);
    rhe_endpoint_url_size |= *(p->data + rhe_endpoint_url_size_offset + 1) << 8;
    rhe_endpoint_url_size |= *(p->data + rhe_endpoint_url_size_offset + 2) << 16;
    rhe_endpoint_url_size |= *(p->data + rhe_endpoint_url_size_offset + 3) << 24;

    const uint32_t rhe_endpoint_url_offset = rhe_endpoint_url_size_offset + OPCUA_ENDPOINT_URL_SIZE_SIZE;
    OpcuaStringAnalysisData endpoint_url_analysis_data = OpcuaStringAnalysisData {
        &rhe_endpoint_url_size,                // pointer to the non-normalized string size
        rhe_endpoint_url_offset,               // byte offset into the packet data where the string starts
        OPCUA_RHE_ENDPOINT_URL_MAX_SIZE,       // anything over 4096 bytes is considered invalid by the spec
        OPCUA_TRIGGER_NULL_STR_SIZE_ALERT,     // a null string here is not expected
        OPCUA_LAST_FIELD,                      // no additional data is expected following this string
    };

    if ( !analyze_opcua_string(p, endpoint_url_analysis_data) )
    {
        return false;
    }

    return inspect_is_final_field(p, ssn_data);
}

static bool parse_msg_opn(Packet* p, OpcuaSessionData* ssn_data)
{
    ssn_data->msg_type = OPCUA_MSG_OPN;

    if ( !inspect_msg_size_field(p, OPCUA_OPN_MIN_SIZE) )
    {
        return false;
    }

    const OpcuaMsgTypeOpn* opn = (const OpcuaMsgTypeOpn*) p->data;

    uint32_t opn_sec_policy_uri_size = opn->raw_sec_policy_uri_size;
    const uint32_t opn_sec_policy_uri_offset = sizeof(OpcuaMsgTypeOpn);
    OpcuaStringAnalysisData opn_sec_policy_uri_analysis_data = OpcuaStringAnalysisData {
        &opn_sec_policy_uri_size,              // pointer to the non-normalized string size
        opn_sec_policy_uri_offset,             // byte offset into the packet data where the string starts
        OPCUA_SECURITY_POLICY_URI_MAX_SIZE,    // anything over 255 bytes is considered invalid by the spec
        OPCUA_NO_ALERT,                        // a null string here is not abnormal or unexpected
        OPCUA_NOT_LAST_FIELD,                  // more data is expected following this string
    };
    if ( !analyze_opcua_string(p, opn_sec_policy_uri_analysis_data) )
    {
        return false;
    }

    const uint32_t opn_sender_cert_size_offset = sizeof(OpcuaMsgTypeOpn) + opn_sec_policy_uri_size;
    if ( p->dsize < opn_sender_cert_size_offset + OPCUA_SENDER_CERT_SIZE_SIZE )
    {
        // fatal alert
        DetectionEngine::queue_event(GID_OPCUA, OPCUA_ABNORMAL_STRING);
        return false;
    }

    // extract the sender certificate size
    uint32_t opn_sender_cert_size = *(p->data + opn_sender_cert_size_offset);
    opn_sender_cert_size |= *(p->data + opn_sender_cert_size_offset + 1) << 8;
    opn_sender_cert_size |= *(p->data + opn_sender_cert_size_offset + 2) << 16;
    opn_sender_cert_size |= *(p->data + opn_sender_cert_size_offset + 3) << 24;

    uint32_t reserved_opn_fields_size = OPCUA_OPN_MIN_SIZE + OPCUA_MINIMUM_BODY_SIZE + opn_sec_policy_uri_size;
    uint32_t max_sender_cert_size = opn->hdr.msg_size > reserved_opn_fields_size ? opn->hdr.msg_size - reserved_opn_fields_size : 0;

    const uint32_t opn_sender_cert_offset = opn_sender_cert_size_offset + OPCUA_SENDER_CERT_SIZE_SIZE;
    OpcuaStringAnalysisData endpoint_url_analysis_data = OpcuaStringAnalysisData {
        &opn_sender_cert_size,                 // pointer to the non-normalized string size
        opn_sender_cert_offset,                // byte offset into the packet data where the string starts
        max_sender_cert_size,                  // not a statically sized value, but must be contained within a single MessageChunk
        OPCUA_NO_ALERT,                        // a null string here is not abnormal or unexpected
        OPCUA_NOT_LAST_FIELD,                  // more data is expected following this string
    };
    if ( !analyze_opcua_string(p, endpoint_url_analysis_data) )
    {
        return false;
    }

    const uint32_t opn_receiver_cert_thumbprint_size_offset = opn_sender_cert_offset + opn_sender_cert_size;
    if ( p->dsize < opn_receiver_cert_thumbprint_size_offset + OPCUA_RECEIVER_CERT_THUMBPRINT_SIZE_SIZE )
    {
        DetectionEngine::queue_event(GID_OPCUA, OPCUA_ABNORMAL_STRING);
        return false;
    }

    uint32_t opn_receiver_cert_thumbprint_size = *(p->data + opn_receiver_cert_thumbprint_size_offset);
    opn_receiver_cert_thumbprint_size |= *(p->data + opn_receiver_cert_thumbprint_size_offset + 1) << 8;
    opn_receiver_cert_thumbprint_size |= *(p->data + opn_receiver_cert_thumbprint_size_offset + 2) << 16;
    opn_receiver_cert_thumbprint_size |= *(p->data + opn_receiver_cert_thumbprint_size_offset + 3) << 24;

    // - If encrypted: must be exactly 20 bytes. If not encrypted: 0 or -1
    // - Any other value is invalid per OPCUA specification
    opn_receiver_cert_thumbprint_size = opn_receiver_cert_thumbprint_size == OPCUA_NULL_STRING_SIZE ? 0 : opn_receiver_cert_thumbprint_size;
    if(opn_receiver_cert_thumbprint_size != 0 && opn_receiver_cert_thumbprint_size != OPCUA_OPN_RECEIVER_CERT_THUMBPRINT_SIZE)
    {
        DetectionEngine::queue_event(GID_OPCUA, OPCUA_INVALID_STRING_SIZE);
        return false;
    }

    const uint32_t opn_receiver_cert_thumbprint_offset = opn_receiver_cert_thumbprint_size_offset + OPCUA_RECEIVER_CERT_THUMBPRINT_SIZE_SIZE;
    if ( !validate_opcua_string_bounds(p, opn_receiver_cert_thumbprint_size, opn_receiver_cert_thumbprint_offset, OPCUA_NOT_LAST_FIELD) )
    {
        return false;
    }

    return inspect_is_final_field(p, ssn_data);
}

static bool parse_msg_msg(Packet* p, OpcuaSessionData* ssn_data)
{
    ssn_data->msg_type = OPCUA_MSG_MSG;

    if ( !inspect_msg_size_field(p, OPCUA_MSG_MIN_SIZE) )
    {
        return false;
    }

    // since the isFinal field means something for type MSG we care about
    // the return code in this instance. when a failure case is returned
    // the inspector will not know how to process the message and as
    // such should bail
    if ( !inspect_is_final_field(p, ssn_data) )
    {
        // applicable builtin alerts thrown during the inspection routine
        return false;
    }

    if ( ssn_data->is_complete_msg )
    {
        if ( ssn_data->chunk_data_len < OPCUA_TYPEID_ENCODING_MASK_SIZE + OPCUA_TYPEID_NAMESPACE_INDEX_SIZE + OPCUA_TYPEID_NODE_ID_SIZE )
        {
            DetectionEngine::queue_event(GID_OPCUA, OPCUA_BAD_TYPEID_ENCODING);
            return false;
        }

        if ( ssn_data->chunk_data[0] == OPCUA_TYPEID_ENCODING_FOUR_BYTES_ENCODED_NUMERIC )
        {
            ssn_data->node_namespace_index = ssn_data->chunk_data[OPCUA_TYPEID_ENCODING_MASK_SIZE];
            if ( ssn_data->node_namespace_index != OPCUA_DEFAULT_NAMESPACE_INDEX )
            {
                DetectionEngine::queue_event(GID_OPCUA, OPCUA_NONZERO_NAMESPACE_INDEX_MSG);
            }

            const uint32_t opcua_typeid_node_id_idx_lo = OPCUA_TYPEID_ENCODING_MASK_SIZE + OPCUA_TYPEID_NAMESPACE_INDEX_SIZE;
            const uint32_t opcua_typeid_node_id_idx_hi = opcua_typeid_node_id_idx_lo + 1;
            uint32_t msg_service = ssn_data->chunk_data[opcua_typeid_node_id_idx_lo];
            msg_service |= ssn_data->chunk_data[opcua_typeid_node_id_idx_hi] << 8;
            ssn_data->node_id = (OpcuaMsgServiceType) msg_service;
        }

        ssn_data->is_chunked = false;
    }
    ssn_data->is_complete_msg = false;

    return true;
}

static bool parse_msg_clo(Packet* p, OpcuaSessionData* ssn_data)
{
    ssn_data->msg_type = OPCUA_MSG_CLO;

    if ( !inspect_msg_size_field(p, OPCUA_CLO_MIN_SIZE) )
    {
        // applicable builtin alerts thrown during the inspection routine
        return false;
    }

    return inspect_is_final_field(p, ssn_data);
}

bool opcua_decode(Packet* p, OpcuaFlowData* opcuafd)
{
    if (p->dsize < OPCUA_HEADER_MIN_SIZE)
    {
        DetectionEngine::queue_event(GID_OPCUA, OPCUA_BAD_MSG_SIZE);
        return false;
    }

    OpcuaPacketDataDirectionType direction;
    if ( p->is_from_client() )
    {
        direction = OPCUA_PACKET_DATA_DIRECTION_CLIENT;
    }
    else if ( p->is_from_server() )
    {
        direction = OPCUA_PACKET_DATA_DIRECTION_SERVER;
    }
    else
    {
        return false;
    }

    OpcuaSessionData* ssn_data = opcuafd->get_ssn_data_by_direction(direction);
    if ( ssn_data == nullptr )
    {
        return false;
    }

    const OpcuaHeader* hdr = (const OpcuaHeader*) p->data;

    bool parse_result = false;

    uint32_t msg_key = make_opcua_msg_key(hdr->msg_type[0], hdr->msg_type[1], hdr->msg_type[2]);
    
    auto it = opcua_msg_parsers.find(msg_key);
    if (it != opcua_msg_parsers.end())
    {
        parse_result = it->second(p, ssn_data);
    }
    else
    {
        DetectionEngine::queue_event(GID_OPCUA, OPCUA_BAD_MSG_TYPE);
        parse_result = false;
    }

    if ( !parse_result )
    {
        opcua_stats.inspector_aborts++;
    }

    return parse_result;
}


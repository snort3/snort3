//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// rule_api.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <string>
#include "rule_states/rule_api.h"
#include "helpers/s2l_util.h"
#include "helpers/converter.h"

namespace rules
{
extern const ConvertMap* ack_map;
extern const ConvertMap* activated_by_map;
extern const ConvertMap* activates_map;
extern const ConvertMap* appid_map;
extern const ConvertMap* asn1_map;
extern const ConvertMap* base64_data_map;
extern const ConvertMap* base64_decode_map;
extern const ConvertMap* byte_extract_map;
extern const ConvertMap* byte_jump_map;
extern const ConvertMap* byte_math_map;
extern const ConvertMap* byte_test_map;
extern const ConvertMap* classtype_map;
extern const ConvertMap* content_map;
extern const ConvertMap* count_map;
extern const ConvertMap* cvs_map;
extern const ConvertMap* dce_iface_map;
extern const ConvertMap* dce_opnum_map;
extern const ConvertMap* dce_stub_data_map;
extern const ConvertMap* detection_filter_map;
extern const ConvertMap* dnp3_data_map;
extern const ConvertMap* dnp3_func_map;
extern const ConvertMap* dnp3_ind_map;
extern const ConvertMap* dnp3_obj_map;
extern const ConvertMap* dsize_map;
extern const ConvertMap* file_data_map;
extern const ConvertMap* file_type_map;
extern const ConvertMap* flags_map;
extern const ConvertMap* flowbits_map;
extern const ConvertMap* flow_map;
extern const ConvertMap* fragbits_map;
extern const ConvertMap* fragoffset_map;
extern const ConvertMap* ftpbounce_map;
extern const ConvertMap* gid_map;
extern const ConvertMap* gtp_info_map;
extern const ConvertMap* gtp_type_map;
extern const ConvertMap* gtp_version_map;
extern const ConvertMap* http_encode_map;
extern const ConvertMap* icmp_id_map;
extern const ConvertMap* icmp_seq_map;
extern const ConvertMap* icode_map;
extern const ConvertMap* id_map;
extern const ConvertMap* ipopts_map;
extern const ConvertMap* ip_proto_map;
extern const ConvertMap* isdataat_map;
extern const ConvertMap* itype_map;
extern const ConvertMap* logto_map;
extern const ConvertMap* metadata_map;
extern const ConvertMap* modbus_data_map;
extern const ConvertMap* modbus_func_map;
extern const ConvertMap* modbus_unit_map;
extern const ConvertMap* msg_map;
extern const ConvertMap* pcre_map;
extern const ConvertMap* pkt_data_map;
extern const ConvertMap* priority_map;
extern const ConvertMap* protected_content_map;
extern const ConvertMap* react_map;
extern const ConvertMap* reference_map;
extern const ConvertMap* replace_map;
extern const ConvertMap* resp_map;
extern const ConvertMap* rev_map;
extern const ConvertMap* rpc_map;
extern const ConvertMap* sameip_map;
extern const ConvertMap* sd_pattern_map;
extern const ConvertMap* seq_map;
extern const ConvertMap* session_map;
extern const ConvertMap* sid_map;
extern const ConvertMap* sip_body_map;
extern const ConvertMap* sip_header_map;
extern const ConvertMap* sip_method_map;
extern const ConvertMap* sip_stat_code_map;
extern const ConvertMap* ssl_state_map;
extern const ConvertMap* ssl_version_map;
extern const ConvertMap* stream_reassemble_map;
extern const ConvertMap* stream_size_map;
extern const ConvertMap* tag_map;
extern const ConvertMap* threshold_map;
extern const ConvertMap* tos_map;
extern const ConvertMap* ttl_map;
extern const ConvertMap* uricontent_map;
extern const ConvertMap* urilen_map;
extern const ConvertMap* window_map;

const std::vector<const ConvertMap*> rule_options_api =
{
    ack_map,
    activated_by_map,
    activates_map,
    appid_map,
    asn1_map,
    base64_data_map,
    base64_decode_map,
    byte_extract_map,
    byte_jump_map,
    byte_math_map,
    byte_test_map,
    classtype_map,
    content_map,
    count_map,
    cvs_map,
    dce_iface_map,
    dce_opnum_map,
    dce_stub_data_map,
    detection_filter_map,
    dnp3_data_map,
    dnp3_func_map,
    dnp3_ind_map,
    dnp3_obj_map,
    dsize_map,
    file_data_map,
    file_type_map,
    flags_map,
    flowbits_map,
    flow_map,
    fragbits_map,
    fragoffset_map,
    ftpbounce_map,
    gid_map,
    gtp_info_map,
    gtp_type_map,
    gtp_version_map,
    http_encode_map,
    icmp_id_map,
    icmp_seq_map,
    icode_map,
    id_map,
    ipopts_map,
    ip_proto_map,
    isdataat_map,
    itype_map,
    logto_map,
    metadata_map,
    modbus_data_map,
    modbus_func_map,
    modbus_unit_map,
    msg_map,
    pcre_map,
    pkt_data_map,
    priority_map,
    protected_content_map,
    react_map,
    reference_map,
    replace_map,
    resp_map,
    rev_map,
    rpc_map,
    sameip_map,
    sd_pattern_map,
    seq_map,
    session_map,
    sid_map,
    sip_body_map,
    sip_header_map,
    sip_method_map,
    sip_stat_code_map,
    ssl_state_map,
    ssl_version_map,
    stream_reassemble_map,
    stream_size_map,
    tag_map,
    threshold_map,
    tos_map,
    ttl_map,
    uricontent_map,
    urilen_map,
    window_map,
};
} // namespace rules


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
// rule_content.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "rule_states/rule_api.h"
#include "helpers/s2l_util.h"

namespace rules
{
/*
 *  To use this template, declared an 'unchanged_rule_ctor<rule_name>'
 *  in the ConvertMap struct.  Everything else will be taken care of and
 *  all of the data between two semicolons will be placed in the new rule AS IS!!
 *  Examples are below the line marked 'FINISHED TEMPLATES'.
 */

template<const std::string* rule_name, bool has_suboptions>
class UnchangedRuleOption : public ConversionState
{
public:
    UnchangedRuleOption(Converter& c) : ConversionState(c) { }

    bool convert(std::istringstream& stream) override
    {
        if (has_suboptions)
        {
            std::string val = util::get_rule_option_args(stream);
            rule_api.add_option(*rule_name, val);
        }
        else
        {
            rule_api.add_option(*rule_name);
        }

        return set_next_rule_state(stream);
    }
};

template<const std::string* rule_name,  bool has_suboptions = true>
static ConversionState* unchanged_rule_ctor(Converter& c)
{
    return new UnchangedRuleOption<rule_name, has_suboptions>(c);
}

/****************************************
 *******   FINISHED TEMPLATES ***********
 ****************************************/

/************************************
 **********  M S G ******************
 ************************************/

static const std::string msg = "msg";
static const ConvertMap rule_msg =
{
    msg,
    unchanged_rule_ctor<& msg>,
};

const ConvertMap* msg_map = &rule_msg;

/************************************
 **********  R E V  *****************
 ************************************/

static const std::string rev = "rev";
static const ConvertMap rule_rev =
{
    rev,
    unchanged_rule_ctor<& rev>,
};

const ConvertMap* rev_map = &rule_rev;

/************************************
 ********  REFERENCE  ***************
 ************************************/

static const std::string reference = "reference";
static const ConvertMap rule_reference =
{
    reference,
    unchanged_rule_ctor<& reference>,
};

const ConvertMap* reference_map = &rule_reference;

/************************************
 **********  CLASSTYPE  *************
 ************************************/

static const std::string classtype = "classtype";
static const ConvertMap rule_classtype =
{
    classtype,
    unchanged_rule_ctor<& classtype>,
};

const ConvertMap* classtype_map = &rule_classtype;

/************************************
 **********  F L O W  ***************
 ************************************/

static const std::string flow = "flow";
static const ConvertMap rule_flow =
{
    flow,
    unchanged_rule_ctor<& flow>,
};

const ConvertMap* flow_map = &rule_flow;

/************************************
 **********  FLOWBITS  **************
 ************************************/

static const std::string flowbits = "flowbits";
static const ConvertMap rule_flowbits =
{
    flowbits,
    unchanged_rule_ctor<& flowbits>,
};

const ConvertMap* flowbits_map = &rule_flowbits;

/************************************
 ************  FRABGITS  ************
 ************************************/

static const std::string fragbits = "fragbits";
static const ConvertMap rule_fragbits =
{
    fragbits,
    unchanged_rule_ctor<& fragbits>,
};

const ConvertMap* fragbits_map = &rule_fragbits;

/************************************
 *********  F L A G S  **************
 ************************************/

static const std::string flags = "flags";
static const ConvertMap rule_flags =
{
    flags,
    unchanged_rule_ctor<& flags>,
};

const ConvertMap* flags_map = &rule_flags;

/************************************
 *********  FRAGOFFSET **************
 ************************************/

static const std::string fragoffset = "fragoffset";
static const ConvertMap rule_fragoffset =
{
    fragoffset,
    unchanged_rule_ctor<& fragoffset>,
};

const ConvertMap* fragoffset_map = &rule_fragoffset;

/************************************
 ************* T O S ****************
 ************************************/

static const std::string tos = "tos";
static const ConvertMap rule_tos =
{
    tos,
    unchanged_rule_ctor<& tos>,
};

const ConvertMap* tos_map = &rule_tos;

/************************************
 *************  I D  ****************
 ************************************/

static const std::string id = "id";
static const ConvertMap rule_id =
{
    id,
    unchanged_rule_ctor<& id>,
};

const ConvertMap* id_map = &rule_id;

/************************************
 ***********  IPOPTS  ***************
 ************************************/

static const std::string ipopts = "ipopts";
static const ConvertMap rule_ipopts =
{
    ipopts,
    unchanged_rule_ctor<& ipopts>,
};

const ConvertMap* ipopts_map = &rule_ipopts;

/************************************
 ************  S E Q  ***************
 ************************************/

static const std::string seq = "seq";
static const ConvertMap rule_seq =
{
    seq,
    unchanged_rule_ctor<& seq>,
};

const ConvertMap* seq_map = &rule_seq;

/************************************
 ************  A C K  ***************
 ************************************/

static const std::string ack = "ack";
static const ConvertMap rule_ack =
{
    ack,
    unchanged_rule_ctor<& ack>,
};

const ConvertMap* ack_map = &rule_ack;

/************************************
 ***********  WINDOW  ***************
 ************************************/

static const std::string window = "window";
static const ConvertMap rule_window =
{
    window,
    unchanged_rule_ctor<& window>,
};

const ConvertMap* window_map = &rule_window;

/************************************
 ************  ITYPE  ***************
 ************************************/

static const std::string itype = "itype";
static const ConvertMap rule_itype =
{
    itype,
    unchanged_rule_ctor<& itype>,
};

const ConvertMap* itype_map = &rule_itype;

/************************************
 ************  ICODE  ***************
 ************************************/

static const std::string icode = "icode";
static const ConvertMap rule_icode =
{
    icode,
    unchanged_rule_ctor<& icode>,
};

const ConvertMap* icode_map = &rule_icode;

/************************************
 ************ ICMP_ID ***************
 ************************************/

static const std::string icmp_id = "icmp_id";
static const ConvertMap rule_icmp_id =
{
    icmp_id,
    unchanged_rule_ctor<& icmp_id>,
};

const ConvertMap* icmp_id_map = &rule_icmp_id;

/************************************
 ***********  ICMP_SEQ  *************
 ************************************/

static const std::string icmp_seq = "icmp_seq";
static const ConvertMap rule_icmp_seq =
{
    icmp_seq,
    unchanged_rule_ctor<& icmp_seq>,
};

const ConvertMap* icmp_seq_map = &rule_icmp_seq;

/************************************
 *************  R P C  **************
 ************************************/

static const std::string rpc = "rpc";
static const ConvertMap rule_rpc =
{
    rpc,
    unchanged_rule_ctor<& rpc>,
};

const ConvertMap* rpc_map = &rule_rpc;

/************************************
 ***********  IP_PROTO  *************
 ************************************/

static const std::string ip_proto = "ip_proto";
static const ConvertMap rule_ip_proto =
{
    ip_proto,
    unchanged_rule_ctor<& ip_proto>,
};

const ConvertMap* ip_proto_map = &rule_ip_proto;

/************************************
 *************  SESSION  ************
 ************************************/

static const std::string session = "session";
static const ConvertMap rule_session =
{
    session,
    unchanged_rule_ctor<& session>,
};

const ConvertMap* session_map = &rule_session;

/************************************
 ************* REPLACE  *************
 ************************************/

static const std::string replace = "replace";
static const ConvertMap rule_replace =
{
    replace,
    unchanged_rule_ctor<& replace>,
};

const ConvertMap* replace_map = &rule_replace;

/************************************
 ******* DETECTION_FILETER  *********
 ************************************/

static const std::string detection_filter = "detection_filter";
static const ConvertMap rule_detection_filter =
{
    detection_filter,
    unchanged_rule_ctor<& detection_filter>,
};

const ConvertMap* detection_filter_map = &rule_detection_filter;

/************************************
 ***********  BYTE_TEST  ************
 ************************************/

static const std::string byte_test = "byte_test";
static const ConvertMap rule_byte_test =
{
    byte_test,
    unchanged_rule_ctor<& byte_test>,
};

const ConvertMap* byte_test_map = &rule_byte_test;

/************************************
 **********  BYTE_MATH  **********
 ************************************/

static const std::string byte_math = "byte_math";
static const ConvertMap rule_byte_math =
{
    byte_math,
    unchanged_rule_ctor<& byte_math>,
};

const ConvertMap* byte_math_map = &rule_byte_math;

/************************************
 ***********  BYTE_JUMP  ************
 ************************************/

static const std::string byte_jump = "byte_jump";
static const ConvertMap rule_byte_jump =
{
    byte_jump,
    unchanged_rule_ctor<& byte_jump>,
};

const ConvertMap* byte_jump_map = &rule_byte_jump;

/************************************
 **********  BYTE_EXTRACT  **********
 ************************************/

static const std::string byte_extract = "byte_extract";
static const ConvertMap rule_byte_extract =
{
    byte_extract,
    unchanged_rule_ctor<& byte_extract>,
};

const ConvertMap* byte_extract_map = &rule_byte_extract;

/************************************
 ************  GTP_INFO  ************
 ************************************/

static const std::string gtp_info = "gtp_info";
static const ConvertMap rule_gtp_info =
{
    gtp_info,
    unchanged_rule_ctor<& gtp_info>,
};

const ConvertMap* gtp_info_map = &rule_gtp_info;

/************************************
 ************  GTP_TYPE  ************
 ************************************/

static const std::string gtp_type = "gtp_type";
static const ConvertMap rule_gtp_type =
{
    gtp_type,
    unchanged_rule_ctor<& gtp_type>,
};

const ConvertMap* gtp_type_map = &rule_gtp_type;

/************************************
 **********  GTP_VERSION  ***********
 ************************************/

static const std::string gtp_version = "gtp_version";
static const ConvertMap rule_gtp_version =
{
    gtp_version,
    unchanged_rule_ctor<& gtp_version>,
};

const ConvertMap* gtp_version_map = &rule_gtp_version;

/************************************
 **********  MODBUS_DATA  ***********
 ************************************/

static const std::string modbus_data = "modbus_data";
static const ConvertMap rule_modbus_data =
{
    modbus_data,
    unchanged_rule_ctor<& modbus_data, false>,
};

const ConvertMap* modbus_data_map = &rule_modbus_data;

/************************************
 **********  MODBUS_FUNC  ***********
 ************************************/

static const std::string modbus_func = "modbus_func";
static const ConvertMap rule_modbus_func =
{
    modbus_func,
    unchanged_rule_ctor<& modbus_func>,
};

const ConvertMap* modbus_func_map = &rule_modbus_func;

/************************************
 **********  MODBUS_UNIT  ***********
 ************************************/

static const std::string modbus_unit = "modbus_unit";
static const ConvertMap rule_modbus_unit =
{
    modbus_unit,
    unchanged_rule_ctor<& modbus_unit>,
};

const ConvertMap* modbus_unit_map = &rule_modbus_unit;

/************************************
 ************  PKT_DATA  ************
 ************************************/

static const std::string pkt_data = "pkt_data";
static const ConvertMap rule_pkt_data =
{
    pkt_data,
    unchanged_rule_ctor<& pkt_data, false>,
};

const ConvertMap* pkt_data_map = &rule_pkt_data;

/************************************
 *************  CVS  ****************
 ************************************/

static const std::string cvs = "cvs";
static const ConvertMap rule_cvs =
{
    cvs,
    unchanged_rule_ctor<& cvs>,
};

const ConvertMap* cvs_map = &rule_cvs;

/************************************
 *********  BASE64_DATA  ************
 ************************************/

static const std::string base64_data = "base64_data";
static const ConvertMap rule_base64_data =
{
    base64_data,
    unchanged_rule_ctor<& base64_data, false>,
};

const ConvertMap* base64_data_map = &rule_base64_data;

/************************************
 *************  ASN1  ***************
 ************************************/

static const std::string asn1 = "asn1";
static const ConvertMap rule_asn1 =
{
    asn1,
    unchanged_rule_ctor<& asn1>,
};

const ConvertMap* asn1_map = &rule_asn1;

/************************************
 ***********  PRIORITY  *************
 ************************************/

static const std::string priority = "priority";
static const ConvertMap rule_priority =
{
    priority,
    unchanged_rule_ctor<& priority>,
};

const ConvertMap* priority_map = &rule_priority;

/************************************
 *******  SIP STAT CODE  ************
 ************************************/

static const std::string sip_stat_code = "sip_stat_code";
static const ConvertMap rule_sip_stat_code =
{
    sip_stat_code,
    unchanged_rule_ctor<& sip_stat_code>,
};

const ConvertMap* sip_stat_code_map = &rule_sip_stat_code;

/************************************
 *******  SIP BODY  ************
 ************************************/

static const std::string sip_body = "sip_body";
static const ConvertMap rule_sip_body =
{
    sip_body,
    unchanged_rule_ctor<& sip_body, false>,
};

const ConvertMap* sip_body_map = &rule_sip_body;

/************************************
 *******  SIP HEADER  ************
 ************************************/

static const std::string sip_header = "sip_header";
static const ConvertMap rule_sip_header =
{
    sip_header,
    unchanged_rule_ctor<& sip_header, false>,
};

const ConvertMap* sip_header_map = &rule_sip_header;

/************************************
 *******  SIP METHOD  ************
 ************************************/

static const std::string sip_method = "sip_method";
static const ConvertMap rule_sip_method =
{
    sip_method,
    unchanged_rule_ctor<& sip_method>,
};

const ConvertMap* sip_method_map = &rule_sip_method;

/************************************
 *********  SSL STATE  **************
 ************************************/

static const std::string ssl_state = "ssl_state";
static const ConvertMap rule_ssl_state =
{
    ssl_state,
    unchanged_rule_ctor<& ssl_state>,
};

const ConvertMap* ssl_state_map = &rule_ssl_state;

/************************************
 *********  SSL VERSION **************
 ************************************/

static const std::string ssl_version = "ssl_version";
static const ConvertMap rule_ssl_version =
{
    ssl_version,
    unchanged_rule_ctor<& ssl_version>,
};

const ConvertMap* ssl_version_map = &rule_ssl_version;

/************************************
 *******  DNP3 DATA  ************
 ************************************/

static const std::string dnp3_data = "dnp3_data";
static const ConvertMap rule_dnp3_data =
{
    dnp3_data,
    unchanged_rule_ctor<& dnp3_data, false>,
};

const ConvertMap* dnp3_data_map = &rule_dnp3_data;

/************************************
 *********  DNP3 FUNC **************
 ************************************/

static const std::string dnp3_func = "dnp3_func";
static const ConvertMap rule_dnp3_func =
{
    dnp3_func,
    unchanged_rule_ctor<& dnp3_func>,
};

const ConvertMap* dnp3_func_map = &rule_dnp3_func;

/************************************
 *********  DCE STUB DATA  **********
 ************************************/

static const std::string dce_stub_data = "dce_stub_data";
static const ConvertMap rule_dce_stub_data =
{
    dce_stub_data,
    unchanged_rule_ctor<& dce_stub_data, false>,
};

const ConvertMap* dce_stub_data_map = &rule_dce_stub_data;
} // namespace rule


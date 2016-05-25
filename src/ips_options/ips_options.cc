//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
// ips_options.cc author Russ Combs <rucombs@cisco.com>

#include "ips_options.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "framework/ips_option.h"

extern const BaseApi* ips_byte_extract;
extern const BaseApi* ips_classtype;
extern const BaseApi* ips_content;
extern const BaseApi* ips_detection_filter;
extern const BaseApi* ips_dsize;
extern const BaseApi* ips_file_data;
extern const BaseApi* ips_flow;
extern const BaseApi* ips_flowbits;
extern const BaseApi* ips_md5;
extern const BaseApi* ips_metadata;
extern const BaseApi* ips_pcre;
extern const BaseApi* ips_pkt_data;
extern const BaseApi* ips_reference;
#ifdef HAVE_HYPERSCAN
extern const BaseApi* ips_regex;
#endif
extern const BaseApi* ips_replace;
extern const BaseApi* ips_sha256;
extern const BaseApi* ips_sha512;
extern const BaseApi* ips_so;

#ifdef STATIC_IPS_OPTIONS
extern const BaseApi* ips_ack;
extern const BaseApi* ips_asn1;
extern const BaseApi* ips_base64_data;
extern const BaseApi* ips_base64_decode;
extern const BaseApi* ips_byte_jump;
extern const BaseApi* ips_byte_test;
extern const BaseApi* ips_cvs;
extern const BaseApi* ips_file_type;
extern const BaseApi* ips_flags;
extern const BaseApi* ips_fragbits;
extern const BaseApi* ips_fragoffset;
extern const BaseApi* ips_gid;
extern const BaseApi* ips_http_uri;
extern const BaseApi* ips_http_header;
extern const BaseApi* ips_http_client_body;
extern const BaseApi* ips_http_method;
extern const BaseApi* ips_http_cookie;
extern const BaseApi* ips_http_stat_code;
extern const BaseApi* ips_http_stat_msg;
extern const BaseApi* ips_http_raw_uri;
extern const BaseApi* ips_http_raw_header;
extern const BaseApi* ips_http_raw_cookie;
extern const BaseApi* ips_icmp_id;
extern const BaseApi* ips_icmp_seq;
extern const BaseApi* ips_icode;
extern const BaseApi* ips_id;
extern const BaseApi* ips_ipopts;
extern const BaseApi* ips_ip_proto;
extern const BaseApi* ips_isdataat;
extern const BaseApi* ips_itype;
extern const BaseApi* ips_msg;
extern const BaseApi* ips_priority;
extern const BaseApi* ips_raw_data;
extern const BaseApi* ips_rem;
extern const BaseApi* ips_rev;
extern const BaseApi* ips_rpc;
extern const BaseApi* ips_sd_pattern;
extern const BaseApi* ips_seq;
extern const BaseApi* ips_session;
extern const BaseApi* ips_sid;
extern const BaseApi* ips_soid;
extern const BaseApi* ips_tag;
extern const BaseApi* ips_tos;
extern const BaseApi* ips_ttl;
extern const BaseApi* ips_bufferlen;
extern const BaseApi* ips_window;
#endif

const BaseApi* ips_options[] =
{
    ips_byte_extract,
    ips_classtype,
    ips_content,
    ips_detection_filter,
    ips_dsize,
    ips_file_data,
    ips_flow,
    ips_flowbits,
    ips_md5,
    ips_metadata,
    ips_pcre,
    ips_pkt_data,
    ips_reference,
#ifdef HAVE_HYPERSCAN
    ips_regex,
#endif
    ips_replace,
    ips_sha256,
    ips_sha512,
    ips_so,

#ifdef STATIC_IPS_OPTIONS
    ips_ack,
    ips_asn1,
    ips_base64_data,
    ips_base64_decode,
    ips_byte_jump,
    ips_byte_test,
    ips_cvs,
    ips_file_type,
    ips_flags,
    ips_fragbits,
    ips_fragoffset,
    ips_gid,
    ips_http_uri,
    ips_http_header,
    ips_http_client_body,
    ips_http_method,
    ips_http_cookie,
    ips_http_stat_code,
    ips_http_stat_msg,
    ips_http_raw_uri,
    ips_http_raw_header,
    ips_http_raw_cookie,
    ips_icmp_id,
    ips_icmp_seq,
    ips_icode,
    ips_id,
    ips_ipopts,
    ips_ip_proto,
    ips_isdataat,
    ips_itype,
    ips_msg,
    ips_priority,
    ips_raw_data,
    ips_rem,
    ips_rev,
    ips_rpc,
    ips_sd_pattern,
    ips_seq,
    ips_session,
    ips_sid,
    ips_soid,
    ips_tag,
    ips_tos,
    ips_ttl,
    ips_bufferlen,
    ips_window,
#endif
    nullptr
};


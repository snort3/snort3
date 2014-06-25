/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2013-2013 Sourcefire, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include "ips_options.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "framework/ips_option.h"

extern const BaseApi* ips_byte_extract;
extern const BaseApi* ips_content;
extern const BaseApi* ips_file_data;
extern const BaseApi* ips_flow;
extern const BaseApi* ips_flowbits;
extern const BaseApi* ips_ip_proto;
extern const BaseApi* ips_pcre;
extern const BaseApi* ips_so;

#ifdef STATIC_IPS_OPTIONS
extern const BaseApi* ips_ack;
extern const BaseApi* ips_asn1;
extern const BaseApi* ips_base64_data;
extern const BaseApi* ips_base64_decode;
extern const BaseApi* ips_byte_jump;
extern const BaseApi* ips_byte_test;
extern const BaseApi* ips_cvs;
extern const BaseApi* ips_dsize;
extern const BaseApi* ips_flags;
extern const BaseApi* ips_fragbits;
extern const BaseApi* ips_fragoffset;
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
extern const BaseApi* ips_isdataat;
extern const BaseApi* ips_itype;
extern const BaseApi* ips_pkt_data;
extern const BaseApi* ips_raw_data;
extern const BaseApi* ips_react;
extern const BaseApi* ips_resp;
extern const BaseApi* ips_rpc;
extern const BaseApi* ips_sameip;
extern const BaseApi* ips_seq;
extern const BaseApi* ips_session;
extern const BaseApi* ips_tos;
extern const BaseApi* ips_ttl;
extern const BaseApi* ips_urilen;
extern const BaseApi* ips_window;
#endif

const BaseApi* ips_options[] =
{
    ips_byte_extract,
    ips_content,
    ips_file_data,
    ips_flow,
    ips_flowbits,
    ips_ip_proto,
    ips_pcre,
    ips_so,
#ifdef STATIC_IPS_OPTIONS
    ips_ack,
    ips_asn1,
    ips_base64_data,
    ips_base64_decode,
    ips_byte_jump,
    ips_byte_test,
    ips_cvs,
    ips_dsize,
    ips_flags,
    ips_fragbits,
    ips_fragoffset,
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
    ips_isdataat,
    ips_itype,
    ips_pkt_data,
    ips_raw_data,
    ips_react,
    ips_resp,
    ips_rpc,
    ips_sameip,
    ips_seq,
    ips_session,
    ips_tos,
    ips_ttl,
    ips_urilen,
    ips_window,
#endif
    nullptr
};


/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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
// nhttp_uri.h author Tom Peters <thopeter@cisco.com>

#ifndef NHTTP_URI_H
#define NHTTP_URI_H

#include "nhttp_scratch_pad.h"
#include "nhttp_str_to_code.h"
#include "nhttp_uri_norm.h"
#include "nhttp_field.h"

//-------------------------------------------------------------------------
// NHttpUri class
//-------------------------------------------------------------------------

class NHttpUri {
public:
    NHttpUri(const uint8_t* start, int32_t length, NHttpEnums::MethodId method) : uri(length, start), method_id(method),
       scratch_pad(2*length+200) {};
    const Field& get_uri() const { return uri; };
    NHttpEnums::UriType get_uri_type() { parse_uri(); return uri_type; };
    const Field& get_scheme() { parse_uri(); return scheme; };
    const Field& get_authority() { parse_uri(); return authority; };
    const Field& get_host() { parse_authority(); return host; };
    const Field& get_port() { parse_authority(); return port; };
    const Field& get_abs_path() { parse_uri(); return abs_path; };
    const Field& get_path() { parse_abs_path(); return path; };
    const Field& get_query() { parse_abs_path(); return query; };
    const Field& get_fragment() { parse_abs_path(); return fragment; };

    uint64_t get_format_infractions() { parse_uri(); return format_infractions; };
    uint64_t get_scheme_infractions() { get_scheme_id(); return scheme_infractions; };
    uint64_t get_host_infractions() { get_norm_host(); return host_infractions; };
    uint64_t get_port_infractions() { get_port_value(); return port_infractions; };
    uint64_t get_path_infractions() { get_norm_path(); return path_infractions; };
    uint64_t get_query_infractions() { get_norm_query(); return query_infractions; };
    uint64_t get_fragment_infractions() { get_norm_fragment(); return fragment_infractions; };
    uint64_t get_uri_infractions() { return get_format_infractions() | get_scheme_infractions() | get_host_infractions() |
       get_port_infractions() | get_path_infractions() | get_query_infractions() | get_fragment_infractions(); };

    NHttpEnums::SchemeId get_scheme_id();
    const Field& get_norm_host();
    int32_t get_port_value();
    const Field& get_norm_path();
    const Field& get_norm_query();
    const Field& get_norm_fragment();
    const Field& get_norm_legacy();

private:
    static const StrCode scheme_list[];

    const Field uri;
    const NHttpEnums::MethodId method_id;

    Field scheme;
    Field authority;
    Field host;
    Field port;
    Field abs_path;
    Field path;
    Field query;
    Field fragment;

    uint64_t format_infractions = 0;
    uint64_t scheme_infractions = 0;
    uint64_t host_infractions = 0;
    uint64_t port_infractions = 0;
    uint64_t path_infractions = 0;
    uint64_t query_infractions = 0;
    uint64_t fragment_infractions = 0;

    NHttpEnums::UriType uri_type = NHttpEnums::URI__NOTCOMPUTE;
    NHttpEnums::SchemeId scheme_id = NHttpEnums::SCH__NOTCOMPUTE;
    Field host_norm;
    int32_t port_value = NHttpEnums::STAT_NOTCOMPUTE;
    Field path_norm;
    Field query_norm;
    Field fragment_norm;
    Field legacy_norm;

    void parse_uri();
    void parse_authority();
    void parse_abs_path();

    ScratchPad scratch_pad;
};

#endif






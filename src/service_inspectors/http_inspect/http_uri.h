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
// http_uri.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP_URI_H
#define HTTP_URI_H

#include "http_str_to_code.h"
#include "http_module.h"
#include "http_uri_norm.h"
#include "http_field.h"
#include "http_infractions.h"
#include "http_event_gen.h"

//-------------------------------------------------------------------------
// HttpUri class
//-------------------------------------------------------------------------

class HttpUri
{
public:
    HttpUri(const uint8_t* start, int32_t length, HttpEnums::MethodId method_id_,
        const HttpParaList::UriParam& uri_param_, HttpInfractions* infractions_,
        HttpEventGen* events_) :
        uri(length, start), infractions(infractions_), events(events_), method_id(method_id_),
        uri_param(uri_param_)
        { normalize(); }
    const Field& get_uri() const { return uri; }
    HttpEnums::UriType get_uri_type() { return uri_type; }
    const Field& get_scheme() { return scheme; }
    const Field& get_authority() { return authority; }
    const Field& get_host() { return host; }
    const Field& get_port() { return port; }
    const Field& get_abs_path() { return abs_path; }
    const Field& get_path() { return path; }
    const Field& get_query() { return query; }
    const Field& get_fragment() { return fragment; }

    const Field& get_norm_host() { return host_norm; }
    const Field& get_norm_path() { return path_norm; }
    const Field& get_norm_query() { return query_norm; }
    const Field& get_norm_fragment() { return fragment_norm; }
    const Field& get_norm_classic() { return classic_norm; }
    size_t get_file_proc_hash();

private:
    const Field uri;

    Field scheme;
    Field authority;
    Field host;
    Field port;
    Field abs_path;
    Field path;
    Field query;
    Field fragment;

    Field host_norm;
    Field path_norm;
    Field query_norm;
    Field fragment_norm;
    Field classic_norm;
    HttpInfractions* const infractions;
    HttpEventGen* const events;
    size_t abs_path_hash = 0;
    HttpEnums::UriType uri_type = HttpEnums::URI__NOT_COMPUTE;
    const HttpEnums::MethodId method_id;
    const HttpParaList::UriParam& uri_param;

    void normalize();
    void parse_uri();
    void parse_authority();
    void parse_abs_path();

    void check_oversize_dir(Field&);
};

#endif


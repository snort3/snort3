//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
// nhttp_uri.h author Tom Peters <thopeter@cisco.com>

#ifndef NHTTP_URI_H
#define NHTTP_URI_H

#include "nhttp_scratch_pad.h"
#include "nhttp_str_to_code.h"
#include "nhttp_uri_norm.h"
#include "nhttp_field.h"
#include "nhttp_infractions.h"
#include "nhttp_event_gen.h"

//-------------------------------------------------------------------------
// NHttpUri class
//-------------------------------------------------------------------------

class NHttpUri
{
public:
    NHttpUri(const uint8_t* start, int32_t length, NHttpEnums::MethodId method,
        NHttpInfractions& infractions_, NHttpEventGen& events_) :
        uri(length, start), method_id(method), infractions(infractions_), events(events_),
        scratch_pad(2*length+200) { normalize(); }
    const Field& get_uri() const { return uri; }
    NHttpEnums::UriType get_uri_type() { return uri_type; }
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

private:
    const Field uri;
    const NHttpEnums::MethodId method_id;
    NHttpInfractions& infractions;
    NHttpEventGen& events;

    Field scheme;
    Field authority;
    Field host;
    Field port;
    Field abs_path;
    Field path;
    Field query;
    Field fragment;

    NHttpEnums::UriType uri_type = NHttpEnums::URI__NOT_COMPUTE;
    Field host_norm;
    Field path_norm;
    Field query_norm;
    Field fragment_norm;
    Field classic_norm;

    void normalize();
    void parse_uri();
    void parse_authority();
    void parse_abs_path();

    // FIXIT-P there is an enormous memory waste that this is always allocated. It is only needed
    // when the URI requires normalization. Most of the time the raw URI is already in normal form.
    ScratchPad scratch_pad;
};

#endif


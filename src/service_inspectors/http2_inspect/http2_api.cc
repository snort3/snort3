//--------------------------------------------------------------------------
// Copyright (C) 2018-2018 Cisco and/or its affiliates. All rights reserved.
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
// http2_api.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_api.h"

#include "http2_inspect.h"

using namespace snort;

const char* Http2Api::http2_my_name = HTTP2_NAME;
const char* Http2Api::http2_help = "the HTTP/2 inspector";

Inspector* Http2Api::http2_ctor(Module* mod)
{
    Http2Module* const http2_mod = (Http2Module*)mod;
    return new Http2Inspect(http2_mod->get_once_params());
}

const char* Http2Api::classic_buffer_names[] =
{
    "http2_frame_type",
    "http2_raw_frame",
    nullptr
};

const InspectApi Http2Api::http2_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        Http2Api::http2_my_name,
        Http2Api::http2_help,
        Http2Api::http2_mod_ctor,
        Http2Api::http2_mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__PDU,
    classic_buffer_names,
    "http2",
    Http2Api::http2_init,
    Http2Api::http2_term,
    nullptr,
    nullptr,
    Http2Api::http2_ctor,
    Http2Api::http2_dtor,
    nullptr,
    nullptr
};

extern const BaseApi* ips_http2_frame_header;
extern const BaseApi* ips_http2_frame_data;

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* sin_http2[] =
#endif
{
    &Http2Api::http2_api.base,
    ips_http2_frame_header,
    ips_http2_frame_data,
    nullptr
};


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
// http_api.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_api.h"

#include "http_inspect.h"

using namespace snort;

const char* HttpApi::http_my_name = HTTP_NAME;
const char* HttpApi::http_help = "the new HTTP inspector!";

Inspector* HttpApi::http_ctor(Module* mod)
{
    HttpModule* const http_mod = (HttpModule*)mod;
    return new HttpInspect(http_mod->get_once_params());
}

const char* HttpApi::classic_buffer_names[] =
{
    "http_client_body",
    "http_cookie",
    "http_header",
    "http_method",
    "http_raw_body",
    "http_raw_cookie",
    "http_raw_header",
    "http_raw_request",
    "http_raw_status",
    "http_raw_trailer",
    "http_raw_uri",
    "http_stat_code",
    "http_stat_msg",
    "http_trailer",
    "http_true_ip",
    "http_uri",
    "http_version",
    nullptr
};

const InspectApi HttpApi::http_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        HttpApi::http_my_name,
        HttpApi::http_help,
        HttpApi::http_mod_ctor,
        HttpApi::http_mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__PDU,
    classic_buffer_names,
    "http",
    HttpApi::http_init,
    HttpApi::http_term,
    nullptr,
    nullptr,
    HttpApi::http_ctor,
    HttpApi::http_dtor,
    nullptr,
    nullptr
};

extern const BaseApi* ips_http_client_body;
extern const BaseApi* ips_http_cookie;
extern const BaseApi* ips_http_header;
extern const BaseApi* ips_http_method;
extern const BaseApi* ips_http_raw_body;
extern const BaseApi* ips_http_raw_cookie;
extern const BaseApi* ips_http_raw_header;
extern const BaseApi* ips_http_raw_request;
extern const BaseApi* ips_http_raw_status;
extern const BaseApi* ips_http_raw_trailer;
extern const BaseApi* ips_http_raw_uri;
extern const BaseApi* ips_http_stat_code;
extern const BaseApi* ips_http_stat_msg;
extern const BaseApi* ips_http_trailer;
extern const BaseApi* ips_http_true_ip;
extern const BaseApi* ips_http_uri;
extern const BaseApi* ips_http_version;

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* sin_http[] =
#endif
{
    &HttpApi::http_api.base,
    ips_http_client_body,
    ips_http_cookie,
    ips_http_header,
    ips_http_method,
    ips_http_raw_body,
    ips_http_raw_cookie,
    ips_http_raw_header,
    ips_http_raw_request,
    ips_http_raw_status,
    ips_http_raw_trailer,
    ips_http_raw_uri,
    ips_http_stat_code,
    ips_http_stat_msg,
    ips_http_trailer,
    ips_http_true_ip,
    ips_http_uri,
    ips_http_version,
    nullptr
};


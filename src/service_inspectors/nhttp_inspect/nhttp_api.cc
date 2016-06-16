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
// nhttp_api.cc author Tom Peters <thopeter@cisco.com>

#include <string.h>
#include <sys/types.h>

#include "nhttp_enum.h"
#include "nhttp_inspect.h"
#include "nhttp_api.h"

const char* NHttpApi::nhttp_my_name = NHTTP_NAME;
const char* NHttpApi::nhttp_help = "the new HTTP inspector!";

Inspector* NHttpApi::nhttp_ctor(Module* mod)
{
    NHttpModule* const nhttp_mod = (NHttpModule*)mod;
    return new NHttpInspect(nhttp_mod->get_once_params());
}

const char* NHttpApi::classic_buffer_names[] =
{
    "http_client_body",
    "http_cookie",
    "http_header",
    "http_method",
    "http_raw_cookie",
    "http_raw_header",
    "http_raw_uri",
    "http_stat_code",
    "http_stat_msg",
    "http_uri",
    "http_version",
    "http_trailer",
    "http_raw_trailer",
    "http_raw_request",
    "http_raw_status",
    nullptr
};

const InspectApi NHttpApi::nhttp_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        NHttpApi::nhttp_my_name,
        NHttpApi::nhttp_help,
        NHttpApi::nhttp_mod_ctor,
        NHttpApi::nhttp_mod_dtor
    },
    IT_SERVICE,
    (uint16_t)PktType::PDU,
    classic_buffer_names,
    "http",
    NHttpApi::nhttp_init,
    NHttpApi::nhttp_term,
    NHttpApi::nhttp_tinit,
    NHttpApi::nhttp_tterm,
    NHttpApi::nhttp_ctor,
    NHttpApi::nhttp_dtor,
    nullptr,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &NHttpApi::nhttp_api.base,
    nullptr
};
#else
const BaseApi* sin_nhttp = &NHttpApi::nhttp_api.base;
#endif


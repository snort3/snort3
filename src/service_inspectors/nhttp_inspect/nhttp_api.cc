/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2003-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

//
//  @author     Tom Peters <thopeter@cisco.com>
//
//  @brief      API for NHttpInspect
//


#include <assert.h>
#include <string.h>
#include <sys/types.h>

#include "snort.h"
#include "target_based/sftarget_protocol_reference.h"
#include "nhttp_enum.h"
#include "nhttp_inspect.h"
#include "nhttp_api.h"

int16_t NHttpApi::appProtocolId;

const char* NHttpApi::nhttp_myName = "nhttp_inspect";

void NHttpApi::nhttp_init()
{
    NHttpFlowData::init();
    appProtocolId = AddProtocolReference("nhttp");
}

Inspector* NHttpApi::nhttp_ctor(Module* mod)
{
    const NHttpModule* nhttpMod = (NHttpModule*) mod;
    return new NHttpInspect(nhttpMod->get_test_input(), nhttpMod->get_test_output(), nhttpMod->get_test_inspect());
}

static const char* buffers[] =
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
    nullptr
};

const InspectApi NHttpApi::nhttp_api =
{
    {
        PT_INSPECTOR,
        NHttpApi::nhttp_myName,
        INSAPI_PLUGIN_V0,
        0,
        NHttpApi::nhttp_mod_ctor,
        NHttpApi::nhttp_mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__TCP,
    buffers,
    "http",
    NHttpApi::nhttp_init,
    NHttpApi::nhttp_term,
    NHttpApi::nhttp_ctor,
    NHttpApi::nhttp_dtor,
    NHttpApi::nhttp_pinit,
    NHttpApi::nhttp_pterm,
    nullptr,
    NHttpApi::nhttp_sum,
    NHttpApi::nhttp_stats,
    NHttpApi::nhttp_reset
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


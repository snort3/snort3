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
#include "framework/parameter.h"
#include "framework/module.h"
#include "framework/inspector.h"
#include "flow/flow.h"
#include "nhttp_enum.h"
#include "nhttp_flowdata.h"
#include "nhttp_scratchpad.h"
#include "nhttp_module.h"
#include "nhttp_strtocode.h"
#include "nhttp_headnorm.h"
#include "nhttp_msgheader.h"
#include "nhttp_testinput.h"
#include "nhttp_api.h"
#include "nhttp_inspect.h"

Module* NHttpApi::nhttp_mod_ctor() { return new NHttpModule; }

void NHttpApi::nhttp_mod_dtor(Module* m) { delete m; }

const char* NHttpApi::nhttp_myName = "nhttp_inspect";

void NHttpApi::nhttp_init()
{
    printf("nhttp_init()\n");
    NHttpFlowData::init();
}

void NHttpApi::nhttp_term()
{
    printf("nhttp_term()\n");
}

Inspector* NHttpApi::nhttp_ctor(Module* mod)
{
    const NHttpModule* nhttpMod = (NHttpModule*) mod;
    printf("nhttp_ctor()\n");
    return new NHttpInspect(nhttpMod->get_test_mode());
}

void NHttpApi::nhttp_dtor(Inspector* p)
{
    printf("nhttp_dtor()\n");
    delete p;
}

void NHttpApi::nhttp_pinit()
{
    printf("nhttp_pinit()\n");
    NHttpInspect::msgHead = new NHttpMsgHeader;
}

void NHttpApi::nhttp_pterm()
{
    printf("nhttp_pterm()\n");
    delete NHttpInspect::msgHead;
}

void NHttpApi::nhttp_sum()
{
    printf("nhttp_sum()\n");
}

void NHttpApi::nhttp_stats()
{
    printf("nhttp_stats()\n");
}

void NHttpApi::nhttp_reset()
{
    printf("nhttp_reset()\n");
}

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
    NHttpApi::nhttp_init,
    NHttpApi::nhttp_term,
    NHttpApi::nhttp_ctor,
    NHttpApi::nhttp_dtor,
    NHttpApi::nhttp_pinit,
    NHttpApi::nhttp_pterm,
    nullptr, // ssn
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


/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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
// sid_18758.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>

#include "main/snort_types.h"
#include "framework/so_rule.h"
#include "detection/detection_defines.h"
#include "sid_18758.h"

static constexpr unsigned crash_test_dummy = 18758;

static int eval(void* v, Packet* p)
{
    unsigned u = *((unsigned*)v);
    assert(u == crash_test_dummy);
    return p ? DETECTION_OPTION_MATCH : DETECTION_OPTION_NO_MATCH;
}

static SoEvalFunc ctor(const char* so, void** pv)
{
    assert(!strcmp(so, "eval"));
    *pv = new unsigned(crash_test_dummy);
    return eval;
}

static void dtor(void* v)
{
    unsigned* u = (unsigned*)v;
    assert(*u == crash_test_dummy);
    delete u;
}

static const SoApi so_api =
{
    {
        PT_SO_RULE,
        "3|18758",
        IPSAPI_PLUGIN_V0,
        8,
        nullptr,
        nullptr
    },
    sid_18758_gz,
    sid_18758_gz_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,
    dtor,
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &so_api.base,
    nullptr
};


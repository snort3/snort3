/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 ** Copyright (C) 1998-2013 Sourcefire, Inc.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#include "snort_types.h"
#include "snort_bounds.h"
#include "protocols/packet.h"
#include "parser.h"
#include "snort_debug.h"
#include "util.h"
#include "mstring.h"
#include "snort.h"
#include "profiler.h"
#include "fpdetect.h"
#include "detection/detection_defines.h"
#include "detection_util.h"
#include "framework/cursor.h"
#include "framework/ips_option.h"

static const char* s_name = "raw_data";

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats rawDataPerfStats;

static PreprocStats* pd_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &rawDataPerfStats;

    return nullptr;
}
#endif

class RawDataOption : public IpsOption
{
public:
    RawDataOption() : IpsOption(s_name) { };

    CursorActionType get_cursor_type() const
    { return CAT_SET_RAW; };

    int eval(Cursor&, Packet*);
};

int RawDataOption::eval(Cursor& c, Packet* p)
{
    PROFILE_VARS;
    PREPROC_PROFILE_START(rawDataPerfStats);

    c.set(s_name, p->data, p->dsize);

    PREPROC_PROFILE_END(rawDataPerfStats);
    return DETECTION_OPTION_MATCH;
}

static IpsOption* raw_data_ctor(
    SnortConfig*, char *data, OptTreeNode*)
{
    if (!IsEmptyStr(data))
        ParseError("raw_data takes no arguments");

    return new RawDataOption;
}

static void raw_data_dtor(IpsOption* p)
{
    delete p;
}

static void raw_data_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterOtnProfile(s_name, &rawDataPerfStats, pd_get_profile);
#endif
}

static const IpsApi raw_data_api =
{
    {
        PT_IPS_OPTION,
        s_name,
        IPSAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    OPT_TYPE_DETECTION,
    0, 0,
    raw_data_ginit,
    nullptr,
    nullptr,
    nullptr,
    raw_data_ctor,
    raw_data_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &raw_data_api.base,
    nullptr
};
#else
const BaseApi* ips_raw_data = &raw_data_api.base;
#endif


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

/* sp_base64_data
 *
 */

#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#include "snort_types.h"
#include "snort_bounds.h"
#include "decode.h"
#include "parser.h"
#include "snort_debug.h"
#include "util.h"
#include "mstring.h"
#include "snort.h"
#include "profiler.h"
#include "fpdetect.h"
#include "detection/detection_defines.h"
#include "detection/detection_util.h"
#include "framework/ips_option.h"

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats base64DataPerfStats;

static const char* s_name = "base64_data";

static PreprocStats* b64_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &base64DataPerfStats;

    return nullptr;
}
#endif

class Base64DataOption : public IpsOption
{
public:
    Base64DataOption() : IpsOption(s_name, RULE_OPTION_TYPE_BASE64_DATA) { };

    int eval(Packet*);
};

int Base64DataOption::eval(Packet *p)
{
    int rval = DETECTION_OPTION_NO_MATCH;
    PROFILE_VARS;

    PREPROC_PROFILE_START(base64DataPerfStats);

    if ((p->dsize == 0) || !base64_decode_size )
    {
        PREPROC_PROFILE_END(base64DataPerfStats);
        return rval;
    }

    SetDoePtr(base64_decode_buf, DOE_BUF_STD);
    SetAltDetect(base64_decode_buf, (uint16_t)base64_decode_size);
    rval = DETECTION_OPTION_MATCH;

    PREPROC_PROFILE_END(base64DataPerfStats);
    return rval;
}

static class IpsOption* base64_data_ctor(
    SnortConfig*, char *data, OptTreeNode *otn)
{
    // FIXIT change base64_data to suboption of base64_decode
    if ( !otn_has_plugin(otn, RULE_OPTION_TYPE_BASE64_DECODE) )
        ParseError("base64_decode needs to be specified before base64_data in a rule");

    if ( !IsEmptyStr(data) )
        ParseError("base64_data takes no arguments");

    return new Base64DataOption;
}

static void base64_data_dtor(IpsOption* p)
{
    delete p;
}

static void base64_data_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterOtnProfile(s_name, &base64DataPerfStats, b64_get_profile);
#endif
}

static const IpsApi base64_data_api =
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
    base64_data_ginit,
    nullptr,
    nullptr,
    nullptr,
    base64_data_ctor,
    base64_data_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &base64_data_api.base,
    nullptr
};
#else
const BaseApi* ips_base64_data = &base64_data_api.base;
#endif


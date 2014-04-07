/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 ** Copyright (C) 2005-2013 Sourcefire, Inc.
 ** Author: Steven Sturges
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

/* sp_ftpbounce
 *
 * Purpose:
 *      Checks the address listed (a,b,c,d format) in the packet
 *      against the source address.
 *
 *      does not update the doe_ptr
 *
 * Arguments:
 *      Required:
 *        None
 *      Optional:
 *        None
 *
 *   sample rules:
 *   alert tcp any any -> any 21 (content: "PORT"; \
 *       ftpbounce;
 *       msg: "FTP Bounce attack";)
 *
 * Effect:
 *
 *      Returns 1 if the address matches, 0 if it doesn't.
 *
 * Comments:
 *
 * Any comments?
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
#include "detection/treenodes.h"
#include "decode.h"
#include "parser.h"
#include "snort_debug.h"
#include "util.h"
#include "mstring.h"
#include "snort.h"
#include "profiler.h"
#include "detection/fpdetect.h"
#include "detection/detection_defines.h"
#include "detection_util.h"
#include "framework/ips_option.h"

static const char* s_name = "ftpbounce";

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats ftpBouncePerfStats;

static PreprocStats* ftpb_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &ftpBouncePerfStats;

    return nullptr;
}
#endif

class FtpBounceOption : public IpsOption
{
public:
    FtpBounceOption() : IpsOption(s_name) { };

    int eval(Packet*);
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

int FtpBounceOption::eval(Packet *p)
{
    uint32_t ip = 0;
    int octet=0;
    const uint8_t *this_param = doe_ptr;

    int dsize;
    const uint8_t *end_ptr, *start_ptr;
    PROFILE_VARS;

    if (!doe_ptr)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                    "[*] ftpbounce no doe_ptr set..\n"););
        return 0;
    }

    PREPROC_PROFILE_START(ftpBouncePerfStats);

    if (Is_DetectFlag(FLAG_ALT_DETECT))
    {
        dsize = DetectBuffer.len;
        start_ptr = DetectBuffer.data;
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
            "Using Alternative Detect buffer!\n"););
    }
    else if(Is_DetectFlag(FLAG_ALT_DECODE))
    {
        dsize = DecodeBuffer.len;
        start_ptr = DecodeBuffer.data;
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                "Using Alternative Decode buffer!\n"););
    }
    else
    {
        start_ptr = p->data;
        if(IsLimitedDetect(p))
            dsize = p->alt_dsize;
        else
            dsize = p->dsize;
    }

    DEBUG_WRAP(
            DebugMessage(DEBUG_PATTERN_MATCH,"[*] ftpbounce firing...\n");
            DebugMessage(DEBUG_PATTERN_MATCH,"payload starts at %p\n", start_ptr);
            );  /* END DEBUG_WRAP */

    /* save off whatever our ending pointer is */
    end_ptr = start_ptr + dsize;

    if(doe_ptr)
    {
        /* @todo: possibly degrade to use the other buffer, seems non-intuitive*/
        if(!inBounds(start_ptr, end_ptr, doe_ptr))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                    "[*] ftpbounce bounds check failed..\n"););
            PREPROC_PROFILE_END(ftpBouncePerfStats);
            return DETECTION_OPTION_NO_MATCH;
        }
    }

    while (isspace((int)*this_param) && (this_param < end_ptr)) this_param++;

    do
    {
        int value = 0;
        do
        {
            if (!isdigit((int)*this_param))
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                    "[*] ftpbounce non digit char failed..\n"););
                PREPROC_PROFILE_END(ftpBouncePerfStats);
                return DETECTION_OPTION_NO_MATCH;
            }
            value = value * 10 + (*this_param - '0');
            this_param++;
        } while ((this_param < end_ptr) &&
                 (*this_param != ',') &&
                  (!(isspace((int)*this_param))));
        if (value > 0xFF)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                "[*] ftpbounce value > 256 ..\n"););
            PREPROC_PROFILE_END(ftpBouncePerfStats);
            return DETECTION_OPTION_NO_MATCH;
        }
        if (octet  < 4)
        {
            ip = (ip << 8) + value;
        }

        if (!isspace((int)*this_param))
            this_param++;
        octet++;
    } while ((this_param < end_ptr) && !isspace((int)*this_param) && (octet < 4));

    if (octet < 4)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
            "[*] ftpbounce insufficient data ..\n"););
        PREPROC_PROFILE_END(ftpBouncePerfStats);
        return DETECTION_OPTION_NO_MATCH;
    }

    if ( ip != ntohl(GET_SRC_IP(p)->ip32[0]) )
    {
        PREPROC_PROFILE_END(ftpBouncePerfStats);
        return DETECTION_OPTION_MATCH;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
        "PORT command not being used in bounce\n"););
    PREPROC_PROFILE_END(ftpBouncePerfStats);
    return DETECTION_OPTION_NO_MATCH;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static IpsOption* ftpbounce_ctor(
    SnortConfig*, char *data, OptTreeNode*)
{
    if ( data )
        ParseError("Bad arguments to ftpbounce: %s\n", data);

    return new FtpBounceOption;
}

static void ftpbounce_dtor(IpsOption* p)
{
    delete p;
}

static void ftpbounce_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterOtnProfile(s_name, &ftpBouncePerfStats, ftpb_get_profile);
#endif
}

static const IpsApi ftpbounce_api =
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
    1, 0,
    ftpbounce_ginit,
    nullptr,
    nullptr,
    nullptr,
    ftpbounce_ctor,
    ftpbounce_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &ftpbounce_api.base,
    nullptr
};
#else
const BaseApi* ips_ftpbounce = &ftpbounce_api.base;
#endif


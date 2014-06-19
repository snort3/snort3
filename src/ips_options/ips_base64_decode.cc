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

/* sp_base64_decode
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
#include "protocols/packet.h"
#include "parser.h"
#include "snort_debug.h"
#include "util.h"
#include "mstring.h"
#include "snort.h"
#include "profiler.h"
#include "fpdetect.h"
#include "utils/sf_base64decode.h"
#include "detection/detection_defines.h"
#include "detection/detection_util.h"
#include "framework/ips_option.h"

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats base64DecodePerfStats;

static const char* s_name = "base64_decode";

static PreprocStats* b64dec_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &base64DecodePerfStats;

    return nullptr;
}
#endif

#define BASE64DECODE_RELATIVE_FLAG 0x01

typedef struct _Base64DecodeData
{
    uint32_t bytes_to_decode;
    uint32_t offset;
    uint8_t  flags;
}Base64DecodeData;

class Base64DecodeOption : public IpsOption
{
public:
    Base64DecodeOption(const Base64DecodeData& c) :
        IpsOption(s_name, RULE_OPTION_TYPE_BASE64_DECODE)
    { config = c; };

    ~Base64DecodeOption() { };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    int eval(Cursor&, Packet*);

private:
    Base64DecodeData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t Base64DecodeOption::hash() const
{
    uint32_t a,b,c;

    a = config.bytes_to_decode;
    b = config.offset;
    c = config.flags;

    mix(a,b,c);
    mix_str(a,b,c,get_name());

    final(a,b,c);

    return c;
}

bool Base64DecodeOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(s_name, ips.get_name()) )
        return false;

    Base64DecodeOption& rhs = (Base64DecodeOption&)ips;
    const Base64DecodeData *left = &config;
    const Base64DecodeData *right = &rhs.config;

    if ((left->bytes_to_decode == right->bytes_to_decode) &&
            ( left->offset == right->offset) &&
            ( left->flags == right->flags))
    {
        return true;
    }

    return false;
}

int Base64DecodeOption::eval(Cursor&, Packet *p)
{
    int rval = DETECTION_OPTION_NO_MATCH;
    const uint8_t *start_ptr = NULL;
    uint8_t base64_buf[DECODE_BLEN];
    uint32_t base64_size =0;
    Base64DecodeData *idx;
    PROFILE_VARS;

    PREPROC_PROFILE_START(base64DecodePerfStats);

    base64_decode_size = 0;

    if ((!p->dsize) || (!p->data))
    {
        PREPROC_PROFILE_END(base64DecodePerfStats);
        return rval;
    }

    idx = (Base64DecodeData *)&config;

    if(idx->flags & BASE64DECODE_RELATIVE_FLAG)
    {
        if(!doe_ptr)
        {
            start_ptr = p->data;
            start_ptr = start_ptr + idx->offset;
        }
        else
        {
            start_ptr = doe_ptr;
            start_ptr = start_ptr + idx->offset;
        }
    }
    else
    {
        start_ptr = p->data + idx->offset;
    }

    if(start_ptr > (p->data + p->dsize) )
    {
        PREPROC_PROFILE_END(base64DecodePerfStats);
        return rval;
    }

    if(sf_unfold_header(start_ptr, p->dsize, base64_buf, sizeof(base64_buf), &base64_size, 0, 0) != 0)
    {
        PREPROC_PROFILE_END(base64DecodePerfStats);
        return rval;
    }


    if (idx->bytes_to_decode && (base64_size > idx->bytes_to_decode))
    {
        base64_size = idx->bytes_to_decode;
    }

    if(sf_base64decode(base64_buf, base64_size, (uint8_t *)base64_decode_buf, sizeof(base64_decode_buf), &base64_decode_size) != 0)
    {
        PREPROC_PROFILE_END(base64DecodePerfStats);
        return rval;
    }

    PREPROC_PROFILE_END(base64DecodePerfStats);

    return DETECTION_OPTION_MATCH;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static void base64_decode_parse(char *data, Base64DecodeData *idx)
{
    char **toks;
    char **toks1;
    int num_toks;
    int num_toks1;
    char *token;
    int i=0;
    char *endptr;
    int value = 0;


    /*no arguments*/
    if (IsEmptyStr(data))
    {
        idx->offset = 0;
        idx->bytes_to_decode = 0;
        idx->flags = 0;
        return;
    }

    toks = mSplit(data, ",", 0, &num_toks, 0);

    if (num_toks > 3 )
    {
         ParseError("Bad arguments to base64_decode.");

    }

    while (i < num_toks )
    {
        token = toks[i];

        if( strcmp(token , "relative") == 0 )
        {
            idx->flags |= BASE64DECODE_RELATIVE_FLAG;
            i++;
            continue;
        }

        toks1 = mSplit(token, " \t", 0, &num_toks1, 0);

        if ( num_toks1 != 2 )
        {
            ParseError("Bad arguments to base64_decode.");
        }

        if( strcmp(toks1[0], "offset") == 0 )
        {
            value = SnortStrtol(toks1[1], &endptr, 10);
            if(*endptr || value < 0)
            {
                ParseError("Bad arguments to base64_decode.");
            }
            idx->offset = value;
        }
        else if( strcmp(toks1[0], "bytes") == 0 )
        {
            value = SnortStrtol(toks1[1], &endptr, 10);
            if(*endptr || (value < 0) )
            {
                ParseError("Bad arguments to base64_decode.");
            }

            if(!value)
            {
                ParseError("'bytes' option to base64_decode cannot be zero.");
            }
            idx->bytes_to_decode = value;
        }
        else
        {
            ParseError("Bad arguments to base64_decode.");
        }

        mSplitFree(&toks1,num_toks1);
        i++;
    }

    mSplitFree(&toks,num_toks);
    return;

}

static IpsOption* base64_decode_ctor(
    SnortConfig*, char *data, OptTreeNode*)
{
    Base64DecodeData idx;
    memset(&idx, 0, sizeof(idx));
    base64_decode_parse(data, &idx);
    return new Base64DecodeOption(idx);
}

static void base64_decode_dtor(IpsOption* p)
{
    delete p;
}

static void base64_decode_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterOtnProfile(s_name, &base64DecodePerfStats, b64dec_get_profile);
#endif
}

static const IpsApi base64_decode_api =
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
    base64_decode_ginit,
    nullptr,
    nullptr,
    nullptr,
    base64_decode_ctor,
    base64_decode_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &base64_decode_api.base,
    nullptr
};
#else
const BaseApi* ips_base64_decode = &base64_decode_api.base;
#endif


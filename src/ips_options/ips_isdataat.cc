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

/* sp_isdataat
 *
 * Purpose:
 *    Test a specific byte to see if there is data.  (Basicly, rule keyword
 *    into inBounds)
 *
 * Arguments:
 *    <int>         byte location to check if there is data
 *    ["relative"]  look for byte location relative to the end of the last
 *                  pattern match
 *    ["rawbytes"]  force use of the non-normalized buffer.
 *
 * Sample:
 *   alert tcp any any -> any 110 (msg:"POP3 user overflow"; \
 *      content:"USER"; isdataat:30,relative; content:!"|0a|"; within:30;)
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
#include "treenodes.h"
#include "protocols/packet.h"
#include "parser.h"
#include "snort_debug.h"
#include "util.h"
#include "mstring.h"
#include "snort.h"
#include "profiler.h"
#include "fpdetect.h"
#include "ips_byte_extract.h"
#include "sfhashfcn.h"
#include "detection/detection_defines.h"
#include "detection_util.h"
#include "framework/cursor.h"
#include "framework/ips_option.h"

static const char* s_name = "isdataat";

#ifdef PERF_PROFILING
static THREAD_LOCAL ProfileStats isDataAtPerfStats;

static ProfileStats* at_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &isDataAtPerfStats;

    return nullptr;
}
#endif

#define ISDATAAT_RELATIVE_FLAG 0x01
#define ISDATAAT_NOT_FLAG      0x02

typedef struct _IsDataAtData
{
    uint32_t offset;        /* byte location into the packet */
    uint8_t  flags;
    int8_t offset_var;      /* index of byte_extract variable for offset */
} IsDataAtData;

class IsDataAtOption : public IpsOption
{
public:
    IsDataAtOption(const IsDataAtData& c) :
        IpsOption(s_name)
    { config = c; };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    int eval(Cursor&, Packet*);

    IsDataAtData* get_data() 
    { return &config; };

    bool is_relative()
    { return (config.flags & ISDATAAT_RELATIVE_FLAG) != 0; };

private:
    IsDataAtData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t IsDataAtOption::hash() const
{
    uint32_t a,b,c;
    const IsDataAtData *data = &config;

    a = data->offset;
    b = data->flags;
    c = data->offset_var;

    mix(a,b,c);
    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool IsDataAtOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    IsDataAtOption& rhs = (IsDataAtOption&)ips;
    IsDataAtData *left = (IsDataAtData*)&config;
    IsDataAtData *right = (IsDataAtData*)&rhs.config;

    if (( left->offset == right->offset) &&
        ( left->flags == right->flags) &&
        ( left->offset_var == right->offset_var) )
    {
        return true;
    }

    return false;
}

int IsDataAtOption::eval(Cursor& c, Packet*)
{
    IsDataAtData *isdata = &config;
    int rval = DETECTION_OPTION_NO_MATCH;
    const uint8_t *base_ptr, *end_ptr, *start_ptr;
    int offset;

    PROFILE_VARS;
    PREPROC_PROFILE_START(isDataAtPerfStats);

    /* Get values from byte_extract variables, if present. */
    if (isdata->offset_var >= 0 && isdata->offset_var < NUM_BYTE_EXTRACT_VARS)
    {
        uint32_t value;
        GetByteExtractValue(&(value), isdata->offset_var);
        offset = (int)value;
    }
    else
        offset = isdata->offset;

    if ( isdata->flags & ISDATAAT_RELATIVE_FLAG )
    {
        start_ptr = c.start();
        end_ptr = start_ptr + c.length();
    }
    else
    {
        start_ptr = c.buffer();
        end_ptr = start_ptr + c.size();
    }
    base_ptr = start_ptr + offset;

    if(inBounds(start_ptr, end_ptr, base_ptr))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                    "[*] IsDataAt succeeded!  there is data...\n"););
        rval = DETECTION_OPTION_MATCH;
    }

    if (isdata->flags & ISDATAAT_NOT_FLAG)
    {
        rval = !rval;
    }

    /* otherwise dump */
    PREPROC_PROFILE_END(isDataAtPerfStats);
    return rval;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static void isdataat_parse(char *data, IsDataAtData *idx)
{
    char **toks;
    int num_toks;
    int i;
    char *cptr;
    char *endp;
    char *offset;

    toks = mSplit(data, ",", 3, &num_toks, 0);

    if(num_toks > 3)
        ParseError("Bad arguments to IsDataAt: %s", data);

    offset = toks[0];

    if(*offset == '!')
    {
        idx->flags |= ISDATAAT_NOT_FLAG;
        offset++;
        while(isspace((int)*offset)) {offset++;}
    }

    /* set how many bytes to process from the packet */
    if (isdigit(offset[0]) || offset[0] == '-')
    {
        idx->offset = strtol(offset, &endp, 10);
        idx->offset_var = -1;

        if(offset == endp)
        {
            ParseError("Unable to parse as byte value %s\n", toks[0]);
        }

        if(idx->offset > 65535)
        {
            ParseError("IsDataAt offset greater than max IPV4 packet size");
        }
    }
    else
    {
        idx->offset_var = GetVarByName(offset);
        if (idx->offset_var == BYTE_EXTRACT_NO_VAR)
        {
            ParseError("%s", BYTE_EXTRACT_INVALID_ERR_STR);
        }
    }

    for (i=1; i< num_toks; i++)
    {
        cptr = toks[i];

        while(isspace((int)*cptr)) {cptr++;}

        if(!strcasecmp(cptr, "relative"))
        {
            /* the offset is relative to the last pattern match */
            idx->flags |= ISDATAAT_RELATIVE_FLAG;
        }
        else
        {
            ParseError("unknown modifier '%s'", toks[1]);
        }
    }

    mSplitFree(&toks,num_toks);
}

static IpsOption* isdataat_ctor(
    SnortConfig*, char *data, OptTreeNode*)
{
    IsDataAtData idx;
    memset(&idx, 0, sizeof(idx));
    isdataat_parse(data, &idx);
    return new IsDataAtOption(idx);
}

static void isdataat_dtor(IpsOption* p)
{
    delete p;
}

static void isdataat_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterOtnProfile(s_name, at_get_profile);
#endif
}

static const IpsApi isdataat_api =
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
    isdataat_ginit,
    nullptr,
    nullptr,
    nullptr,
    isdataat_ctor,
    isdataat_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &isdataat_api.base,
    nullptr
};
#else
const BaseApi* ips_isdataat = &isdataat_api.base;
#endif


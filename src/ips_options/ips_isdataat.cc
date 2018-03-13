//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 1998-2013 Sourcefire, Inc.
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

/* sp_isdataat
 *
 * Purpose:
 *    Test a specific byte to see if there is data.  (Basically, rule keyword
 *    into inBounds)
 *
 * Arguments:
 *    <int>         byte location to check if there is data
 *    ["relative"]  look for byte location relative to the end of the last
 *                  pattern match
 *
 * Sample:
 *   alert tcp any any -> any 110 (msg:"POP3 user overflow"; \
 *      content:"USER"; isdataat:30,relative; content:!"|0a|"; within:30;)
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstdlib>

#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hashfcn.h"
#include "log/messages.h"
#include "parser/mstring.h"
#include "profiler/profiler.h"
#include "utils/snort_bounds.h"

#include "extract.h"

using namespace snort;

#define s_name "isdataat"

static THREAD_LOCAL ProfileStats isDataAtPerfStats;

#define ISDATAAT_RELATIVE_FLAG 0x01
#define ISDATAAT_NOT_FLAG      0x02

typedef struct _IsDataAtData
{
    uint32_t offset;        /* byte location into the packet */
    uint8_t flags;
    int8_t offset_var;      /* index of byte_extract variable for offset */
} IsDataAtData;

class IsDataAtOption : public IpsOption
{
public:
    IsDataAtOption(const IsDataAtData& c) :
        IpsOption(s_name)
    { config = c; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

    IsDataAtData* get_data()
    { return &config; }

    bool is_relative() override
    { return (config.flags & ISDATAAT_RELATIVE_FLAG) != 0; }

private:
    IsDataAtData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t IsDataAtOption::hash() const
{
    uint32_t a,b,c;
    const IsDataAtData* data = &config;

    a = data->offset;
    b = data->flags;
    c = data->offset_var;

    mix(a,b,c);
    mix_str(a,b,c,get_name());
    finalize(a,b,c);

    return c;
}

bool IsDataAtOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    const IsDataAtOption& rhs = (const IsDataAtOption&)ips;
    const IsDataAtData* left = &config;
    const IsDataAtData* right = &rhs.config;

    if (( left->offset == right->offset) &&
        ( left->flags == right->flags) &&
        ( left->offset_var == right->offset_var) )
    {
        return true;
    }

    return false;
}

IpsOption::EvalStatus IsDataAtOption::eval(Cursor& c, Packet*)
{
    Profile profile(isDataAtPerfStats);

    int offset;

    // Get values from byte_extract variables, if present.
    if (config.offset_var >= 0 && config.offset_var < NUM_IPS_OPTIONS_VARS)
    {
        uint32_t value;
        GetVarValueByIndex(&(value), config.offset_var);
        offset = (int)value;
    }
    else
        offset = config.offset;

    const uint8_t* start_ptr;
    if ( config.flags & ISDATAAT_RELATIVE_FLAG )
    {
        start_ptr = c.start();
    }
    else
    {
        start_ptr = c.buffer();
    }
    start_ptr += offset;
    EvalStatus rval = NO_MATCH;

    if (inBounds(c.buffer(), c.endo(), start_ptr))
        rval = MATCH;

    if (config.flags & ISDATAAT_NOT_FLAG)
        rval = (rval == MATCH) ? NO_MATCH : MATCH;

    // otherwise dump
    return rval;
}

//-------------------------------------------------------------------------
// parser
//-------------------------------------------------------------------------

static void isdataat_parse(const char* data, IsDataAtData* idx)
{
    char** toks;
    int num_toks;
    char* endp;
    char* offset;

    toks = mSplit(data, ",", 3, &num_toks, 0);
    offset = toks[0];

    if (*offset == '!')
    {
        idx->flags |= ISDATAAT_NOT_FLAG;
        offset++;
        while (isspace((int)*offset))
        {
            offset++;
        }
    }

    /* set how many bytes to process from the packet */
    if (isdigit(offset[0]) || offset[0] == '-')
    {
        idx->offset = strtol(offset, &endp, 10);
        idx->offset_var = -1;

        if (offset == endp)
        {
            ParseError("unable to parse as byte value %s", toks[0]);
            return;
        }

        if (idx->offset > 65535)
        {
            ParseError("isdataat offset greater than max IPV4 packet size");
            return;
        }
        idx->offset_var = IPS_OPTIONS_NO_VAR;
    }
    else
    {
        idx->offset_var = GetVarByName(offset);
        if (idx->offset_var == IPS_OPTIONS_NO_VAR)
        {
            ParseError(INVALID_VAR_ERR_STR, "isdataat offset", offset);
            return;
        }
    }

    mSplitFree(&toks,num_toks);
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~length", Parameter::PT_STRING, nullptr, nullptr,
      "num | !num" },

    { "relative", Parameter::PT_IMPLIED, nullptr, nullptr,
      "offset from cursor instead of start of buffer" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to check for the presence of payload data"

class IsDataAtModule : public Module
{
public:
    IsDataAtModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &isDataAtPerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    IsDataAtData data;
};

bool IsDataAtModule::begin(const char*, int, SnortConfig*)
{
    memset(&data, 0, sizeof(data));
    return true;
}

bool IsDataAtModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("~length") )
        isdataat_parse(v.get_string(), &data);

    else if ( v.is("relative") )
        data.flags |= ISDATAAT_RELATIVE_FLAG;

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new IsDataAtModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* isdataat_ctor(Module* p, OptTreeNode*)
{
    IsDataAtModule* m = (IsDataAtModule*)p;
    return new IsDataAtOption(m->data);
}

static void isdataat_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi isdataat_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, 0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    isdataat_ctor,
    isdataat_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_isdataat[] =
#endif
{
    &isdataat_api.base,
    nullptr
};


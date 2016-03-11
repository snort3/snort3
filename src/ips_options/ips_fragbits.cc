//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

/* Snort Detection Plugin Source File for IP Fragment Bits plugin */

/* sp_ip_fragbits
 *
 * Purpose:
 *
 * Check the fragmentation bits of the IP header for set values.  Possible
 * bits are don't fragment (DF), more fragments (MF), and reserved (RB).
 *
 * Arguments:
 *
 * The keyword to reference this plugin is "fragbits".  Possible arguments are
 * D, M and R for DF, MF and RB, respectively.
 *
 * Effect:
 *
 * Inidicates whether any of the specified bits have been set.
 *
 * Comments:
 *
 * Ofir Arkin should be a little happier now. :)
 *
 */

#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "protocols/packet.h"
#include "parser/parser.h"
#include "utils/util.h"
#include "profiler/profiler.h"
#include "hash/sfhashfcn.h"
#include "detection/treenodes.h"
#include "detection/detection_defines.h"
#include "framework/ips_option.h"
#include "framework/parameter.h"
#include "framework/module.h"

#define GREATER_THAN            1
#define LESS_THAN               2

#define FB_NORMAL   0
#define FB_ALL      1
#define FB_ANY      2
#define FB_NOT      3

#define FB_RB  0x8000
#define FB_DF  0x4000
#define FB_MF  0x2000

#define s_name "fragbits"

static THREAD_LOCAL ProfileStats fragBitsPerfStats;

typedef struct _FragBitsData
{
    char mode;
    uint16_t frag_bits;
} FragBitsData;

class FragBitsOption : public IpsOption
{
public:
    FragBitsOption(const FragBitsData& c) :
        IpsOption(s_name)
    { config = c; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    int eval(Cursor&, Packet*) override;

private:
    FragBitsData config;
};

static uint16_t bitmask = 0x0;

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

uint32_t FragBitsOption::hash() const
{
    uint32_t a,b,c;
    const FragBitsData* data = &config;

    a = data->mode;
    b = data->frag_bits;
    c = 0;

    mix_str(a,b,c,get_name());
    finalize(a,b,c);

    return c;
}

bool FragBitsOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    FragBitsOption& rhs = (FragBitsOption&)ips;
    FragBitsData* left = (FragBitsData*)&config;
    FragBitsData* right = (FragBitsData*)&rhs.config;

    if ((left->mode == right->mode) &&
        (left->frag_bits == right->frag_bits))
    {
        return true;
    }

    return false;
}

int FragBitsOption::eval(Cursor&, Packet* p)
{
    Profile profile(fragBitsPerfStats);

    FragBitsData* fb = &config;

    if ( !p->has_ip() )
        return DETECTION_OPTION_NO_MATCH;


    const uint16_t frag_offset = p->ptrs.ip_api.off_w_flags();


    DebugMessage(DEBUG_IPS_OPTION, "           <!!> CheckFragBits: ");
        DebugFormat(DEBUG_IPS_OPTION, "[rule: 0x%X:%d   pkt: 0x%X] ",
        fb->frag_bits, fb->mode, frag_offset & bitmask);

    switch (fb->mode)
    {
    case FB_NORMAL:
        /* check if the rule bits match the bits in the packet */
        if (fb->frag_bits == (frag_offset & bitmask))
        {
            DebugMessage(DEBUG_IPS_OPTION,"Got Normal bits match\n");
            return DETECTION_OPTION_MATCH;
        }
        else
        {
            DebugMessage(DEBUG_IPS_OPTION,"Normal test failed\n");
        }

        break;

    case FB_NOT:
        /* check if the rule bits don't match the bits in the packet */
        if ((fb->frag_bits & (frag_offset & bitmask)) == 0)
        {
            DebugMessage(DEBUG_IPS_OPTION,"Got NOT bits match\n");
            return DETECTION_OPTION_MATCH;
        }
        else
        {
            DebugMessage(DEBUG_IPS_OPTION,"NOT test failed\n");
        }
        break;

    case FB_ALL:
        /* check if the rule bits are present in the packet */
        if ((fb->frag_bits & (frag_offset & bitmask)) == fb->frag_bits)
        {
            DebugMessage(DEBUG_IPS_OPTION,"Got ALL bits match\n");
            return DETECTION_OPTION_MATCH;
        }
        else
        {
            DebugMessage(DEBUG_IPS_OPTION,"ALL test failed\n");
        }
        break;

    case FB_ANY:
        /* check if any of the rule bits match the bits in the packet */
        if ((fb->frag_bits & (frag_offset & bitmask)) != 0)
        {
            DebugMessage(DEBUG_IPS_OPTION,"Got ANY bits match\n");
            return DETECTION_OPTION_MATCH;
        }
        else
        {
            DebugMessage(DEBUG_IPS_OPTION,"ANY test failed\n");
        }
        break;

    default:
        break;
    }

    /* if the test isn't successful, this function *must* return 0 */
    return DETECTION_OPTION_NO_MATCH;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static void fragbits_parse(const char* data, FragBitsData* ds_ptr)
{
    const char* fptr;
    const char* fend;

    /* manipulate the option arguments here */
    fptr = data;

    while (isspace((u_char) *fptr))
    {
        fptr++;
    }

    if (strlen(fptr) == 0)
    {
        ParseError("no arguments to the fragbits keyword");
        return;
    }

    fend = fptr + strlen(fptr);

    ds_ptr->mode = FB_NORMAL;  /* default value */

    while (fptr < fend)
    {
        switch ((*fptr&0xFF))
        {
        case 'd':
        case 'D':     /* don't frag bit */
            ds_ptr->frag_bits |= FB_DF;
            break;

        case 'm':
        case 'M':     /* more frags bit */
            ds_ptr->frag_bits |= FB_MF;
            break;

        case 'r':
        case 'R':     /* reserved bit */
            ds_ptr->frag_bits |= FB_RB;
            break;

        case '!':     /* NOT flag, fire if flags are not set */
            ds_ptr->mode = FB_NOT;
            break;

        case '*':     /* ANY flag, fire on any of these bits */
            ds_ptr->mode = FB_ANY;
            break;

        case '+':     /* ALL flag, fire on these bits plus any others */
            ds_ptr->mode = FB_ALL;
            break;

        default:
            ParseError(
                "Bad Frag Bits = '%c'. Valid options are: RDM+!*", *fptr);
            return;
        }

        fptr++;
    }

    /* put the bits in network order for fast comparisons */
    ds_ptr->frag_bits = htons(ds_ptr->frag_bits);
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~flags", Parameter::PT_STRING, nullptr, nullptr,
      "these flags are tested" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to test IP frag flags"

class FragBitsModule : public Module
{
public:
    FragBitsModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &fragBitsPerfStats; }

    FragBitsData data;
};

bool FragBitsModule::begin(const char*, int, SnortConfig*)
{
    memset(&data, 0, sizeof(data));
    return true;
}

bool FragBitsModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("~flags") )
        fragbits_parse(v.get_string(), &data);

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new FragBitsModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static void fragbits_init(SnortConfig*)
{
    bitmask = htons(0xE000);
}

static IpsOption* fragbits_ctor(Module* p, OptTreeNode*)
{
    FragBitsModule* m = (FragBitsModule*)p;
    return new FragBitsOption(m->data);
}

static void fragbits_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi fragbits_api =
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
    1, 0,
    fragbits_init,
    nullptr,
    nullptr,
    nullptr,
    fragbits_ctor,
    fragbits_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &fragbits_api.base,
    nullptr
};
#else
const BaseApi* ips_fragbits = &fragbits_api.base;
#endif


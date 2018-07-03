//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

// ips_dce_opnum.cc author Maya Dagon <mdagon@cisco.com>
// based on work by Todd Wease

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hashfcn.h"
#include "profiler/profiler.h"
#include "utils/util.h"

#include "dce_common.h"

using namespace snort;

//-------------------------------------------------------------------------
// dcerpc2 opnum rule options
//-------------------------------------------------------------------------

#define s_name "dce_opnum"
#define s_help \
    "detection option to check dcerpc operation number"

#define DCE2_OPNUM__MAX  (UINT16_MAX)
#define DCE2_OPNUM__MAX_INDEX  (DCE2_OPNUM__MAX / 8 + 1)
#define DCE2_CFG_TOK__OPNUM_RANGE    '-'

/********************************************************************
 * Enumerations
 ********************************************************************/

enum DCE2_OpnumListState
{
    DCE2_OPNUM_LIST_STATE__START,
    DCE2_OPNUM_LIST_STATE__OPNUM_START,
    DCE2_OPNUM_LIST_STATE__OPNUM_LO,
    DCE2_OPNUM_LIST_STATE__OPNUM_RANGE,
    DCE2_OPNUM_LIST_STATE__OPNUM_HI,
    DCE2_OPNUM_LIST_STATE__OPNUM_END,
    DCE2_OPNUM_LIST_STATE__END
};

/********************************************************************
 * Structures
 ********************************************************************/

struct DCE2_Opnum
{
    uint8_t* mask;
    uint16_t mask_size;
    uint16_t opnum_lo;
    uint16_t opnum_hi;
};

/********************************************************************
 * Private function prototyes
 ********************************************************************/
static inline bool DCE2_IsOpnumRangeChar(const char c);
static inline void DCE2_OpnumSet(uint8_t*, const uint16_t);
static inline void DCE2_OpnumSetRange(uint8_t*, uint16_t, uint16_t);
static inline bool DCE2_OpnumIsSet(const uint8_t*, const uint16_t, const uint16_t, const uint16_t);
static void DCE2_OpnumFreeMask(DCE2_Opnum* opnum);
static DCE2_Ret DCE2_ParseOpnumList(char** ptr, const char* end, uint8_t* opnum_mask);
static DCE2_Ret DCE2_OpnumParse(char* args, DCE2_Opnum* opnum);

static THREAD_LOCAL ProfileStats dce2_opnum_perf_stats;

/********************************************************************
 * Function: DCE2_IsOpnumChar()
 *
 * Determines if the character passed in is a character that
 * the preprocessor considers a to be a valid character for a
 * DCE/RPC opnum.
 *
 * Arguments:
 *  const char
 *      The character to make the determination on.
 *
 * Returns:
 *  bool
 *      true if a valid DCE/RPC opnum character.
 *      false if not a valid DCE/RPC opnum character.
 *
 ********************************************************************/
static inline bool DCE2_IsOpnumChar(const char c)
{
    if (isdigit((int)c))
        return true;
    return false;
}

/********************************************************************
 * Function: DCE2_IsOpnumRangeChar()
 *
 * Determines if the character passed in is a character that is
 * used to indicate a range of DCE/RPC opnums.
 *
 * Arguments:
 *  const char
 *      The character to make the determination on.
 *
 * Returns:
 *  bool
 *      true if a valid DCE/RPC opnum range character.
 *      false if not a valid DCE/RPC opnum range character.
 *
 ********************************************************************/
static inline bool DCE2_IsOpnumRangeChar(const char c)
{
    if (c == DCE2_CFG_TOK__OPNUM_RANGE)
        return true;
    return false;
}

static void DCE2_OpnumFreeMask(DCE2_Opnum* opnum)
{
    if (opnum->mask != nullptr)
    {
        snort_free((void*)opnum->mask);
        opnum->mask = nullptr;
        opnum->mask_size = 0;
    }
}

static DCE2_Ret DCE2_ParseOpnumList(char** ptr, const char* end, uint8_t* opnum_mask)
{
    char* lo_start = nullptr;
    char* hi_start = nullptr;
    DCE2_OpnumListState state = DCE2_OPNUM_LIST_STATE__START;
    uint16_t lo_opnum = 0, hi_opnum = 0;

    while (*ptr < end)
    {
        char c = **ptr;

        if (state == DCE2_OPNUM_LIST_STATE__END)
            break;

        switch (state)
        {
        case DCE2_OPNUM_LIST_STATE__START:
            if (DCE2_IsOpnumChar(c))
            {
                lo_start = *ptr;
                state = DCE2_OPNUM_LIST_STATE__OPNUM_LO;
            }
            else if (!DCE2_IsSpaceChar(c))
            {
                return DCE2_RET__ERROR;
            }

            break;

        case DCE2_OPNUM_LIST_STATE__OPNUM_LO:
            if (!DCE2_IsOpnumChar(c))
            {
                DCE2_Ret status = DCE2_GetValue(lo_start, *ptr, &lo_opnum,
                    0, DCE2_INT_TYPE__UINT16, 10);

                if (status != DCE2_RET__SUCCESS)
                {
                    return DCE2_RET__ERROR;
                }

                if (DCE2_IsOpnumRangeChar(c))
                {
                    state = DCE2_OPNUM_LIST_STATE__OPNUM_RANGE;
                }
                else
                {
                    DCE2_OpnumSet(opnum_mask, lo_opnum);
                    state = DCE2_OPNUM_LIST_STATE__OPNUM_END;
                    continue;
                }
            }

            break;

        case DCE2_OPNUM_LIST_STATE__OPNUM_RANGE:
            if (DCE2_IsOpnumChar(c))
            {
                hi_start = *ptr;
                state = DCE2_OPNUM_LIST_STATE__OPNUM_HI;
            }
            else
            {
                DCE2_OpnumSetRange(opnum_mask, lo_opnum, UINT16_MAX);
                state = DCE2_OPNUM_LIST_STATE__OPNUM_END;
                continue;
            }

            break;

        case DCE2_OPNUM_LIST_STATE__OPNUM_HI:
            if (!DCE2_IsOpnumChar(c))
            {
                DCE2_Ret status = DCE2_GetValue(hi_start, *ptr, &hi_opnum,
                    0, DCE2_INT_TYPE__UINT16, 10);

                if (status != DCE2_RET__SUCCESS)
                {
                    return status;
                }

                DCE2_OpnumSetRange(opnum_mask, lo_opnum, hi_opnum);
                state = DCE2_OPNUM_LIST_STATE__OPNUM_END;
                continue;
            }

            break;

        case DCE2_OPNUM_LIST_STATE__OPNUM_END:
            if (DCE2_IsSpaceChar(c))
            {
                state = DCE2_OPNUM_LIST_STATE__START;
            }
            else if (DCE2_IsConfigEndChar(c))
            {
                state = DCE2_OPNUM_LIST_STATE__END;
            }
            else
            {
                return DCE2_RET__ERROR;
            }

            break;

        default:
            return DCE2_RET__ERROR;
        }

        (*ptr)++;
    }

    if (state != DCE2_OPNUM_LIST_STATE__END)
    {
        return DCE2_RET__ERROR;
    }

    return DCE2_RET__SUCCESS;
}

static inline bool DCE2_OpnumIsSet(const uint8_t* opnum_mask, const uint16_t opnum_lo,
    const uint16_t opnum_hi, const uint16_t opnum)
{
    uint16_t otmp = opnum - opnum_lo;

    if ((opnum < opnum_lo) || (opnum > opnum_hi))
        return false;

    return opnum_mask[(otmp / 8)] & (1 << (otmp % 8));
}

static inline void DCE2_OpnumSet(uint8_t* opnum_mask, const uint16_t opnum)
{
    opnum_mask[(opnum / 8)] |= (1 << (opnum % 8));
}

static inline void DCE2_OpnumSetRange(uint8_t* opnum_mask, uint16_t lo_opnum, uint16_t hi_opnum)
{
    unsigned int i;

    if (lo_opnum > hi_opnum)
    {
        uint16_t tmp = lo_opnum;
        lo_opnum = hi_opnum;
        hi_opnum = tmp;
    }

    for (i = lo_opnum; i <= hi_opnum; i++)
        DCE2_OpnumSet(opnum_mask, i);
}

static DCE2_Ret DCE2_OpnumParse(char* args, DCE2_Opnum* opnum)
{
    uint8_t opnum_mask[DCE2_OPNUM__MAX_INDEX];  /* 65536 bits */
    char* args_end;
    uint16_t num_opnums = 0;
    unsigned int i;

    /* Include NULL byte for parsing */
    args_end = args + (strlen(args) + 1);
    memset(opnum_mask, 0, sizeof(opnum_mask));

    DCE2_Ret status = DCE2_ParseOpnumList(&args, args_end, opnum_mask);
    if (status != DCE2_RET__SUCCESS)
    {
        return status;
    }

    /* Must have at least one bit set or the parsing would have errored */
    for (i = 0; i <= DCE2_OPNUM__MAX; i++)
    {
        if (DCE2_OpnumIsSet(opnum_mask, 0, DCE2_OPNUM__MAX, (uint16_t)i))
        {
            num_opnums++;

            if (opnum->opnum_lo == DCE2_OPNUM__MAX)
                opnum->opnum_lo = (uint16_t)i;

            opnum->opnum_hi = (uint16_t)i;
        }
    }

    if (num_opnums > 1)
    {
        int opnum_range = opnum->opnum_hi - opnum->opnum_lo;
        opnum->mask_size = (opnum_range / 8) + 1;
        opnum->mask = (uint8_t*)snort_calloc(opnum->mask_size);

        /* Set the opnum bits in our reduced size opnum mask */
        for (i = (unsigned int)opnum->opnum_lo; i <= (unsigned int)opnum->opnum_hi; i++)
        {
            if (DCE2_OpnumIsSet(opnum_mask, 0, DCE2_OPNUM__MAX, (uint16_t)i))
                DCE2_OpnumSet(opnum->mask, (uint16_t)(i - opnum->opnum_lo));
        }
    }

    return DCE2_RET__SUCCESS;
}

class Dce2OpnumOption : public IpsOption
{
public:
    Dce2OpnumOption(DCE2_Opnum& src_opnum) : IpsOption(s_name)
    { opnum = src_opnum; }
    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;
    EvalStatus eval(Cursor&, Packet*) override;
    ~Dce2OpnumOption() override;

private:
    DCE2_Opnum opnum;
};

uint32_t Dce2OpnumOption::hash() const
{
    uint32_t a = opnum.opnum_lo, b = opnum.opnum_hi, c = opnum.mask_size;

    mix_str(a,b,c,get_name());

    if (opnum.mask_size != 0)
    {
        uint32_t i;
        /* Don't care about potential wrapping if it exists */
        for (i = 0; i < opnum.mask_size; i++)
            c += opnum.mask[i];

        mix(a,b,c);
    }

    finalize(a, b, c);

    return c;
}

bool Dce2OpnumOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    const Dce2OpnumOption& rhs = (const Dce2OpnumOption&)ips;

    if ((opnum.mask_size != rhs.opnum.mask_size) ||
        (opnum.opnum_lo != rhs.opnum.opnum_lo) ||
        (opnum.opnum_hi != rhs.opnum.opnum_hi))
    {
        return false;
    }

    uint32_t i;
    for (i = 0; i < opnum.mask_size; i++)
    {
        if (opnum.mask[i] != rhs.opnum.mask[i])
            return false;
    }

    return true;
}

IpsOption::EvalStatus Dce2OpnumOption::eval(Cursor&, Packet* p)
{
    Profile profile(dce2_opnum_perf_stats);

    if (p->dsize == 0)
    {
        return NO_MATCH;
    }

    if (DceContextData::is_noinspect(p))
    {
        return NO_MATCH;
    }

    DCE2_Roptions* ropts = DceContextData::get_current_ropts(p);

    if ( !ropts )
        return NO_MATCH;

    if (ropts->opnum == DCE2_SENTINEL)
    {
        return NO_MATCH;
    }

    if (opnum.mask_size == 0)
    {
        if (ropts->opnum == opnum.opnum_lo)
        {
            return MATCH;
        }
    }
    else
    {
        if (DCE2_OpnumIsSet(opnum.mask, opnum.opnum_lo,
            opnum.opnum_hi, (uint16_t)ropts->opnum))
        {
            return MATCH;
        }
    }

    return NO_MATCH;
}

Dce2OpnumOption::~Dce2OpnumOption()
{
    DCE2_OpnumFreeMask(&opnum);
}

//-------------------------------------------------------------------------
// dce2_opnum module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~", Parameter::PT_STRING, nullptr, nullptr,
      "match given dcerpc operation number, range or list" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class Dce2OpnumModule : public Module
{
public:
    Dce2OpnumModule() : Module(s_name, s_help, s_params)
    { memset(&opnum, 0, sizeof(opnum)); }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;
    ProfileStats* get_profile() const override;
    ~Dce2OpnumModule() override;

    Usage get_usage() const override
    { return DETECT; }

public:
    DCE2_Opnum opnum;
};

bool Dce2OpnumModule::begin(const char*, int, SnortConfig*)
{
    opnum.opnum_lo = DCE2_OPNUM__MAX;
    opnum.opnum_hi = 0;
    opnum.mask_size = 0;
    opnum.mask = nullptr;

    return true;
}

bool Dce2OpnumModule::set(const char*, Value& v, SnortConfig*)
{
    if ( !v.is("~") )
        return false;

    if (v.get_string())
    {
        std::string tok (v.get_string());
        if ( tok[0] == '"' )
            tok.erase(0, 1);

        if ( tok[tok.length()-1] == '"' )
            tok.erase(tok.length()-1, 1);

        char* s = snort_strdup(tok.c_str());
        DCE2_Ret status = DCE2_OpnumParse(s, &opnum);
        snort_free(s);

        if (status == DCE2_RET__SUCCESS)
            return true;
    }

    return false;
}

ProfileStats* Dce2OpnumModule::get_profile() const
{
    return &dce2_opnum_perf_stats;
}

Dce2OpnumModule::~Dce2OpnumModule()
{
    DCE2_OpnumFreeMask(&opnum);
}

//-------------------------------------------------------------------------
// dce2_opnum api
//-------------------------------------------------------------------------

static Module* dce2_opnum_mod_ctor()
{
    return new Dce2OpnumModule;
}

static void dce2_opnum_mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* dce2_opnum_ctor(Module* p, OptTreeNode*)
{
    Dce2OpnumModule* m = (Dce2OpnumModule*)p;
    DCE2_Opnum opnum = m->opnum;
    m->opnum.mask = nullptr;
    return new Dce2OpnumOption(opnum);
}

static void dce2_opnum_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi dce2_opnum_api =
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
        dce2_opnum_mod_ctor,
        dce2_opnum_mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP | PROTO_BIT__UDP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    dce2_opnum_ctor,
    dce2_opnum_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// plugin
//-------------------------------------------------------------------------

// added to snort_plugins in dce2.cc
const BaseApi* ips_dce_opnum = &dce2_opnum_api.base;


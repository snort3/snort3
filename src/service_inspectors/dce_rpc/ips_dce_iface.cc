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

// ips_dce_iface.cc author Maya Dagon <mdagon@cisco.com>
// based on work by Todd Wease

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cerrno>

#include "detection/pattern_match_data.h"
#include "framework/module.h"
#include "framework/ips_option.h"
#include "framework/range.h"
#include "hash/hashfcn.h"
#include "profiler/profiler.h"
#include "target_based/snort_protocols.h"
#include "utils/util.h"

#include "dce_common.h"

using namespace snort;

//-------------------------------------------------------------------------
// dcerpc2 interface rule options
//-------------------------------------------------------------------------

#define DCE2_RTOKEN__ARG_SEP      " \t"   /* Rule option argument separator */
#define DCE2_RTOKEN__IFACE_SEP    "-"     /* Rule option interface separator */

#define DCE2_IFACE__LEN  36  /* counting the dashes */
#define DCE2_IFACE__TIME_LOW_LEN    8
#define DCE2_IFACE__TIME_MID_LEN    4
#define DCE2_IFACE__TIME_HIGH_LEN   4
#define DCE2_IFACE__CLOCK_SEQ_LEN   4
#define DCE2_IFACE__NODE_LEN       12

#define s_name "dce_iface"
#define s_help \
    "detection option to check dcerpc interface"

static THREAD_LOCAL ProfileStats dce2_iface_perf_stats;

static bool DCE2_ParseIface(char* token, Uuid* uuid)
{
    char* iface, * ifaceptr = nullptr;
    char* if_hex, * if_hexptr = nullptr;
    int num_pieces = 0;

    /* Has to be a uuid in string format, e.g 4b324fc8-1670-01d3-1278-5a47bf6ee188
     * Check the length */
    if (strlen(token) != DCE2_IFACE__LEN)
        return false;

    /* Detach token */
    iface = strtok_r(token, DCE2_RTOKEN__ARG_SEP, &ifaceptr);
    if (iface == nullptr)
        return false;

    /* Cut into pieces separated by '-' */
    if_hex = strtok_r(iface, DCE2_RTOKEN__IFACE_SEP, &if_hexptr);
    if (if_hex == nullptr)
        return false;

    do
    {
        char* endptr;

        switch (num_pieces)
        {
        case 0:
        {
            unsigned long int time_low;

            if (strlen(if_hex) != DCE2_IFACE__TIME_LOW_LEN)
                return false;

            time_low = strtoul(if_hex, &endptr, 16);
            if ((errno == ERANGE) || (*endptr != '\0'))
                return false;

            uuid->time_low = (uint32_t)time_low;
        }

        break;

        case 1:
        {
            unsigned long int time_mid;

            if (strlen(if_hex) != DCE2_IFACE__TIME_MID_LEN)
                return false;

            time_mid = strtoul(if_hex, &endptr, 16);
            if ((errno == ERANGE) || (*endptr != '\0'))
                return false;

            /* Length check ensures 16 bit value */
            uuid->time_mid = (uint16_t)time_mid;
        }

        break;

        case 2:
        {
            unsigned long int time_high;

            if (strlen(if_hex) != DCE2_IFACE__TIME_HIGH_LEN)
                return false;

            time_high = strtoul(if_hex, &endptr, 16);
            if ((errno == ERANGE) || (*endptr != '\0'))
                return false;

            /* Length check ensures 16 bit value */
            uuid->time_high_and_version = (uint16_t)time_high;
        }

        break;

        case 3:
        {
            unsigned long int clock_seq_and_reserved, clock_seq_low;

            if (strlen(if_hex) != DCE2_IFACE__CLOCK_SEQ_LEN)
                return false;

            /* Work backwards */
            clock_seq_low = strtoul(&if_hex[2], &endptr, 16);
            if ((errno == ERANGE) || (*endptr != '\0'))
                return false;

            uuid->clock_seq_low = (uint8_t)clock_seq_low;

            /* Set third byte to null so we can _dpd.SnortStrtoul the first part */
            if_hex[2] = '\x00';

            clock_seq_and_reserved = strtoul(if_hex, &endptr, 16);
            if ((errno == ERANGE) || (*endptr != '\0'))
                return false;

            uuid->clock_seq_and_reserved = (uint8_t)clock_seq_and_reserved;
        }

        break;

        case 4:
        {
            int i, j;

            if (strlen(if_hex) != DCE2_IFACE__NODE_LEN)
                return false;

            /* Walk back a byte at a time - 2 hex digits */
            for (i = DCE2_IFACE__NODE_LEN - 2, j = sizeof(uuid->node) - 1;
                (i >= 0) && (j >= 0);
                i -= 2, j--)
            {
                /* Only giving strtoul 1 byte */
                uuid->node[j] = (uint8_t)strtoul(&if_hex[i], &endptr, 16);
                if ((errno == ERANGE) || (*endptr != '\0'))
                    return false;
                if_hex[i] = '\0';
            }
        }
        break;

        default:
            break;
        }

        num_pieces++;
    }
    while ((if_hex = strtok_r(nullptr, DCE2_RTOKEN__IFACE_SEP, &if_hexptr)) != nullptr);

    if (num_pieces != 5)
        return false;

    /* Check for more arguments */
    iface = strtok_r(nullptr, DCE2_RTOKEN__ARG_SEP, &ifaceptr);
    if (iface != nullptr)
        return false;

    return true;
}

class Dce2IfaceOption : public IpsOption
{
public:
    Dce2IfaceOption(const RangeCheck& iface_version, bool iface_any_frag, const Uuid& iface_uuid) :
        IpsOption(s_name), version(iface_version), any_frag(iface_any_frag), uuid(iface_uuid),
        pmd(), alt_pmd()
    {
        pmd.set_literal();
        alt_pmd.set_literal();
    }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;
    EvalStatus eval(Cursor&, Packet*) override;
    PatternMatchData* get_pattern(SnortProtocolId snort_protocol_id, RuleDirection direction) override;
    PatternMatchData* get_alternate_pattern() override;
    ~Dce2IfaceOption() override;

private:
    const RangeCheck version;
    const bool any_frag;
    const Uuid uuid;
    PatternMatchData pmd;
    PatternMatchData alt_pmd;
};

Dce2IfaceOption::~Dce2IfaceOption()
{
    if ( pmd.pattern_buf)
    {
        snort_free(const_cast<char*>(pmd.pattern_buf));
    }
    if ( alt_pmd.pattern_buf)
    {
        snort_free(const_cast<char*>(alt_pmd.pattern_buf));
    }
}

static char* make_pattern_buffer( const Uuid &uuid, DceRpcBoFlag type )
{
    int index = 0;
    char* pattern_buf = (char*)snort_alloc(sizeof(Uuid));

    uint32_t time32 = DceRpcNtohl(&uuid.time_low, type);
    memcpy(&pattern_buf[index], &time32, sizeof(uint32_t));
    index += sizeof(uint32_t);

    uint16_t time16 = DceRpcNtohs(&uuid.time_mid, type);
    memcpy(&pattern_buf[index], &time16, sizeof(uint16_t));
    index += sizeof(uint16_t);

    time16 = DceRpcNtohs(&uuid.time_high_and_version, type);
    memcpy(&pattern_buf[index], &time16, sizeof(uint16_t));
    index += sizeof(uint16_t);

    pattern_buf[index] = uuid.clock_seq_and_reserved;
    index += sizeof(uint8_t);

    pattern_buf[index] = uuid.clock_seq_low;
    index += sizeof(uint8_t);

    memcpy(&pattern_buf[index], uuid.node, 6);

    return pattern_buf;
}

PatternMatchData* Dce2IfaceOption::get_pattern(SnortProtocolId snort_protocol_id, RuleDirection direction)
{
    if (pmd.pattern_buf)
    {
        return &pmd;
    }

    if (snort_protocol_id == SNORT_PROTO_TCP)
    {
        const char client_fp[] = "\x05\x00\x00";
        const char server_fp[] = "\x05\x00\x02";
        const char no_dir_fp[] = "\x05\x00";

        switch (direction)
        {
        case RULE_FROM_CLIENT:
            pmd.pattern_size = 3;
            pmd.pattern_buf = (char*)snort_alloc(pmd.pattern_size);
            memcpy((void*)pmd.pattern_buf, client_fp, pmd.pattern_size);
            break;

        case RULE_FROM_SERVER:
            pmd.pattern_size = 3;
            pmd.pattern_buf = (char*)snort_alloc(pmd.pattern_size);
            memcpy((void*)pmd.pattern_buf, server_fp, pmd.pattern_size);
            break;

        default:
            pmd.pattern_size = 2;
            pmd.pattern_buf = (char*)snort_alloc(pmd.pattern_size);
            memcpy((void*)pmd.pattern_buf, no_dir_fp, pmd.pattern_size);
            break;
        }
        return &pmd;
    }
    else if (snort_protocol_id == SNORT_PROTO_UDP)
    {
        pmd.pattern_buf = make_pattern_buffer( uuid, DCERPC_BO_FLAG__LITTLE_ENDIAN );
        pmd.pattern_size = sizeof(Uuid);
        alt_pmd.pattern_buf = make_pattern_buffer( uuid, DCERPC_BO_FLAG__BIG_ENDIAN );
        alt_pmd.pattern_size = sizeof(Uuid);

        return &pmd;
    }

    return nullptr;
}

PatternMatchData* Dce2IfaceOption::get_alternate_pattern()
{
    if (alt_pmd.pattern_buf)
    {
        return &alt_pmd;
    }

    return nullptr;
}

uint32_t Dce2IfaceOption::hash() const
{
    uint32_t a, b, c;

    a = uuid.time_low;
    b = (uuid.time_mid << 16) | (uuid.time_high_and_version);
    c = (uuid.clock_seq_and_reserved << 24) |
        (uuid.clock_seq_low << 16) |
        (uuid.node[0] << 8) |
        (uuid.node[1]);

    mix_str(a, b, c, get_name());

    a += (uuid.node[2] << 24) |
        (uuid.node[3] << 16) |
        (uuid.node[4] << 8) |
        (uuid.node[5]);
    b += version.max;
    c += version.min;

    mix(a, b, c);

    a += version.op;
    b += any_frag;

    finalize(a, b, c);

    return c;
}

bool Dce2IfaceOption::operator==(const IpsOption& ips) const
{
    // FIXIT-L
    // Fast pattern is calculated only after the entire rule is parsed.
    // The rule option can be mistaken as a duplicate because we don't take the fast pattern into
    // account. Instead of comparing values, make sure it is the same object.
    return this == &ips;
}

IpsOption::EvalStatus Dce2IfaceOption::eval(Cursor&, Packet* p)
{
    Profile profile(dce2_iface_perf_stats);

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

    if (ropts->first_frag == DCE2_SENTINEL)
    {
        return NO_MATCH;
    }

    if (!any_frag && !ropts->first_frag)
    {
        return NO_MATCH;
    }

    if (DCE2_UuidCompare((void*)&ropts->iface, &uuid) != 0)
    {
        return NO_MATCH;
    }

    if (version.is_set())
    {
        if (p->has_tcp_data())
        {
            if (!version.eval(ropts->iface_vers_maj))
            {
                return NO_MATCH;
            }
        }
        else
        {
            if (!version.eval(ropts->iface_vers))
            {
                return NO_MATCH;
            }
        }
    }

    return MATCH;
}

//-------------------------------------------------------------------------
// dce2_iface module
//-------------------------------------------------------------------------

#define RANGE "0:"

static const Parameter s_params[] =
{
    { "uuid", Parameter::PT_STRING, nullptr, nullptr,
      "match given dcerpc uuid" },
    { "version",Parameter::PT_INTERVAL, RANGE, nullptr,
      "interface version" },
    { "any_frag", Parameter::PT_IMPLIED, nullptr, nullptr,
      "match on any fragment" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class Dce2IfaceModule : public Module
{
public:
    Dce2IfaceModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;
    ProfileStats* get_profile() const override;

    Usage get_usage() const override
    { return DETECT; }

public:
    RangeCheck version;
    bool any_frag;
    Uuid uuid;
};

bool Dce2IfaceModule::begin(const char*, int, SnortConfig*)
{
    version.init();
    any_frag = false;
    return true;
}

bool Dce2IfaceModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("version") )
        return version.validate(v.get_string(), RANGE);
    else if ( v.is("any_frag") )
        any_frag = true;
    else if ( v.is("uuid") )
    {
        char* token = const_cast<char*>(v.get_string());
        token = DCE2_PruneWhiteSpace(token);
        return DCE2_ParseIface(token, &uuid);
    }
    else
        return false;

    return true;
}

ProfileStats* Dce2IfaceModule::get_profile() const
{
    return &dce2_iface_perf_stats;
}

//-------------------------------------------------------------------------
// dce2_iface api
//-------------------------------------------------------------------------

static Module* dce2_iface_mod_ctor()
{
    return new Dce2IfaceModule;
}

static void dce2_iface_mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* dce2_iface_ctor(Module* p, OptTreeNode*)
{
    Dce2IfaceModule* m = (Dce2IfaceModule*)p;
    return new Dce2IfaceOption(m->version, m->any_frag, m->uuid);
}

static void dce2_iface_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi dce2_iface_api =
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
        dce2_iface_mod_ctor,
        dce2_iface_mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP | PROTO_BIT__UDP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    dce2_iface_ctor,
    dce2_iface_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// plugin
//-------------------------------------------------------------------------

// added to snort_plugins in dce2.cc
const BaseApi* ips_dce_iface = &dce2_iface_api.base;


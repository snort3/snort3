//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cassert>

#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hashfcn.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"

using namespace snort;

#define M_NORMAL  0
#define M_ALL     1
#define M_ANY     2
#define M_NOT     3

#define R_FIN          0x01
#define R_SYN          0x02
#define R_RST          0x04
#define R_PSH          0x08
#define R_ACK          0x10
#define R_URG          0x20
#define R_ECE          0x40  /* ECN echo, RFC 3168 */
#define R_CWR          0x80  /* Congestion Window Reduced, RFC 3168 */

#define s_name "flags"

static THREAD_LOCAL ProfileStats tcpFlagsPerfStats;

struct TcpFlagCheckData
{
    uint8_t mode;
    uint8_t tcp_flags;
    uint8_t tcp_mask; /* Mask to take away from the flags check */
};

class TcpFlagOption : public IpsOption
{
public:
    TcpFlagOption(const TcpFlagCheckData& c) :
        IpsOption(s_name)
    { config = c; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

private:
    TcpFlagCheckData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t TcpFlagOption::hash() const
{
    uint32_t a,b,c;
    const TcpFlagCheckData* data = &config;

    a = data->mode;
    b = data->tcp_flags | (data->tcp_mask << 8);
    c = 0;

    mix_str(a,b,c,get_name());
    finalize(a,b,c);

    return c;
}

bool TcpFlagOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    const TcpFlagOption& rhs = (const TcpFlagOption&)ips;
    const TcpFlagCheckData* left = &config;
    const TcpFlagCheckData* right = &rhs.config;

    if ((left->mode == right->mode) &&
        (left->tcp_flags == right->tcp_flags) &&
        (left->tcp_mask == right->tcp_mask))
    {
        return true;
    }

    return false;
}

IpsOption::EvalStatus TcpFlagOption::eval(Cursor&, Packet* p)
{
    Profile profile(tcpFlagsPerfStats);

    // if error appeared when tcp header was processed,
    // test fails automagically.
    if (!p->ptrs.tcph)
        return NO_MATCH;

    /* the flags we really want to check are all the ones
     */

    TcpFlagCheckData* flagptr = &config;
    uint8_t tcp_flags = p->ptrs.tcph->th_flags & (0xFF ^ flagptr->tcp_mask);

    switch ((flagptr->mode))
    {
    case M_NORMAL:
        if (flagptr->tcp_flags == tcp_flags)    /* only these set */
        {
            return MATCH;
        }
        break;

    case M_ALL:
        /* all set */
        if ((flagptr->tcp_flags & tcp_flags) == flagptr->tcp_flags)
        {
            return MATCH;
        }
        break;

    case M_NOT:
        if ((flagptr->tcp_flags & tcp_flags) == 0)     /* none set */
        {
            return MATCH;
        }
        break;

    case M_ANY:
        if ((flagptr->tcp_flags & tcp_flags) != 0)     /* something set */
        {
            return MATCH;
        }
        break;

    default:      /* Should never see this */
        break;
    }

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// parse methods
//-------------------------------------------------------------------------

static void flags_parse_test(const char* rule, TcpFlagCheckData* idx)
{
    const char* fptr;
    const char* fend;

    fptr = rule;
    assert(fptr and *fptr);

    /* find the end of the alert string */
    fend = fptr + strlen(fptr);

    idx->mode = M_NORMAL; /* this is the default, unless overridden */

    while (fptr < fend)
    {
        switch (*fptr)
        {
        case 'f':
        case 'F':
            idx->tcp_flags |= R_FIN;
            break;

        case 's':
        case 'S':
            idx->tcp_flags |= R_SYN;
            break;

        case 'r':
        case 'R':
            idx->tcp_flags |= R_RST;
            break;

        case 'p':
        case 'P':
            idx->tcp_flags |= R_PSH;
            break;

        case 'a':
        case 'A':
            idx->tcp_flags |= R_ACK;
            break;

        case 'u':
        case 'U':
            idx->tcp_flags |= R_URG;
            break;

        case '0':
            idx->tcp_flags = 0;
            break;

        case '1':     /* reserved bit flags */
        case 'c':
        case 'C':
            idx->tcp_flags |= R_CWR;     /* Congestion Window Reduced, RFC 3168 */
            break;

        case '2':     /* reserved bit flags */
        case 'e':
        case 'E':
            idx->tcp_flags |= R_ECE;     /* ECN echo, RFC 3168 */
            break;

        case '!':     /* not, fire if all flags specified are not present,
                         other are don't care */
            idx->mode = M_NOT;
            break;
        case '*':     /* star or any, fire if any flags specified are
                         present, other are don't care */
            idx->mode = M_ANY;
            break;
        case '+':     /* plus or all, fire if all flags specified are
                         present, other are don't care */
            idx->mode = M_ALL;
            break;
        default:
            ParseError(
                "bad TCP flag = '%c'"
                "Valid options: UAPRSFCE or 0 for NO flags (e.g. NULL scan),"
                " and !, + or * for modifiers",
                *fptr);
            return;
        }

        fptr++;
    }
}

static void flags_parse_mask(const char* rule, TcpFlagCheckData* idx)
{
    const char* fptr;
    const char* fend;

    fptr = rule;
    assert(fptr and *fptr);

    /* find the end of the alert string */
    fend = fptr + strlen(fptr);

    /* create the mask portion now */
    while (fptr < fend)
    {
        switch (*fptr)
        {
        case 'f':
        case 'F':
            idx->tcp_mask |= R_FIN;
            break;

        case 's':
        case 'S':
            idx->tcp_mask |= R_SYN;
            break;

        case 'r':
        case 'R':
            idx->tcp_mask |= R_RST;
            break;

        case 'p':
        case 'P':
            idx->tcp_mask |= R_PSH;
            break;

        case 'a':
        case 'A':
            idx->tcp_mask |= R_ACK;
            break;

        case 'u':
        case 'U':
            idx->tcp_mask |= R_URG;
            break;

        case '1':     /* reserved bit flags */
        case 'c':
        case 'C':
            idx->tcp_mask |= R_CWR;     /* Congestion Window Reduced, RFC 3168 */
            break;

        case '2':     /* reserved bit flags */
        case 'e':
        case 'E':
            idx->tcp_mask |= R_ECE;     /* ECN echo, RFC 3168 */
            break;
        default:
            ParseError("bad TCP flag = '%c'. Valid options: UAPRSFCE", *fptr);
            return;
        }

        fptr++;
    }
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~test_flags", Parameter::PT_STRING, nullptr, nullptr,
      "these flags are tested" },

    { "~mask_flags", Parameter::PT_STRING, nullptr, nullptr,
      "these flags are don't cares" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to test TCP control flags"

class FlagsModule : public Module
{
public:
    FlagsModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &tcpFlagsPerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    TcpFlagCheckData data;
};

bool FlagsModule::begin(const char*, int, SnortConfig*)
{
    memset(&data, 0, sizeof(data));
    return true;
}

bool FlagsModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("~test_flags") )
        flags_parse_test(v.get_string(), &data);

    else if ( v.is("~mask_flags") )
        flags_parse_mask(v.get_string(), &data);

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new FlagsModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* flags_ctor(Module* p, OptTreeNode*)
{
    FlagsModule* m = (FlagsModule*)p;
    return new TcpFlagOption(m->data);
}

static void flags_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi flags_api =
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
    1, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    flags_ctor,
    flags_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_flags[] =
#endif
{
    &flags_api.base,
    nullptr
};


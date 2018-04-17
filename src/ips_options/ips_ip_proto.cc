//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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

#include <netdb.h>

#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hashfcn.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "utils/util_cstring.h"

using namespace snort;

#define s_name "ip_proto"

static THREAD_LOCAL ProfileStats ipProtoPerfStats;

#define IP_PROTO__EQUAL         0
#define IP_PROTO__NOT_EQUAL     1
#define IP_PROTO__GREATER_THAN  2
#define IP_PROTO__LESS_THAN     3

struct IpProtoData
{
    IpProtocol protocol;
    uint8_t comparison_flag;
};

class IpProtoOption : public IpsOption
{
public:
    IpProtoOption(const IpProtoData& c) :
        IpsOption(s_name)
    { config = c; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

    IpProtoData* get_data()
    { return &config; }

private:
    IpProtoData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t IpProtoOption::hash() const
{
    uint32_t a,b,c;
    const IpProtoData* data = &config;

    a = to_utype(data->protocol);
    b = data->comparison_flag;
    c = 0;

    mix_str(a,b,c,get_name());
    finalize(a,b,c);

    return c;
}

bool IpProtoOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    const IpProtoOption& rhs = (const IpProtoOption&)ips;
    const IpProtoData* left = &config;
    const IpProtoData* right = &rhs.config;

    if ((left->protocol == right->protocol) &&
        (left->comparison_flag == right->comparison_flag))
    {
        return true;
    }

    return false;
}

IpsOption::EvalStatus IpProtoOption::eval(Cursor&, Packet* p)
{
    Profile profile(ipProtoPerfStats);

    IpProtoData* ipd = &config;

    if (!p->has_ip())
    {
        return NO_MATCH;
    }

    const IpProtocol ip_proto = p->get_ip_proto_next();

    switch (ipd->comparison_flag)
    {
    case IP_PROTO__EQUAL:
        if (ip_proto == ipd->protocol)
            return MATCH;

        break;

    case IP_PROTO__NOT_EQUAL:
        if (ip_proto != ipd->protocol)
            return MATCH;

        break;

    case IP_PROTO__GREATER_THAN:
        if (ip_proto > ipd->protocol)
            return MATCH;

        break;

    case IP_PROTO__LESS_THAN:
        if (ip_proto < ipd->protocol)
            return MATCH;

        break;
    }

    /* if the test isn't successful, this function *must* return 0 */
    return NO_MATCH;
}

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

static void ip_proto_parse(const char* data, IpProtoData* ds_ptr)
{
    while (isspace((int)*data))
        data++;

    if (*data == '!')
    {
        ds_ptr->comparison_flag = IP_PROTO__NOT_EQUAL;
        data++;
    }
    else if (*data == '>')
    {
        ds_ptr->comparison_flag = IP_PROTO__GREATER_THAN;
        data++;
    }
    else if (*data == '<')
    {
        ds_ptr->comparison_flag = IP_PROTO__LESS_THAN;
        data++;
    }
    else
    {
        ds_ptr->comparison_flag = IP_PROTO__EQUAL;
    }

    /* check for a number or a protocol name */
    if (isdigit((int)*data))
    {
        unsigned long ip_proto;
        char* endptr;

        ip_proto = SnortStrtoul(data, &endptr, 10);
        if ((errno == ERANGE) || (ip_proto >= NUM_IP_PROTOS))
        {
            ParseError("invalid protocol number for 'ip_proto' "
                "rule option.  Value must be between 0 and 255.");
            return;
        }

        ds_ptr->protocol = (IpProtocol)ip_proto;
    }
    else
    {
        struct protoent* pt = getprotobyname(data);  // main thread only

        if ( pt and pt->p_proto < NUM_IP_PROTOS )
        {
            ds_ptr->protocol = (IpProtocol)pt->p_proto;
        }
        else
        {
            ParseError("invalid protocol name for \"ip_proto\" rule option: '%s'.", data);
            return;
        }
    }
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~proto", Parameter::PT_STRING, nullptr, nullptr,
      "[!|>|<] name or number" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to check the IP protocol number"

class IpProtoModule : public Module
{
public:
    IpProtoModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &ipProtoPerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    IpProtoData data;
};

bool IpProtoModule::begin(const char*, int, SnortConfig*)
{
    memset(&data, 0, sizeof(data));
    return true;
}

bool IpProtoModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("~proto") )
        ip_proto_parse(v.get_string(), &data);

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new IpProtoModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* ip_proto_ctor(Module* p, OptTreeNode*)
{
    IpProtoModule* m = (IpProtoModule*)p;
    return new IpProtoOption(m->data);
}

static void ip_proto_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi ip_proto_api =
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
    0, PROTO_BIT__IP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    ip_proto_ctor,
    ip_proto_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_ip_proto[] =
#endif
{
    &ip_proto_api.base,
    nullptr
};


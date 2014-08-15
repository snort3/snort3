/****************************************************************************
 *
 * Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2003-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

#include "ips_ip_proto.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>

#include "treenodes.h"
#include "protocols/packet.h"
#include "parser.h"
#include "snort_debug.h"
#include "util.h"
#include "snort.h"
#include "profiler.h"
#include "fpdetect.h"
#include "sfhashfcn.h"
#include "detection/detection_defines.h"
#include "framework/ips_option.h"
#include "framework/parameter.h"
#include "framework/module.h"

static const char* s_name = "ip_proto";

static THREAD_LOCAL ProfileStats ipProtoPerfStats;

#define IP_PROTO__EQUAL         0
#define IP_PROTO__NOT_EQUAL     1
#define IP_PROTO__GREATER_THAN  2
#define IP_PROTO__LESS_THAN     3

typedef struct _IpProtoData
{
    uint8_t protocol;
    uint8_t comparison_flag;

} IpProtoData;

class IpProtoOption : public IpsOption
{
public:
    IpProtoOption(const IpProtoData& c) :
        IpsOption(s_name, RULE_OPTION_TYPE_IP_PROTO)
    { config = c; };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    int eval(Cursor&, Packet*);

    IpProtoData* get_data() 
    { return &config; };

private:
    IpProtoData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t IpProtoOption::hash() const
{
    uint32_t a,b,c;
    const IpProtoData *data = &config;

    a = data->protocol;
    b = data->comparison_flag;
    c = 0;

    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool IpProtoOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    IpProtoOption& rhs = (IpProtoOption&)ips;
    IpProtoData *left = (IpProtoData*)&config;
    IpProtoData *right = (IpProtoData*)&rhs.config;

    if ((left->protocol == right->protocol) &&
        (left->comparison_flag == right->comparison_flag))
    {
        return true;
    }

    return false;
}

int IpProtoOption::eval(Cursor&, Packet *p)
{
    IpProtoData *ipd = &config;
    int rval = DETECTION_OPTION_NO_MATCH;
    PROFILE_VARS;

    if(!p->ip_api.is_valid())
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Not IP\n"););
        return rval;
    }

    MODULE_PROFILE_START(ipProtoPerfStats);

    switch (ipd->comparison_flag)
    {
        case IP_PROTO__EQUAL:
            if (p->ip_api.proto() == ipd->protocol)
                rval = DETECTION_OPTION_MATCH;
            break;

        case IP_PROTO__NOT_EQUAL:
            if (p->ip_api.proto() != ipd->protocol)
                rval = DETECTION_OPTION_MATCH;
            break;

        case IP_PROTO__GREATER_THAN:
            if (p->ip_api.proto() > ipd->protocol)
                rval = DETECTION_OPTION_MATCH;
            break;

        case IP_PROTO__LESS_THAN:
            if (p->ip_api.proto() < ipd->protocol)
                rval = DETECTION_OPTION_MATCH;
            break;

        default:
            ErrorMessage("%s(%d) Invalid comparison flag.\n",
                         __FILE__, __LINE__);
            break;
    }

    /* if the test isn't successful, this function *must* return 0 */
    MODULE_PROFILE_END(ipProtoPerfStats);
    return rval;
}

//-------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

bool CheckOtnIpProto(OptTreeNode *otn, int proto)
{
   if ( !otn )
       return false;

   IpProtoOption* opt = (IpProtoOption*)
       get_rule_type_data(otn, RULE_OPTION_TYPE_IP_PROTO);

   if ( !opt )
       return false;

   IpProtoData* ipd = opt->get_data();

    switch (ipd->comparison_flag)
    {
        case IP_PROTO__EQUAL:
            return ( proto == ipd->protocol );

        case IP_PROTO__NOT_EQUAL:
            return ( proto != ipd->protocol );

        case IP_PROTO__GREATER_THAN:
            return ( proto > ipd->protocol );

        case IP_PROTO__LESS_THAN:
            return ( proto < ipd->protocol );
    }
    return false;
}

int GetOtnIpProto(OptTreeNode *otn)
{
   if ( !otn )
       return -1;

   IpProtoOption* opt = (IpProtoOption*)
       get_rule_type_data(otn, RULE_OPTION_TYPE_IP_PROTO);

   if ( !opt )
       return -1;

   IpProtoData* ipd = opt->get_data();

   if ( ipd->comparison_flag == IP_PROTO__EQUAL )
       return (int)ipd->protocol;

   return -1;
}

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

static void ip_proto_parse(const char* data, IpProtoData* ds_ptr)
{
    while(isspace((int)*data)) data++;

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
    if(isdigit((int)*data))
    {
        unsigned long ip_proto;
        char *endptr;

        ip_proto = SnortStrtoul(data, &endptr, 10);
        if ((errno == ERANGE) || (ip_proto >= NUM_IP_PROTOS))
        {
            ParseError("invalid protocol number for 'ip_proto' "
                       "rule option.  Value must be between 0 and 255.");
            return;
        }

        ds_ptr->protocol = (uint8_t)ip_proto;
    }
    else
    {
        struct protoent *pt = getprotobyname(data);  // main thread only

        if (pt != NULL)
        {
            /* p_proto should be a number less than 256 */
            ds_ptr->protocol = (uint8_t)pt->p_proto;
        }
        else
        {
            ParseError("invalid protocol name for \"ip_proto\" "
                       "rule option: '%s'.", data);
            return;
        }
    }
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter ip_proto_params[] =
{
    { "~proto", Parameter::PT_STRING, nullptr, nullptr, 
      "[!|>|<] name or number" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class IpProtoModule : public Module
{
public:
    IpProtoModule() : Module(s_name, ip_proto_params) { };

    bool begin(const char*, int, SnortConfig*);
    bool set(const char*, Value&, SnortConfig*);

    ProfileStats* get_profile() const
    { return &ipProtoPerfStats; };

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
        s_name,
        IPSAPI_PLUGIN_V0,
        0,
        mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    1, PROTO_BIT__IP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    ip_proto_ctor,
    ip_proto_dtor,
    nullptr
};

const BaseApi* ips_ip_proto = &ip_proto_api.base;


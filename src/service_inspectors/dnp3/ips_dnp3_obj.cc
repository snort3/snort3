//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// ips_dnp3_obj.cc author Maya Dagon <mdagon@cisco.com>
// based on work by Ryan Jordan

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hashfcn.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

#include "dnp3.h"

using namespace snort;

//-------------------------------------------------------------------------
// DNP3 object headers rule options
//-------------------------------------------------------------------------

#define s_name "dnp3_obj"
#define s_help \
    "detection option to check DNP3 object headers"

/* Object decoding constants */
#define DNP3_OBJ_HDR_MIN_LEN 3 /* group, var, qualifier */

static THREAD_LOCAL ProfileStats dnp3_obj_perf_stats;

static IpsOption::EvalStatus dnp3_decode_object(
    uint8_t* buf, uint16_t buflen, uint8_t rule_group, uint8_t rule_var)
{
    uint8_t group, var;

    if (buf == nullptr || buflen < DNP3_OBJ_HDR_MIN_LEN)
        return IpsOption::NO_MATCH;

    /* Decode group */
    group = *buf;
    buf++;

    /* Decode var */
    var = *buf;

    /* Match the rule option here, quit decoding if we found the right header. */
    if ((group == rule_group) && (var == rule_var))
        return IpsOption::MATCH;

    return IpsOption::NO_MATCH;
}

class Dnp3ObjOption : public IpsOption
{
public:
    Dnp3ObjOption(uint8_t obj_group, uint8_t obj_var) :
        IpsOption(s_name)
    { group = obj_group; var = obj_var; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;
    EvalStatus eval(Cursor&, Packet*) override;

private:
    uint8_t group;
    uint8_t var;
};

uint32_t Dnp3ObjOption::hash() const
{
    uint32_t a = group, b = var, c = 0;

    mix_str(a,b,c,get_name());
    finalize(a,b,c);

    return c;
}

bool Dnp3ObjOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    const Dnp3ObjOption& rhs = (const Dnp3ObjOption&)ips;

    return ((group == rhs.group) &&
           (var == rhs.var));
}

IpsOption::EvalStatus Dnp3ObjOption::eval(Cursor&, Packet* p)
{
    Profile profile(dnp3_obj_perf_stats);

    size_t header_size;

    if ((p->has_tcp_data() && !p->is_full_pdu()) || !p->flow || !p->dsize)
        return NO_MATCH;

    Dnp3FlowData* fd = (Dnp3FlowData*)p->flow->get_flow_data(Dnp3FlowData::inspector_id);

    if (!fd)
        return NO_MATCH;

    dnp3_session_data_t* dnp3_session = &fd->dnp3_session;
    dnp3_reassembly_data_t* rdata;

    if (dnp3_session->direction == DNP3_CLIENT)
    {
        rdata = &(dnp3_session->client_rdata);
        header_size = sizeof(dnp3_app_request_header_t);
    }
    else
    {
        rdata = &(dnp3_session->server_rdata);
        header_size = sizeof(dnp3_app_response_header_t);
    }

    /* Only evaluate rules against complete Application-layer fragments */
    if (rdata->state != DNP3_REASSEMBLY_STATE__DONE)
        return NO_MATCH;

    /* Skip over the App request/response header.
       They are different sizes, depending on whether it is a request or response! */
    if (rdata->buflen < header_size)
        return NO_MATCH;

    uint8_t* obj_buffer = (uint8_t*)rdata->buffer + header_size;
    uint16_t obj_buflen = rdata->buflen - header_size;

    return dnp3_decode_object(obj_buffer, obj_buflen, group, var);
}

//-------------------------------------------------------------------------
// dnp3_obj module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "group", Parameter::PT_INT, "0:255", "0",
      "match given DNP3 object header group" },
    { "var", Parameter::PT_INT, "0:255", "0",
      "match given DNP3 object header var" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class Dnp3ObjModule : public Module
{
public:
    Dnp3ObjModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;
    ProfileStats* get_profile() const override;

    Usage get_usage() const override
    { return DETECT; }

public:
    uint8_t group;
    uint8_t var;
};

bool Dnp3ObjModule::begin(const char*, int, SnortConfig*)
{
    group = 0;
    var = 0;
    return true;
}

bool Dnp3ObjModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("group") )
        group = v.get_long();
    else if ( v.is("var") )
        var = v.get_long();

    return true;
}

ProfileStats* Dnp3ObjModule::get_profile() const
{
    return &dnp3_obj_perf_stats;
}

//-------------------------------------------------------------------------
// dnp3_obj api
//-------------------------------------------------------------------------

static Module* dnp3_obj_mod_ctor()
{
    return new Dnp3ObjModule;
}

static void dnp3_obj_mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* dnp3_obj_ctor(Module* p, OptTreeNode*)
{
    Dnp3ObjModule* m = (Dnp3ObjModule*)p;
    return new Dnp3ObjOption(m->group, m->var);
}

static void dnp3_obj_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi dnp3_obj_api =
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
        dnp3_obj_mod_ctor,
        dnp3_obj_mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP | PROTO_BIT__UDP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    dnp3_obj_ctor,
    dnp3_obj_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// plugin
//-------------------------------------------------------------------------

// added to snort_plugins in dnp3.cc
const BaseApi* ips_dnp3_obj = &dnp3_obj_api.base;


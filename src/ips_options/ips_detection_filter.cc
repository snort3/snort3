//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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
// ips_detection_filter.cc author Russ Combs <rucombs@cisco.com>
// FIXIT-L add DetectionFilterOption::eval() instead of special case

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "filters/detection_filter.h"
#include "filters/sfthd.h"
#include "framework/decode_data.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "main/snort_config.h"

using namespace snort;

#define s_name "detection_filter"

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "track", Parameter::PT_ENUM, "by_src | by_dst", nullptr,
      "track hits by source or destination IP address" },

    { "count", Parameter::PT_INT, "1:max32", nullptr,
      "hits in interval before allowing the rule to fire" },

    { "seconds", Parameter::PT_INT, "1:max32", nullptr,
      "length of interval to count hits" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to require multiple hits before a rule generates an event"

class DetectionFilterModule : public Module
{
public:
    DetectionFilterModule() : Module(s_name, s_help, s_params) { }
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &detectionFilterPerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    bool trk_src = false;
    uint32_t count = 0, seconds = 0;
};

bool DetectionFilterModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("track") )
        trk_src = v.get_uint8() == 0;

    else if ( v.is("count") )
        count = v.get_uint32();

    else if ( v.is("seconds") )
        seconds = v.get_uint32();

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new DetectionFilterModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* detection_filter_ctor(Module* p, IpsInfo& info)
{
    DetectionFilterModule* m = (DetectionFilterModule*)p;
    IpsOption::set_detection_filter(info, m->trk_src, m->count, m->seconds);
    return nullptr;
}

static const IpsApi detection_filter_api =
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
    OPT_TYPE_META,
    1, PROTO_BIT__NONE,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    detection_filter_ctor,
    nullptr,
    nullptr
};

const BaseApi* ips_detection_filter[] =
{
    &detection_filter_api.base,
    nullptr
};


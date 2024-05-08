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
// ips_option.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ips_option.h"

#include <cstring>

#include "detection/rules.h"
#include "detection/signature.h"
#include "detection/treenodes.h"
#include "filters/detection_filter.h"
#include "filters/sfthd.h"
#include "framework/ips_info.h"
#include "hash/hash_key_operations.h"
#include "main/snort_config.h"
#include "managers/so_manager.h"
#include "parser/parse_conf.h"
#include "utils/util.h"

using namespace snort;

namespace snort
{
//-------------------------------------------------------------------------

IpsOption::IpsOption(const char* s, option_type_t t)
{
    name = s;
    type = t;
}

uint32_t IpsOption::hash() const
{
    uint32_t a = 0, b = 0, c = 0;
    mix_str(a, b, c, get_name());
    finalize(a, b, c);
    return c;
}

bool IpsOption::operator==(const IpsOption& ips) const
{
    return !strcmp(get_name(), ips.get_name());
}

section_flags IpsOption::get_pdu_section(bool) const
{
    return section_to_flag(PS_NONE);
}

//-------------------------------------------------------------------------
// static / instantiator methods
//-------------------------------------------------------------------------

bool IpsOption::has_plugin(IpsInfo& info, const char* name)
{ return otn_has_plugin(info.otn, name); }

void IpsOption::set_priority(const IpsInfo& info, uint32_t pri)
{ info.otn->sigInfo.priority = pri; }

void IpsOption::set_classtype(IpsInfo& info, const char* type)
{
    const ClassType* ct = get_classification(info.sc, type);

    if ( !ct and info.sc->dump_rule_info() )
    {
        add_classification(info.sc, type, type, 1);
        ct = get_classification(info.sc, type);
    }

    info.otn->sigInfo.class_type = ct;

    if ( ct )
    {
        info.otn->sigInfo.class_id = ct->id;
        info.otn->sigInfo.priority = ct->priority;
    }
}

void IpsOption::set_detection_filter(IpsInfo& info, bool track_src, uint32_t count, uint32_t seconds)
{
    THDX_STRUCT thdx = { };
    thdx.type = THD_TYPE_DETECT;
    thdx.tracking = (track_src ? THD_TRK_SRC : THD_TRK_DST);
    thdx.count = count;
    thdx.seconds = seconds;
    info.otn->detection_filter = detection_filter_create(info.sc->detection_filter_config, &thdx);
}

void IpsOption::set_enabled(IpsInfo& info, Enable ie)
{
    if ( !info.sc->rule_states )
        info.sc->rule_states = new RuleStateMap;

    IpsPolicy::Enable e;

    switch (ie)
    {
        case IpsOption::NO: e = IpsPolicy::DISABLED; break;
        case IpsOption::INHERIT: e = IpsPolicy::INHERIT_ENABLE; break;
        default: e = IpsPolicy::ENABLED; break;
    }
    info.otn->set_enabled(e);
}

void IpsOption::set_file_id(const IpsInfo& info, uint64_t fid)
{ info.otn->sigInfo.file_id = fid; }

void IpsOption::set_flowbits_check(IpsInfo& info)
{ info.otn->set_flowbits_check(); }

void IpsOption::set_stateless(IpsInfo& info)
{ info.otn->set_stateless(); }

void IpsOption::set_to_client(IpsInfo& info)
{ info.otn->set_to_client(); }

void IpsOption::set_to_server(IpsInfo& info)
{ info.otn->set_to_server(); }

void IpsOption::set_gid(const IpsInfo& info, uint32_t gid)
{ info.otn->sigInfo.gid = gid; }

void IpsOption::set_sid(const IpsInfo& info, uint32_t sid)
{ info.otn->sigInfo.sid = sid; }

void IpsOption::set_rev(const IpsInfo& info, uint32_t rev)
{ info.otn->sigInfo.rev = rev; }

void IpsOption::set_message(const IpsInfo& info, const char* msg)
{ info.otn->sigInfo.message = msg; }

void IpsOption::set_metadata_match(IpsInfo& info)
{ info.otn->set_metadata_match(); }

void IpsOption::set_tag(IpsInfo& info, TagData* td)
{ info.otn->tag = td; }

void IpsOption::set_target(const IpsInfo& info, bool src_ip)
{ info.otn->sigInfo.target = (src_ip ? TARGET_SRC : TARGET_DST); }

void IpsOption::add_reference(IpsInfo& info, const char* scheme, const char* id)
{ ::add_reference(info.sc, info.otn, scheme, id); }

void IpsOption::add_service(IpsInfo& info, const char* svc)
{ add_service_to_otn(info.sc, info.otn, svc); }

void IpsOption::set_soid(IpsInfo& info, const char* s)
{ info.otn->soid = snort_strdup(s); }

const char* IpsOption::get_soid(const IpsInfo& info)
{ return info.otn->soid; }

IpsOption::SoEvalFunc IpsOption::get_so_eval(IpsInfo& info, const char* name, void*& data)
{ return SoManager::get_so_eval(info.otn->soid, name, &data, info.sc); }

SnortProtocolId IpsOption::get_protocol_id(const IpsInfo& info)
{ return info.otn->snort_protocol_id; }

SoRules* IpsOption::get_so_rules(const IpsInfo& info)
{ return info.sc->so_rules; }

} // snort

//-------------------------------------------------------------------------
// UNIT TESTS
//-------------------------------------------------------------------------
#ifdef UNIT_TEST
#include "catch/snort_catch.h"

class StubIpsOption : public IpsOption
{
public:
    StubIpsOption(const char* name, option_type_t option_type) :
        IpsOption(name, option_type)
    { }
};

TEST_CASE("IpsOption test", "[ips_option]")
{
    StubIpsOption main_ips("ips_test",
        option_type_t::RULE_OPTION_TYPE_OTHER);

    SECTION("IpsOperator == test")
    {
        StubIpsOption case_diff_name("not_hello_world",
            option_type_t::RULE_OPTION_TYPE_LEAF_NODE);

        REQUIRE((main_ips == case_diff_name) == false);

        StubIpsOption case_diff_option("hello_world",
            option_type_t::RULE_OPTION_TYPE_CONTENT);
        REQUIRE((main_ips == case_diff_option) == false);

        StubIpsOption case_option_na("hello_world",
            option_type_t::RULE_OPTION_TYPE_OTHER);
        REQUIRE((main_ips == case_option_na) == false);
    }

    SECTION("hash test")
    {
        StubIpsOption other_main_ips("ips_test",
            option_type_t::RULE_OPTION_TYPE_OTHER);

        SECTION("hash test with short string")
        {
            StubIpsOption main_ips_short("ips_test",
                option_type_t::RULE_OPTION_TYPE_OTHER);
            REQUIRE((other_main_ips.hash() == main_ips_short.hash()) == true);

            StubIpsOption main_ips_short_diff("not_ips_test",
                option_type_t::RULE_OPTION_TYPE_OTHER);
            REQUIRE((other_main_ips.hash() == main_ips_short_diff.hash()) == false);
        }

        SECTION("hash test with long string")
        {
            std::string really_long_string =
                "101010101010101010101010101010101010101010101010101010101010101" \
                "101010101010101010101010101010101010101010101010101010101010101" \
                "101010101010101010101010101010101010101010101010101010101010101" \
                "101010101010101010101010101010101010101010101010101010101010101" \
                "101010101010101010101010101010101010101010101010101010101010101" \
                "101010101010101010101010101010101010101010101010101010101010101" \
                "101010101010101010101010101010101010101010101010101010101010101" \
                "101010101010101010101010101010101010101010101010101010101010101" \
                "101010101010101010101010101010101010101010101010101010101010101" \
                "101010101010101010101010101010101010101010101010101010101010101" \
                "101010101010101010101010101010101010101010101010101010101010101" \
                "101010101010101010101010101010101010101010101010101010101010101" \
                "101010101010101010101010101010101010101010101010101010101010101";

            StubIpsOption main_ips_long_first(really_long_string.c_str(),
                option_type_t::RULE_OPTION_TYPE_OTHER);
            StubIpsOption main_ips_long_second(really_long_string.c_str(),
                option_type_t::RULE_OPTION_TYPE_OTHER);
            REQUIRE(main_ips_long_first.hash() == main_ips_long_second.hash());

            REQUIRE(main_ips_long_first.hash() != other_main_ips.hash());
        }
    }
}

#endif

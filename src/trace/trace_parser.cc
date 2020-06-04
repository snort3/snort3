//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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
// trace_parser.cc author Oleksandr Serhiienko <oserhiie@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "trace_parser.h"

#include "framework/module.h"
#include "framework/packet_constraints.h"
#include "managers/module_manager.h"

#include "trace_config.h"

using namespace snort;

std::map<std::string, std::map<std::string, bool>> TraceParser::s_configured_trace_options;

TraceParser::TraceParser(TraceConfig* tc)
    : trace_config(tc)
{
    assert(trace_config);

    // Will be initialized only once when first TraceParser instance created
    if ( s_configured_trace_options.empty() )
        init_configured_trace_options();
    else
        reset_configured_trace_options();
}

bool TraceParser::set_traces(const std::string& module_name, const Value& val)
{
    if ( !s_configured_trace_options.count(module_name) )
        return false;

    if ( val.is(DEFAULT_TRACE_OPTION_NAME) )
    {
        const auto& trace_options = s_configured_trace_options[module_name];
        for ( const auto& trace_option : trace_options )
        {
            if ( !trace_option.second )
                trace_config->set_trace(module_name, trace_option.first, val.get_uint8());
        }

        return true;
    }
    else
    {
        bool res = trace_config->set_trace(module_name, val.get_name(), val.get_uint8());
        s_configured_trace_options[module_name][val.get_name()] = res;
        return res;
    }
}

bool TraceParser::set_constraints(const Value& val)
{
    if ( !trace_config->constraints )
        trace_config->constraints = new PacketConstraints;

    auto& cs = *trace_config->constraints;

    if ( val.is("ip_proto") )
    {
        cs.ip_proto = static_cast<IpProtocol>(val.get_uint8());
        cs.set_bits |= PacketConstraints::SetBits::IP_PROTO;
    }
    else if ( val.is("src_port") )
    {
        cs.src_port = val.get_uint16();
        cs.set_bits |= PacketConstraints::SetBits::SRC_PORT;
    }
    else if ( val.is("dst_port") )
    {
        cs.dst_port = val.get_uint16();
        cs.set_bits |= PacketConstraints::SetBits::DST_PORT;
    }
    else if ( val.is("src_ip") )
    {
        const char* str = val.get_string();
        if ( cs.src_ip.set(str) != SFIP_SUCCESS )
            return false;

        cs.set_bits |= PacketConstraints::SetBits::SRC_IP;
    }
    else if ( val.is("dst_ip") )
    {
        const char* str = val.get_string();
        if ( cs.dst_ip.set(str) != SFIP_SUCCESS )
            return false;

        cs.set_bits |= PacketConstraints::SetBits::DST_IP;
    }
    else
        return false;

    return true;
}

void TraceParser::clear_traces()
{ trace_config->clear_traces(); }

void TraceParser::clear_constraints()
{
    delete trace_config->constraints;
    trace_config->constraints = nullptr;
}

void TraceParser::reset_configured_trace_options()
{
    for ( auto& module_trace_options : s_configured_trace_options )
    {
        for ( auto& trace_options : module_trace_options.second )
            trace_options.second = false;
    }
}

void TraceParser::init_configured_trace_options()
{
    auto trace_modules = ModuleManager::get_all_modules();
    for ( const auto* module : trace_modules )
    {
        const TraceOption* trace_options = module->get_trace_options();
        if ( trace_options )
        {
            auto& module_trace_options = s_configured_trace_options[module->get_name()];
            if ( !trace_options->name )
                module_trace_options[DEFAULT_TRACE_OPTION_NAME] = false;

            while ( trace_options->name )
            {
                module_trace_options[trace_options->name] = false;
                ++trace_options;
            }
        }
    }
}

#ifdef UNIT_TEST

#include <catch/snort_catch.h>

TEST_CASE("packet constraints", "[TraceParser]")
{
    TraceConfig tc;
    TraceParser tp(&tc);

    SECTION("ip_proto")
    {
        const Parameter ip_proto_param("ip_proto", Parameter::PT_INT, "0:255", nullptr,
            "test ip_proto param");

        Value val(false);
        val.set(&ip_proto_param);

        val.set(6l);
        CHECK( tp.set_constraints(val) );
    }
    SECTION("src_ip")
    {
        const Parameter src_ip_param("src_ip", Parameter::PT_STRING, nullptr, nullptr,
          "test src_ip param");

        Value val(false);
        val.set(&src_ip_param);

        val.set("10.1.2.3");
        CHECK( tp.set_constraints(val) );

        val.set("10.1.2.300");
        CHECK( !tp.set_constraints(val) );
    }
    SECTION("src_port")
    {
        const Parameter src_port_param("src_port", Parameter::PT_INT, "0:65535", nullptr,
          "test src_port param");

        Value val(false);
        val.set(&src_port_param);

        val.set(100l);
        CHECK( tp.set_constraints(val) );
    }
    SECTION("dst_ip")
    {
        const Parameter dst_ip_param("dst_ip", Parameter::PT_STRING, nullptr, nullptr,
          "test dst_ip param");

        Value val(false);
        val.set(&dst_ip_param);

        val.set("10.3.2.1");
        CHECK( tp.set_constraints(val) );

        val.set("10.300.2.1");
        CHECK( !tp.set_constraints(val) );
    }
    SECTION("dst_port")
    {
        const Parameter dst_port_param("dst_port", Parameter::PT_INT, "0:65535", nullptr,
          "test dst_port param");

        Value val(false);
        val.set(&dst_port_param);

        val.set(200l);
        CHECK( tp.set_constraints(val) );
    }
    SECTION("invalid_param")
    {
        const Parameter invalid_param("invalid_param", Parameter::PT_INT, "0:8", nullptr,
          "test invalid param");

        Value val(false);
        val.set(&invalid_param);

        val.set(5l);
        CHECK( !tp.set_constraints(val) );
    }
}

TEST_CASE("modules traces", "[TraceParser]")
{
    TraceConfig tc;
    TraceParser tp(&tc);

    SECTION("set_option")
    {
        const Parameter detection_rule_eval("rule_eval", Parameter::PT_INT, "0:255", nullptr,
            "test detection_rule_eval param");

        const Parameter detection_detect_engine("detect_engine", Parameter::PT_INT, "0:255", nullptr,
            "test detection_detect_engine param");

        Value val_opt1(false);
        Value val_opt2(false);
        val_opt1.set(&detection_rule_eval);
        val_opt2.set(&detection_detect_engine);

        val_opt1.set(1l);
        CHECK( tp.set_traces("detection", val_opt1) );

        val_opt2.set(1l);
        CHECK( tp.set_traces("detection", val_opt2) );
    }
    SECTION("set_all")
    {
        const Parameter decode_all(DEFAULT_TRACE_OPTION_NAME, Parameter::PT_INT, "0:255", nullptr,
            "test decode_all param");

        Value val_all(false);
        val_all.set(&decode_all);

        val_all.set(1l);
        CHECK( tp.set_traces("decode", val_all) );
        CHECK( tp.set_traces("detection", val_all) );
    }
    SECTION("set_invalid_option")
    {
        const Parameter invalid_param("invalid_opt", Parameter::PT_INT, "0:255", nullptr,
            "test invalid param");

        Value invalid_val(false);
        invalid_val.set(&invalid_param);

        invalid_val.set(1l);
        CHECK( !tp.set_traces("detection", invalid_val) );
    }
    SECTION("set_invalid_module")
    {
        const Parameter all_param(DEFAULT_TRACE_OPTION_NAME, Parameter::PT_INT, "0:255", nullptr,
            "test all param");

        Value val(false);
        val.set(&all_param);

        val.set(1l);
        CHECK( !tp.set_traces("invalid_module", val) );
    }
}

#endif // UNIT_TEST


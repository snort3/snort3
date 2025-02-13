//--------------------------------------------------------------------------
// Copyright (C) 2020-2025 Cisco and/or its affiliates. All rights reserved.
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
#include "managers/module_manager.h"
#include "utils/util.h"

#include "trace_config.h"

using namespace snort;

std::map<std::string, std::map<std::string, bool>> TraceParser::s_configured_trace_options;

TraceParser::TraceParser(TraceConfig& tc)
    : trace_config(tc)
{
    // Will be initialized only once when first TraceParser instance created
    if (s_configured_trace_options.empty())
        init_configured_trace_options();
    else
        reset_configured_trace_options();
}

bool TraceParser::set_traces(const std::string& module_name, const Value& val)
{
    if (!s_configured_trace_options.count(module_name) 
        and module_name != DEFAULT_TRACE_OPTION_NAME)
        return false;

    if (module_name == DEFAULT_TRACE_OPTION_NAME)
    {
        for (const auto& trace_options : s_configured_trace_options)
        {
            if (trace_options.second.at(DEFAULT_TRACE_OPTION_NAME))
                continue;

            for (const auto& trace_option : trace_options.second)
            {
                if (!trace_option.second)
                    trace_config.set_trace(trace_options.first, trace_option.first,
                        val.get_uint8());
            }
        }

        return true;
    }
    else if (val.is(DEFAULT_TRACE_OPTION_NAME))
    {
        auto& trace_options = s_configured_trace_options[module_name];
        for (const auto& trace_option : trace_options)
        {
            if (!trace_option.second)
                trace_config.set_trace(module_name, trace_option.first, val.get_uint8());
        }
        trace_options[DEFAULT_TRACE_OPTION_NAME] = true;

        return true;
    }
    else
    {
        bool res = trace_config.set_trace(module_name, val.get_name(), val.get_uint8());
        s_configured_trace_options[module_name][val.get_name()] = res;
        return res;
    }
}

bool TraceParser::set_constraints(const Value& val)
{
    if (val.is("ip_proto"))
    {
        parsed_constraints.ip_proto = static_cast<IpProtocol>(val.get_uint8());
        parsed_constraints.set_bits |= PacketConstraints::SetBits::IP_PROTO;
    }
    else if (val.is("src_port"))
    {
        parsed_constraints.src_port = val.get_uint16();
        parsed_constraints.set_bits |= PacketConstraints::SetBits::SRC_PORT;
    }
    else if (val.is("dst_port"))
    {
        parsed_constraints.dst_port = val.get_uint16();
        parsed_constraints.set_bits |= PacketConstraints::SetBits::DST_PORT;
    }
    else if (val.is("src_ip"))
    {
        const char* str = val.get_string();
        if (parsed_constraints.src_ip.set(str) != SFIP_SUCCESS)
            return false;

        parsed_constraints.set_bits |= PacketConstraints::SetBits::SRC_IP;
    }
    else if (val.is("dst_ip"))
    {
        const char* str = val.get_string();
        if (parsed_constraints.dst_ip.set(str) != SFIP_SUCCESS)
            return false;

        parsed_constraints.set_bits |= PacketConstraints::SetBits::DST_IP;
    }
    else if (val.is("match"))
        parsed_constraints.match = val.get_bool();
    else if (val.is("tenants"))
    {
        const char* tenants_str = val.get_string();
        if (!tenants_str)
            return false;

        str_to_int_vector(tenants_str, ',', parsed_constraints.tenants);
        parsed_constraints.set_bits |= PacketConstraints::SetBits::TENANT;
    }
    else
        return false;

    return true;
}

void TraceParser::finalize_constraints()
{
    if (!parsed_constraints.match or parsed_constraints.set_bits)
        trace_config.constraints = new PacketConstraints(parsed_constraints);
}

void TraceParser::clear_traces()
{ trace_config.clear_traces(); }

void TraceParser::clear_constraints()
{
    delete trace_config.constraints;
    trace_config.constraints = nullptr;
}

void TraceParser::reset_configured_trace_options()
{
    for (auto& module_trace_options : s_configured_trace_options)
    {
        for (auto& trace_options : module_trace_options.second)
            trace_options.second = false;
    }
}

void TraceParser::init_configured_trace_options()
{
    auto trace_modules = ModuleManager::get_all_modules();
    for (const auto* module : trace_modules)
    {
        const TraceOption* trace_options = module->get_trace_options();
        if (!trace_options)
            continue;

        auto& module_trace_options = s_configured_trace_options[module->get_name()];

        module_trace_options[DEFAULT_TRACE_OPTION_NAME] = false;
        while (trace_options->name)
        {
            module_trace_options[trace_options->name] = false;
            ++trace_options;
        }
    }
}

#ifdef UNIT_TEST

#include <catch/snort_catch.h>

#include "main/snort_config.h"

#define CONFIG_OPTION(name, value, type, range)                         \
    const Parameter name##_param(                                       \
        #name, type, range, nullptr, #name " test");                    \
    Value name(false);                                                  \
    name.set(&name##_param);                                            \
    name.set(value)

#define MODULE_OPTION(name, value) \
    CONFIG_OPTION(name, (uint64_t)value, Parameter::PT_INT, "0:255")

#define PROTO_OPTION(name, value) \
    CONFIG_OPTION(name, (uint64_t)value, Parameter::PT_INT, "0:255")

#define ADDR_OPTION(name, value) \
    CONFIG_OPTION(name, value, Parameter::PT_STRING, nullptr)

#define PORT_OPTION(name, value) \
    CONFIG_OPTION(name, (uint64_t)value, Parameter::PT_INT, "0:65535")

#define TENANT_OPTION(name, value) \
    CONFIG_OPTION(name, value, Parameter::PT_STRING, nullptr)

enum { OPT_1, OPT_2 };

static const TraceOption s_trace_options[] =
{
    { "option1", OPT_1, "test option 1" },
    { "option2", OPT_2, "test option 2" },
    { nullptr, 0, nullptr }
};

static const Trace *m1_trace, *m2_trace;

class Module1 : public Module
{
public:
    Module1() : Module("mod_1", "testing trace parser module 1") { }
    void set_trace(const Trace* t) const override { m1_trace = t; }
    const TraceOption* get_trace_options() const override { return s_trace_options; }

};

class Module2 : public Module
{
public:
    Module2() : Module("mod_2", "testing trace parser module 2") { }
    void set_trace(const Trace* t) const override { m2_trace = t; }
    const TraceOption* get_trace_options() const override { return s_trace_options; }

};

TEST_CASE("modules traces", "[TraceParser]")
{
    static bool once = []()
    {
        ModuleManager::add_module(new Module1);
        ModuleManager::add_module(new Module2);
        return true;
    } ();
    (void)once;

    TraceConfig tc;
    TraceParser tp(tc);
    tc.setup_module_trace();

    SECTION("invalid module")
    {
        MODULE_OPTION(all, 10);
        CHECK(false == tp.set_traces("invalid_module", all));
    }

    SECTION("invalid option")
    {
        MODULE_OPTION(invalid_option, 10);
        CHECK(false == tp.set_traces("mod_1", invalid_option));
    }

    SECTION("unset")
    {
        REQUIRE(m1_trace != nullptr);
        REQUIRE(m2_trace != nullptr);

        CHECK(false == m1_trace->enabled(OPT_1));
        CHECK(false == m1_trace->enabled(OPT_2));
        CHECK(false == m2_trace->enabled(OPT_1));
        CHECK(false == m2_trace->enabled(OPT_2));
    }

    SECTION("all modules")
    {
        MODULE_OPTION(all, 3);
        CHECK(true == tp.set_traces("all", all));

        REQUIRE(m1_trace != nullptr);
        REQUIRE(m2_trace != nullptr);

        CHECK(true == m1_trace->enabled(OPT_1, 3));
        CHECK(true == m1_trace->enabled(OPT_2, 3));
        CHECK(true == m2_trace->enabled(OPT_1, 3));
        CHECK(true == m2_trace->enabled(OPT_2, 3));

        CHECK(false == m1_trace->enabled(OPT_1, 4));
        CHECK(false == m1_trace->enabled(OPT_2, 4));
        CHECK(false == m2_trace->enabled(OPT_1, 4));
        CHECK(false == m2_trace->enabled(OPT_2, 4));
    }

    SECTION("module all")
    {
        MODULE_OPTION(all, 3);
        CHECK(true == tp.set_traces("mod_1", all));

        REQUIRE(m1_trace != nullptr);
        REQUIRE(m2_trace != nullptr);

        CHECK(true == m1_trace->enabled(OPT_1, 3));
        CHECK(true == m1_trace->enabled(OPT_2, 3));
        CHECK(false == m2_trace->enabled(OPT_1, 3));
        CHECK(false == m2_trace->enabled(OPT_2, 3));
    }

    SECTION("options")
    {
        MODULE_OPTION(option1, 1);
        MODULE_OPTION(option2, 5);
        CHECK(true == tp.set_traces("mod_1", option1));
        CHECK(true == tp.set_traces("mod_1", option2));
        CHECK(true == tp.set_traces("mod_2", option1));
        CHECK(true == tp.set_traces("mod_2", option2));

        REQUIRE(m1_trace != nullptr);
        REQUIRE(m2_trace != nullptr);

        CHECK(true == m1_trace->enabled(OPT_1, 1));
        CHECK(true == m1_trace->enabled(OPT_2, 1));
        CHECK(true == m2_trace->enabled(OPT_1, 1));
        CHECK(true == m2_trace->enabled(OPT_2, 1));

        CHECK(false == m1_trace->enabled(OPT_1, 5));
        CHECK(true == m1_trace->enabled(OPT_2, 5));
        CHECK(false == m2_trace->enabled(OPT_1, 5));
        CHECK(true == m2_trace->enabled(OPT_2, 5));
    }

    SECTION("override all modules")
    {
        MODULE_OPTION(option1, 1);
        MODULE_OPTION(option2, 2);
        MODULE_OPTION(all, 3);
        CHECK(true == tp.set_traces("mod_1", option1));
        CHECK(true == tp.set_traces("mod_2", option2));
        CHECK(true == tp.set_traces("all", all));

        REQUIRE(m1_trace != nullptr);
        REQUIRE(m2_trace != nullptr);

        CHECK(true == m1_trace->enabled(OPT_1, 1));
        CHECK(true == m1_trace->enabled(OPT_2, 1));
        CHECK(true == m2_trace->enabled(OPT_1, 1));
        CHECK(true == m2_trace->enabled(OPT_2, 1));

        CHECK(false == m1_trace->enabled(OPT_1, 2));
        CHECK(true == m1_trace->enabled(OPT_2, 2));
        CHECK(true == m2_trace->enabled(OPT_1, 2));
        CHECK(true == m2_trace->enabled(OPT_2, 2));

        CHECK(false == m1_trace->enabled(OPT_1, 3));
        CHECK(true == m1_trace->enabled(OPT_2, 3));
        CHECK(true == m2_trace->enabled(OPT_1, 3));
        CHECK(false == m2_trace->enabled(OPT_2, 3));
    }

    auto sc = SnortConfig::get_conf();
    if (sc and sc->trace_config)
        sc->trace_config->setup_module_trace();
}

TEST_CASE("packet constraints", "[TraceParser]")
{
    TraceConfig tc;
    TraceParser tp(tc);

    SECTION("ip_proto")
    {
        PROTO_OPTION(ip_proto, 6);
        const PacketConstraints exp = PacketConstraints(IpProtocol::TCP, 0, 0,
            SfIp(), SfIp(), PacketConstraints::IP_PROTO, true);

        CHECK(true == tp.set_constraints(ip_proto));
        tp.finalize_constraints();

        REQUIRE(tc.constraints != nullptr);
        CHECK(tc.constraints->set_bits == exp.set_bits);
        CHECK(tc.constraints->ip_proto == exp.ip_proto);
        CHECK(*tc.constraints == exp);
    }

    SECTION("src_ip")
    {
        ADDR_OPTION(src_ip, "10.1.2.3");
        const uint32_t exp_ip = 0x0302010a;
        const PacketConstraints exp = PacketConstraints(IpProtocol::PROTO_NOT_SET, 0, 0,
            SfIp(&exp_ip, AF_INET), SfIp(), PacketConstraints::SRC_IP, true);

        CHECK(true == tp.set_constraints(src_ip));
        tp.finalize_constraints();

        REQUIRE(tc.constraints != nullptr);
        CHECK(tc.constraints->set_bits == exp.set_bits);
        CHECK(tc.constraints->src_ip == exp.src_ip);
        CHECK(*tc.constraints == exp);
    }

    SECTION("invalid src_ip")
    {
        ADDR_OPTION(src_ip, "10.1.2.300");
        CHECK(false == tp.set_constraints(src_ip));
    }

    SECTION("src_port")
    {
        const PacketConstraints exp = PacketConstraints(IpProtocol::PROTO_NOT_SET, 100, 0,
            SfIp(), SfIp(), PacketConstraints::SRC_PORT, true);
        PORT_OPTION(src_port, 100);

        CHECK(true == tp.set_constraints(src_port));
        tp.finalize_constraints();

        REQUIRE(tc.constraints != nullptr);
        CHECK(tc.constraints->set_bits == exp.set_bits);
        CHECK(tc.constraints->src_port == exp.src_port);
        CHECK(*tc.constraints == exp);
    }

    SECTION("dst_ip")
    {
        ADDR_OPTION(dst_ip, "10.3.2.1");
        const uint32_t exp_ip = 0x0102030a;
        const PacketConstraints exp = PacketConstraints(IpProtocol::PROTO_NOT_SET, 0, 0,
            SfIp(), SfIp(&exp_ip, AF_INET), PacketConstraints::DST_IP, true);

        CHECK(true == tp.set_constraints(dst_ip));
        tp.finalize_constraints();

        REQUIRE(tc.constraints != nullptr);
        CHECK(tc.constraints->set_bits == exp.set_bits);
        CHECK(tc.constraints->dst_ip == exp.dst_ip);
        CHECK(*tc.constraints == exp);
    }

    SECTION("invalid dst_ip")
    {
        ADDR_OPTION(dst_ip, "10.300.2.1");
        CHECK(false == tp.set_constraints(dst_ip));
    }

    SECTION("dst_port")
    {
        PORT_OPTION(dst_port, 200);
        const PacketConstraints exp = PacketConstraints(IpProtocol::PROTO_NOT_SET, 0, 200,
            SfIp(), SfIp(), PacketConstraints::DST_PORT, true);

        CHECK(true == tp.set_constraints(dst_port));
        tp.finalize_constraints();

        REQUIRE(tc.constraints != nullptr);
        CHECK(tc.constraints->set_bits == exp.set_bits);
        CHECK(tc.constraints->dst_port == exp.dst_port);
        CHECK(*tc.constraints == exp);
    }

    SECTION("invalid option")
    {
        CONFIG_OPTION(invalid_option, (uint64_t)5, Parameter::PT_INT, "0:8");
        CHECK(false == tp.set_constraints(invalid_option));
    }

    SECTION("tenants")
    {
        TENANT_OPTION(tenants, "11,12");
        const auto expected_tenants = std::vector<uint32_t>{ 11, 12 };
        
        const PacketConstraints expected_constraints = PacketConstraints(IpProtocol::PROTO_NOT_SET, 0, 0,
            SfIp(), SfIp(), PacketConstraints::TENANT, true, expected_tenants);

        CHECK(true == tp.set_constraints(tenants));
        tp.finalize_constraints();

        REQUIRE(tc.constraints != nullptr);
        CHECK(*tc.constraints == expected_constraints);
    }
}

#endif // UNIT_TEST

//--------------------------------------------------------------------------
// Copyright (C) 2026 Cisco and/or its affiliates. All rights reserved.
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
// socks_ips_test.cc author Raza Shafiq <rshafiq@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "../socks_flow_data.h"
#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hash_key_operations.h"
#include "protocols/packet.h"
#include "service_inspectors/socks/socks_module.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

static snort::FlowData* stored_flow_data = nullptr;

namespace snort
{
unsigned FlowData::flow_data_id = 0;

unsigned FlowData::create_flow_data_id()
{ return ++flow_data_id; }

FlowData::FlowData(unsigned u) : id(u) {}
FlowData::~FlowData() = default;

FlowDataStore::~FlowDataStore() = default;
FlowData* FlowDataStore::get(unsigned) const { return stored_flow_data; }
void FlowDataStore::set(FlowData* fd) { stored_flow_data = fd; }
void FlowDataStore::erase(unsigned) {}
void FlowDataStore::erase(FlowData*) {}
void FlowDataStore::clear() {}
bool FlowDataStore::empty() const { return stored_flow_data == nullptr; }
void FlowDataStore::call_handlers(Packet*, FlowDataHandlerType) const {}

Flow::~Flow() = default;

// cppcheck-suppress uninitMemberVar ; mock class - only data/dsize used in tests
Packet::Packet(bool) { }
Packet::~Packet() = default;

// cppcheck-suppress uninitMemberVar ; mock IpsOption does not init base members
IpsOption::IpsOption(const char*, option_type_t) { }
uint32_t IpsOption::hash() const { return 0; }
bool IpsOption::operator==(const IpsOption&) const { return true; }
uint16_t IpsOption::get_pdu_section(bool) const { return 0; }

// cppcheck-suppress uninitMemberVar ; mock Module does not init base members
Module::Module(const char*, const char*) { }
// cppcheck-suppress uninitMemberVar ; mock Module does not init base members
Module::Module(const char*, const char*, const Parameter*, bool) { }
void Module::sum_stats(bool) { }
void Module::show_interval_stats(std::vector<unsigned>&, FILE*) { }
void Module::show_stats() { }
void Module::init_stats(bool) { }
void Module::reset_stats() { }
void Module::main_accumulate_stats() { }
PegCount Module::get_global_count(char const*) const { return 0; }

uint64_t Parameter::get_uint(const char* r)
{
    bool ok = false;
    return Parameter::get_uint(r, ok);
}

uint64_t Parameter::get_uint(const char* r, bool& is_correct)
{
    char* end = nullptr;
    uint64_t value = strtoull(r, &end, 0);
    is_correct = (end && *end == '\0');
    return value;
}

void mix_str(uint32_t&, uint32_t&, uint32_t&, const char*, unsigned) { }

THREAD_LOCAL bool TimeProfilerStats::enabled = false;
}

THREAD_LOCAL SocksStats socks_stats = {};
THREAD_LOCAL snort::ProfileStats socksPerfStats = {};

#include "../socks_ips.cc"

TEST_GROUP(SocksIpsStateTest)
{
    void setup() override
    {
        SocksFlowData::init();
        stored_flow_data = nullptr;
    }

    void teardown() override
    {
        stored_flow_data = nullptr;
    }
};

TEST(SocksIpsStateTest, no_flow_or_flow_data_no_match)
{
    SocksStateOption opt(SOCKS_STATE_CLASS_ESTABLISHED);
    Cursor c;
    Packet p(true);

    p.flow = nullptr;
    CHECK_EQUAL(IpsOption::NO_MATCH, opt.eval(c, &p));

    snort::Flow f;
    p.flow = &f;
    stored_flow_data = nullptr;
    CHECK_EQUAL(IpsOption::NO_MATCH, opt.eval(c, &p));
}

TEST(SocksIpsStateTest, state_class_mapping_matches)
{
    SocksStateOption opt_auth(SOCKS_STATE_CLASS_AUTH);
    SocksStateOption opt_req(SOCKS_STATE_CLASS_REQUEST_RESPONSE);
    SocksStateOption opt_est(SOCKS_STATE_CLASS_ESTABLISHED);
    SocksStateOption opt_err(SOCKS_STATE_CLASS_ERROR);

    SocksFlowData fd;
    snort::Flow f;
    f.set_flow_data(&fd);

    Packet p(true);
    p.flow = &f;
    Cursor c;

    fd.set_state(SOCKS_STATE_INIT);
    CHECK_EQUAL(IpsOption::NO_MATCH, opt_auth.eval(c, &p));

    fd.set_state(SOCKS_STATE_V5_AUTH_NEGOTIATION);
    CHECK_EQUAL(IpsOption::MATCH, opt_auth.eval(c, &p));

    fd.set_state(SOCKS_STATE_V5_CONNECT_RESPONSE);
    CHECK_EQUAL(IpsOption::MATCH, opt_req.eval(c, &p));

    fd.set_state(SOCKS_STATE_ESTABLISHED);
    CHECK_EQUAL(IpsOption::MATCH, opt_est.eval(c, &p));

    fd.set_state(SOCKS_STATE_ERROR);
    CHECK_EQUAL(IpsOption::MATCH, opt_err.eval(c, &p));
}

TEST(SocksIpsStateTest, parses_named_and_numeric_states)
{
    SocksStateModule mod;
    Value v_named("established");
    v_named.set(&socks_state_params[0]);
    CHECK_TRUE(mod.set(nullptr, v_named, nullptr));
    CHECK_EQUAL(SOCKS_STATE_CLASS_ESTABLISHED, mod.state_class);

    Value v_numeric("3");
    v_numeric.set(&socks_state_params[0]);
    CHECK_TRUE(mod.set(nullptr, v_numeric, nullptr));
    CHECK_EQUAL(SOCKS_STATE_CLASS_ESTABLISHED, mod.state_class);

    Value v_invalid("0");
    v_invalid.set(&socks_state_params[0]);
    CHECK_FALSE(mod.set(nullptr, v_invalid, nullptr));
}

TEST(SocksIpsStateTest, socks_version_matches)
{
    SocksVersionOption opt(SOCKS5_VERSION);
    Cursor c;
    Packet p(true);

    SocksFlowData fd;
    snort::Flow f;
    f.set_flow_data(&fd);
    p.flow = &f;

    fd.set_socks_version(SOCKS5_VERSION);
    CHECK_EQUAL(IpsOption::MATCH, opt.eval(c, &p));

    fd.set_socks_version(SOCKS4_VERSION);
    CHECK_EQUAL(IpsOption::NO_MATCH, opt.eval(c, &p));
}

TEST(SocksIpsStateTest, socks_command_matches_when_target_set)
{
    SocksCommandOption opt(SOCKS_CMD_CONNECT);
    Cursor c;
    Packet p(true);

    SocksFlowData fd;
    snort::Flow f;
    f.set_flow_data(&fd);
    p.flow = &f;

    fd.set_command(SOCKS_CMD_CONNECT);
    fd.set_target_address("10.0.0.1");
    CHECK_EQUAL(IpsOption::MATCH, opt.eval(c, &p));

    fd.set_command(SOCKS_CMD_BIND);
    CHECK_EQUAL(IpsOption::NO_MATCH, opt.eval(c, &p));

    fd.set_command(SOCKS_CMD_CONNECT);
    fd.set_target_address("");
    CHECK_EQUAL(IpsOption::NO_MATCH, opt.eval(c, &p));
}

TEST(SocksIpsStateTest, socks_address_type_matches_when_target_set)
{
    Socks5AddressTypeOption opt(SOCKS_ATYP_DOMAIN);
    Cursor c;
    Packet p(true);

    SocksFlowData fd;
    snort::Flow f;
    f.set_flow_data(&fd);
    p.flow = &f;

    fd.set_target("example.com", SOCKS_ATYP_DOMAIN, 80);
    CHECK_EQUAL(IpsOption::MATCH, opt.eval(c, &p));

    fd.set_address_type(SOCKS_ATYP_IPV4);
    CHECK_EQUAL(IpsOption::NO_MATCH, opt.eval(c, &p));

    fd.set_target_address("");
    CHECK_EQUAL(IpsOption::NO_MATCH, opt.eval(c, &p));
}

TEST(SocksIpsStateTest, socks_remote_address_matches_and_sets_cursor)
{
    SocksRemoteAddressOption opt_match("example");
    SocksRemoteAddressOption opt_cursor;
    Cursor c;
    Packet p(true);

    SocksFlowData fd;
    snort::Flow f;
    f.set_flow_data(&fd);
    p.flow = &f;

    const std::string addr = "bad.example.com";
    fd.set_target_address(addr);

    CHECK_EQUAL(IpsOption::MATCH, opt_match.eval(c, &p));

    CHECK_EQUAL(IpsOption::MATCH, opt_cursor.eval(c, &p));
    CHECK_TRUE(c.get_name() != nullptr);
    CHECK_EQUAL(0, strcmp(c.get_name(), "socks_remote_address"));
    CHECK_EQUAL(addr.size(), c.size());
    const std::string buf(reinterpret_cast<const char*>(c.buffer()), c.size());
    CHECK_EQUAL(addr, buf);
}

TEST(SocksIpsStateTest, socks_remote_port_matches)
{
    SocksRemotePortOption opt(443);
    Cursor c;
    Packet p(true);

    SocksFlowData fd;
    snort::Flow f;
    f.set_flow_data(&fd);
    p.flow = &f;

    fd.set_target_port(443);
    CHECK_EQUAL(IpsOption::MATCH, opt.eval(c, &p));

    fd.set_target_port(80);
    CHECK_EQUAL(IpsOption::NO_MATCH, opt.eval(c, &p));
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

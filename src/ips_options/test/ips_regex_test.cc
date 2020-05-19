//--------------------------------------------------------------------------
// Copyright (C) 2015-2020 Cisco and/or its affiliates. All rights reserved.
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

// ips_regex_test.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/base_api.h"
#include "framework/counts.h"
#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "main/snort_config.h"
#include "profiler/profiler_defs.h"
#include "protocols/packet.h"

// must appear after snort_config.h to avoid broken c++ map include
#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

//-------------------------------------------------------------------------
// stubs, spies, etc.
//-------------------------------------------------------------------------

namespace snort
{

void mix_str(uint32_t& a, uint32_t&, uint32_t&, const char* s, unsigned)
{ a += strlen(s); }

SnortConfig s_conf;
THREAD_LOCAL SnortConfig* snort_conf = &s_conf;

static std::vector<void *> s_state;
static ScratchAllocator* scratcher = nullptr;

SnortConfig::SnortConfig(const SnortConfig* const)
{
    state = &s_state;
    num_slots = 1;
}

SnortConfig::~SnortConfig() = default;

int SnortConfig::request_scratch(ScratchAllocator* s)
{
    scratcher = s;
    s_state.resize(1);
    return 0;
}

void SnortConfig::release_scratch(int) { }

const SnortConfig* SnortConfig::get_conf()
{ return snort_conf; }

Packet::Packet(bool) { }
Packet::~Packet() = default;

static unsigned s_parse_errors = 0;

void ParseError(const char*, ...)
{ s_parse_errors++; }

unsigned get_instance_id()
{ return 0; }

char* snort_strdup(const char* s)
{ return strdup(s); }

MemoryContext::MemoryContext(MemoryTracker&) { }
MemoryContext::~MemoryContext() = default;

bool TimeProfilerStats::enabled = false;
}

extern const BaseApi* ips_regex;

Cursor::Cursor(Packet* p)
{ set("pkt_data", p->data, p->dsize); }

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, const IndexVec&, const char*, FILE*) { }

//-------------------------------------------------------------------------
// helpers
//-------------------------------------------------------------------------

static const Parameter* get_param(Module* m, const char* s)
{
    const Parameter* p = m->get_parameters();

    while ( p and p->name )
    {
        if ( !strcmp(p->name, s) )
            return p;
        ++p;
    }
    return nullptr;
}

static IpsOption* get_option(Module* mod, const char* pat, bool relative = false)
{
    mod->begin(ips_regex->name, 0, nullptr);

    Value vs(pat);
    vs.set(get_param(mod, "~re"));
    mod->set(ips_regex->name, vs, nullptr);

    if ( relative )
    {
        Value vb(relative);
        vb.set(get_param(mod, "relative"));
        mod->set(ips_regex->name, vb, nullptr);
    }
    mod->end(ips_regex->name, 0, nullptr);

    const IpsApi* api = (const IpsApi*) ips_regex;
    IpsOption* opt = api->ctor(mod, nullptr);

    return opt;
}

//-------------------------------------------------------------------------
// base tests
//-------------------------------------------------------------------------

TEST_GROUP(ips_regex_base)
{
    void setup() override
    { CHECK(ips_regex); }
};

TEST(ips_regex_base, base)
{
    CHECK(ips_regex->type == PT_IPS_OPTION);
    CHECK(ips_regex->name);
    CHECK(ips_regex->help);

    CHECK(!strcmp(ips_regex->name, "regex"));

    CHECK(ips_regex->mod_ctor);
    CHECK(ips_regex->mod_dtor);
}

TEST(ips_regex_base, ips_option)
{
    const IpsApi* ips_api = (const IpsApi*) ips_regex;

    CHECK(ips_api->ctor);
    CHECK(ips_api->dtor);
}

//-------------------------------------------------------------------------
// module tests
//-------------------------------------------------------------------------

TEST_GROUP(ips_regex_module)
{
    Module* mod = nullptr;
    bool end = true;
    unsigned expect = 0;

    void setup() override
    {
        s_parse_errors = 0;
        mod = ips_regex->mod_ctor();
        CHECK(mod);
        CHECK(mod->begin(ips_regex->name, 0, nullptr));
    }
    void teardown() override
    {
        CHECK(mod->end(ips_regex->name, 0, nullptr) == end);
        LONGS_EQUAL(expect, s_parse_errors);
        ips_regex->mod_dtor(mod);
    }
};

TEST(ips_regex_module, basic)
{
    // always need a re
    Value vs("foo");
    const Parameter* p = get_param(mod, "~re");
    CHECK(p);
    vs.set(p);
    CHECK(mod->set(ips_regex->name, vs, nullptr));

    CHECK(mod->get_profile());
}

TEST(ips_regex_module, config_pass)
{
    Value vs("foo");
    const Parameter* p = get_param(mod, "~re");
    CHECK(p);
    vs.set(p);
    CHECK(mod->set(ips_regex->name, vs, nullptr));

    Value vb(true);
    p = get_param(mod, "dotall");
    CHECK(p);
    vb.set(p);
    CHECK(mod->set(ips_regex->name, vb, nullptr));

    p = get_param(mod, "fast_pattern");
    CHECK(p);
    vb.set(p);
    CHECK(mod->set(ips_regex->name, vb, nullptr));

    p = get_param(mod, "multiline");
    CHECK(p);
    vb.set(p);
    CHECK(mod->set(ips_regex->name, vb, nullptr));

    p = get_param(mod, "nocase");
    CHECK(p);
    vb.set(p);
    CHECK(mod->set(ips_regex->name, vb, nullptr));

    p = get_param(mod, "relative");
    CHECK(p);
    vb.set(p);
    CHECK(mod->set(ips_regex->name, vb, nullptr));
}

TEST(ips_regex_module, config_fail_name)
{
    Value vs("unknown");
    Parameter bad { "bad", Parameter::PT_STRING, nullptr, nullptr, "bad" };
    vs.set(&bad);
    CHECK(!mod->set(ips_regex->name, vs, nullptr));
    expect = 1;
    end = false;
}

TEST(ips_regex_module, config_fail_regex)
{
    Value vs("[[:fubar:]]");
    const Parameter* p = get_param(mod, "~re");
    CHECK(p);
    vs.set(p);
    CHECK(mod->set(ips_regex->name, vs, nullptr));
    expect = 1;
    end = false;
}

//-------------------------------------------------------------------------
// option tests
//-------------------------------------------------------------------------

TEST_GROUP(ips_regex_option)
{
    Module* mod = nullptr;
    IpsOption* opt = nullptr;
    bool do_cleanup = false;

    void setup() override
    {
        mod = ips_regex->mod_ctor();
        opt = get_option(mod, " foo ");
    }
    void teardown() override
    {
        const IpsApi* api = (const IpsApi*) ips_regex;
        api->dtor(opt);
        if ( do_cleanup )
            scratcher->cleanup(snort_conf);
        ips_regex->mod_dtor(mod);
    }
};

TEST(ips_regex_option, hash)
{
    IpsOption* opt2 = get_option(mod, "bar");
    CHECK(opt2);

    uint32_t h1 = opt->hash();
    uint32_t h2 = opt2->hash();
    CHECK(h1 != h2);

    do_cleanup = scratcher->setup(snort_conf);

    const IpsApi* api = (const IpsApi*) ips_regex;
    api->dtor(opt2);
}

TEST(ips_regex_option, opeq)
{
    IpsOption* opt2 = get_option(mod, " foo ");
    CHECK(opt2);

    do_cleanup = scratcher->setup(snort_conf);

    const IpsApi* api = (const IpsApi*) ips_regex;
    api->dtor(opt2);
}

TEST(ips_regex_option, match_absolute)
{
    do_cleanup = scratcher->setup(snort_conf);

    Packet pkt;
    pkt.data = (const uint8_t*) "* foo stew *";
    pkt.dsize = strlen((const char*) pkt.data);

    Cursor c(&pkt);
    CHECK(opt->eval(c, &pkt) == IpsOption::MATCH);
    CHECK(!strcmp((const char*) c.start(), " stew *"));
    CHECK(opt->retry(c));
}

TEST(ips_regex_option, no_match_delta)
{
    do_cleanup = scratcher->setup(snort_conf);

    Packet pkt;
    pkt.data = (const uint8_t*) "* foo stew *";
    pkt.dsize = strlen((const char*) pkt.data);

    Cursor c(&pkt);
    c.set_delta(3);

    CHECK(opt->eval(c, &pkt) == IpsOption::NO_MATCH);
}

//-------------------------------------------------------------------------
// relative tests
//-------------------------------------------------------------------------

TEST_GROUP(ips_regex_option_relative)
{
    Module* mod = nullptr;
    IpsOption* opt = nullptr;
    bool do_cleanup = false;

    void setup() override
    {
        mod = ips_regex->mod_ctor();
        opt = get_option(mod, "\\bfoo", true);
    }
    void teardown() override
    {
        const IpsApi* api = (const IpsApi*) ips_regex;
        api->dtor(opt);
        if ( do_cleanup )
            scratcher->cleanup(snort_conf);
        ips_regex->mod_dtor(mod);
    }
};

TEST(ips_regex_option_relative, no_match)
{
    do_cleanup = scratcher->setup(snort_conf);

    Packet pkt;
    pkt.data = (const uint8_t*)"* foo stew *";
    pkt.dsize = strlen((const char*) pkt.data);

    Cursor c(&pkt);
    c.add_pos(3);

    CHECK(opt->is_relative());
    CHECK(opt->eval(c, &pkt) == IpsOption::NO_MATCH);
    CHECK(!opt->retry(c));
}

//-------------------------------------------------------------------------
// main
//-------------------------------------------------------------------------

int main(int argc, char** argv)
{
    // FIXIT-L cpputest hangs or crashes in the leak detector
    MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    return CommandLineTestRunner::RunAllTests(argc, argv);
}


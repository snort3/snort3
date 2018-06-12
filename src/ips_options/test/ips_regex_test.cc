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
#include "profiler/memory_profiler_defs.h"
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

ScScratchFunc scratch_setup;
ScScratchFunc scratch_cleanup;

SnortConfig::SnortConfig(const SnortConfig* const)
{
    state = &s_state;
    num_slots = 1;
}

SnortConfig::~SnortConfig() = default;

int SnortConfig::request_scratch(ScScratchFunc setup, ScScratchFunc cleanup)
{
    scratch_setup = setup;
    scratch_cleanup = cleanup;
    s_state.resize(1);

    return 0;
}

SnortConfig* SnortConfig::get_conf()
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
}

extern const BaseApi* ips_regex;

Cursor::Cursor(Packet* p)
{ set("pkt_data", p->data, p->dsize); }

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, IndexVec&, const char*, FILE*) { }

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

static IpsOption* get_option(const char* pat, bool relative = false)
{
    Module* mod = ips_regex->mod_ctor();
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

    IpsApi* api = (IpsApi*)ips_regex;
    IpsOption* opt = api->ctor(mod, nullptr);

    ips_regex->mod_dtor(mod);
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
    const IpsApi* ips_api = (IpsApi*)ips_regex;

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
    IpsOption* opt = nullptr;

    void setup() override
    {
        opt = get_option(" foo ");
        scratch_setup(snort_conf);
    }
    void teardown() override
    {
        IpsApi* api = (IpsApi*)ips_regex;
        api->dtor(opt);
        scratch_cleanup(snort_conf);
        api->pterm(snort_conf);
    }
};

TEST(ips_regex_option, hash)
{
    IpsOption* opt2 = get_option("bar");
    CHECK(opt2);
    CHECK(*opt != *opt2);

    uint32_t h1 = opt->hash();
    uint32_t h2 = opt2->hash();
    CHECK(h1 != h2);

    IpsApi* api = (IpsApi*)ips_regex;
    api->dtor(opt2);
}

TEST(ips_regex_option, opeq)
{
    IpsOption* opt2 = get_option(" foo ");
    CHECK(opt2);
    // this is forced unequal for now
    CHECK(*opt != *opt2);

    IpsApi* api = (IpsApi*)ips_regex;
    api->dtor(opt2);
}

TEST(ips_regex_option, match_absolute)
{
    Packet pkt;
    pkt.data = (uint8_t*)"* foo stew *";
    pkt.dsize = strlen((char*)pkt.data);

    Cursor c(&pkt);
    CHECK(opt->eval(c, &pkt) == IpsOption::MATCH);
    CHECK(!strcmp((char*)c.start(), " stew *"));
    CHECK(opt->retry(c));
}

TEST(ips_regex_option, no_match_delta)
{
    Packet pkt;
    pkt.data = (uint8_t*)"* foo stew *";
    pkt.dsize = strlen((char*)pkt.data);

    Cursor c(&pkt);
    c.set_delta(3);

    CHECK(opt->eval(c, &pkt) == IpsOption::NO_MATCH);
}

//-------------------------------------------------------------------------
// relative tests
//-------------------------------------------------------------------------

TEST_GROUP(ips_regex_option_relative)
{
    IpsOption* opt = nullptr;

    void setup() override
    {
        opt = get_option("\\bfoo", true);
        scratch_setup(snort_conf);
    }
    void teardown() override
    {
        IpsApi* api = (IpsApi*)ips_regex;
        api->dtor(opt);
        scratch_cleanup(snort_conf);
    }
};

TEST(ips_regex_option_relative, no_match)
{
    Packet pkt;
    pkt.data = (uint8_t*)"* foo stew *";
    pkt.dsize = strlen((char*)pkt.data);

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


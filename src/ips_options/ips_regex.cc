//--------------------------------------------------------------------------
// Copyright (C) 2015-2015 Cisco and/or its affiliates. All rights reserved.
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

// ips_regex.cc author Russ Combs <rucombs@cisco.com>

#include <assert.h>
#include <string>

#include <hs/hs_compile.h>
#include <hs/hs_runtime.h>

#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "detection/detection_defines.h"
#include "hash/sfhashfcn.h"
#include "main/thread.h"
#include "parser/parser.h"
#include "time/profiler.h"

#define s_name "regex"

#define s_help \
    "rule option for matching payload data with hyperscan regex"

struct RegexConfig
{
    std::string re;
    hs_database_t* db;
    unsigned flags;
    bool relative;

    void reset()
    {
        re.clear();
        db = nullptr;
        flags = 0;
        relative = false;
    }
};

// we need to update scratch in the main thread as each pattern
// is processed and then clone to packet thread in tinit()
static hs_scratch_t* s_scratch = NULL;
static THREAD_LOCAL hs_scratch_t* t_scratch = NULL;
static THREAD_LOCAL unsigned s_to = 0;
static THREAD_LOCAL ProfileStats regex_perf_stats;

//-------------------------------------------------------------------------
// option
//-------------------------------------------------------------------------

class RegexOption : public IpsOption
{
public:
    RegexOption(RegexConfig&);
    ~RegexOption();

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    bool is_relative() override
    { return config.relative; }

    int eval(Cursor&, Packet*) override;

private:
    RegexConfig config;
};

RegexOption::RegexOption(RegexConfig& c) : IpsOption(s_name, RULE_OPTION_TYPE_OTHER)
{
    config = c;

    if ( /*hs_error_t err =*/ hs_alloc_scratch(config.db, &s_scratch) )
    {
        // FIXIT-H why is this failing but everything is working?
        //ParseError("can't initialize regex for '%s' (%d) %p",
        //    config.re.c_str(), err, s_scratch);
    }
}

RegexOption::~RegexOption()
{
    if ( config.db )
        hs_free_database(config.db);
}

uint32_t RegexOption::hash() const
{
    uint32_t a = config.flags, b = config.relative, c = 0;
    mix_str(a, b, c, config.re.c_str());
    mix_str(a, b, c, get_name());
    finalize(a, b, c);
    return c;
}

bool RegexOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    RegexOption& rhs = (RegexOption&)ips;

    if ( config.re == rhs.config.re and 
         config.flags == rhs.config.flags and
         config.relative == rhs.config.relative )
        return true;

    return false;
}

static int hs_match(
    unsigned int /*id*/, unsigned long long /*from*/, unsigned long long to,
    unsigned int /*flags*/, void* /*context*/)
{
    s_to = (unsigned)to;
    return 1;  // stop search
}

int RegexOption::eval(Cursor& c, Packet*)
{
    PERF_PROFILE(regex_perf_stats);

    unsigned pos = c.get_delta();

    if ( !pos && is_relative() )
        pos = c.get_pos();

    if ( pos > c.size() )
        return DETECTION_OPTION_NO_MATCH;

    s_to = 0;

    hs_error_t stat = hs_scan(
        config.db, (char*)c.buffer()+pos, c.size()-pos, config.flags,
        t_scratch, hs_match, nullptr);

    if ( s_to and stat == HS_SCAN_TERMINATED )
    {
        c.set_pos(s_to);
        c.set_delta(s_to);
        return DETECTION_OPTION_MATCH;
    }
    return DETECTION_OPTION_NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~", Parameter::PT_STRING, nullptr, nullptr,
      "hyperscan regular expression" },

    { "nocase", Parameter::PT_IMPLIED, nullptr, nullptr,
      "case insensitive match" },

    { "dotall", Parameter::PT_IMPLIED, nullptr, nullptr,
      "matching a . will not exclude newlines" },

    { "multiline", Parameter::PT_IMPLIED, nullptr, nullptr,
      "^ and $ anchors match any newlines in data" },

    { "relative", Parameter::PT_IMPLIED, nullptr, nullptr,
      "start search from end of last match instead of start of buffer" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class RegexModule : public Module
{
public:
    RegexModule() : Module(s_name, s_help, s_params) { }
    ~RegexModule();

    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &regex_perf_stats; }

    void get_data(RegexConfig& c)
    {
        c = config;
        config.reset();
    }

private:
    RegexConfig config;
};

RegexModule::~RegexModule()
{
    if ( config.db )
        hs_free_database(config.db);
}

bool RegexModule::begin(const char*, int, SnortConfig*)
{
    config.reset();
    return true;
}

bool RegexModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("~") )
    {
        config.re = v.get_string();
        // remove quotes
        config.re.erase(0, 1);
        config.re.erase(config.re.length()-1, 1);
    }

    else if ( v.is("nocase") )
        config.flags |= HS_FLAG_CASELESS;

    else if ( v.is("dotall") )
        config.flags |= HS_FLAG_DOTALL;

    else if ( v.is("multiline") )
        config.flags |= HS_FLAG_MULTILINE;

    else if ( v.is("relative") )
        config.relative = true;

    else
        return false;

    return true;
}

bool RegexModule::end(const char*, int, SnortConfig*)
{
    hs_compile_error_t* err = nullptr;

    if ( hs_compile(config.re.c_str(), config.flags, HS_MODE_BLOCK, NULL, &config.db, &err)
        or !config.db )
    {
        ParseError("can't compile regex '%s'", config.re.c_str());
        hs_free_compile_error(err);
        return false;
    }
    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new RegexModule; }

static void mod_dtor(Module* p)
{ delete p; }

static IpsOption* regex_ctor(Module* m, OptTreeNode*)
{
    RegexModule* mod = (RegexModule*)m;
    RegexConfig c;
    mod->get_data(c);
    return new RegexOption(c);
}

static void regex_dtor(IpsOption* p)
{ delete p; }

static void regex_tinit(SnortConfig*)
{
    if ( s_scratch )
        hs_clone_scratch(s_scratch, &t_scratch);
}

static void regex_tterm(SnortConfig*)
{
    if ( t_scratch )
        hs_free_scratch(t_scratch);
}

static const IpsApi regex_api =
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
    0, 0,
    nullptr,
    nullptr,
    regex_tinit,
    regex_tterm,
    regex_ctor,
    regex_dtor,
    nullptr
};

const BaseApi* ips_regex = &regex_api.base;


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

// ips_regex.cc author Russ Combs <rucombs@cisco.com>
// FIXIT-M add ! and anchor support like pcre and update retry

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <hs_compile.h>
#include <hs_runtime.h>

#include <cassert>

#include "detection/pattern_match_data.h"
#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hash_key_operations.h"
#include "helpers/hyper_scratch_allocator.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "profiler/profiler.h"

using namespace snort;

#define s_name "regex"

#define s_help \
    "rule option for matching payload data with hyperscan regex"

struct RegexConfig
{
    hs_database_t* db;
    std::string re;
    PatternMatchData pmd;
    bool pcre_conversion;

    RegexConfig()
    { reset(); }

    void reset()
    {
        memset(&pmd, 0, sizeof(pmd));
        re.clear();
        db = nullptr;
        pcre_conversion = false;
    }
};

static HyperScratchAllocator* scratcher = nullptr;
static THREAD_LOCAL ProfileStats regex_perf_stats;

//-------------------------------------------------------------------------
// option
//-------------------------------------------------------------------------

class RegexOption : public IpsOption
{
public:
    RegexOption(const RegexConfig&);
    ~RegexOption() override;

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    CursorActionType get_cursor_type() const override
    { return CAT_ADJUST; }

    bool is_relative() override
    { return config.pmd.is_relative(); }

    bool retry(Cursor&) override;

    PatternMatchData* get_pattern(SnortProtocolId, RuleDirection) override
    { return &config.pmd; }

    EvalStatus eval(Cursor&, Packet*) override;

private:
    RegexConfig config;
};

RegexOption::RegexOption(const RegexConfig& c) :
    IpsOption(s_name, RULE_OPTION_TYPE_CONTENT)
{
    config = c;

    if ( !scratcher->allocate(config.db) )
        ParseError("can't allocate scratch for regex '%s'", config.re.c_str());

    config.pmd.pattern_buf = config.re.c_str();
    config.pmd.pattern_size = config.re.size();

    config.pmd.fp_length = config.pmd.pattern_size;
    config.pmd.fp_offset = 0;
}

RegexOption::~RegexOption()
{
    if ( config.db )
        hs_free_database(config.db);
}

uint32_t RegexOption::hash() const
{
    uint32_t a = config.pmd.flags, b = config.pmd.mpse_flags, c = 0;
    mix_str(a, b, c, config.re.c_str());
    mix_str(a, b, c, get_name());
    finalize(a, b, c);
    return c;
}

// see ContentOption::operator==()
bool RegexOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const RegexOption& rhs = (const RegexOption&)ips;

    if ( config.pcre_conversion && rhs.config.pcre_conversion )
        if ( config.re == rhs.config.re and
             config.pmd.flags == rhs.config.pmd.flags and
             config.pmd.mpse_flags == rhs.config.pmd.mpse_flags )
            return true;

    return false;
}

struct ScanContext
{
    unsigned index;
    bool found = false;
};

static int hs_match(
    unsigned int /*id*/, unsigned long long /*from*/, unsigned long long to,
    unsigned int /*flags*/, void* context)
{
    ScanContext* scan = (ScanContext*)context;
    scan->index = (unsigned)to;
    scan->found = true;
    return 1;
}

IpsOption::EvalStatus RegexOption::eval(Cursor& c, Packet*)
{
    RuleProfile profile(regex_perf_stats);

    unsigned pos = c.get_delta();

    if ( !pos && is_relative() )
        pos = c.get_pos();

    if ( pos > c.size() )
        return NO_MATCH;

    ScanContext scan;

    hs_error_t stat = hs_scan(
        config.db, (const char*)c.buffer()+pos, c.size()-pos, 0,
        scratcher->get(), hs_match, &scan);

    if ( scan.found and stat == HS_SCAN_TERMINATED )
    {
        scan.index += pos;
        c.set_pos(scan.index);
        c.set_delta(scan.index);
        return MATCH;
    }
    return NO_MATCH;
}

bool RegexOption::retry(Cursor&)
{ return !is_relative(); }

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~re", Parameter::PT_STRING, nullptr, nullptr,
      "hyperscan regular expression" },

    { "dotall", Parameter::PT_IMPLIED, nullptr, nullptr,
      "matching a . will not exclude newlines" },

    { "fast_pattern", Parameter::PT_IMPLIED, nullptr, nullptr,
      "use this content in the fast pattern matcher instead of the content selected by default" },

    { "multiline", Parameter::PT_IMPLIED, nullptr, nullptr,
      "^ and $ anchors match any newlines in data" },

    { "nocase", Parameter::PT_IMPLIED, nullptr, nullptr,
      "case insensitive match" },

    { "relative", Parameter::PT_IMPLIED, nullptr, nullptr,
      "start search from end of last match instead of start of buffer" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class RegexModule : public Module
{
public:
    RegexModule() : Module(s_name, s_help, s_params)
    { scratcher = new HyperScratchAllocator; }

    ~RegexModule() override;

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

    Usage get_usage() const override
    { return DETECT; }

private:
    RegexConfig config;
    bool convert_pcre_to_regex_form();
};

RegexModule::~RegexModule()
{
    if ( config.db )
        hs_free_database(config.db);

    delete scratcher;
}

bool RegexModule::begin(const char* name, int, SnortConfig*)
{
    config.reset();
    config.pmd.flags |= PatternMatchData::NO_FP;
    config.pmd.mpse_flags |= HS_FLAG_SINGLEMATCH;

    // if regex is in pcre syntax set conversion mode
    if ( strcmp(name, "pcre") == 0 )
        config.pcre_conversion = true;

    return true;
}

// The regex string received from the ips_pcre plugin must be scrubbed to remove
// two characters from  the front; an extra '"' and the '/' and also the same
// two characters from the end of the string as well as any pcre modifier flags
// included in the expression.  The modifier flags are checked to set the
// corresponding hyperscan regex engine flags.
// Hyperscan regex also does not support negated pcre expression so negated expression
// are not converted and will be compiled by the pcre engine.
bool RegexModule::convert_pcre_to_regex_form()
{
    size_t pos = config.re.find_first_of("\"!");
    if (pos != std::string::npos and config.re[pos] == '!')
        return false;

    config.re.erase(0,2);
    std::size_t re_end = config.re.rfind("/");
    if ( re_end != std::string::npos )
    {
        std::size_t mod_len = (config.re.length() - 2) - re_end;
        std::string modifiers = config.re.substr(re_end + 1, mod_len);
        std::size_t erase_len = config.re.length() - re_end;
        config.re.erase(re_end, erase_len);

        for( char& c : modifiers )
        {
            switch (c)
            {
            case 'i':
                config.pmd.mpse_flags |= HS_FLAG_CASELESS;
                config.pmd.set_no_case();
                break;

            case 'm':
                config.pmd.mpse_flags |= HS_FLAG_MULTILINE;
                break;

            case 's':
                config.pmd.mpse_flags |= HS_FLAG_DOTALL;
                break;

            case 'O':
                break;

            case 'R':
                config.pmd.set_relative();
                break;

            default:
                return false;
                break;
            }
        }

        return true;
    }

    return false;
}

bool RegexModule::set(const char*, Value& v, SnortConfig*)
{
    bool valid_opt = true;

    if ( v.is("~re") )
    {
        config.re = v.get_string();

        if ( config.pcre_conversion )
            valid_opt = convert_pcre_to_regex_form();
        else
        {
            // remove quotes
            config.re.erase(0, 1);
            config.re.erase(config.re.length() - 1, 1);
        }
    }
    else if ( v.is("dotall") )
        config.pmd.mpse_flags |= HS_FLAG_DOTALL;
    else if ( v.is("fast_pattern") )
    {
        config.pmd.flags &= ~PatternMatchData::NO_FP;
        config.pmd.flags |= PatternMatchData::FAST_PAT;
    }
    else if ( v.is("multiline") )
        config.pmd.mpse_flags |= HS_FLAG_MULTILINE;
    else if ( v.is("nocase") )
    {
        config.pmd.mpse_flags |= HS_FLAG_CASELESS;
        config.pmd.set_no_case();
    }
    else if ( v.is("relative") )
        config.pmd.set_relative();
    else
        valid_opt = false;

    return valid_opt;
}

bool RegexModule::end(const char*, int, SnortConfig*)
{
    if ( hs_valid_platform() != HS_SUCCESS )
    {
        ParseError("This host does not support Hyperscan.");
        return false;
    }

    hs_compile_error_t* err = nullptr;

    if ( hs_compile(config.re.c_str(), config.pmd.mpse_flags, HS_MODE_BLOCK,
        nullptr, &config.db, &err) or !config.db )
    {
        if ( !config.pcre_conversion )
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
    nullptr,
    nullptr,
    regex_ctor,
    regex_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_regex[] =
#endif
{
    &regex_api.base,
    nullptr
};

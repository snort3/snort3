//--------------------------------------------------------------------------
// Copyright (C) 2015-2023 Cisco and/or its affiliates. All rights reserved.
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
#include "detection/treenodes.h"
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
    "rule option for matching payload data with hyperscan regex; uses pcre syntax"

struct RegexConfig
{
    hs_database_t* db;
    std::string re;
    PatternMatchData pmd = { };
    bool pcre_upgrade;

    RegexConfig()
    { reset(); }

    void reset()
    {
        re.clear();
        db = nullptr;
        pcre_upgrade = false;
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

    bool retry(Cursor&, const Cursor&) override;

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
    uint32_t a = config.pmd.flags;
    uint32_t b = config.pmd.mpse_flags;
    uint32_t c = IpsOption::hash();

    mix(a, b, c);
    mix_str(a, b, c, config.re.c_str());

    finalize(a, b, c);

    return c;
}

bool RegexOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const RegexOption& rhs = (const RegexOption&)ips;

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

bool RegexOption::retry(Cursor&, const Cursor&)
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
    config.pmd.mpse_flags |= HS_FLAG_SINGLEMATCH;

    if ( strcmp(name, "pcre") == 0 )
        config.pcre_upgrade = true;

    return true;
}

// The regex string is in pcre syntax so it must be scrubbed to remove
// two characters from  the front; an extra '"' and the '/' and also the same
// two characters from the end of the string as well as any pcre modifier flags
// included in the expression.  The modifier flags are checked to set the
// corresponding hyperscan regex engine flags.
bool RegexModule::convert_pcre_to_regex_form()
{
    // we get string with quotes so length is at least 3
    // start with a bang:  ! "/regex/smi"
    if ( config.re[0] == '!' )
    {
        if ( !config.pcre_upgrade )
            ParseError("regex does not (yet) support negation");
        return false;
    }

    // remove quotes: "/regex/smi" -> /regex/smi
    config.re.erase(0, 1);
    config.re.erase(config.re.length() - 1, 1);

    // remove leading slash: /regex/smi -> regex/smi
    size_t len = config.re.length();

    if ( len < 3 or config.re[0] != '/' )
    {
        ParseError("regex uses pcre syntax");
        return false;
    }
    config.re.erase(0, 1);

    // remove trailing slash: regex/smi -> regexsmi
    size_t re_end = config.re.rfind("/");

    if ( re_end == std::string::npos )
    {
        ParseError("regex uses pcre syntax");
        return false;
    }
    config.re.erase(re_end, 1);

    // capture and remove optional modifiers: regex/smi -> regex, smi
    std::string modifiers;
    len = config.re.length() - re_end;

    if ( len > 0 )
    {
        modifiers = config.re.substr(re_end, len);
        config.re.erase(re_end, len);
    }

    // finally, process the modifiers
    for ( char& c : modifiers )
    {
        switch ( c )
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
            if ( !config.pcre_upgrade )
                ParseWarning(WARN_RULES, "regex does not support override, ignored");
            break;

        case 'R':
            config.pmd.set_relative();
            break;

        default:
            return false;
        }
    }
    return true;
}

bool RegexModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("~re") )
    {
        config.re = v.get_string();
        return convert_pcre_to_regex_form();
    }
    else if ( v.is("fast_pattern") )
        config.pmd.set_fast_pattern();

    else if ( v.is("nocase") )
    {
        config.pmd.mpse_flags |= HS_FLAG_CASELESS;
        config.pmd.set_no_case();
    }
    return true;
}

bool RegexModule::end(const char*, int, SnortConfig*)
{
    if ( hs_valid_platform() != HS_SUCCESS )
    {
        ParseError("This host does not support Hyperscan.");
        return false;
    }

    if ( !config.pmd.is_fast_pattern() )
        config.pmd.flags |= PatternMatchData::NO_FP;

    hs_compile_error_t* err = nullptr;

    if ( hs_compile(config.re.c_str(), config.pmd.mpse_flags, HS_MODE_BLOCK,
        nullptr, &config.db, &err) or !config.db )
    {
        // gracefully fall back to pcre upon upgrade failure
        if ( !config.pcre_upgrade )
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

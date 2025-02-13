//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
// Copyright (C) 2003 Brian Caswell <bmc@snort.org>
// Copyright (C) 2003 Michael J. Pomraning <mjp@securepipe.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cassert>

#include "detection/ips_context.h"
#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "framework/parameter.h"
#include "framework/pig_pen.h"
#include "hash/hash_key_operations.h"
#include "log/log_stats.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "managers/ips_manager.h"
#include "managers/module_manager.h"
#include "profiler/profiler.h"
#include "utils/snort_pcre.h"
#include "utils/stats.h"
#include "utils/util.h"

// Unset to disable JIT for Xcode
#define USE_JIT 1

using namespace snort;

#define SNORT_PCRE_RELATIVE         0x00010 // relative to the end of the last match
#define SNORT_PCRE_INVERT           0x00020 // invert detect
#define SNORT_PCRE_ANCHORED         0x00040
#define SNORT_OVERRIDE_MATCH_LIMIT  0x00080 // Override default limits on match & match recursion

#define s_name "pcre"
#define mod_regex_name "regex"

void show_pcre_counts();

struct PcreData
{
    pcre2_code* re;                       /* compiled regex */
    pcre2_match_context* match_context;   /* match_context */
    pcre2_match_data* match_data;         /* match data space for storing results */
    int options;                          /* sp_pcre specific options (relative & inverse) */
    char* expression;
};

static THREAD_LOCAL ProfileStats pcrePerfStats;

struct PcreCounts
{
    unsigned pcre_rules;
#ifdef HAVE_HYPERSCAN
    unsigned pcre_to_hyper;
#endif
    unsigned pcre_native;
};

PcreCounts pcre_counts;

void show_pcre_counts()
{
    if (pcre_counts.pcre_rules == 0)
        return;

    LogLabel("pcre counts");
    LogCount("pcre_rules", pcre_counts.pcre_rules);
#ifdef HAVE_HYPERSCAN
    LogCount("pcre_to_hyper", pcre_counts.pcre_to_hyper);
#endif
    LogCount("pcre_native", pcre_counts.pcre_native);
}

//-------------------------------------------------------------------------
// stats foo
//-------------------------------------------------------------------------

struct PcreStats
{
    PegCount pcre_match_limit;
    PegCount pcre_recursion_limit;
    PegCount pcre_error;
};

const PegInfo pcre_pegs[] =
{
    { CountType::SUM, "pcre_match_limit", "total number of times pcre hit the match limit" },
    { CountType::SUM, "pcre_recursion_limit", "total number of times pcre hit the recursion limit" },
    { CountType::SUM, "pcre_error", "total number of times pcre returns error" },

    { CountType::END, nullptr, nullptr }
};

THREAD_LOCAL PcreStats pcre_stats;

//-------------------------------------------------------------------------
// implementation foo
//-------------------------------------------------------------------------

static void pcre_check_anchored(PcreData* pcre_data)
{
    int rc;
    unsigned long int options = 0;

    if ((pcre_data == nullptr) || (pcre_data->re == nullptr))
        return;

    rc = pcre2_pattern_info(pcre_data->re, PCRE2_INFO_ARGOPTIONS, (void*)&options);
    switch (rc)
    {
    /* pcre_fullinfo fails for the following:
     * PCRE_ERROR_NULL - the argument code was null
     *                   the argument where was null
     * PCRE_ERROR_BADMAGIC - the "magic number" was not found
     * PCRE_ERROR_BADOPTION - the value of what was invalid
     * so a failure here means we passed in bad values and we should
     * probably fatal error */

    case 0:
        /* This is the success code */
        break;

    case PCRE2_ERROR_NULL:
        ParseError("pcre2: code and/or where were null.");
        return;

    case PCRE2_ERROR_BADMAGIC:
        ParseError("pcre2: compiled code didn't have correct magic.");
        return;

    case PCRE2_ERROR_BADOPTION:
        ParseError("pcre2: option type is invalid.");
        return;

    default:
        ParseError("pcre2: Unknown error code.");
        return;
    }

    if ((options & PCRE2_ANCHORED) && !(options & PCRE2_MULTILINE))
    {
        /* This means that this pcre rule option shouldn't be EvalStatus
         * even if any of it's relative children should fail to match.
         * It is anchored to the cursor set by the previous cursor setting
         * rule option */
        pcre_data->options |= SNORT_PCRE_ANCHORED;
    }
}

static void pcre_parse(const SnortConfig* sc, const char* data, PcreData* pcre_data)
{
    PCRE2_UCHAR error[128];
    char* re, * free_me;
    char* opts;
    char delimit = '/';
    int errorcode;
    PCRE2_SIZE erroffset;
    int compile_flags = 0;

    if (data == nullptr)
    {
        ParseError("pcre requires a regular expression");
        return;
    }

    free_me = snort_strdup(data);
    re = free_me;

    /* get rid of starting and ending whitespace */
    while (isspace((int)re[strlen(re)-1]))
        re[strlen(re)-1] = '\0';
    while (isspace((int)*re))
        re++;

    if (*re == '!')
    {
        pcre_data->options |= SNORT_PCRE_INVERT;
        re++;
        while (isspace((int)*re))
            re++;
    }

    if ( *re == '"')
        re++;

    if ( re[strlen(re)-1] == '"' )
        re[strlen(re) - 1] = '\0';

    /* 'm//' or just '//' */

    if (*re == 'm')
    {
        re++;
        if (!*re)
            goto syntax;

        /* Space as a ending delimiter?  Uh, no. */
        if (isspace((int)*re))
            goto syntax;
        /* using R would be bad, as it triggers RE */
        if (*re == 'R')
            goto syntax;

        delimit = *re;
    }
    else if (*re != delimit)
        goto syntax;

    pcre_data->expression = snort_strdup(re);

    /* find ending delimiter, trim delimit chars */
    opts = strrchr(re, delimit);
    if (opts == nullptr)
        goto syntax;

    if (!((opts - re) > 1)) /* empty regex(m||) or missing delim not OK */
        goto syntax;

    re++;
    *opts++ = '\0';

    /* process any /regex/ismxR options */
    while (*opts != '\0')
    {
        switch (*opts)
        {
        case 'i':  compile_flags |= PCRE2_CASELESS;            break;
        case 's':  compile_flags |= PCRE2_DOTALL;              break;
        case 'm':  compile_flags |= PCRE2_MULTILINE;           break;
        case 'x':  compile_flags |= PCRE2_EXTENDED;            break;

        /*
         * these are pcre specific... don't work with perl
         */
        case 'A':  compile_flags |= PCRE2_ANCHORED;            break;
        case 'E':  compile_flags |= PCRE2_DOLLAR_ENDONLY;      break;
        case 'G':  compile_flags |= PCRE2_UNGREEDY;            break;

        /*
         * these are snort specific don't work with pcre or perl
         */
        case 'R':  pcre_data->options |= SNORT_PCRE_RELATIVE; break;
        case 'O':
            if ( sc->pcre_override )
                pcre_data->options |= SNORT_OVERRIDE_MATCH_LIMIT;
            break;

        default:
            ParseError("unknown/extra pcre option encountered");
            return;
        }
        opts++;
    }

    /* now compile the re */
    pcre_data->re = pcre2_compile((PCRE2_SPTR)re, PCRE2_ZERO_TERMINATED, compile_flags,
        &errorcode, &erroffset, nullptr);

    if (pcre_data->re == nullptr)
    {
        pcre2_get_error_message(errorcode, error, sizeof(error)/sizeof(char));
        ParseError("pcre2 compile of '%s' failed at offset "
            "%zu : %s", re, erroffset, error);
        return;
    }

    /* create match context */
    pcre_data->match_context = pcre2_match_context_create(NULL);
    if (pcre_data->match_context == NULL)
    {
        ParseError("failed to allocate memory for match context");
        return;
    }

    pcre_data->match_data = pcre2_match_data_create_from_pattern(pcre_data->re, nullptr);

     /* now study it... */
    if (USE_JIT)
    {
        // It is possible that we fail to study a re with JIT. In that case,
        // we fallback to normal processing (as non-JIT)
        errorcode = pcre2_jit_compile(pcre_data->re, PCRE2_JIT_COMPLETE);

        if (errorcode)
        {
            pcre2_get_error_message(errorcode, error, sizeof(error)/sizeof(char));
            ParseWarning(WARN_RULES, "pcre2 JIT compile of '%s' failed : %s\n", re, error);
        }
    }

    if ((sc->get_pcre_match_limit() != 0) && !(pcre_data->options & SNORT_OVERRIDE_MATCH_LIMIT))
        pcre2_set_match_limit(pcre_data->match_context, sc->get_pcre_match_limit());

    if ((sc->get_pcre_match_limit_recursion() != 0) && !(pcre_data->options & SNORT_OVERRIDE_MATCH_LIMIT))
        pcre2_set_depth_limit(pcre_data->match_context, sc->get_pcre_match_limit_recursion());

    pcre_check_anchored(pcre_data);
    snort_free(free_me);
    return;

syntax:
    snort_free(free_me);

    // ensure integrity from parse error to fatal error
    if ( !pcre_data->expression )
        pcre_data->expression = snort_strdup("");

    ParseError("unable to parse pcre %s", data);
}

/*
 * Perform a search of the PCRE data.
 * found_offset will be set to -1 when the find is unsuccessful OR the routine is inverted
 */
static bool pcre_search(
    Packet*,
    const PcreData* pcre_data,
    const uint8_t* buf,
    unsigned len,
    unsigned start_offset,
    int& found_offset)
{
    PCRE2_SIZE* ovector;
    bool matched;

    found_offset = -1;

    int result = pcre2_match(
        pcre_data->re,              /* result of pcre_compile() */
        (PCRE2_SPTR)buf,            /* the subject string */
        (PCRE2_SIZE)len,            /* the length of the subject string */
        (PCRE2_SIZE)start_offset,   /* start at offset 0 in the subject */
        0,                          /* options (handled at compile time) */
        pcre_data->match_data,      /* match data to store the match results */
        pcre_data->match_context);  /* match context for limits */

    if (result >= 0)
    {
        matched = true;

        /* From the PCRE man page: When a match is successful, information
         * about captured substrings is returned in pairs of integers,
         * starting at the beginning of ovector, and continuing up to
         * two-thirds of its length at the most.  The first element of a
         * pair is set to the offset of the first character in a substring,
         * and the second is set to the offset of the first character after
         * the end of a substring. The first pair, ovector[0] and
         * ovector[1], identify the portion of the subject string matched
         * by the entire pattern.  The next pair is used for the first
         * capturing subpattern, and so on. The value returned by
         * pcre_search() is the number of pairs that have been set. If there
         * are no capturing subpatterns, the return value from a successful
         * match is 1, indicating that just the first pair of offsets has
         * been set.
         *
         * In Snort's case, the ovector size only allows for the first pair
         * and a single int for scratch space.
         */

        ovector = pcre2_get_ovector_pointer(pcre_data->match_data);
        found_offset = ovector[1];
    }
    else if (result == PCRE2_ERROR_NOMATCH)
    {
        matched = false;
    }
    else if (result == PCRE2_ERROR_MATCHLIMIT)
    {
        pcre_stats.pcre_match_limit++;
        matched = false;
    }
    else if (result == PCRE2_ERROR_RECURSIONLIMIT)
    {
        pcre_stats.pcre_recursion_limit++;
        matched = false;
    }
    else
    {
        pcre_stats.pcre_error++;
        return false;
    }

    /* invert sense of match */
    if (pcre_data->options & SNORT_PCRE_INVERT)
    {
        matched = !matched;
    }

    return matched;
}

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

class PcreOption : public IpsOption
{
public:
    PcreOption(PcreData* c) :
        IpsOption(s_name, RULE_OPTION_TYPE_CONTENT)
    { config = c; }

    ~PcreOption() override;

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    CursorActionType get_cursor_type() const override
    { return CAT_ADJUST; }

    bool is_relative() override
    { return (config->options & SNORT_PCRE_RELATIVE) != 0; }

    EvalStatus eval(Cursor&, Packet*) override;
    bool retry(Cursor&) override;

    PcreData* get_data()
    { return config; }

    void set_data(PcreData* pcre)
    { config = pcre; }

private:
    PcreData* config;
};

PcreOption::~PcreOption()
{
    if ( !config )
        return;

    if ( config->expression )
        snort_free(config->expression);

    pcre2_match_context_free(config->match_context);
    pcre2_code_free(config->re);
    pcre2_match_data_free(config->match_data);

    snort_free(config);
}

uint32_t PcreOption::hash() const
{
    uint32_t a = 0, b = 0, c = 0;
    int expression_len = strlen(config->expression);
    int i, j;

    for (i=0,j=0; i<expression_len; i+=4)
    {
        uint32_t tmp = 0;
        int k = expression_len - i;

        if (k > 4)
            k=4;

        for (int l=0; l<k; l++)
        {
            tmp |= *(config->expression + i + l) << l*8;
        }

        switch (j)
        {
        case 0:
            a += tmp;
            break;
        case 1:
            b += tmp;
            break;
        case 2:
            c += tmp;
            break;
        }
        j++;

        if (j == 3)
        {
            mix(a,b,c);
            j=0;
        }
    }

    if (j != 0)
    {
        mix(a,b,c);
    }

    a += config->options;
    b += IpsOption::hash();

    mix(a,b,c);
    finalize(a,b,c);

    return c;
}

bool PcreOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const PcreOption& rhs = (const PcreOption&)ips;
    PcreData* left = config;
    PcreData* right = rhs.config;

    if (( strcmp(left->expression, right->expression) == 0) &&
        ( left->options == right->options))
    {
        return true;
    }

    return false;
}

IpsOption::EvalStatus PcreOption::eval(Cursor& c, Packet* p)
{
    // cppcheck-suppress unreadVariable
    RuleProfile profile(pcrePerfStats);

    // short circuit this for testing pcre performance impact
    if ( p->context->conf->no_pcre() )
        return NO_MATCH;

    unsigned pos = c.get_delta();
    unsigned adj = 0;

    if ( pos > c.size() )
        return NO_MATCH;

    if ( !pos && is_relative() )
        adj = c.get_pos();

    int found_offset = -1; // where is the ending location of the pattern

    if ( pcre_search(p, config, c.buffer()+adj, c.size()-adj, pos, found_offset) )
    {
        if ( found_offset > 0 )
        {
            found_offset += adj;
            c.set_pos(found_offset);
            c.set_delta(found_offset);
        }
        return MATCH;
    }

    return NO_MATCH;
}

// we always advance by found_offset so no adjustments to cursor are done
// here; note also that this means relative pcre matches on overlapping
// patterns won't work.  given the test pattern "ABABACD":
//
// ( sid:1; content:"ABA"; content:"C"; within:1; )
// ( sid:2; pcre:"/ABA/"; content:"C"; within:1; )
//
// sid 1 will fire but sid 2 will NOT.  this example is easily fixed by
// using content, but more advanced pcre won't work for the relative /
// overlap case.

bool PcreOption::retry(Cursor&)
{
    if ((config->options & (SNORT_PCRE_INVERT | SNORT_PCRE_ANCHORED)))
    {
        return false; // no go
    }
    return true;  // continue
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~re", Parameter::PT_STRING, nullptr, nullptr,
      "Snort regular expression" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option for matching payload data with pcre"

class PcreModule : public Module
{
public:
    PcreModule() : Module(s_name, s_help, s_params)
    { data = nullptr; }

    ~PcreModule() override
    { delete data; }

#ifdef HAVE_HYPERSCAN
    bool begin(const char*, int, SnortConfig*) override;
#endif
    bool set(const char*, Value&, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &pcrePerfStats; }

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    PcreData* get_data();

    Usage get_usage() const override
    { return DETECT; }

    Module* get_mod_regex() const
    { return mod_regex; }

private:
    PcreData* data;
    Module* mod_regex = nullptr;
    std::string re;
};

PcreData* PcreModule::get_data()
{
    PcreData* tmp = data;
    data = nullptr;
    return tmp;
}

const PegInfo* PcreModule::get_pegs() const
{ return pcre_pegs; }

PegCount* PcreModule::get_counts() const
{ return (PegCount*)&pcre_stats; }

#ifdef HAVE_HYPERSCAN
bool PcreModule::begin(const char* name, int v, SnortConfig* sc)
{
    if ( sc->pcre_to_regex )
    {
        if ( !mod_regex )
            mod_regex = ModuleManager::get_module(mod_regex_name);

        if( mod_regex )
            mod_regex = mod_regex->begin(name, v, sc) ? mod_regex : nullptr;
    }

    return true;
}
#endif

bool PcreModule::set(const char* name, Value& v, SnortConfig* sc)
{
    assert(v.is("~re"));
    re = v.get_string();

    if( mod_regex )
        mod_regex = mod_regex->set(name, v, sc) ? mod_regex : nullptr;

    return true;
}

bool PcreModule::end(const char* name, int v, SnortConfig* sc)
{
    if( mod_regex )
        mod_regex = mod_regex->end(name, v, sc) ? mod_regex : nullptr;

    if ( !mod_regex )
    {
        data = (PcreData*)snort_calloc(sizeof(*data));
        pcre_parse(sc, re.c_str(), data);
    }

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new PcreModule; }

static void mod_dtor(Module* m)
{ delete m; }

static IpsOption* pcre_ctor(Module* p, IpsInfo& info)
{
    pcre_counts.pcre_rules++;
    PcreModule* m = (PcreModule*)p;

#ifdef HAVE_HYPERSCAN
    Module* mod_regex = m->get_mod_regex();
    if ( mod_regex )
    {
        pcre_counts.pcre_to_hyper++;
        const IpsApi* opt_api = IpsManager::get_option_api(mod_regex_name);
        return opt_api->ctor(mod_regex, info);
    }
    else
#else
    UNUSED(info);
#endif
    {
        pcre_counts.pcre_native++;
        PcreData* d = m->get_data();
        return new PcreOption(d);
    }
}

static void pcre_dtor(IpsOption* p)
{ delete p; }

static const IpsApi pcre_api =
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
    pcre_ctor,
    pcre_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_pcre[] =
#endif
{
    &pcre_api.base,
    nullptr
};

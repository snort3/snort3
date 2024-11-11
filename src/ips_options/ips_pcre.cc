//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#include <cassert>

#include "detection/ips_context.h"
#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "framework/parameter.h"
#include "framework/pig_pen.h"
#include "hash/hash_key_operations.h"
#include "helpers/scratch_allocator.h"
#include "log/log_stats.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "managers/ips_manager.h"
#include "managers/module_manager.h"
#include "profiler/profiler.h"
#include "utils/stats.h"
#include "utils/util.h"

using namespace snort;

#ifndef PCRE2_STUDY_JIT_COMPILE
#define PCRE2_STUDY_JIT_COMPILE 0
#endif

//#define NO_JIT // uncomment to disable JIT for Xcode

#ifdef NO_JIT
#define PCRE2_JIT 0
#else
#define PCRE2_JIT PCRE2_STUDY_JIT_COMPILE
#endif
#define pcre2_release(x) pcre2_code_free(x)

#define SNORT_PCRE_RELATIVE         0x00010 // relative to the end of the last match
#define SNORT_PCRE_INVERT           0x00020 // invert detect
#define SNORT_PCRE_ANCHORED         0x00040
#define SNORT_OVERRIDE_MATCH_LIMIT  0x00080 // Override default limits on match & match recursion

#define s_name "pcre2"
#define mod_regex_name "regex"

void show_pcre_counts();

struct Pcre2Data
{
    pcre2_code* re;     /* compiled regex */
    pcre2_match_context* match_context; /* match_context for limits */
    int options;        /* sp_pcre specific options (relative & inverse) */
    char* expression;
};

// we need to specify the vector length for our pcre_exec call.  we only care
// about the first vector, which if the match is successful will include the
// offset to the end of the full pattern match.  if we decide to store other
// matches, make *SURE* that this is a multiple of 3 as pcre requires it.

// this is a temporary value used during parsing and set in snort conf
// by verify; search uses the value in snort conf
static int s_ovector_max = -1;

static THREAD_LOCAL ProfileStats pcre2PerfStats;

struct Pcre2Counts
{
    unsigned pcre2_rules;
#ifdef HAVE_HYPERSCAN
    unsigned pcre2_to_hyper;
#endif
    unsigned pcre2_native;
};

Pcre2Counts pcre2_counts;

void show_pcre_counts()
{
    if (pcre2_counts.pcre2_rules == 0)
        return;

    LogLabel("pcre2 counts");
    LogCount("pcre2_rules", pcre2_counts.pcre2_rules);
#ifdef HAVE_HYPERSCAN
    LogCount("pcre2_to_hyper", pcre2_counts.pcre2_to_hyper);
#endif
    LogCount("pcre2_native", pcre2_counts.pcre2_native);
}

//-------------------------------------------------------------------------
// stats foo
//-------------------------------------------------------------------------

struct Pcre2Stats
{
    PegCount pcre2_match_limit;
    PegCount pcre2_recursion_limit;
    PegCount pcre2_error;
};

const PegInfo pcre2_pegs[] =
{
    { CountType::SUM, "pcre2_match_limit", "total number of times pcre2 hit the match limit" },
    { CountType::SUM, "pcre2_recursion_limit", "total number of times pcre2 hit the recursion limit" },
    { CountType::SUM, "pcre2_error", "total number of times pcre2 returns error" },

    { CountType::END, nullptr, nullptr }
};

THREAD_LOCAL Pcre2Stats pcre2_stats;

//-------------------------------------------------------------------------
// implementation foo
//-------------------------------------------------------------------------

static void pcre2_capture(const void* code)
{
    int tmp_ovector_size = 0;

    pcre2_pattern_info((const pcre2_code *)code,
        PCRE2_INFO_CAPTURECOUNT, &tmp_ovector_size);

    if (tmp_ovector_size > s_ovector_max)
        s_ovector_max = tmp_ovector_size;
}

static void pcre2_check_anchored(Pcre2Data* pcre2_data)
{
    int rc;
    unsigned long int options = 0;

    if ((pcre2_data == nullptr) || (pcre2_data->re == nullptr))
        return;

    rc = pcre2_pattern_info(pcre2_data->re, PCRE2_INFO_ARGOPTIONS, (void*)&options);
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
        ParseError("pcre2_fullinfo: code and/or where were null.");
        return;

    case PCRE2_ERROR_BADMAGIC:
        ParseError("pcre2_fullinfo: compiled code didn't have correct magic.");
        return;

    case PCRE2_ERROR_BADOPTION:
        ParseError("pcre2_fullinfo: option type is invalid.");
        return;

    default:
        ParseError("pcre2_fullinfo: Unknown error code.");
        return;
    }

    if ((options & PCRE2_ANCHORED) && !(options & PCRE2_MULTILINE))
    {
        /* This means that this pcre rule option shouldn't be EvalStatus
         * even if any of it's relative children should fail to match.
         * It is anchored to the cursor set by the previous cursor setting
         * rule option */
        pcre2_data->options |= SNORT_PCRE_ANCHORED;
    }
}

static void pcre2_parse(const SnortConfig* sc, const char* data, Pcre2Data* pcre2_data)
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
        pcre2_data->options |= SNORT_PCRE_INVERT;
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

    pcre2_data->expression = snort_strdup(re);

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
         * these are snort specific don't work with pcre2 or perl
         */
        case 'R':  pcre2_data->options |= SNORT_PCRE_RELATIVE; break;
        case 'O':
            if ( sc->pcre2_override )
                pcre2_data->options |= SNORT_OVERRIDE_MATCH_LIMIT;
            break;

        default:
            ParseError("unknown/extra pcre option encountered");
            return;
        }
        opts++;
    }

    /* now compile the re */
    pcre2_data->re = pcre2_compile((PCRE2_SPTR)re, PCRE2_ZERO_TERMINATED, compile_flags, &errorcode, &erroffset, nullptr);

    if (pcre2_data->re == nullptr)
    {
        pcre2_get_error_message(errorcode, error, 128);
        ParseError(": pcre2 compile of '%s' failed at offset "
            "%zu : %s", re, erroffset, error);
        return;
    }

    /* now create match context */
    pcre2_data->match_context = pcre2_match_context_create(NULL);
    if(pcre2_data->match_context == NULL)
    {
        ParseError(": failed to allocate memory for match context");
        return;
    }

    /* now study it... */
    if (PCRE2_JIT)
        errorcode = pcre2_jit_compile(pcre2_data->re, PCRE2_JIT_COMPLETE);

    if (PCRE2_JIT || errorcode)
    {
        if ((sc->get_pcre2_match_limit() != 0) &&
            !(pcre2_data->options & SNORT_OVERRIDE_MATCH_LIMIT))
        {
            pcre2_set_match_limit(pcre2_data->match_context, sc->get_pcre2_match_limit());
        }

        if ((sc->get_pcre2_match_limit_recursion() != 0) &&
            !(pcre2_data->options & SNORT_OVERRIDE_MATCH_LIMIT))
        {
            pcre2_set_match_limit(pcre2_data->match_context, sc->get_pcre2_match_limit_recursion());
        }
    }
    else
    {
        if (!(pcre2_data->options & SNORT_OVERRIDE_MATCH_LIMIT) &&
            ((sc->get_pcre2_match_limit() != 0) ||
             (sc->get_pcre2_match_limit_recursion() != 0)))
        {
            if (sc->get_pcre2_match_limit() != 0)
            {
                pcre2_set_match_limit(pcre2_data->match_context, sc->get_pcre2_match_limit());
            }

            if (sc->get_pcre2_match_limit_recursion() != 0)
            {
                pcre2_set_match_limit(pcre2_data->match_context, sc->get_pcre2_match_limit_recursion());
            }
        }
    }

    if (PCRE2_JIT && errorcode)
    {
        ParseError("pcre2 JIT failed : %s", error);
        return;
    }

    pcre2_capture(pcre2_data->re);
    pcre2_check_anchored(pcre2_data);

    snort_free(free_me);
    return;

syntax:
    snort_free(free_me);

    // ensure integrity from parse error to fatal error
    if ( !pcre2_data->expression )
        pcre2_data->expression = snort_strdup("");

    ParseError("unable to parse pcre2 %s", data);
}

/*
 * Perform a search of the PCRE2 data.
 * found_offset will be set to -1 when the find is unsuccessful OR the routine is inverted
 */
static bool pcre2_search(
    Packet* p,
    const Pcre2Data* pcre2_data,
    const uint8_t* buf,
    unsigned len,
    unsigned start_offset,
    int& found_offset)
{
    pcre2_match_data *match_data;
    PCRE2_SIZE *ovector;
    bool matched;

    found_offset = -1;

    match_data = pcre2_match_data_create(p->context->conf->pcre2_ovector_size, NULL);
    if (match_data == nullptr) {
        pcre2_stats.pcre2_error++;
        return false;
    }

    int result = pcre2_match(
        pcre2_data->re,  /* result of pcre_compile() */
        (PCRE2_SPTR)buf, /* the subject string */
        (PCRE2_SIZE)len, /* the length of the subject string */
        (PCRE2_SIZE)start_offset, /* start at offset 0 in the subject */
        0,               /* options(handled at compile time */
        match_data,      /* match data to store the match results */
        pcre2_data->match_context); /* match context for limits */

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
         * pcre_exec() is the number of pairs that have been set. If there
         * are no capturing subpatterns, the return value from a successful
         * match is 1, indicating that just the first pair of offsets has
         * been set.
         *
         * In Snort's case, the ovector size only allows for the first pair
         * and a single int for scratch space.
         */

        ovector = pcre2_get_ovector_pointer(match_data);
        found_offset = ovector[1];
    }
    else if (result == PCRE2_ERROR_NOMATCH)
    {
        matched = false;
    }
    else if (result == PCRE2_ERROR_MATCHLIMIT)
    {
        pcre2_stats.pcre2_match_limit++;
        matched = false;
    }
    else if (result == PCRE2_ERROR_RECURSIONLIMIT)
    {
        pcre2_stats.pcre2_recursion_limit++;
        matched = false;
    }
    else
    {
        pcre2_stats.pcre2_error++;
        return false;
    }

    /* invert sense of match */
    if (pcre2_data->options & SNORT_PCRE_INVERT)
    {
        matched = !matched;
    }

    pcre2_match_data_free(match_data);

    return matched;
}

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

class Pcre2Option : public IpsOption
{
public:
    Pcre2Option(Pcre2Data* c) :
        IpsOption(s_name, RULE_OPTION_TYPE_CONTENT)
    { config = c; }

    ~Pcre2Option() override;

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    CursorActionType get_cursor_type() const override
    { return CAT_ADJUST; }

    bool is_relative() override
    { return (config->options & SNORT_PCRE_RELATIVE) != 0; }

    EvalStatus eval(Cursor&, Packet*) override;
    bool retry(Cursor&) override;

    Pcre2Data* get_data()
    { return config; }

    void set_data(Pcre2Data* pcre)
    { config = pcre; }

private:
    Pcre2Data* config;
};

Pcre2Option::~Pcre2Option()
{
    if ( !config )
        return;

    if ( config->expression )
        snort_free(config->expression);

    if ( config->match_context )
        pcre2_match_context_free(config->match_context);

    if ( config->re )
        pcre2_code_free(config->re);  // external allocation

    snort_free(config);
}

uint32_t Pcre2Option::hash() const
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

bool Pcre2Option::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const Pcre2Option& rhs = (const Pcre2Option&)ips;
    Pcre2Data* left = config;
    Pcre2Data* right = rhs.config;

    if (( strcmp(left->expression, right->expression) == 0) &&
        ( left->options == right->options))
    {
        return true;
    }

    return false;
}

IpsOption::EvalStatus Pcre2Option::eval(Cursor& c, Packet* p)
{
    // cppcheck-suppress unreadVariable
    RuleProfile profile(pcre2PerfStats);

    // short circuit this for testing pcre2 performance impact
    if ( p->context->conf->no_pcre2() )
        return NO_MATCH;

    unsigned pos = c.get_delta();
    unsigned adj = 0;

    if ( pos > c.size() )
        return NO_MATCH;

    if ( !pos && is_relative() )
        adj = c.get_pos();

    int found_offset = -1; // where is the ending location of the pattern

    if ( pcre2_search(p, config, c.buffer()+adj, c.size()-adj, pos, found_offset) )
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
// here; note also that this means relative pcre2 matches on overlapping
// patterns won't work.  given the test pattern "ABABACD":
//
// ( sid:1; content:"ABA"; content:"C"; within:1; )
// ( sid:2; pcre2:"/ABA/"; content:"C"; within:1; )
//
// sid 1 will fire but sid 2 will NOT.  this example is easily fixed by
// using content, but more advanced pcre2 won't work for the relative /
// overlap case.

bool Pcre2Option::retry(Cursor&)
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
    "rule option for matching payload data with pcre2"

class Pcre2Module : public Module
{
public:
    Pcre2Module() : Module(s_name, s_help, s_params)
    {
        data = nullptr;
    }

    ~Pcre2Module() override
    {
        delete data;
    }

#ifdef HAVE_HYPERSCAN
    bool begin(const char*, int, SnortConfig*) override;
#endif
    bool set(const char*, Value&, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &pcre2PerfStats; }

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    Pcre2Data* get_data();

    Usage get_usage() const override
    { return DETECT; }

    Module* get_mod_regex() const
    { return mod_regex; }

private:
    Pcre2Data* data;
    Module* mod_regex = nullptr;
    std::string re;
};

Pcre2Data* Pcre2Module::get_data()
{
    Pcre2Data* tmp = data;
    data = nullptr;
    return tmp;
}

const PegInfo* Pcre2Module::get_pegs() const
{ return pcre2_pegs; }

PegCount* Pcre2Module::get_counts() const
{ return (PegCount*)&pcre2_stats; }

#ifdef HAVE_HYPERSCAN
bool Pcre2Module::begin(const char* name, int v, SnortConfig* sc)
{
    if ( sc->pcre2_to_regex )
    {
        if ( !mod_regex )
            mod_regex = ModuleManager::get_module(mod_regex_name);

        if( mod_regex )
            mod_regex = mod_regex->begin(name, v, sc) ? mod_regex : nullptr;
    }
    return true;
}
#endif

bool Pcre2Module::set(const char* name, Value& v, SnortConfig* sc)
{
    assert(v.is("~re"));
    re = v.get_string();

    if( mod_regex )
        mod_regex = mod_regex->set(name, v, sc) ? mod_regex : nullptr;

    return true;
}

bool Pcre2Module::end(const char* name, int v, SnortConfig* sc)
{
    if( mod_regex )
        mod_regex = mod_regex->end(name, v, sc) ? mod_regex : nullptr;

    if ( !mod_regex )
    {
        data = (Pcre2Data*)snort_calloc(sizeof(*data));
        pcre2_parse(sc, re.c_str(), data);
    }

    // The pcre_fullinfo() function can be used to find out how many
    // capturing subpatterns there are in a compiled pattern. The
    // smallest size for ovector that will allow for n captured
    // substrings, in addition to the offsets of the substring matched
    // by the whole pattern is 3(n+1).
    if ( s_ovector_max >= 0 ) {
        sc->pcre2_ovector_size = 3 * (s_ovector_max + 1);
        s_ovector_max = -1;
    }

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new Pcre2Module; }

static void mod_dtor(Module* m)
{ delete m; }

static IpsOption* pcre2_ctor(Module* p, IpsInfo& info)
{
    pcre2_counts.pcre2_rules++;
    Pcre2Module* m = (Pcre2Module*)p;

#ifdef HAVE_HYPERSCAN
    Module* mod_regex = m->get_mod_regex();
    if ( mod_regex )
    {
        pcre2_counts.pcre2_to_hyper++;
        const IpsApi* opt_api = IpsManager::get_option_api(mod_regex_name);
        return opt_api->ctor(mod_regex, info);
    }
    else
#else
    UNUSED(info);
#endif
    {
        pcre2_counts.pcre2_native++;
        Pcre2Data* d = m->get_data();
        return new Pcre2Option(d);
    }
}

static void pcre2_dtor(IpsOption* p)
{ delete p; }

static const IpsApi pcre2_api =
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
    pcre2_ctor,
    pcre2_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_pcre2[] =
#endif
{
    &pcre2_api.base,
    nullptr
};

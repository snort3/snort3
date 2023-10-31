//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

#include <pcre.h>

#include <cassert>

#include "detection/ips_context.h"
#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "framework/parameter.h"
#include "hash/hash_key_operations.h"
#include "helpers/scratch_allocator.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "managers/ips_manager.h"
#include "managers/module_manager.h"
#include "profiler/profiler.h"
#include "utils/util.h"

using namespace snort;

#ifndef PCRE_STUDY_JIT_COMPILE
#define PCRE_STUDY_JIT_COMPILE 0
#endif

//#define NO_JIT // uncomment to disable JIT for Xcode

#ifdef NO_JIT
#define PCRE_STUDY_FLAGS 0
#define pcre_release(x) pcre_free(x)
#else
#define PCRE_STUDY_FLAGS PCRE_STUDY_JIT_COMPILE
#define pcre_release(x) pcre_free_study(x)
#endif

#define SNORT_PCRE_RELATIVE         0x00010 // relative to the end of the last match
#define SNORT_PCRE_INVERT           0x00020 // invert detect
#define SNORT_PCRE_ANCHORED         0x00040
#define SNORT_OVERRIDE_MATCH_LIMIT  0x00080 // Override default limits on match & match recursion

#define s_name "pcre"
#define mod_regex_name "regex"

struct PcreData
{
    pcre* re;           /* compiled regex */
    pcre_extra* pe;     /* studied regex foo */
    bool free_pe;
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

static unsigned scratch_index;
static ScratchAllocator* scratcher = nullptr;

static THREAD_LOCAL ProfileStats pcrePerfStats;

//-------------------------------------------------------------------------
// implementation foo
//-------------------------------------------------------------------------

static void pcre_capture(
    const void* code, const void* extra)
{
    int tmp_ovector_size = 0;

    pcre_fullinfo((const pcre*)code, (const pcre_extra*)extra,
        PCRE_INFO_CAPTURECOUNT, &tmp_ovector_size);

    if (tmp_ovector_size > s_ovector_max)
        s_ovector_max = tmp_ovector_size;
}

static void pcre_check_anchored(PcreData* pcre_data)
{
    int rc;
    unsigned long int options = 0;

    if ((pcre_data == nullptr) || (pcre_data->re == nullptr) || (pcre_data->pe == nullptr))
        return;

    rc = pcre_fullinfo(pcre_data->re, pcre_data->pe, PCRE_INFO_OPTIONS, (void*)&options);
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

    case PCRE_ERROR_NULL:
        ParseError("pcre_fullinfo: code and/or where were null.");
        return;

    case PCRE_ERROR_BADMAGIC:
        ParseError("pcre_fullinfo: compiled code didn't have correct magic.");
        return;

    case PCRE_ERROR_BADOPTION:
        ParseError("pcre_fullinfo: option type is invalid.");
        return;

    default:
        ParseError("pcre_fullinfo: Unknown error code.");
        return;
    }

    if ((options & PCRE_ANCHORED) && !(options & PCRE_MULTILINE))
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
    const char* error;
    char* re, * free_me;
    char* opts;
    char delimit = '/';
    int erroffset;
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
        case 'i':  compile_flags |= PCRE_CASELESS;            break;
        case 's':  compile_flags |= PCRE_DOTALL;              break;
        case 'm':  compile_flags |= PCRE_MULTILINE;           break;
        case 'x':  compile_flags |= PCRE_EXTENDED;            break;

        /*
         * these are pcre specific... don't work with perl
         */
        case 'A':  compile_flags |= PCRE_ANCHORED;            break;
        case 'E':  compile_flags |= PCRE_DOLLAR_ENDONLY;      break;
        case 'G':  compile_flags |= PCRE_UNGREEDY;            break;

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
    pcre_data->re = pcre_compile(re, compile_flags, &error, &erroffset, nullptr);

    if (pcre_data->re == nullptr)
    {
        ParseError(": pcre compile of '%s' failed at offset "
            "%d : %s", re, erroffset, error);
        return;
    }

    /* now study it... */
    pcre_data->pe = pcre_study(pcre_data->re, PCRE_STUDY_FLAGS, &error);

    if (pcre_data->pe)
    {
        if ((sc->get_pcre_match_limit() != 0) &&
            !(pcre_data->options & SNORT_OVERRIDE_MATCH_LIMIT))
        {
            if ( !(pcre_data->pe->flags & PCRE_EXTRA_MATCH_LIMIT) )
                pcre_data->pe->flags |= PCRE_EXTRA_MATCH_LIMIT;

            pcre_data->pe->match_limit = sc->get_pcre_match_limit();
        }

        if ((sc->get_pcre_match_limit_recursion() != 0) &&
            !(pcre_data->options & SNORT_OVERRIDE_MATCH_LIMIT))
        {
            if ( !(pcre_data->pe->flags & PCRE_EXTRA_MATCH_LIMIT_RECURSION) )
                pcre_data->pe->flags |= PCRE_EXTRA_MATCH_LIMIT_RECURSION;

            pcre_data->pe->match_limit_recursion =
                sc->get_pcre_match_limit_recursion();
        }
    }
    else
    {
        if (!(pcre_data->options & SNORT_OVERRIDE_MATCH_LIMIT) &&
            ((sc->get_pcre_match_limit() != 0) ||
             (sc->get_pcre_match_limit_recursion() != 0)))
        {
            pcre_data->pe = (pcre_extra*)snort_calloc(sizeof(pcre_extra));
            pcre_data->free_pe = true;

            if (sc->get_pcre_match_limit() != 0)
            {
                pcre_data->pe->flags |= PCRE_EXTRA_MATCH_LIMIT;
                pcre_data->pe->match_limit = sc->get_pcre_match_limit();
            }

            if (sc->get_pcre_match_limit_recursion() != 0)
            {
                pcre_data->pe->flags |= PCRE_EXTRA_MATCH_LIMIT_RECURSION;
                pcre_data->pe->match_limit_recursion =
                    sc->get_pcre_match_limit_recursion();
            }
        }
    }

    if (error != nullptr)
    {
        ParseError("pcre study failed : %s", error);
        return;
    }

    pcre_capture(pcre_data->re, pcre_data->pe);
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
    Packet* p,
    const PcreData* pcre_data,
    const uint8_t* buf,
    unsigned len,
    unsigned start_offset,
    int& found_offset)
{
    bool matched;

    found_offset = -1;

    std::vector<void *> ss = p->context->conf->state[get_instance_id()];
    assert(ss[scratch_index]);

    int result = pcre_exec(
        pcre_data->re,  /* result of pcre_compile() */
        pcre_data->pe,  /* result of pcre_study()   */
        (const char*)buf, /* the subject string */
        len,            /* the length of the subject string */
        start_offset,   /* start at offset 0 in the subject */
        0,              /* options(handled at compile time */
        (int*)ss[scratch_index], /* vector for substring information */
        p->context->conf->pcre_ovector_size); /* number of elements in the vector */

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

        found_offset = ((int*)ss[scratch_index])[1];
    }
    else if (result == PCRE_ERROR_NOMATCH)
    {
        matched = false;
    }
    else if (result == PCRE_ERROR_MATCHLIMIT)
    {
        pc.pcre_match_limit++;
        matched = false;
    }
    else if (result == PCRE_ERROR_RECURSIONLIMIT)
    {
        pc.pcre_recursion_limit++;
        matched = false;
    }
    else
    {
        pc.pcre_error++;
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
    bool retry(Cursor&, const Cursor&) override;

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

    if ( config->pe )
    {
        if ( config->free_pe )
            snort_free(config->pe);
        else
            pcre_release(config->pe);
    }

    if ( config->re )
        free(config->re);  // external allocation

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

bool PcreOption::retry(Cursor&, const Cursor&)
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

struct PcreStats
{
    PegCount pcre_rules;
#ifdef HAVE_HYPERSCAN
    PegCount pcre_to_hyper;
#endif
    PegCount pcre_native;
    PegCount pcre_negated;
};

const PegInfo pcre_pegs[] =
{
    { CountType::SUM, "pcre_rules", "total rules processed with pcre option" },
#ifdef HAVE_HYPERSCAN
    { CountType::SUM, "pcre_to_hyper", "total pcre rules by hyperscan engine" },
#endif
    { CountType::SUM, "pcre_native", "total pcre rules compiled by pcre engine" },
    { CountType::SUM, "pcre_negated", "total pcre rules using negation syntax" },
    { CountType::END, nullptr, nullptr }
};

PcreStats pcre_stats;

#define s_help \
    "rule option for matching payload data with pcre"

class PcreModule : public Module
{
public:
    PcreModule() : Module(s_name, s_help, s_params)
    {
        data = nullptr;
        scratcher = new SimpleScratchAllocator(scratch_setup, scratch_cleanup);
        scratch_index = scratcher->get_id();
    }

    ~PcreModule() override
    {
        delete data;
        delete scratcher;
    }

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

    static bool scratch_setup(SnortConfig*);
    static void scratch_cleanup(SnortConfig*);
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

bool PcreModule::scratch_setup(SnortConfig* sc)
{
    if ( s_ovector_max < 0 )
        return false;

    // The pcre_fullinfo() function can be used to find out how many
    // capturing subpatterns there are in a compiled pattern. The
    // smallest size for ovector that will allow for n captured
    // substrings, in addition to the offsets of the substring matched
    // by the whole pattern is 3(n+1).

    sc->pcre_ovector_size = 3 * (s_ovector_max + 1);
    s_ovector_max = -1;

    for ( unsigned i = 0; i < sc->num_slots; ++i )
    {
        std::vector<void *>& ss = sc->state[i];
        ss[scratch_index] = snort_calloc(sc->pcre_ovector_size, sizeof(int));
    }
    return true;
}

void PcreModule::scratch_cleanup(SnortConfig* sc)
{
    for ( unsigned i = 0; i < sc->num_slots; ++i )
    {
        std::vector<void *>& ss = sc->state[i];
        snort_free(ss[scratch_index]);
        ss[scratch_index] = nullptr;
    }
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new PcreModule; }

static void mod_dtor(Module* m)
{ delete m; }

static IpsOption* pcre_ctor(Module* p, OptTreeNode* otn)
{
    pcre_stats.pcre_rules++;
    PcreModule* m = (PcreModule*)p;

#ifdef HAVE_HYPERSCAN
    Module* mod_regex = m->get_mod_regex();
    if ( mod_regex )
    {
        pcre_stats.pcre_to_hyper++;
        const IpsApi* opt_api = IpsManager::get_option_api(mod_regex_name);
        return opt_api->ctor(mod_regex, otn);
    }
    else
#else
    UNUSED(otn);
#endif
    {
        pcre_stats.pcre_native++;
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

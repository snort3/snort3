//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

#include "detection/pattern_match_data.h"
#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hashfcn.h"
#include "log/messages.h"
#include "parser/parse_utils.h"
#include "profiler/profiler.h"
#include "utils/boyer_moore.h"
#include "utils/util.h"
#include "utils/stats.h"

#include "extract.h"

using namespace snort;

#define MAX_PATTERN_SIZE 2048

#define s_name "content"

static THREAD_LOCAL ProfileStats contentPerfStats;

static IpsOption::EvalStatus CheckANDPatternMatch(struct ContentData*, Cursor&);

//-------------------------------------------------------------------------
// instance data
//-------------------------------------------------------------------------

struct ContentData
{
    PatternMatchData pmd;

    int8_t offset_var;      /* byte_extract variable indices for offset, */
    int8_t depth_var;       /* depth, distance, within */

    unsigned match_delta;   /* Maximum distance we can jump to search for this pattern again. */

    int* skip_stride;       /* B-M skip array */
    int* shift_stride;      /* B-M shift array */

    void init();
    void setup_bm();
    void set_max_jump_size();
};

void ContentData::init()
{
    offset_var = IPS_OPTIONS_NO_VAR;
    depth_var = IPS_OPTIONS_NO_VAR;
}

void ContentData::setup_bm()
{
    skip_stride = snort::make_skip(pmd.pattern_buf, pmd.pattern_size);
    shift_stride = make_shift(pmd.pattern_buf, pmd.pattern_size);
}

// find the maximum number of characters we can jump ahead
// from the current offset when checking for this pattern again

void ContentData::set_max_jump_size()
{
    unsigned j = 0;

    for ( unsigned i = 1; i < pmd.pattern_size; i++ )
    {
        if ( pmd.pattern_buf[j] != pmd.pattern_buf[i] )
        {
            j = 0;
            continue;
        }
        if ( i == (pmd.pattern_size - 1) )
        {
            match_delta = pmd.pattern_size - j - 1;
            return;
        }
        j++;
    }
    match_delta = pmd.pattern_size;
}

//-------------------------------------------------------------------------
// rule option
//-------------------------------------------------------------------------

class ContentOption : public IpsOption
{
public:
    ContentOption(ContentData* c) : IpsOption(s_name, RULE_OPTION_TYPE_CONTENT)
    { config = c; }

    ~ContentOption() override;

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    CursorActionType get_cursor_type() const override
    { return CAT_ADJUST; }

    bool is_relative() override
    { return config->pmd.is_relative(); }

    bool retry(Cursor&) override;

    ContentData* get_data()
    { return config; }

    void set_data(ContentData* cd)
    { config = cd; }

    EvalStatus eval(Cursor& c, Packet*) override
    { return CheckANDPatternMatch(config, c); }

    PatternMatchData* get_pattern(SnortProtocolId, RuleDirection) override
    { return &config->pmd; }

protected:
    ContentData* config;
};

ContentOption::~ContentOption()
{
    ContentData* cd = config;

    if ( !cd )
        return;

    if ( cd->pmd.pattern_buf )
        snort_free(const_cast<char*>(cd->pmd.pattern_buf));

    if ( cd->pmd.last_check )
        snort_free(cd->pmd.last_check);

    if ( cd->skip_stride )
        snort_free(cd->skip_stride);

    if ( cd->shift_stride )
        snort_free(cd->shift_stride);

    snort_free(cd);
}

bool ContentOption::retry(Cursor& c)
{
    if ( config->pmd.is_negated() )
        return false;

    if ( !config->pmd.depth )
        return true;

    // FIXIT-L consider moving adjusting delta from eval to retry
    assert(c.get_delta() >= config->match_delta);

    unsigned min = c.get_delta() + config->pmd.pattern_size;
    unsigned max = c.get_delta() - config->match_delta + config->pmd.offset + config->pmd.depth;

    return min <= max;
}

uint32_t ContentOption::hash() const
{
    uint32_t a,b,c;
    const ContentData* cd = config;

    a = cd->pmd.flags;
    b = cd->pmd.offset;
    c = cd->pmd.depth;

    mix(a,b,c);

    a += cd->pmd.pattern_size;
    b += cd->pmd.fp_offset;
    c += cd->pmd.fp_length;

    mix(a,b,c);

    if ( cd->pmd.pattern_size )
        mix_str(a, b, c, cd->pmd.pattern_buf, cd->pmd.pattern_size);

    mix_str(a,b,c,get_name());

    a += cd->depth_var;
    b += cd->offset_var;
    c += cd->match_delta;

    mix(a,b,c);
    finalize(a,b,c);

    return c;
}

#if 0
// see below for why this is disabled
static bool same_buffers(
    unsigned len1, const char* buf1, bool no_case1,
    unsigned len2, const char* buf2, bool no_case2)
{
    /* Sizes will be most different, check that first */
    if ( len1 != len2 or no_case1 != no_case2 )
        return false;

    if ( !len1 )
        return true;

    /* Next compare the patterns for uniqueness */
    if ( no_case1 )
    {
        /* If no_case is set, do case insensitive compare on pattern */
        for ( unsigned i = 0; i < len1; ++i )
        {
            if ( toupper(buf1[i]) != toupper(buf2[i]) )
                return false;
        }
    }
    else
    {
        /* If no_case is not set, do case sensitive compare on pattern */
        if ( memcmp(buf1, buf2, len1) )
            return false;
    }
    return true;
}

#endif

// FIXIT-P FAST_PAT and fp_only are set after hash table comparisons so this must
// return this == &ips to avoid unnecessary reevaluation and false positives.
// when this is fixed, add PatternMatchData::operator==().
bool ContentOption::operator==(const IpsOption& ips) const
{
#if 0
    if ( !IpsOption::operator==(ips) )
        return false;

    ContentOption& rhs = (ContentOption&)ips;
    const ContentData& left = *config;
    const ContentData& right = *rhs.config;

    if ( !same_buffers(left.pmd.pattern_size, left.pmd.pattern_buf, left.pmd.is_no_case(),
        right.pmd.pattern_size, right.pmd.pattern_buf, right.pmd.is_no_case()) )
        return false;

    /* Now check the rest of the options */
    if ((left.pmd.flags == right.pmd.flags) &&
        (left.pmd.fp_offset == right.pmd.fp_offset) &&
        (left.pmd.fp_length == right.pmd.fp_length) &&
        (left.pmd.offset == right.pmd.offset) &&
        (left.pmd.depth == right.pmd.depth) &&
        // pattern_size and pattern_buf already checked
        // pm_type set later (but determined by CAT)
        (left.match_delta == right.match_delta) &&
        (left.offset_var == right.offset_var) &&
        (left.depth_var == right.depth_var) )
    {
        return true;
    }
#endif
    return this == &ips;
}

//-------------------------------------------------------------------------
// runtime functions
//-------------------------------------------------------------------------

/*
 * single search function.
 *
 * return  1 for found
 * return  0 for not found
 * return -1 for error (search out of bounds)
 */
static int uniSearchReal(ContentData* cd, Cursor& c)
{
    int offset, depth;

    /* Get byte_extract variables */
    if (cd->offset_var >= 0 && cd->offset_var < NUM_IPS_OPTIONS_VARS)
    {
        uint32_t extract;
        GetVarValueByIndex(&extract, cd->offset_var);
        offset = (int)extract;
    }
    else
        offset = cd->pmd.offset;

    if (cd->depth_var >= 0 && cd->depth_var < NUM_IPS_OPTIONS_VARS)
    {
        uint32_t extract;
        GetVarValueByIndex(&extract, cd->depth_var);
        depth = (int)extract;
    }
    else
        depth = cd->pmd.depth;

    int pos = c.get_delta();

    if ( !pos )
    {
        if ( cd->pmd.is_relative() )
            pos = c.get_pos();

        pos += offset;
    }

    if ( pos < 0 )
        pos = 0;

    int len = c.size() - pos;

    if ( !depth || len < depth )
        depth = len;

    unsigned end = pos + cd->pmd.pattern_size;

    // If the pattern size is greater than the amount of data we have to
    // search, there's no way we can match, but return 0 here for the
    // case where the match is inverted and there is at least some data.
    if ( end > c.size() || (int)end > pos + depth )
    {
        if ( cd->pmd.is_negated() && (depth > 0) )
            return 0;

        return -1;
    }

    const uint8_t* base = c.buffer() + pos;
    int found;

    if ( cd->pmd.is_no_case() )
    {
        found = mSearchCI(
            (const char*)base, depth, cd->pmd.pattern_buf, cd->pmd.pattern_size,
            cd->skip_stride, cd->shift_stride);
    }
    else
    {
        found = mSearch(
            (const char*)base, depth, cd->pmd.pattern_buf, cd->pmd.pattern_size,
            cd->skip_stride, cd->shift_stride);
    }

    if ( found >= 0 )
    {
        int at = pos + found;
        c.set_delta(at + cd->match_delta);
        c.set_pos(at + cd->pmd.pattern_size);
        return 1;
    }

    return 0;
}

static IpsOption::EvalStatus CheckANDPatternMatch(ContentData* idx, Cursor& c)
{
    Profile profile(contentPerfStats);

    int found = uniSearchReal(idx, c);

    if ( found == -1 )
    {
        /* On error, mark as not found.  This is necessary to handle !content
           cases.  In that case, a search that is outside the given buffer will
           return 0, and !0 is 1, so a !content out of bounds will return true,
           which is not what we want.  */
        found = 0;
    }
    else
    {
        found ^= idx->pmd.is_negated();
    }

    if ( found )
    {
        return IpsOption::MATCH;
    }
    else
    {
        return IpsOption::NO_MATCH;
    }
}

//-------------------------------------------------------------------------
// helper foo
//-------------------------------------------------------------------------

typedef enum
{
    CMF_DISTANCE = 0x1, CMF_WITHIN = 0x2, CMF_OFFSET = 0x4, CMF_DEPTH = 0x8
} ContentModifierFlags;

static unsigned GetCMF(ContentData* cd)
{
    unsigned cmf = 0;
    if ( (cd->pmd.offset != 0) || (cd->offset_var != -1) )
        cmf |= CMF_OFFSET;
    if ( (cd->pmd.depth != 0) || (cd->depth_var != -1) )
        cmf |= CMF_DEPTH;
    return cmf;
}

#define BAD_DISTANCE (CMF_DISTANCE | CMF_OFFSET | CMF_DEPTH)
#define BAD_WITHIN (CMF_WITHIN | CMF_OFFSET | CMF_DEPTH)
#define BAD_OFFSET (CMF_OFFSET | CMF_DISTANCE | CMF_WITHIN)
#define BAD_DEPTH (CMF_DEPTH | CMF_DISTANCE | CMF_WITHIN)

//-------------------------------------------------------------------------
// parsing methods
//-------------------------------------------------------------------------

static void parse_content(ContentData* cd, const char* rule)
{
    bool negated;
    std::string buf;

    if ( !parse_byte_code(rule, negated, buf) )
        return;

    const char* tmp_buf = buf.c_str();
    unsigned dummy_size = buf.size();

    char* pattern_buf = (char*)snort_alloc(dummy_size+1);
    memcpy(pattern_buf, tmp_buf, dummy_size);
    pattern_buf[dummy_size] = '\0';

    cd->pmd.pattern_buf = pattern_buf;
    cd->pmd.pattern_size = dummy_size;

    cd->pmd.set_literal();

    if ( negated )
        cd->pmd.set_negated();

    cd->set_max_jump_size();
}

static void parse_offset(ContentData* cd, const char* data)
{
    if ( GetCMF(cd) & BAD_OFFSET && cd->pmd.is_relative() )
    {
        ParseError("offset can't be used with itself, distance, or within");
        return;
    }

    if (data == nullptr)
    {
        ParseError("missing argument to 'offset' option");
        return;
    }

    if (isdigit(data[0]) || data[0] == '-')
    {
        cd->pmd.offset = parse_int(data, "offset");
        cd->offset_var = IPS_OPTIONS_NO_VAR;
    }
    else
    {
        cd->offset_var = GetVarByName(data);
        if (cd->offset_var == IPS_OPTIONS_NO_VAR)
        {
            ParseError(INVALID_VAR_ERR_STR, "content offset", data);
            return;
        }
    }

}

static void parse_depth(ContentData* cd, const char* data)
{
    if ( GetCMF(cd) & BAD_DEPTH && cd->pmd.is_relative() )
    {
        ParseError("depth can't be used with itself, distance, or within");
        return;
    }

    if (data == nullptr)
    {
        ParseError("missing argument to 'depth' option");
        return;
    }

    if (isdigit(data[0]) || data[0] == '-')
    {
        cd->pmd.depth = parse_int(data, "depth");

        /* check to make sure that this the depth allows this rule to fire */
        if (cd->pmd.depth < (int)cd->pmd.pattern_size)
        {
            ParseError("the depth (%d) is less than the size of the content(%u)",
                cd->pmd.depth, cd->pmd.pattern_size);
            return;
        }
        cd->depth_var = IPS_OPTIONS_NO_VAR;
    }
    else
    {
        cd->depth_var = GetVarByName(data);
        if (cd->depth_var == IPS_OPTIONS_NO_VAR)
        {
            ParseError(INVALID_VAR_ERR_STR, "content depth", data);
            return;
        }
    }

}

static void parse_distance(ContentData* cd, const char* data)
{
    if ( GetCMF(cd) & BAD_DISTANCE && !cd->pmd.is_relative() )
    {
        ParseError("distance can't be used with itself, offset, or depth");
        return;
    }

    if (data == nullptr)
    {
        ParseError("missing argument to 'distance' option");
        return;
    }

    if (isdigit(data[0]) || data[0] == '-')
    {
        cd->pmd.offset = parse_int(data, "distance");
        cd->offset_var = IPS_OPTIONS_NO_VAR;
    }
    else
    {
        cd->offset_var = GetVarByName(data);
        if (cd->offset_var == IPS_OPTIONS_NO_VAR)
        {
            ParseError(INVALID_VAR_ERR_STR, "content distance", data);
            return;
        }
    }

    cd->pmd.set_relative();
}

static void parse_within(ContentData* cd, const char* data)
{
    if ( GetCMF(cd) & BAD_WITHIN && !cd->pmd.is_relative() )
    {
        ParseError("within can't be used with itself, offset, or depth");
        return;
    }

    if (data == nullptr)
    {
        ParseError("missing argument to 'within' option");
        return;
    }

    if (isdigit(data[0]) || data[0] == '-')
    {
        cd->pmd.depth = parse_int(data, "within");

        if (cd->pmd.depth < (int)cd->pmd.pattern_size)
        {
            ParseError("within (%d) is smaller than size of pattern", cd->pmd.depth);
            return;
        }
        cd->depth_var = IPS_OPTIONS_NO_VAR;
    }
    else
    {
        cd->depth_var = GetVarByName(data);
        if (cd->depth_var == IPS_OPTIONS_NO_VAR)
        {
            ParseError(INVALID_VAR_ERR_STR, "content within", data);
            return;
        }
    }


    cd->pmd.set_relative();
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~data", Parameter::PT_STRING, nullptr, nullptr,
      "data to match" },

    { "nocase", Parameter::PT_IMPLIED, nullptr, nullptr,
      "case insensitive match" },

    { "fast_pattern", Parameter::PT_IMPLIED, nullptr, nullptr,
      "use this content in the fast pattern matcher instead of the content selected by default" },

    { "fast_pattern_offset", Parameter::PT_INT, "0:", "0",
      "number of leading characters of this content the fast pattern matcher should exclude" },

    { "fast_pattern_length", Parameter::PT_INT, "1:", nullptr,
      "maximum number of characters from this content the fast pattern matcher should use" },

    { "offset", Parameter::PT_STRING, nullptr, nullptr,
      "var or number of bytes from start of buffer to start search" },

    { "depth", Parameter::PT_STRING, nullptr, nullptr,
      "var or maximum number of bytes to search from beginning of buffer" },

    { "distance", Parameter::PT_STRING, nullptr, nullptr,
      "var or number of bytes from cursor to start search" },

    { "within", Parameter::PT_STRING, nullptr, nullptr,
      "var or maximum number of bytes to search from cursor" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "payload rule option for basic pattern matching"

class ContentModule : public Module
{
public:
    ContentModule() : Module(s_name, s_help, s_params)
    { cd = nullptr; }

    ~ContentModule() override
    { delete cd; }

    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &contentPerfStats; }

    ContentData* get_data();

    Usage get_usage() const override
    { return DETECT; }

private:
    ContentData* cd;
};

ContentData* ContentModule::get_data()
{
    ContentData* tmp = cd;
    cd = nullptr;
    return tmp;
}

bool ContentModule::begin(const char*, int, SnortConfig*)
{
    cd = (ContentData*)snort_calloc(sizeof(ContentData));
    cd->init();
    return true;
}

bool ContentModule::end(const char*, int, SnortConfig*)
{
    if ( (int)cd->pmd.pattern_size <= cd->pmd.fp_offset )
    {
        ParseError(
            "fast_pattern_offset must be less "
            "than the actual pattern length which is %u.",
            cd->pmd.pattern_size);
        return false;
    }
    if ( (int)cd->pmd.pattern_size < (cd->pmd.fp_offset + cd->pmd.fp_length) )
    {
        ParseError(
            "fast_pattern_offset + fast_pattern_length must be less "
            "than or equal to the actual pattern length which is %u.",
            cd->pmd.pattern_size);
        return false;
    }
    if ( cd->pmd.is_no_case() )
    {
        char* s = const_cast<char*>(cd->pmd.pattern_buf);

        for ( unsigned i = 0; i < cd->pmd.pattern_size; i++ )
            s[i] = toupper(cd->pmd.pattern_buf[i]);
    }
    cd->setup_bm();
    return true;
}

bool ContentModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("~data") )
        parse_content(cd, v.get_string());

    else if ( v.is("offset") )
        parse_offset(cd, v.get_string());

    else if ( v.is("depth") )
        parse_depth(cd, v.get_string());

    else if ( v.is("distance") )
        parse_distance(cd, v.get_string());

    else if ( v.is("within") )
        parse_within(cd, v.get_string());

    else if ( v.is("nocase") )
        cd->pmd.set_no_case();

    else if ( v.is("fast_pattern") )
        cd->pmd.set_fast_pattern();

    else if ( v.is("fast_pattern_offset") )
    {
        cd->pmd.fp_offset = v.get_long();
        cd->pmd.set_fast_pattern();
    }
    else if ( v.is("fast_pattern_length") )
    {
        cd->pmd.fp_length = v.get_long();
        cd->pmd.set_fast_pattern();
    }
    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new ContentModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* content_ctor(Module* p, OptTreeNode*)
{
    ContentModule* m = (ContentModule*)p;
    ContentData* cd = m->get_data();
    return new ContentOption(cd);
}

static void content_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi content_api =
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
    content_ctor,
    content_dtor,
    nullptr
};

// FIXIT-L need boyer_moore.cc funcs but they
// aren't otherwise called
//#ifdef BUILDING_SO
//SO_PUBLIC const BaseApi* snort_plugins[] =
//{
//    &content_api.base,
//    nullptr
//};
//#else
const BaseApi* ips_content = &content_api.base;
//#endif


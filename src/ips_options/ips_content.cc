//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

#include "detection/extract.h"
#include "detection/pattern_match_data.h"
#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hash_key_operations.h"
#include "helpers/literal_search.h"
#include "log/messages.h"
#include "main/thread_config.h"
#include "parser/parse_utils.h"
#include "profiler/profiler.h"
#include "utils/util.h"

using namespace snort;

#define MAX_PATTERN_SIZE 2048

#define s_name "content"

static THREAD_LOCAL ProfileStats contentPerfStats;
static LiteralSearch::Handle* search_handle = nullptr;

static IpsOption::EvalStatus CheckANDPatternMatch(class ContentData*, Cursor&);

//-------------------------------------------------------------------------
// instance data
//-------------------------------------------------------------------------

class ContentData
{
public:
    ContentData();
    ~ContentData();

    void setup_bm();
    void set_max_jump_size();

    PatternMatchData pmd = {};

    LiteralSearch* searcher;

    int8_t offset_var;      /* byte_extract variable indices for offset, */
    int8_t depth_var;       /* depth, distance, within */
    bool offset_set = false;

    unsigned match_delta;   /* Maximum distance we can jump to search for this pattern again. */

    bool depth_configured = true;

    uint8_t char_width;  /* Byte width to expand to */
    bool little_endian;  /* Endianness of multi-byte characters */
};

ContentData::ContentData()
{
    searcher = nullptr;
    offset_var = IPS_OPTIONS_NO_VAR;
    depth_var = IPS_OPTIONS_NO_VAR;
    match_delta = 0;
    char_width = 1;
    little_endian = false;
}

ContentData::~ContentData()
{
    if ( searcher )
        delete searcher;

    if ( pmd.pattern_buf )
        snort_free(const_cast<char*>(pmd.pattern_buf));

    if ( pmd.last_check )
        snort_free(pmd.last_check);
}

void ContentData::setup_bm()
{
    const uint8_t* pattern = (const uint8_t*)pmd.pattern_buf;
    searcher = LiteralSearch::instantiate(search_handle, pattern, pmd.pattern_size, pmd.is_no_case());
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

    ~ContentOption() override
    { delete config; }

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

static inline bool retry(const PatternMatchData& pmd, const Cursor& c)
{
    if ( pmd.is_negated() )
        return false;

    // since we're already out-of-bound, no reason to retry
    if ( c.get_pos() >= c.size() )
        return false;

    if ( !pmd.depth )
        return true;

    return c.get_delta() + pmd.pattern_size <= pmd.depth;
}

bool ContentOption::retry(Cursor& c)
{
    return ::retry(config->pmd, c);
}

uint32_t ContentOption::hash() const
{
    uint32_t a = config->pmd.flags;
    uint32_t b = config->pmd.offset;
    uint32_t c = config->pmd.depth;

    mix(a,b,c);

    a += config->pmd.pattern_size;
    b += config->pmd.fp_offset;
    c += config->pmd.fp_length;

    mix(a,b,c);

    b += IpsOption::hash();

    mix(a, b, c);

    if ( config->pmd.pattern_size )
        mix_str(a, b, c, config->pmd.pattern_buf, config->pmd.pattern_size);

    a += config->depth_var;
    b += config->offset_var;
    c += config->match_delta;

    mix(a, b, c);
    finalize(a, b, c);

    return c;
}

static bool same_buffers(
    unsigned len1, const char* buf1, bool no_case1,
    unsigned len2, const char* buf2, bool no_case2)
{
    if ( len1 != len2 or no_case1 != no_case2 )
        return false;

    if ( !len1 )
        return true;

    if ( no_case1 )
    {
        for ( unsigned i = 0; i < len1; ++i )
        {
            if ( toupper(buf1[i]) != toupper(buf2[i]) )
                return false;
        }
    }
    else
    {
        if ( memcmp(buf1, buf2, len1) )
            return false;
    }
    return true;
}

bool ContentOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const ContentOption& rhs = (const ContentOption&)ips;
    const ContentData& left = *config;
    const ContentData& right = *rhs.config;

    if ( !same_buffers(left.pmd.pattern_size, left.pmd.pattern_buf, left.pmd.is_no_case(),
        right.pmd.pattern_size, right.pmd.pattern_buf, right.pmd.is_no_case()) )
        return false;

    if (
        (left.pmd.flags == right.pmd.flags) and
        (left.pmd.offset == right.pmd.offset) and
        (left.pmd.depth == right.pmd.depth) and
        (left.pmd.fp_offset == right.pmd.fp_offset) and
        (left.pmd.fp_length == right.pmd.fp_length) and
        (left.match_delta == right.match_delta) and
        (left.offset_var == right.offset_var) and
        (left.depth_var == right.depth_var) )
    {
        return true;
    }
    return false;
}

//-------------------------------------------------------------------------
// runtime functions
//-------------------------------------------------------------------------

/*
 * single search function.
 *
 * return  true for found
 * return  false for all other cases
 */
static bool uniSearchReal(ContentData* cd, Cursor& c)
{
    // byte_extract variables are strictly unsigned, used for sizes and forward offsets
    // converting from uint32_t to int64_t ensures all extracted values remain positive
    int64_t offset, depth, orig_depth;

    if (cd->offset_var >= 0 && cd->offset_var < NUM_IPS_OPTIONS_VARS)
    {
        uint32_t extract;
        GetVarValueByIndex(&extract, cd->offset_var);
        offset = extract;
    }
    else
        offset = cd->pmd.offset;

    if (cd->depth_var >= 0 && cd->depth_var < NUM_IPS_OPTIONS_VARS)
    {
        uint32_t extract;
        GetVarValueByIndex(&extract, cd->depth_var);
        orig_depth = depth = extract;
    }
    else
        orig_depth = depth = cd->pmd.depth;

    uint32_t file_pos = c.get_file_pos();

    if (file_pos and cd->offset_set)
    {
        offset -= file_pos;
        if (offset < 0)
            return false;
    }

    int64_t pos = 0;

    if ( !c.get_delta() and !c.is_re_eval() )
    {
        // first - adjust from cursor or buffer start
        pos = (cd->pmd.is_relative() ? c.get_pos() : 0) + offset;

        if ( pos < 0 )
        {
            if ( cd->depth_configured )
                depth += pos;

            pos = 0;
        }
    }
    else
    {
        // retry - adjust from start of last match
        pos = (int64_t)c.get_pos() - cd->pmd.pattern_size + cd->match_delta;

        if ( cd->depth_configured )
            depth -= (int64_t)c.get_delta();

        if ( pos < 0 )
            return false;
    }

    if ( (cd->depth_configured and depth <= 0) or !c.size() )
        return false;

    unsigned last_position = c.size() - 1;

    if ( last_position < pos )
    {
        if ( !cd->pmd.is_negated() )
        {
            unsigned next_pkt_pos = pos - last_position + c.size();

            c.set_pos(next_pkt_pos);
            c.set_re_eval(true);
        }

        return false;
    }

    unsigned min_bytes_to_match = pos + cd->pmd.pattern_size;

    if ( min_bytes_to_match > c.size() )
    {
        constexpr unsigned current_byte_evaluated = 1;
        unsigned depth_skipped = last_position - pos + current_byte_evaluated;

        if ( !cd->pmd.is_negated() && depth >= depth_skipped + cd->pmd.pattern_size )
        {
            assert(cd->pmd.pattern_size >= depth_skipped);

            // IPS content takes into account repeated parts of
            // the pattern during retries. But in next PDU, such influence
            // is harmful, so some extra bytes are needed
            unsigned extra_offset = cd->pmd.pattern_size - cd->match_delta;
            unsigned next_pkt_pos = extra_offset + c.size();

            c.set_pos(next_pkt_pos);
            c.set_re_eval(true);
            c.set_delta(depth_skipped);
        }

        return false;
    }

    int64_t bytes_left = c.size() - pos;

    if ( !cd->depth_configured or bytes_left < depth )
        depth = bytes_left;

    if ( cd->pmd.pattern_size > depth )
        return false;

    const uint8_t* base = c.buffer() + pos;
    int found = cd->searcher->search(search_handle, base, (unsigned)depth);

    if ( found >= 0 )
    {
        if ( !cd->pmd.is_negated() )
        {
            c.set_delta(c.get_delta() + found + cd->match_delta);
            c.set_pos(pos + found + cd->pmd.pattern_size);
        }

        return true;
    }
    else if ( cd->depth_configured )
    {
        unsigned used_depth = depth + c.get_delta();

        if ( orig_depth <= used_depth + cd->pmd.pattern_size )
            return false;

        // Continuation should be created only on the last evaluation of current node,
        // where node means current ips option during detection process
        if ( c.get_delta() == 0 and !c.is_re_eval() and !retry(cd->pmd, c) )
            return false;

        unsigned next_pkt_pos = c.size() + 0;

        c.set_pos(next_pkt_pos);
        c.set_re_eval(true);
        c.set_delta(used_depth);
    }

    return false;
}

static IpsOption::EvalStatus CheckANDPatternMatch(ContentData* idx, Cursor& c)
{
    // cppcheck-suppress unreadVariable
    RuleProfile profile(contentPerfStats);

    bool found = uniSearchReal(idx, c);

    found ^= idx->pmd.is_negated();

    return found ? IpsOption::MATCH : IpsOption::NO_MATCH;
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
        cd->offset_set = true;
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
        cd->pmd.depth = parse_int(data, "depth", cd->pmd.pattern_size);
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
        cd->pmd.depth = parse_int(data, "within", cd->pmd.pattern_size);
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

    { "fast_pattern_offset", Parameter::PT_INT, "0:65535", "0",
      "number of leading characters of this content the fast pattern matcher should exclude" },

    { "fast_pattern_length", Parameter::PT_INT, "1:65535", nullptr,
      "maximum number of characters from this content the fast pattern matcher should use" },

    { "offset", Parameter::PT_STRING, nullptr, nullptr,
      "var or number of bytes from start of buffer to start search" },

    { "depth", Parameter::PT_STRING, nullptr, nullptr,
      "var or maximum number of bytes to search from beginning of buffer" },

    { "distance", Parameter::PT_STRING, nullptr, nullptr,
      "var or number of bytes from cursor to start search" },

    { "within", Parameter::PT_STRING, nullptr, nullptr,
      "var or maximum number of bytes to search from cursor" },

    { "width", Parameter::PT_ENUM, "8|16|32", "8",
      "char width to convert to" },

    { "endian", Parameter::PT_ENUM, "big|little", "big",
      "specify big/little endian for wide string conversions" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "payload rule option for basic pattern matching"

class ContentModule : public Module
{
public:
    ContentModule() : Module(s_name, s_help, s_params)
    {
        cd = nullptr;
        search_handle = LiteralSearch::setup();
    }

    ~ContentModule() override
    {
        delete cd;
        LiteralSearch::cleanup(search_handle);
    }

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
    delete cd;
    cd = new ContentData();
    return true;
}

bool ContentModule::end(const char*, int, SnortConfig*)
{
    if ( cd->char_width > 1 )
    {
        // An endian flip of a single byte is just an offset
        int endian_offset = cd->little_endian ? 0 : cd->char_width - 1;

        char* temp = new char[cd->char_width * cd->pmd.pattern_size]();

        for ( unsigned i = 0; i < cd->pmd.pattern_size; i++ )
        {
            temp[(i * cd->char_width) + endian_offset] = cd->pmd.pattern_buf[i];
        }

        delete[] cd->pmd.pattern_buf;
        cd->pmd.pattern_buf = temp;
        cd->pmd.pattern_size *= cd->char_width;
        cd->pmd.fp_length *= cd->char_width;
        cd->pmd.fp_offset *= cd->char_width;
    }

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

    if ( !cd->pmd.has_alpha() )
        cd->pmd.set_no_case();

    if ( cd->pmd.is_negated() )
    {
        if (cd->pmd.fp_length || cd->pmd.fp_offset)
        {
            ParseWarning(WARN_RULES,
                "Fast pattern constraints for negated "
                "content will be ignored");

            cd->pmd.fp_length = cd->pmd.pattern_size;
            cd->pmd.fp_offset = 0;
        }

        cd->pmd.last_check = (PmdLastCheck*)snort_calloc(
            ThreadConfig::get_instance_max(), sizeof(*cd->pmd.last_check));
    }

    if ( cd->pmd.depth == 0 and cd->depth_var == IPS_OPTIONS_NO_VAR )
        cd->depth_configured = false;

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
        cd->pmd.fp_offset = v.get_uint16();
        cd->pmd.set_fast_pattern();
    }
    else if ( v.is("fast_pattern_length") )
    {
        cd->pmd.fp_length = v.get_uint16();
        cd->pmd.set_fast_pattern();
    }
    else if ( v.is("width") )
    {
        switch ( v.get_uint8() )
        {
        case 0:  // "8"
            cd->char_width = 1;
            break;
        case 1:  // "16"
            cd->char_width = 2;
            break;
        case 2:  // "32"
            cd->char_width = 4;
            break;
        }
    }
    else if ( v.is("endian") )
    {
        cd->little_endian = v.get_uint8() == 1;
    }

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

static IpsOption* content_ctor(Module* p, IpsInfo&)
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

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_content[] =
#endif
{
    &content_api.base,
    nullptr
};


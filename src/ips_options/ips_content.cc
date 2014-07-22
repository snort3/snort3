/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include "ips_content.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#ifdef DEBUG_MSGS
# include <assert.h>
#endif

#include "snort_types.h"
#include "snort_bounds.h"
#include "detection/treenodes.h"
#include "snort_debug.h"
#include "parser/mstring.h"
#include "utils/boyer_moore.h"
#include "util.h"
#include "parser/parser.h"
#include "sfhashfcn.h"
#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "snort.h"
#include "profiler.h"
#include "fpdetect.h"
#include "sfhashfcn.h"
#include "detection/detection_defines.h"
#include "ips_byte_extract.h"
#include "detection/detection_util.h"
#include "framework/parameter.h"
#include "framework/module.h"

#define MAX_PATTERN_SIZE 2048

static const char* s_name = "content";

static THREAD_LOCAL ProfileStats contentPerfStats;

static int CheckANDPatternMatch(PatternMatchData*, Cursor&);

class ContentOption : public IpsOption
{
public:
    ContentOption(PatternMatchData* c,
        option_type_t t = RULE_OPTION_TYPE_CONTENT) :
        IpsOption(s_name, t)
    { config = c; };

    ~ContentOption();

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    CursorActionType get_cursor_type() const
    { return CAT_ADJUST; };

    bool is_relative()
    { return (config->relative == 1); };

    PatternMatchData* get_data()
    { return config; };

    void set_data(PatternMatchData* pmd)
    { config = pmd; };

    int eval(Cursor& c, Packet*)
    { return CheckANDPatternMatch(config, c); };

protected:
    PatternMatchData* config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

ContentOption::~ContentOption()
{
    PatternMatchData *pmd = config;

    if ( !pmd )
        return;

    if (pmd->pattern_buf)
        free(pmd->pattern_buf);
    if(pmd->skip_stride)
        free(pmd->skip_stride);
    if(pmd->shift_stride)
        free(pmd->shift_stride);

    free(pmd->last_check);
    free(pmd);
}

uint32_t ContentOption::hash() const
{
    uint32_t a,b,c;
    const PatternMatchData *pmd = config;

    a = pmd->negated;
    b = pmd->offset;
    c = pmd->depth;

    mix(a,b,c);

    a += pmd->pattern_size;
    b += pmd->relative;
    c += pmd->match_delta;

    mix(a,b,c);

    if ( pmd->pattern_size )
        mix_str(a,b,c,pmd->pattern_buf, pmd->pattern_size);

    a += pmd->no_case;
    b += pmd->fp;
    c += pmd->fp_only;

    mix(a,b,c);
    mix_str(a,b,c,get_name());

    a += pmd->fp_offset;
    b += pmd->fp_length;
    c += pmd->offset_var;

    mix(a,b,c);

    a += pmd->depth_var;

    final(a,b,c);

    return c;
}

bool ContentOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    ContentOption& rhs = (ContentOption&)ips;
    PatternMatchData *left = config;
    PatternMatchData *right = rhs.config;
    unsigned int i;

    /* Sizes will be most different, check that first */
    if ((left->pattern_size != right->pattern_size) ||
        (left->no_case != right->no_case))
        return false;

    /* Next compare the patterns for uniqueness */
    if (left->pattern_size)
    {
        if (left->no_case)
        {
            /* If no_case is set, do case insensitive compare on pattern */
            for (i=0;i<left->pattern_size;i++)
            {
                if (toupper(left->pattern_buf[i]) != toupper(right->pattern_buf[i]))
                {
                    return false;
                }
            }
        }
        else
        {
            /* If no_case is not set, do case sensitive compare on pattern */
            if (memcmp(left->pattern_buf, right->pattern_buf, left->pattern_size) != 0)
            {
                return false;
            }
        }
    }

    /* Now check the rest of the options */
    if ((left->negated == right->negated) &&
        (left->offset == right->offset) &&
        (left->depth == right->depth) &&
        (left->relative == right->relative) &&
        (left->match_delta == right->match_delta) &&
        (left->fp == right->fp) &&
        (left->fp_only == right->fp_only) &&
        (left->fp_offset == right->fp_offset) &&
        (left->fp_length == right->fp_length) &&
        (left->offset_var == right->offset_var) &&
        (left->depth_var == right->depth_var) )
    {
        return true;
    }

    return false;
}

//-------------------------------------------------------------------------
// private helpers
//-------------------------------------------------------------------------

static PatternMatchData* new_pmd()
{
    PatternMatchData *pmd = (PatternMatchData*)SnortAlloc(sizeof(PatternMatchData));

    /* Set any non-zero default values here. */
    pmd->offset_var = BYTE_EXTRACT_NO_VAR;
    pmd->depth_var = BYTE_EXTRACT_NO_VAR;

    return pmd;
}

static int fast_pattern_count(OptTreeNode *otn, int list_type)
{
    OptFpList* fpl = otn ? otn->opt_func : nullptr;
    int c = 0;

    while ( fpl )
    {
        if ( fpl->type == list_type )
        {
            ContentOption* opt = (ContentOption*)fpl->context;
            PatternMatchData* pmd = opt->get_data();

            if ( pmd->fp )
                c++;
        }
        fpl = fpl->next;
    }
    return c;
}

static int32_t parse_int(
    const char* data, const char* tag, int low = -65535, int high = 65535)
{
    int32_t value = 0;
    char *endptr = NULL;

    value = SnortStrtol(data, &endptr, 10);

    if (*endptr)
        ParseError("Invalid '%s' format.", tag);

    if (errno == ERANGE)
        ParseError("Range problem on '%s' value.", tag);

    if ((value > high) || (value < low))
        ParseError("'%s' must in %d:%d", tag, low, high);

    return value;
}

static void validate_content(
    PatternMatchData* pmd, OptTreeNode* otn)
{
    if ( fast_pattern_count(otn, RULE_OPTION_TYPE_CONTENT) > 1 )
        ParseError("Only one content per rule may be used for fast pattern matching.");

    if ( pmd->negated )
        pmd->last_check = (PmdLastCheck*)SnortAlloc(get_instance_max() * sizeof(*pmd->last_check));
}

static void make_precomp(PatternMatchData * idx)
{
    idx->skip_stride = make_skip(idx->pattern_buf, idx->pattern_size);
    idx->shift_stride = make_shift(idx->pattern_buf, idx->pattern_size);
}

/****************************************************************************
 *
 * Function: GetMaxJumpSize(char *, int)
 *
 * Purpose: Find the maximum number of characters we can jump ahead
 *          from the current offset when checking for this pattern again.
 *
 * Arguments: data => the pattern string
 *            data_len => length of pattern string
 *
 * Returns: int => number of bytes before pattern repeats within itself
 *
 ***************************************************************************/
static unsigned int GetMaxJumpSize(char *data, int data_len)
{
    int i, j;

    j = 0;
    for ( i = 1; i < data_len; i++ )
    {
        if ( data[j] != data[i] )
        {
            j = 0;
            continue;
        }
        if ( i == (data_len - 1) )
        {
            return (data_len - j - 1);
        }
        j++;
    }
    return data_len;
}

//-------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

PatternMatchData* get_pmd(OptFpList* ofl)
{
    if ( ofl->type != RULE_OPTION_TYPE_CONTENT )
        return nullptr;

    ContentOption* opt = (ContentOption*)ofl->context;
    return opt->get_data();
}

bool is_fast_pattern_only(OptFpList* ofl)
{
    PatternMatchData* pmd = get_pmd(ofl);

    if ( !pmd )
        return false;

    return pmd->fp_only != 0;
}

void clear_fast_pattern_only(OptFpList* ofl)
{
    PatternMatchData* pmd = get_pmd(ofl);

    if ( pmd )
        pmd->fp_only = 0;
}

bool is_unbounded(void* pv)
{
    ContentOption* opt = (ContentOption*)pv;
    PatternMatchData* pmd = opt->get_data();
    return ( pmd->depth == 0 );
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
static int uniSearchReal(PatternMatchData* pmd, Cursor& c)
{
    int offset, depth;

    /* Get byte_extract variables */
    if (pmd->offset_var >= 0 && pmd->offset_var < NUM_BYTE_EXTRACT_VARS)
    {
        uint32_t extract;
        GetByteExtractValue(&extract, pmd->offset_var);
        offset = (int) extract;
    }
    else
        offset = pmd->offset;

    if (pmd->depth_var >= 0 && pmd->depth_var < NUM_BYTE_EXTRACT_VARS)
    {
        uint32_t extract;
        GetByteExtractValue(&extract, pmd->depth_var);
        depth = (int) extract;
    }
    else
        depth = pmd->depth;

    int pos = c.get_delta();

    if ( !pos && pmd->relative )
        pos = c.get_pos();

    pos += offset;

    if ( pos < 0 )
        pos = 0;

    int len = c.size() - pos;

    if ( !depth || len < depth )
        depth = len;

    unsigned end = pos + pmd->pattern_size;

    // If the pattern size is greater than the amount of data we have to
    // search, there's no way we can match, but return 0 here for the
    // case where the match is inverted and there is at least some data.
    if ( end > c.size() || (int)end > pos + depth )
    {
        if ( pmd->negated && (depth > 0) )
            return 0;

        return -1;
    }

    const uint8_t* base = c.buffer() + pos;
    int found;

    if ( pmd->no_case )
    {
        found = mSearchCI(
            (const char*)base, depth, pmd->pattern_buf, pmd->pattern_size,
            pmd->skip_stride, pmd->shift_stride);
    }
    else
    {
        found = mSearch(
            (const char*)base, depth, pmd->pattern_buf, pmd->pattern_size,
            pmd->skip_stride, pmd->shift_stride);
    }

    if ( found >= 0 )
    {
        int at = pos + found;
        c.set_delta(at + pmd->match_delta);
        c.set_pos(at + pmd->pattern_size);
        return 1;
    }

    return -1;
}

static int CheckANDPatternMatch(PatternMatchData* idx, Cursor& c)
{
    int rval = DETECTION_OPTION_NO_MATCH;
    int found = 0;

    PROFILE_VARS;
    PREPROC_PROFILE_START(contentPerfStats);

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "CheckPatternANDMatch: "););

    found = uniSearchReal(idx, c);

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
        found ^= idx->negated;
    }

    if ( found )
    {
        rval = DETECTION_OPTION_MATCH;
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Pattern match found\n"););
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Pattern match failed\n"););
    }

    PREPROC_PROFILE_END(contentPerfStats);
    return rval;
}

PatternMatchData* content_get_data(void* pv)
{
    ContentOption* opt = (ContentOption*)pv;
    return opt->get_data();
}

/* current should be the cursor after this content rule option matched
 * orig is the place from where we first did evaluation of this content */
bool content_next(PatternMatchData* pmd)
{
    if ( pmd->negated )
        return false;

    return true;
}

//-------------------------------------------------------------------------
// helper foo
//-------------------------------------------------------------------------

typedef enum {
    CMF_DISTANCE = 0x1, CMF_WITHIN = 0x2, CMF_OFFSET = 0x4, CMF_DEPTH = 0x8
} ContentModifierFlags;

static unsigned GetCMF (PatternMatchData* pmd)
{
    unsigned cmf = 0;
    if ( (pmd->offset != 0) || (pmd->offset_var != -1) ) cmf |= CMF_OFFSET;
    if ( (pmd->depth != 0) || (pmd->depth_var != -1) ) cmf |= CMF_DEPTH;
    return cmf;
}

#define BAD_DISTANCE (CMF_DISTANCE | CMF_OFFSET | CMF_DEPTH)
#define BAD_WITHIN (CMF_WITHIN | CMF_OFFSET | CMF_DEPTH)
#define BAD_OFFSET (CMF_OFFSET | CMF_DISTANCE | CMF_WITHIN)
#define BAD_DEPTH (CMF_DEPTH | CMF_DISTANCE | CMF_WITHIN)

//-------------------------------------------------------------------------
// parsing methods
//-------------------------------------------------------------------------

static void parse_content(PatternMatchData* ds_idx, const char* rule)
{
    char tmp_buf[MAX_PATTERN_SIZE];

    /* got enough ptrs for you? */
    char *start_ptr;
    char *end_ptr;
    char *idx;
    char *dummy_idx;
    char *dummy_end;
    char *tmp;
    char hex_buf[3];
    u_int dummy_size = 0;
    int size;
    int hexmode = 0;
    int hexsize = 0;
    int pending = 0;
    int cnt = 0;
    int literal = 0;
    int negated = 0;

    /* clear out the temp buffer */
    memset(tmp_buf, 0, MAX_PATTERN_SIZE);

    if (rule == NULL)
        ParseError("content_parse Got Null enclosed in quotation marks (\")");

    while(isspace((int)*rule))
        rule++;

    if(*rule == '!')
    {
        negated = 1;
        while(isspace((int)*++rule));
    }

    /* find the start of the data */
    start_ptr = strchr(rule, '"');

    if (start_ptr != rule)
        ParseError("Content data needs to be enclosed in quotation marks (\")");

    /* move the start up from the beggining quotes */
    start_ptr++;

    /* find the end of the data */
    end_ptr = strrchr(start_ptr, '"');

    if (end_ptr == NULL)
        ParseError("Content data needs to be enclosed in quotation marks (\")");

    /* Move the null termination up a bit more */
    *end_ptr = '\0';

    /* Is there anything other than whitespace after the trailing
     * double quote? */
    tmp = end_ptr + 1;
    while (*tmp != '\0' && isspace ((int)*tmp))
        tmp++;

    if (strlen (tmp) > 0)
    {
        ParseError("Bad data (possibly due to missing semicolon) after "
                "trailing double quote.");
    }

    /* how big is it?? */
    size = end_ptr - start_ptr;

    /* uh, this shouldn't happen */
    if (size <= 0)
        ParseError("Bad pattern length");

    /* set all the pointers to the appropriate places... */
    idx = start_ptr;

    /* set the indexes into the temp buffer */
    dummy_idx = tmp_buf;
    dummy_end = (dummy_idx + size);

    /* why is this buffer so small? */
    memset(hex_buf, '0', 2);
    hex_buf[2] = '\0';

    /* BEGIN BAD JUJU..... */
    while(idx < end_ptr)
    {
        if (dummy_size >= MAX_PATTERN_SIZE-1)
        {
            /* Have more data to parse and pattern is about to go beyond end of buffer */
            ParseError("content_parse() dummy buffer overflow, make a smaller "
                    "pattern please! (Max size = %d)", MAX_PATTERN_SIZE-1);
        }

        DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "processing char: %c\n", *idx););
        switch(*idx)
        {
            case '|':
                DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "Got bar... "););
                if(!literal)
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "not in literal mode... "););
                    if(!hexmode)
                    {
                        DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "Entering hexmode\n"););
                        hexmode = 1;
                    }
                    else
                    {
                        DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "Exiting hexmode\n"););

                        /*
                        **  Hexmode is not even.
                        */
                        if(!hexsize || hexsize % 2)
                        {
                            ParseError("Content hexmode argument has invalid "
                                    "number of hex digits.  The argument '%s' "
                                    "must contain a full even byte string.", start_ptr);
                        }

                        hexmode = 0;
                        pending = 0;
                    }

                    if(hexmode)
                        hexsize = 0;
                }
                else
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "literal set, Clearing\n"););
                    literal = 0;
                    tmp_buf[dummy_size] = start_ptr[cnt];
                    dummy_size++;
                }

                break;

            case '\\':
                DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Got literal char... "););

                if(!literal)
                {
                    /* Make sure the next char makes this a valid
                     * escape sequence.
                     */
                    if (idx [1] != '\0' && strchr ("\\\":;", idx [1]) == NULL)
                    {
                        ParseError("Bad escape sequence starting with '%s'.", idx);
                    }

                    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Setting literal\n"););

                    literal = 1;
                }
                else
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Clearing literal\n"););
                    tmp_buf[dummy_size] = start_ptr[cnt];
                    literal = 0;
                    dummy_size++;
                }

                break;
            case '"':
                if (!literal)
                    ParseError("Non-escaped '\"' character!");
                /* otherwise process the character as default */
            default:
                if(hexmode)
                {
                    if(isxdigit((int) *idx))
                    {
                        hexsize++;

                        if(!pending)
                        {
                            hex_buf[0] = *idx;
                            pending++;
                        }
                        else
                        {
                            hex_buf[1] = *idx;
                            pending--;

                            if(dummy_idx < dummy_end)
                            {
                                tmp_buf[dummy_size] = (u_char)
                                    strtol(hex_buf, (char **) NULL, 16)&0xFF;

                                dummy_size++;
                                memset(hex_buf, '0', 2);
                                hex_buf[2] = '\0';
                            }
                            else
                            {
                                ParseError("content_parse() dummy buffer "
                                        "overflow, make a smaller pattern "
                                        "please! (Max size = %d)", MAX_PATTERN_SIZE-1);
                            }
                        }
                    }
                    else
                    {
                        if(*idx != ' ')
                        {
                            ParseError("What is this '%c'(0x%X) doing in "
                                    "your binary buffer?  Valid hex values "
                                    "only please! (0x0 - 0xF) Position: %d",
                                    (char) *idx, (char) *idx, cnt);
                        }
                    }
                }
                else
                {
                    if(*idx >= 0x1F && *idx <= 0x7e)
                    {
                        if(dummy_idx < dummy_end)
                        {
                            tmp_buf[dummy_size] = start_ptr[cnt];
                            dummy_size++;
                        }
                        else
                        {
                            ParseError("content_parse() dummy buffer "
                                    "overflow, make a smaller pattern "
                                    "please! (Max size = %d)", MAX_PATTERN_SIZE-1);
                        }

                        if(literal)
                        {
                            literal = 0;
                        }
                    }
                    else
                    {
                        if(literal)
                        {
                            tmp_buf[dummy_size] = start_ptr[cnt];
                            dummy_size++;
                            DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "Clearing literal\n"););
                            literal = 0;
                        }
                        else
                        {
                            ParseError("Character value out of range, try a "
                                    "binary buffer.");
                        }
                    }
                }

                break;
        }

        dummy_idx++;
        idx++;
        cnt++;
    }
    /* ...END BAD JUJU */

    /* error prunning */

    if (literal)
        ParseError("Backslash escape is not completed.");

    if (hexmode)
        ParseError("Hexmode is not completed.");

    ds_idx->pattern_buf = (char *)SnortAlloc(dummy_size+1);
    memcpy(ds_idx->pattern_buf, tmp_buf, dummy_size);

    ds_idx->pattern_size = dummy_size;

    make_precomp(ds_idx);
    ds_idx->negated = negated;

    ds_idx->match_delta = GetMaxJumpSize(ds_idx->pattern_buf, ds_idx->pattern_size);
}

static void parse_offset(PatternMatchData* pmd, const char *data)
{
    if ( GetCMF(pmd) & BAD_OFFSET && pmd->relative )
        ParseError("offset can't be used with itself, distance, or within");

    if (data == NULL)
    {
        ParseError("Missing argument to 'offset' option");
        return;
    }

    if (isdigit(data[0]) || data[0] == '-')
    {
        pmd->offset = parse_int(data, "offset");
    }
    else
    {
        pmd->offset_var = GetVarByName(data);
        if (pmd->offset_var == BYTE_EXTRACT_NO_VAR)
        {
            ParseError(BYTE_EXTRACT_INVALID_ERR_STR);
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "Pattern offset = %d\n",
                pmd->offset););
}

static void parse_depth(PatternMatchData* pmd, const char *data)
{
    if ( GetCMF(pmd) & BAD_DEPTH && pmd->relative )
        ParseError("depth can't be used with itself, distance, or within");

    if (data == NULL)
    {
        ParseError("Missing argument to 'depth' option");
        return;
    }

    if (isdigit(data[0]) || data[0] == '-')
    {
        pmd->depth = parse_int(data, "depth");

        /* check to make sure that this the depth allows this rule to fire */
        if (pmd->depth < (int)pmd->pattern_size)
        {
            ParseError("The depth (%d) is less than the size of the content(%u)!",
                    pmd->depth, pmd->pattern_size);
        }
    }
    else
    {
        pmd->depth_var = GetVarByName(data);
        if (pmd->depth_var == BYTE_EXTRACT_NO_VAR)
        {
            ParseError(BYTE_EXTRACT_INVALID_ERR_STR);
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Pattern depth = %d\n",
                pmd->depth););
}

static void parse_distance(PatternMatchData* pmd, const char *data)
{
    if ( GetCMF(pmd) & BAD_DISTANCE && !pmd->relative )
        ParseError("distance can't be used with itself, offset, or depth");

    if (data == NULL)
    {
        ParseError("Missing argument to 'distance' option");
        return;
    }

    if (isdigit(data[0]) || data[0] == '-')
    {
        pmd->offset = parse_int(data, "distance");
    }
    else
    {
        pmd->offset_var = GetVarByName(data);
        if (pmd->offset_var == BYTE_EXTRACT_NO_VAR)
        {
            ParseError(BYTE_EXTRACT_INVALID_ERR_STR);
        }
    }

    pmd->relative = 1;
}

static void parse_within(PatternMatchData* pmd, const char *data)
{
    if ( GetCMF(pmd) & BAD_WITHIN && !pmd->relative )
        ParseError("within can't be used with itself, offset, or depth");

    if (data == NULL)
    {
        ParseError("Missing argument to 'within' option");
        return;
    }

    if (isdigit(data[0]) || data[0] == '-')
    {
        pmd->depth = parse_int(data, "within");

        if (pmd->depth < (int)pmd->pattern_size)
            ParseError("within (%d) is smaller than size of pattern", pmd->depth);
    }
    else
    {
        pmd->depth_var = GetVarByName(data);
        if (pmd->depth_var == BYTE_EXTRACT_NO_VAR)
        {
            ParseError(BYTE_EXTRACT_INVALID_ERR_STR);
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Pattern within = %d\n",
                pmd->depth););

    pmd->relative = 1;
}

static const char* error_str = 
    "fast_pattern_offset + fast_pattern_length must be less "
    "than or equal to the actual pattern length which is %u.";

static void parse_fast_pattern_offset(PatternMatchData* pmd, const char *data)
{
    if (data == NULL)
        ParseError("Missing argument to 'fast_pattern_offset' option");

    long offset = parse_int(data, "fast_pattern_offset", 0, UINT16_MAX);

    if ((int)pmd->pattern_size < (offset + pmd->fp_length))
        ParseError(error_str, data, pmd->pattern_size);

    pmd->fp_offset = offset;
    pmd->fp = 1;
}

static void parse_fast_pattern_length(PatternMatchData* pmd, const char *data)
{
    if (data == NULL)
        ParseError("Missing argument to 'fast_pattern_length' option");

    long length = parse_int(data, "fast_pattern_length", 0, UINT16_MAX);

    if ((int)pmd->pattern_size < (pmd->fp_offset + length))
        ParseError(error_str, data, pmd->pattern_size);

    pmd->fp_length = length;
    pmd->fp = 1;
}

//-------------------------------------------------------------------------
// content api methods
//-------------------------------------------------------------------------

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter content_params[] =
{
    { "*data", Parameter::PT_STRING, nullptr, nullptr,
      "data to match" },

    { "nocase", Parameter::PT_IMPLIED, nullptr, nullptr,
      "case insensitive match" },

    { "fast_pattern", Parameter::PT_IMPLIED, nullptr, nullptr,
      "use this content in the fast pattern matcher instead of the content selected by default" },

    { "fast_pattern_offset", Parameter::PT_INT, nullptr, nullptr,
      "number of leading characters of this content the fast pattern matcher should exclude" },

    { "fast_pattern_length", Parameter::PT_INT, nullptr, nullptr,
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

class ContentModule : public Module
{
public:
    ContentModule() : Module(s_name, content_params)
    { pmd = nullptr; };

    ~ContentModule()
    { delete pmd; };

    bool begin(const char*, int, SnortConfig*);
    bool end(const char*, int, SnortConfig*);
    bool set(const char*, Value&, SnortConfig*);

    ProfileStats* get_profile() const
    { return &contentPerfStats; };

    PatternMatchData* get_data();

private:
    PatternMatchData* pmd;
};

PatternMatchData* ContentModule::get_data()
{
    PatternMatchData* tmp = pmd;
    pmd = nullptr;
    return tmp;
}

bool ContentModule::begin(const char*, int, SnortConfig*)
{
    pmd = new_pmd();
    return true;
}

bool ContentModule::end(const char*, int, SnortConfig*)
{
    if ( pmd->no_case )
    {
        for ( unsigned i = 0; i < pmd->pattern_size; i++ )
            pmd->pattern_buf[i] = toupper((int)pmd->pattern_buf[i]);
    }
    return true;
}

bool ContentModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("*data") )
        parse_content(pmd, v.get_string());

    else if ( v.is("offset") )
        parse_offset(pmd, v.get_string());

    else if ( v.is("depth") )
        parse_depth(pmd, v.get_string());

    else if ( v.is("distance") )
        parse_distance(pmd, v.get_string());

    else if ( v.is("within") )
        parse_within(pmd, v.get_string());

    else if ( v.is("nocase") )
        pmd->no_case = 1;

    else if ( v.is("fast_pattern") )
        pmd->fp = 1;

    else if ( v.is("fast_pattern_offset") )
        parse_fast_pattern_offset(pmd, v.get_string());

    else if ( v.is("fast_pattern_length") )
        parse_fast_pattern_length(pmd, v.get_string());

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

static IpsOption* content_ctor(Module* p, OptTreeNode * otn)
{
    ContentModule* m = (ContentModule*)p;
    PatternMatchData* pmd = m->get_data();
    validate_content(pmd, otn);
    return new ContentOption(pmd);
}

static void content_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi content_api =
{
    {
        PT_IPS_OPTION,
        s_name,
        IPSAPI_PLUGIN_V0,
        0,
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

const BaseApi* ips_content = &content_api.base;


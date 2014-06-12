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
#include "replace.h"
#include "snort_bounds.h"
#include "detection/treenodes.h"
#include "snort_debug.h"
#include "mstring.h"
#include "util.h"
#include "parser.h"
#include "sfhashfcn.h"
#include "framework/ips_option.h"
#include "snort.h"
#include "profiler.h"
#include "fpdetect.h"
#include "sfhashfcn.h"
#include "detection/detection_defines.h"
#include "ips_byte_extract.h"
#include "detection/detection_util.h"

#define MAX_PATTERN_SIZE 2048
#define PM_FP_ONLY  "only"

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats contentPerfStats;
static THREAD_LOCAL PreprocStats uricontentPerfStats;

static PreprocStats* con_get_profile(const char* key)
{
    if ( !strcmp(key, "content") )
        return &contentPerfStats;

    if ( !strcmp(key, "uricontent") )
        return &uricontentPerfStats;

    return nullptr;
}
#endif

static int CheckANDPatternMatch(PatternMatchData*, Packet*);
static int CheckUriPatternMatch(PatternMatchData*, Packet*);

class ContentOption : public IpsOption
{
public:
    ContentOption(PatternMatchData* c, const char* s,
        option_type_t t = RULE_OPTION_TYPE_CONTENT) :
        IpsOption(s, t)
    { config = c; };

    ~ContentOption();

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    bool is_relative()
    { return (config->use_doe == 1); };

    PatternMatchData* get_data()
    { return config; };

    void set_data(PatternMatchData* pmd)
    { config = pmd; };

    int eval(Packet* p)
    { return CheckANDPatternMatch(config, p); };

protected:
    PatternMatchData* config;
};

class UriContentOption : public ContentOption
{
public:
    UriContentOption(PatternMatchData* c) : 
        ContentOption(c, "uricontent", RULE_OPTION_TYPE_CONTENT_URI) { };

    int eval(Packet* p)
    { return CheckUriPatternMatch(config, p); };
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

    if (pmd->replace_buf)
        free(pmd->replace_buf);
    if ( pmd->replace_depth )
        free(pmd->replace_depth);

    free(pmd->last_check);
    free(pmd);
}

uint32_t ContentOption::hash() const
{
    uint32_t a,b,c;
    const PatternMatchData *pmd = config;

    a = pmd->exception_flag;
    b = pmd->offset;
    c = pmd->depth;

    mix(a,b,c);

    a += pmd->distance;
    b += pmd->within;
    c += pmd->rawbytes;

    mix(a,b,c);

    a += pmd->nocase;
    b += pmd->use_doe;
    c += pmd->http_buffer;

    mix(a,b,c);

    a += pmd->pattern_size;
    b += pmd->replace_size;
    c += pmd->pattern_max_jump_size;

    mix(a,b,c);

    if ( pmd->pattern_size )
        mix_str(a,b,c,pmd->pattern_buf, pmd->pattern_size);

    if ( pmd->replace_size )
        mix_str(a,b,c,pmd->replace_buf, pmd->replace_size);

    b += pmd->fp;
    c += pmd->fp_only;

    mix(a,b,c);
    mix_str(a,b,c,get_name());

    a += pmd->fp_offset;
    b += pmd->fp_length;
    c += pmd->offset_var;

    mix(a,b,c);

    a += pmd->depth_var;
    b += pmd->distance_var;
    c += pmd->within_var;

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

    if (left->buffer_func != right->buffer_func)
        return false;

    /* Sizes will be most different, check that first */
    if ((left->pattern_size != right->pattern_size) ||
        (left->replace_size != right->replace_size) ||
        (left->nocase != right->nocase))
        return false;

    /* Next compare the patterns for uniqueness */
    if (left->pattern_size)
    {
        if (left->nocase)
        {
            /* If nocase is set, do case insensitive compare on pattern */
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
            /* If nocase is not set, do case sensitive compare on pattern */
            if (memcmp(left->pattern_buf, right->pattern_buf, left->pattern_size) != 0)
            {
                return false;
            }
        }
    }

    /* Check the replace pattern if exists */
    if (left->replace_size)
    {
        if (memcmp(left->replace_buf, right->replace_buf, left->replace_size) != 0)
        {
            return false;
        }
    }

    /* Now check the rest of the options */
    if ((left->exception_flag == right->exception_flag) &&
        (left->offset == right->offset) &&
        (left->depth == right->depth) &&
        (left->distance == right->distance) &&
        (left->within == right->within) &&
        (left->rawbytes == right->rawbytes) &&
        (left->use_doe == right->use_doe) &&
        (left->http_buffer == right->http_buffer) &&
        (left->search == right->search) &&
        (left->pattern_max_jump_size == right->pattern_max_jump_size) &&
        (left->fp == right->fp) &&
        (left->fp_only == right->fp_only) &&
        (left->fp_offset == right->fp_offset) &&
        (left->fp_length == right->fp_length) &&
        (left->offset_var == right->offset_var) &&
        (left->depth_var == right->depth_var) &&
        (left->distance_var == right->distance_var) &&
        (left->within_var == right->within_var) )
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
    pmd->distance_var = BYTE_EXTRACT_NO_VAR;
    pmd->within_var = BYTE_EXTRACT_NO_VAR;

    return pmd;
}

static void update_pmd(PatternMatchData* pmd)
{
    if ( pmd->exception_flag )
        pmd->last_check = (PmdLastCheck*)SnortAlloc(get_instance_max() * sizeof(*pmd->last_check));
}

static int HasFastPattern(OptTreeNode *otn, int list_type)
{
    OptFpList* fpl = otn ? otn->opt_func : nullptr;

    while ( fpl )
    {
        if ( fpl->type == list_type )
        {
            ContentOption* opt = (ContentOption*)fpl->context;
            PatternMatchData* pmd = opt->get_data();

            if ( pmd->fp )
                return 1;
        }
        fpl = fpl->next;
    }
    return 0;
}

static int32_t ParseInt(const char* data, const char* tag)
{
    int32_t value = 0;
    char *endptr = NULL;

    value = SnortStrtol(data, &endptr, 10);

    if (*endptr)
        ParseError("Invalid '%s' format.", tag);

    if (errno == ERANGE)
        ParseError("Range problem on '%s' value.", tag);

    if ((value > 65535) || (value < -65535))
        ParseError("'%s' must in -65535:65535", tag);

    return value;
}

/* Options that can't be used with http content modifiers.  Additionally
 * http_inspect preprocessor needs to be enabled */
static void ValidateHttpContentModifiers(
    SnortConfig*, PatternMatchData *pmd)
{
    if (pmd == NULL)
        ParseError("Please place 'content' rules before http content modifiers");

#if 0
    // FIXIT HI should make the content modifiers available and
    // if not available parsing of the modifier should fail
    if (!IsPreprocEnabled(sc, PP_HTTPINSPECT))
    {
        ParseError("Please enable the HTTP Inspect preprocessor "
                "before using the http content modifiers");
    }
#endif

    if (pmd->replace_buf != NULL)
    {
        ParseError("'replace' option is not supported in conjunction with "
                "http content modifiers");
    }

    if (pmd->rawbytes == 1)
    {
        ParseError("Cannot use 'rawbytes' and http content as modifiers for "
                "the same 'content'");
    }
}

static void set_last_type(OptTreeNode *otn, option_type_t type)
{
    OptFpList* fpl = otn ? otn->opt_func : nullptr;
    OptFpList* last = nullptr;

    while ( fpl )
    {
        if ( (fpl->type == RULE_OPTION_TYPE_CONTENT) ||
             (fpl->type == RULE_OPTION_TYPE_CONTENT_URI) )
        {
            last = fpl;
        }
        fpl = fpl->next;
    }
    if ( last )
        last->type = type;
}

/* This is used if we get an http content modifier, since specifying "content"
 * defaults to the RULE_OPTION_TYPE_CONTENT list.  We need to move the pmd to the
 * RULE_OPTION_TYPE_CONTENT_URI list */
static void MovePmdToUriDsList(OptTreeNode *otn, PatternMatchData *pmd)
{
    set_last_type(otn, RULE_OPTION_TYPE_CONTENT_URI);  // FIXIT make this unnecessary
    pmd->buffer_func = CHECK_URI_PATTERN_MATCH;
}

/* Since each content modifier can be parsed as a rule option, do this check
 * after parsing the entire rule in FinalizeContentUniqueness() */
static void ValidateContent(
    SnortConfig* sc, PatternMatchData *pmd, int type){
    if (pmd == NULL)
        return;

    if (pmd->fp)
    {
        if ((type == RULE_OPTION_TYPE_CONTENT_URI) && !IsHttpBufFpEligible(pmd->http_buffer))

        {
            ParseError(
                "Cannot use the fast_pattern content modifier for a lone "
                "http cookie/http raw uri /http raw header /http raw cookie "
                "/status code / status msg /http method buffer content.");
        }

        if (pmd->use_doe || (pmd->offset != 0) || (pmd->depth != 0))
        {
            if (pmd->exception_flag)
            {
                ParseError(
                    "Cannot use the fast_pattern modifier for negated, "
                    "relative or non-zero offset/depth content searches.");
            }

            if (pmd->fp_only)
            {
                ParseError(
                    "Fast pattern only contents cannot be relative or "
                    "have non-zero offset/depth content modifiers.");
            }
        }

        if (pmd->fp_only)
        {
            if (pmd->replace_buf != NULL)
            {
                ParseError(
                    "Fast pattern only contents cannot use replace modifier.");
            }

            if (pmd->exception_flag)
                ParseError("Fast pattern only contents cannot be negated.");
        }
    }

    if (type == RULE_OPTION_TYPE_CONTENT_URI)
        ValidateHttpContentModifiers(sc, pmd);
}

static void make_precomp(PatternMatchData * idx)
{
    if(idx->skip_stride)
       free(idx->skip_stride);
    if(idx->shift_stride)
       free(idx->shift_stride);

    idx->skip_stride = make_skip(idx->pattern_buf, idx->pattern_size);

    idx->shift_stride = make_shift(idx->pattern_buf, idx->pattern_size);
}

static char *PayloadExtractParameter(char *data, int *result_len)
{
    char *quote_one = NULL, *quote_two = NULL;
    char *comma = NULL;

    quote_one = strchr(data, '"');
    if (quote_one)
    {
        quote_two = strchr(quote_one+1, '"');
        while ( quote_two && quote_two[-1] == '\\' )
            quote_two = strchr(quote_two+1, '"');
    }

    if (quote_one && quote_two)
    {
        comma = strchr(quote_two, ',');
    }
    else if (!quote_one)
    {
        comma = strchr(data, ',');
    }

    if (comma)
    {
        *result_len = comma - data;
        *comma = '\0';
    }
    else
    {
        *result_len = strlen(data);
    }

    return data;
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
    if ( (ofl->type != RULE_OPTION_TYPE_CONTENT) &&
         (ofl->type != RULE_OPTION_TYPE_CONTENT_URI) )
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

bool is_unbounded(void* pv)
{
    ContentOption* opt = (ContentOption*)pv;
    PatternMatchData* pmd = opt->get_data();
    return ( pmd->within == 0 );
}

//-------------------------------------------------------------------------
// runtime functions
//-------------------------------------------------------------------------

/*
 * single search function.
 *
 * data = ptr to buffer to search
 * dlen = distance to the back of the buffer being tested, validated
 *        against offset + depth before function entry (not distance/within)
 * pmd = pointer to pattern match data struct
 * nocase = 0 means case sensitve, 1 means case insensitive
 *
 * return  1 for found
 * return  0 for not found
 * return -1 for error (search out of bounds)
 */
// FIXIT PMD
static int uniSearchReal(const char *data, int dlen, PatternMatchData *pmd, int nocase)
{
    /*
     * in theory computeDepth doesn't need to be called because the
     * depth + offset adjustments have been made by the calling function
     */
    int depth = dlen;
    int success = 0;
    const char *start_ptr = data;
    const char *end_ptr = data + dlen;
    const char *base_ptr;// = start_ptr;
    uint32_t extract_offset, extract_depth, extract_distance, extract_within;

    if(pmd->use_doe != 1)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "NOT Using Doe Ptr\n"););
        UpdateDoePtr(NULL, 0); /* get rid of all our pattern match state */
    }

    /* Get byte_extract variables */
    // FIXIT these need to be thread local
    if (pmd->offset_var >= 0 && pmd->offset_var < NUM_BYTE_EXTRACT_VARS)
    {
        GetByteExtractValue(&extract_offset, pmd->offset_var);
        pmd->offset = (int) extract_offset;
    }
    if (pmd->depth_var >= 0 && pmd->depth_var < NUM_BYTE_EXTRACT_VARS)
    {
        GetByteExtractValue(&extract_depth, pmd->depth_var);
        pmd->depth = (int) extract_depth;
    }
    if (pmd->distance_var >= 0 && pmd->distance_var < NUM_BYTE_EXTRACT_VARS)
    {
        GetByteExtractValue(&extract_distance, pmd->distance_var);
        pmd->distance = (int) extract_distance;
    }
    if (pmd->within_var >= 0 && pmd->within_var < NUM_BYTE_EXTRACT_VARS)
    {
        GetByteExtractValue(&extract_within, pmd->within_var);
        pmd->within = (u_int) extract_within;
    }

    // Set our initial starting point
    if (doe_ptr)
    {
        // Sanity check to make sure the doe_ptr is within the buffer we're
        // searching.  It could be at the very end of the buffer due to a
        // previous match, but may have a negative distance here.
        if (((char *)doe_ptr < start_ptr) || ((char *)doe_ptr > end_ptr))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Returning because "
                        "doe_ptr isn't within the buffer we're searching: "
                        "start_ptr: %p, end_ptr: %p, doe_ptr: %p\n",
                        start_ptr, end_ptr, doe_ptr););
            return -1;
        }

        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                    "Setting base_ptr to doe_ptr (%p)\n", doe_ptr););

        base_ptr = (const char *)doe_ptr;
        depth = dlen - ((char *)doe_ptr - data);
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                    "Setting base_ptr to start_ptr (%p)\n", start_ptr););

        base_ptr = start_ptr;
        depth = dlen;
    }

    // Adjust base_ptr and depth based on distance/within
    // or offset/depth parameters.
    if ((pmd->distance != 0) || (pmd->within != 0))
    {
        if (pmd->distance != 0)
        {
            base_ptr += pmd->distance;
            depth -= pmd->distance;
        }

        // If the distance is negative and puts us before start_ptr
        // set base_ptr to start_ptr and adjust depth based on within.
        if (base_ptr < start_ptr)
        {
            int delta = (int)pmd->within - (start_ptr - base_ptr);
            base_ptr = start_ptr;
            depth = ((pmd->within == 0) || (delta > dlen)) ? dlen : delta;
        }
        else if ((pmd->within != 0) && ((int)pmd->within < depth))
        {
            depth = (int)pmd->within;
        }
    }
    else if ((pmd->offset != 0) || (pmd->depth != 0))
    {
        if (pmd->offset != 0)
        {
            base_ptr += pmd->offset;
            depth -= pmd->offset;
        }

        if ((pmd->depth != 0) && (pmd->depth < depth))
            depth = pmd->depth;
    }

    // If the pattern size is greater than the amount of data we have to
    // search, there's no way we can match, but return 0 here for the
    // case where the match is inverted and there is at least some data.
    if ((int)pmd->pattern_size > depth)
    {
        if (pmd->exception_flag && (depth > 0))
            return 0;

        return -1;
    }

#ifdef DEBUG_MSGS
    {
        char *hexbuf;

        assert(depth <= dlen);

        DebugMessage(DEBUG_PATTERN_MATCH, "uniSearchReal:\n ");

        hexbuf = hex((u_char *)pmd->pattern_buf, pmd->pattern_size);
        DebugMessage(DEBUG_PATTERN_MATCH, "   p->data: %p\n   doe_ptr: %p\n   "
                "base_ptr: %p\n   depth: %d\n   searching for: %s\n",
                data, doe_ptr, base_ptr, depth, hexbuf);
        free(hexbuf);
    }
#endif /* DEBUG_MSGS */

    if(nocase)
    {
        success = mSearchCI(base_ptr, depth,
                            pmd->pattern_buf,
                            pmd->pattern_size,
                            pmd->skip_stride,
                            pmd->shift_stride);
    }
    else
    {
        success = mSearch(base_ptr, depth,
                          pmd->pattern_buf,
                          pmd->pattern_size,
                          pmd->skip_stride,
                          pmd->shift_stride);
    }


#ifdef DEBUG_MSGS
    if(success)
    {
        DebugMessage(DEBUG_PATTERN_MATCH, "matched, doe_ptr: %p (%d)\n",
                     doe_ptr, ((char *)doe_ptr - data));
    }
#endif

    return success;
}

/*
 * case sensitive search
 *
 * data = ptr to buffer to search
 * dlen = distance to the back of the buffer being tested, validated
 *        against offset + depth before function entry (not distance/within)
 * pmd = pointer to pattern match data struct
 */

static int uniSearch(const char *data, int dlen, PatternMatchData *pmd)
{
    return uniSearchReal(data, dlen, pmd, 0);
}

/*
 * case insensitive search
 *
 * data = ptr to buffer to search
 * dlen = distance to the back of the buffer being tested, validated
 *        against offset + depth before function entry (not distance/within)
 * pmd = pointer to pattern match data struct
 */
static int uniSearchCI(const char *data, int dlen, PatternMatchData *pmd)
{
    return uniSearchReal(data, dlen, pmd, 1);
}

static int CheckANDPatternMatch(PatternMatchData* idx, Packet *p)
{
    int rval = DETECTION_OPTION_NO_MATCH;
    int found = 0;
    int dsize;
    char *dp;
    PROFILE_VARS;

    PREPROC_PROFILE_START(contentPerfStats);

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "CheckPatternANDMatch: "););

    if(idx->rawbytes == 0)
    {
        if(Is_DetectFlag(FLAG_ALT_DETECT))
        {
            dsize = DetectBuffer.len;
            dp = (char *) DetectBuffer.data;
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                        "Using Alternative Detect buffer!\n"););
        }
        else if(Is_DetectFlag(FLAG_ALT_DECODE))
        {
            dsize = DecodeBuffer.len;
            dp = (char *) DecodeBuffer.data;
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                        "Using Alternative Decode buffer!\n"););
        }
        else
        {
            if(IsLimitedDetect(p))
            {
                dsize = p->alt_dsize;
                DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                    "Using Limited Packet Data!\n"););
            }
            else
            {
                dsize = p->dsize;
                DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                    "Using Full Packet Data!\n"););
            }
            dp = (char *) p->data;
        }
    }
    else
    {
        dsize = p->dsize;
        dp = (char *) p->data;
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
            "Using Full Packet Data!\n"););
    }

    if(doe_buf_flags & DOE_BUF_URI)
        UpdateDoePtr(NULL, 0);

    doe_buf_flags = DOE_BUF_STD;

    found = idx->search(dp, dsize, idx);

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
        found ^= idx->exception_flag;
    }

    if ( found )
    {
        if ( idx->replace_buf && !PacketWasCooked(p) )
        {
            //fix the packet buffer to have the new string
            int detect_depth = (char *)doe_ptr - idx->pattern_size - dp;

            // this check should be redundant (never be true)
            if (detect_depth < 0)
            {
                Replace_ResetOffset(idx);
                PREPROC_PROFILE_END(contentPerfStats);
                return rval;
            }
            Replace_StoreOffset(idx, detect_depth);
        }
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

static int CheckUriPatternMatch(PatternMatchData* idx, Packet*)
{
    int rval = DETECTION_OPTION_NO_MATCH;
    int found = 0;
    const HttpBuffer* hb = GetHttpBuffer(idx->http_buffer);
    PROFILE_VARS;

    if ( !hb )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_HTTP_DECODE,"CheckUriPatternMatch: no "
            "HTTP buffers set, retuning"););
        return rval;
    }

    PREPROC_PROFILE_START(uricontentPerfStats);

    /*
    * have to reset the doe_ptr for each new UriBuf
    */
    if(idx->use_doe != 1)
        UpdateDoePtr(NULL, 0);

    else if(!(doe_buf_flags & DOE_BUF_URI))
        SetDoePtr(hb->buf, DOE_BUF_URI);

    /* this now takes care of all the special cases where we'd run
     * over the buffer */
    found = idx->search((const char *)hb->buf, hb->length, idx);

    if (found == -1)
        found = 0;
    else
        found ^= idx->exception_flag;

    if(found > 0 )
    {
        doe_buf_flags = DOE_BUF_URI;
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Pattern Match successful!\n"););

        /* call the next function in the OTN */
        PREPROC_PROFILE_END(uricontentPerfStats);
        return DETECTION_OPTION_MATCH;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Pattern match failed\n"););
    PREPROC_PROFILE_END(uricontentPerfStats);
    return rval;
}

void PatternMatchDuplicatePmd(void *src, PatternMatchData *pmd_dup)
{
    ContentOption* opt = (ContentOption*)src;
    PatternMatchData *pmd_src = opt->get_data();
    *pmd_dup = *pmd_src;
    Replace_ResetOffset(pmd_dup);
}

// FIXIT this kinda hurts ...
int eval_dup_content(void* v, Packet* p, PatternMatchData* dup)
{
    ContentOption* opt = (ContentOption*)v;

    if ( opt->get_type() == RULE_OPTION_TYPE_CONTENT )
    {
        ContentOption tmp(dup, "content");
        int rval = tmp.eval(p);
        tmp.set_data(nullptr);
        return rval;
    }
    UriContentOption tmp(dup);
    int rval = tmp.eval(p);
    tmp.set_data(nullptr);
    return rval;
}   

/* current_cursor should be the doe_ptr after this content rule option matched
 * orig_cursor is the place from where we first did evaluation of this content */
int PatternMatchAdjustRelativeOffsets(
    void* pv, PatternMatchData *dup_pmd,
    const uint8_t *current_cursor, const uint8_t *orig_cursor)
{
    ContentOption* opt = (ContentOption*)pv;
    PatternMatchData* orig_pmd = opt->get_data();

    /* Adjust for repeating patterns, e.g. ABAB
     * This is where the new search for this content should start */
    const uint8_t *start_cursor =
        (current_cursor - dup_pmd->pattern_size) + dup_pmd->pattern_max_jump_size;

    if (orig_pmd->depth != 0)
    {
        /* This was relative to a previously found pattern.  No space left to
         * search, we're done */
        if ((start_cursor + dup_pmd->pattern_size)
                > (orig_cursor + dup_pmd->offset + dup_pmd->depth))
        {
            return 0;
        }

        /* Adjust offset and depth to reflect new position */
        /* Lop off what we used */
        dup_pmd->depth -= start_cursor - (orig_cursor + dup_pmd->offset);
        /* Make offset where we will start the next search */
        dup_pmd->offset = start_cursor - orig_cursor;
    }
    else if (orig_pmd->within != 0)
    {
        /* This was relative to a previously found pattern.  No space left to
         * search, we're done */
        if ((start_cursor + dup_pmd->pattern_size)
                > (orig_cursor + dup_pmd->distance + dup_pmd->within))
        {
            return 0;
        }

        /* Adjust distance and within to reflect new position */
        /* Lop off what we used */
        dup_pmd->within -= start_cursor - (orig_cursor + dup_pmd->distance);
        /* Make distance where we will start the next search */
        dup_pmd->distance = start_cursor - orig_cursor;
    }
    else if (orig_pmd->use_doe)
    {
        dup_pmd->distance = start_cursor - orig_cursor;
    }
    else
    {
        dup_pmd->offset = start_cursor - orig_cursor;
    }

    return 1;
}
// FIXIT PMD

//-------------------------------------------------------------------------
// suboption handlers
//-------------------------------------------------------------------------

static void PayloadSearchHttpMethod(
    PatternMatchData* pmd, char *data, OptTreeNode * otn)
{
    if (data != NULL)
        ParseError("'http_method' does not take an argument");

    if ( pmd->http_buffer )
        ParseWarning("at most one http buffer can be specified per content option");

    pmd->http_buffer = HTTP_BUFFER_METHOD;
    MovePmdToUriDsList(otn, pmd);
}

static void PayloadSearchHttpUri(
    PatternMatchData* pmd, char *data, OptTreeNode * otn)
{
    if (data != NULL)
        ParseError("'http_uri' does not take an argument");

    if ( pmd->http_buffer )
        ParseWarning("at most one http buffer can be specified per content option");

    pmd->http_buffer = HTTP_BUFFER_URI;
    MovePmdToUriDsList(otn, pmd);
}

static void PayloadSearchHttpHeader(
    PatternMatchData* pmd, char *data, OptTreeNode * otn)
{
    if (data != NULL)
        ParseError("'http_header' does not take an argument");

    if ( pmd->http_buffer )
        ParseWarning("at most one http buffer can be specified per content option");

    pmd->http_buffer = HTTP_BUFFER_HEADER;
    MovePmdToUriDsList(otn, pmd);
}

static void PayloadSearchHttpCookie(
    PatternMatchData* pmd, char *data, OptTreeNode * otn)
{
    if (data != NULL)
        ParseError("'http_cookie' does not take an argument");

    if ( pmd->http_buffer )
        ParseWarning("at most one http buffer can be specified per content option");

    pmd->http_buffer = HTTP_BUFFER_COOKIE;
    MovePmdToUriDsList(otn, pmd);
}

static void PayloadSearchHttpBody(
    PatternMatchData* pmd, char *data, OptTreeNode * otn)
{
    if (data != NULL)
        ParseError("'http_client_body' does not take an argument");

    if ( pmd->http_buffer )
        ParseWarning("at most one http buffer can be specified per content option");

    pmd->http_buffer = HTTP_BUFFER_CLIENT_BODY;
    MovePmdToUriDsList(otn, pmd);
}

static void PayloadSearchHttpRawUri(
    PatternMatchData* pmd, char *data, OptTreeNode * otn)
{
    if (data != NULL)
        ParseError("'http_raw_uri' does not take an argument");

    if ( pmd->http_buffer )
        ParseWarning("at most one http buffer can be specified per content option");

    pmd->http_buffer = HTTP_BUFFER_RAW_URI;
    MovePmdToUriDsList(otn, pmd);
}

static void PayloadSearchHttpRawHeader(
    PatternMatchData* pmd, char *data, OptTreeNode * otn)
{
    if (data != NULL)
        ParseError("'http_raw_header' does not take an argument");

    if ( pmd->http_buffer )
        ParseWarning("at most one http buffer can be specified per content option");

    pmd->http_buffer = HTTP_BUFFER_RAW_HEADER;
    MovePmdToUriDsList(otn, pmd);
}
static void PayloadSearchHttpRawCookie(
    PatternMatchData* pmd, char *data, OptTreeNode * otn)
{
    if (data != NULL)
        ParseError("'http_raw_cookie' does not take an argument");

    if ( pmd->http_buffer )
        ParseWarning("at most one http buffer can be specified per content option");

    pmd->http_buffer = HTTP_BUFFER_RAW_COOKIE;
    MovePmdToUriDsList(otn, pmd);
}
static void PayloadSearchHttpStatCode(
    PatternMatchData* pmd, char *data, OptTreeNode * otn)
{
    if (data != NULL)
        ParseError("'http_stat_code' does not take an argument");

    if ( pmd->http_buffer )
        ParseWarning("at most one http buffer can be specified per content option");

    pmd->http_buffer = HTTP_BUFFER_STAT_CODE;
    MovePmdToUriDsList(otn, pmd);
}
static void PayloadSearchHttpStatMsg(
    PatternMatchData* pmd, char *data, OptTreeNode * otn)
{
    if (data != NULL)
        ParseError("'http_stat_msg' does not take an argument");

    if ( pmd->http_buffer )
        ParseWarning("at most one http buffer can be specified per content option");

    pmd->http_buffer = HTTP_BUFFER_STAT_MSG;
    MovePmdToUriDsList(otn, pmd);
}

typedef enum {
    CMF_DISTANCE = 0x1, CMF_WITHIN = 0x2, CMF_OFFSET = 0x4, CMF_DEPTH = 0x8
} ContentModifierFlags;

static unsigned GetCMF (PatternMatchData* pmd)
{
    unsigned cmf = 0;
    if ( (pmd->distance != 0) || (pmd->distance_var != -1) ) cmf |= CMF_DISTANCE;
    if ( (pmd->within != 0) || (pmd->within_var != -1) ) cmf |= CMF_WITHIN;
    if ( (pmd->offset != 0) || (pmd->offset_var != -1) ) cmf |= CMF_OFFSET;
    if ( (pmd->depth != 0) || (pmd->depth_var != -1) ) cmf |= CMF_DEPTH;
    return cmf;
}

#define BAD_DISTANCE (CMF_DISTANCE | CMF_OFFSET | CMF_DEPTH)
#define BAD_WITHIN (CMF_WITHIN | CMF_OFFSET | CMF_DEPTH)
#define BAD_OFFSET (CMF_OFFSET | CMF_DISTANCE | CMF_WITHIN)
#define BAD_DEPTH (CMF_DEPTH | CMF_DISTANCE | CMF_WITHIN)

static void PayloadSearchOffset(
    PatternMatchData* pmd, char *data, OptTreeNode*)
{
    if ( GetCMF(pmd) & BAD_OFFSET )
        ParseError("offset can't be used with itself, distance, or within");

    if (data == NULL)
        ParseError("Missing argument to 'offset' option");

    if (isdigit(data[0]) || data[0] == '-')
    {
        pmd->offset = ParseInt(data, "offset");
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

static void PayloadSearchDepth(
    PatternMatchData* pmd, char *data, OptTreeNode*)
{
    if ( GetCMF(pmd) & BAD_DEPTH )
        ParseError("depth can't be used with itself, distance, or within");

    if (data == NULL)
        ParseError("Missing argument to 'depth' option");

    if (isdigit(data[0]) || data[0] == '-')
    {
        pmd->depth = ParseInt(data, "depth");

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

static void PayloadSearchDistance(
    PatternMatchData* pmd, char *data, OptTreeNode*)
{
    if ( GetCMF(pmd) & BAD_DISTANCE )
        ParseError("distance can't be used with itself, offset, or depth");

    if (data == NULL)
        ParseError("Missing argument to 'distance' option");

    if (isdigit(data[0]) || data[0] == '-')
    {
        pmd->distance = ParseInt(data, "distance");
    }
    else
    {
        pmd->distance_var = GetVarByName(data);
        if (pmd->distance_var == BYTE_EXTRACT_NO_VAR)
        {
            ParseError(BYTE_EXTRACT_INVALID_ERR_STR);
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Pattern distance = %d\n",
                pmd->distance););

    pmd->use_doe = 1;
}

static void PayloadSearchWithin(
    PatternMatchData* pmd, char *data, OptTreeNode*)
{
    if ( GetCMF(pmd) & BAD_WITHIN )
        ParseError("within can't be used with itself, offset, or depth");

    if (data == NULL)
        ParseError("Missing argument to 'within' option");

    if (isdigit(data[0]) || data[0] == '-')
    {
        pmd->within = ParseInt(data, "within");

        if (pmd->within < pmd->pattern_size)
            ParseError("within (%d) is smaller than size of pattern", pmd->within);
    }
    else
    {
        pmd->within_var = GetVarByName(data);
        if (pmd->within_var == BYTE_EXTRACT_NO_VAR)
        {
            ParseError(BYTE_EXTRACT_INVALID_ERR_STR);
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "Pattern within = %d\n",
                pmd->within););

    pmd->use_doe = 1;
}

static void PayloadSearchNocase(
    PatternMatchData* pmd, char *data, OptTreeNode*)
{
    unsigned int i;

    if (data != NULL)
        ParseError("'nocase' does not take an argument");

    for (i = 0; i < pmd->pattern_size; i++)
        pmd->pattern_buf[i] = toupper((int)pmd->pattern_buf[i]);

    pmd->nocase = 1;

    pmd->search = uniSearchCI;
    make_precomp(pmd);
}

static void PayloadSearchRawbytes(
    PatternMatchData* pmd, char *data, OptTreeNode*)
{
    if (data != NULL)
        ParseError("'rawbytes' does not take an argument");

    /* mark this as inspecting a raw pattern match rather than a
     * decoded application buffer */
    pmd->rawbytes = 1;
}

static void PayloadSearchFastPattern(
    PatternMatchData* pmd, char *data, OptTreeNode *otn)
{
    /* There can only be one fast pattern content in the rule, whether
     * normal, http or other */
    if (pmd->fp)
    {
        ParseError("Cannot set fast_pattern modifier more than once "
                "for the same \"content\".");
    }

    if (HasFastPattern(otn, RULE_OPTION_TYPE_CONTENT))
        ParseError("Can only use the fast_pattern modifier once in a rule.");
    if (HasFastPattern(otn, RULE_OPTION_TYPE_CONTENT_URI))
        ParseError("Can only use the fast_pattern modifier once in a rule.");

    pmd->fp = 1;

    if (data != NULL)
    {
        const char *error_str = "Rule option \"fast_pattern\": Invalid parameter: "
            "\"%s\".  Valid parameters are: \"only\" | <offset>,<length>.  "
            "Offset and length must be integers less than 65536, offset cannot "
            "be negative, length must be positive and (offset + length) must "
            "evaluate to less than or equal to the actual pattern length.  "
            "Pattern length: %u";

        if (isdigit((int)*data))
        {
            /* Specifying offset and length of pattern to use for
             * fast pattern matcher */

            long int offset, length;
            char *endptr;
            char **toks;
            int num_toks;

            toks = mSplit(data, " ", 0, &num_toks, 0);
            if (num_toks != 2)
            {
                mSplitFree(&toks, num_toks);
                ParseError(error_str, data, pmd->pattern_size);
            }

            offset = SnortStrtol(toks[0], &endptr, 0);
            if ((errno == ERANGE) || (*endptr != '\0')
                    || (offset < 0) || (offset > UINT16_MAX))
            {
                mSplitFree(&toks, num_toks);
                ParseError(error_str, data, pmd->pattern_size);
            }

            length = SnortStrtol(toks[1], &endptr, 0);
            if ((errno == ERANGE) || (*endptr != '\0')
                    || (length <= 0) || (length > UINT16_MAX))
            {
                mSplitFree(&toks, num_toks);
                ParseError(error_str, data, pmd->pattern_size);
            }

            mSplitFree(&toks, num_toks);

            if ((int)pmd->pattern_size < (offset + length))
                ParseError(error_str, data, pmd->pattern_size);

            pmd->fp_offset = (uint16_t)offset;
            pmd->fp_length = (uint16_t)length;
        }
        else
        {
            /* Specifies that this content should only be used for
             * fast pattern matching */

            if (strcasecmp(data, PM_FP_ONLY) != 0)
                ParseError(error_str, data, pmd->pattern_size);

            pmd->fp_only = 1;
        }
    }
}

//-------------------------------------------------------------------------
// content api methods
//-------------------------------------------------------------------------

static void content_parse(char *rule, PatternMatchData* ds_idx)
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
    int exception_flag = 0;

    /* clear out the temp buffer */
    memset(tmp_buf, 0, MAX_PATTERN_SIZE);

    if (rule == NULL)
        ParseError("content_parse Got Null enclosed in quotation marks (\")");

    while(isspace((int)*rule))
        rule++;

    if(*rule == '!')
    {
        exception_flag = 1;
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
    ds_idx->search = uniSearch;

    make_precomp(ds_idx);
    ds_idx->exception_flag = exception_flag;

    ds_idx->pattern_max_jump_size = GetMaxJumpSize(ds_idx->pattern_buf, ds_idx->pattern_size);
}

static IpsOption* content_ctor(
    SnortConfig* sc, char *data, OptTreeNode * otn){
    PatternMatchData *pmd;
    char *data_end;
    char *data_dup;
    char *opt_data;
    int opt_len = 0;
    char *next_opt;

    pmd = new_pmd();

    if (!data)
        ParseError("No content pattern specified!");

    data_dup = SnortStrdup(data);
    data_end = data_dup + strlen(data_dup);

    opt_data = PayloadExtractParameter(data_dup, &opt_len);
    content_parse(opt_data, pmd);
    update_pmd(pmd);
    next_opt = opt_data + opt_len;

    pmd->http_buffer = HTTP_BUFFER_NONE;
    pmd->buffer_func = CHECK_AND_PATTERN_MATCH;

    while (next_opt < data_end)
    {
        char **opts;        /* dbl ptr for mSplit call, holds rule tokens */
        int num_opts;       /* holds number of tokens found by mSplit */
        char* opt1;

        next_opt++;
        if (next_opt == data_end)
            break;

        opt_len = 0;
        opt_data = PayloadExtractParameter(next_opt, &opt_len);
        if (!opt_data)
            break;

        next_opt = opt_data + opt_len;

        opts = mSplit(opt_data, ": \t", 2, &num_opts, 0);

        if (!opts)
            continue;
        opt1 = (num_opts == 2) ? opts[1] : NULL;

        if (!strcasecmp(opts[0], "offset"))
        {
            PayloadSearchOffset(pmd, opt1, otn);
        }
        else if (!strcasecmp(opts[0], "depth"))
        {
            PayloadSearchDepth(pmd, opt1, otn);
        }
        else if (!strcasecmp(opts[0], "nocase"))
        {
            PayloadSearchNocase(pmd, opt1, otn);
        }
        else if (!strcasecmp(opts[0], "rawbytes"))
        {
            PayloadSearchRawbytes(pmd, opt1, otn);
        }
        else if (!strcasecmp(opts[0], "http_uri"))
        {
            PayloadSearchHttpUri(pmd, opt1, otn);
        }
        else if (!strcasecmp(opts[0], "http_client_body"))
        {
            PayloadSearchHttpBody(pmd, opt1, otn);
        }
        else if (!strcasecmp(opts[0], "http_header"))
        {
            PayloadSearchHttpHeader(pmd, opt1, otn);
        }
        else if (!strcasecmp(opts[0], "http_method"))
        {
            PayloadSearchHttpMethod(pmd, opt1, otn);
        }
        else if (!strcasecmp(opts[0], "http_cookie"))
        {
            PayloadSearchHttpCookie(pmd, opt1, otn);
        }
        else if (!strcasecmp(opts[0], "http_raw_uri"))
        {
            PayloadSearchHttpRawUri(pmd, opt1, otn);
        }
        else if (!strcasecmp(opts[0], "http_raw_header"))
        {
            PayloadSearchHttpRawHeader(pmd, opt1, otn);
        }
        else if (!strcasecmp(opts[0], "http_raw_cookie"))
        {
            PayloadSearchHttpRawCookie(pmd, opt1, otn);
        }
        else if (!strcasecmp(opts[0], "http_stat_code"))
        {
            PayloadSearchHttpStatCode(pmd, opt1, otn);
        }
        else if (!strcasecmp(opts[0], "http_stat_msg"))
        {
            PayloadSearchHttpStatMsg(pmd, opt1, otn);
        }
        else if (!strcasecmp(opts[0], "fast_pattern"))
        {
            PayloadSearchFastPattern(pmd, opt1, otn);
        }
        else if (!strcasecmp(opts[0], "distance"))
        {
            PayloadSearchDistance(pmd, opt1, otn);
        }
        else if (!strcasecmp(opts[0], "within"))
        {
            PayloadSearchWithin(pmd, opt1, otn);
        }
        else if (!strcasecmp(opts[0], "replace"))
        {
            PayloadReplaceInit(pmd, opt1, otn);
        }
        else
        {
            ParseError("Invalid content parameter specified: %s", opts[0]);
        }
        mSplitFree(&opts, num_opts);
    }

    free(data_dup);
    ValidateContent(sc, pmd, RULE_OPTION_TYPE_CONTENT);

    if ( pmd->buffer_func == CHECK_URI_PATTERN_MATCH )
        return new UriContentOption(pmd);

    return new ContentOption(pmd, "content");
}

static void content_dtor(IpsOption* p)
{
    delete p;
}

static void content_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterOtnProfile("content", &contentPerfStats, con_get_profile);
#endif
}

static const IpsApi content_api =
{
    {
        PT_IPS_OPTION,
        "content",
        IPSAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    OPT_TYPE_DETECTION,
    0, 0,
    content_ginit,
    nullptr,
    nullptr,
    nullptr,
    content_ctor,
    content_dtor,
    nullptr
};

const BaseApi* ips_content = &content_api.base;


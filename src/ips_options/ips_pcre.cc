/*
** Copyright (C) 2003 Brian Caswell <bmc@snort.org>
** Copyright (C) 2003 Michael J. Pomraning <mjp@securepipe.com>
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2003-2013 Sourcefire, Inc.
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

#include "ips_pcre.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <pcre.h>

#include "snort_types.h"
#include "snort_bounds.h"
#include "treenodes.h"
#include "snort_debug.h"
#include "decode.h"
#include "parser.h"
#include "util.h"
#include "mstring.h"
#include "sfhashfcn.h"
#include "snort.h"
#include "profiler.h"
#include "fpdetect.h"
#include "sfhashfcn.h"
#include "detection/detection_defines.h"
#include "detection_util.h"
#include "framework/ips_option.h"

static const char* s_name = "pcre";

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats pcrePerfStats;

static PreprocStats* pcre_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &pcrePerfStats;

    return nullptr;
}
#endif

/*
 * we need to specify the vector length for our pcre_exec call.  we only care
 * about the first vector, which if the match is successful will include the
 * offset to the end of the full pattern match.  If we decide to store other
 * matches, make *SURE* that this is a multiple of 3 as pcre requires it.
 */
// the wrong size caused the pcre lib to segfault but that has since been
// fixed.  it may be that with the updated lib, the need to get the size
// exactly correct is obviated and thus the need to reload as well.

/* Since SO rules are loaded 1 time at startup, regardless of
 * configuraton, we won't pcre_capture count again, so save the max.  */
static int s_ovector_max = 0;

class PcreOption : public IpsOption
{
public:
    PcreOption(PcreData* c) :
        IpsOption(s_name, RULE_OPTION_TYPE_PCRE)
    { config = c; };

    ~PcreOption();

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    bool is_relative()
    { return (config->options & SNORT_PCRE_RELATIVE) != 0; };

    int eval(Packet*);

    PcreData* get_data()
    { return config; };

    void set_data(PcreData* pcre)
    { config = pcre; };

private:
    PcreData* config;
};

static int pcre_search(
    const PcreData*, const char*, int len, int start_offset, int* found_offset);

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

PcreOption::~PcreOption()
{
    if ( !config )
        return;

    if (config->expression)
        free(config->expression);
    if (config->pe)
        free(config->pe);
    if (config->re)
        free(config->re);

    free(config);
}

uint32_t PcreOption::hash() const
{
    int i,j,k,l,expression_len;
    uint32_t a,b,c,tmp;
    const PcreData *data = config;

    expression_len = strlen(data->expression);
    a = b = c = 0;

    for (i=0,j=0;i<expression_len;i+=4)
    {
        tmp = 0;
        k = expression_len - i;
        if (k > 4)
            k=4;

        for (l=0;l<k;l++)
        {
            tmp |= *(data->expression + i + l) << l*8;
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

    a += data->options;

    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool PcreOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    PcreOption& rhs = (PcreOption&)ips;
    PcreData *left = config;
    PcreData *right = rhs.config;

    if (( strcmp(left->expression, right->expression) == 0) &&
        ( left->options == right->options))
    {
        return true;
    }

    return false;
}

int PcreOption::eval(Packet *p)
{
    PcreData *pcre_data = config;
    int found_offset = -1;  /* where is the ending location of the pattern */
    const uint8_t *base_ptr, *end_ptr, *start_ptr;
    int dsize;
    int length; /* length of the buffer pointed to by base_ptr  */
    int matched = 0;
    uint8_t rst_doe_flags = 1;
    HTTP_BUFFER hb_type;
    DEBUG_WRAP(char *hexbuf;)

    PROFILE_VARS;
    PREPROC_PROFILE_START(pcrePerfStats);

    //short circuit this for testing pcre performance impact
    if (ScNoPcre())
    {
        PREPROC_PROFILE_END(pcrePerfStats);
        return DETECTION_OPTION_NO_MATCH;
    }

    /* This is the HTTP case */
    if ( (hb_type = (HTTP_BUFFER)(pcre_data->options & SNORT_PCRE_HTTP_BUFS)) )
    {
        const HttpBuffer* hb = GetHttpBuffer(hb_type);

        if ( hb )
        {
            matched = pcre_search(
                pcre_data, (const char*)hb->buf, hb->length, 0, &found_offset);

            if ( matched )
            {
                /* don't touch doe_ptr on URI contents */
                PREPROC_PROFILE_END(pcrePerfStats);
                return DETECTION_OPTION_MATCH;
            }
        }
        PREPROC_PROFILE_END(pcrePerfStats);
        return DETECTION_OPTION_NO_MATCH;
    }
    /* end of the HTTP case */

    if( !(pcre_data->options & SNORT_PCRE_RAWBYTES))
    {
        if(Is_DetectFlag(FLAG_ALT_DETECT))
        {
            dsize = DetectBuffer.len;
            start_ptr = DetectBuffer.data;
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                "using alternative detect buffer in pcre!\n"););
        }
        else if(Is_DetectFlag(FLAG_ALT_DECODE))
        {
            dsize = DecodeBuffer.len;
            start_ptr = DecodeBuffer.data;
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                "using alternative decode buffer in pcre!\n"););
        }
        else
        {
            if(IsLimitedDetect(p))
                dsize = p->alt_dsize;
            else
                dsize = p->dsize;
            start_ptr = p->data;
        }
    }
    else
    {
        dsize = p->dsize;
        start_ptr = p->data;
    }

    base_ptr = start_ptr;
    end_ptr = start_ptr + dsize;

    /* doe_ptr's would be set by the previous content option */
    if(pcre_data->options & SNORT_PCRE_RELATIVE && doe_ptr)
    {
        if(!inBounds(start_ptr, end_ptr, doe_ptr))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                    "pcre bounds check failed on a relative content match\n"););
            PREPROC_PROFILE_END(pcrePerfStats);
            return DETECTION_OPTION_NO_MATCH;
        }

        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "pcre ... checking relative offset\n"););
        base_ptr = doe_ptr;
        rst_doe_flags = 0;
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "pcre ... checking absolute offset\n"););
        base_ptr = start_ptr;
    }

    length = end_ptr - base_ptr;

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                            "pcre ... base: %p start: %p end: %p doe: %p length: %d\n",
                            base_ptr, start_ptr, end_ptr, doe_ptr, length););

    DEBUG_WRAP(hexbuf = hex(base_ptr, length);
               DebugMessage(DEBUG_PATTERN_MATCH, "pcre payload: %s\n", hexbuf);
               free(hexbuf);
               );

    matched = pcre_search(pcre_data, (const char *)base_ptr, length, pcre_data->search_offset, &found_offset);

    /* set the doe_ptr if we have a valid offset */
    if(found_offset > 0)
    {
        UpdateDoePtr(((uint8_t *) base_ptr + found_offset), rst_doe_flags);
    }

    if (matched)
    {
        PREPROC_PROFILE_END(pcrePerfStats);
        return DETECTION_OPTION_MATCH;
    }

    /* finally return 0 */
    PREPROC_PROFILE_END(pcrePerfStats);
    return DETECTION_OPTION_NO_MATCH;
}

//-------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

void PcreDuplicatePcreData(void *src, PcreData *pcre_dup)
{
    PcreOption* opt = (PcreOption*)src;
    PcreData* pcre_src = opt->get_data();
    *pcre_dup = *pcre_src;
    pcre_dup->search_offset = 0;
}

// FIXIT this kinda hurts ...
int eval_dup_pcre(void*, Packet* p, PcreData* dup)
{
    PcreOption tmp(dup);
    int rval = tmp.eval(p);
    tmp.set_data(nullptr);
    return rval;
}

int PcreAdjustRelativeOffsets(PcreData *pcre, uint32_t search_offset)
{
    if ((pcre->options & (SNORT_PCRE_INVERT | SNORT_PCRE_ANCHORED)))
    {
        return 0; /* Don't search again */
    }

    if (pcre->options & ( SNORT_PCRE_HTTP_BUFS ))
    {
        return 0;
    }

    /* What's coming in has the absolute offset */
    pcre->search_offset += search_offset;

    return 1; /* Continue searcing */
}

//-------------------------------------------------------------------------
// implementation foo
//-------------------------------------------------------------------------

/**
 * Perform a search of the PCRE data.
 *
 * @param pcre_data structure that options and patterns are passed in
 * @param buf buffer to search
 * @param len size of buffer
 * @param start_offset initial offset into the buffer
 * @param found_offset pointer to an integer so that we know where the search ended
 *
 * *found_offset will be set to -1 when the find is unsucessful OR the routine is inverted
 *
 * @return 1 when we find the string, 0 when we don't (unless we've been passed a flag to invert)
 */
static int pcre_search(
    const PcreData *pcre_data,
    const char *buf,
    int len,
    int start_offset,
    int *found_offset)
{
    int matched;
    int result;

    if(pcre_data == NULL
       || buf == NULL
       || len <= 0
       || start_offset < 0
       || start_offset >= len
       || found_offset == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
            "Returning 0 because we didn't have the required parameters!\n"););
        return 0;
    }

    *found_offset = -1;

    SnortState* ss = snort_conf->state + get_instance_id();

    result = pcre_exec(
        pcre_data->re,  /* result of pcre_compile() */
        pcre_data->pe,  /* result of pcre_study()   */
        buf,            /* the subject string */
        len,            /* the length of the subject string */
        start_offset,   /* start at offset 0 in the subject */
        0,              /* options(handled at compile time */
        ss->pcre_ovector,      /* vector for substring information */
        snort_conf->pcre_ovector_size);/* number of elements in the vector */

    if(result >= 0)
    {
        matched = 1;

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

        *found_offset = ss->pcre_ovector[1];
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
            "Setting Doe_ptr and found_offset: %p %d\n", doe_ptr, found_offset););
    }
    else if(result == PCRE_ERROR_NOMATCH)
    {
        matched = 0;
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "pcre_exec error : %d \n", result););
        return 0;
    }

    /* invert sense of match */
    if(pcre_data->options & SNORT_PCRE_INVERT)
    {
        matched = !matched;
    }

    return matched;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static void ValidatePcreHttpContentModifiers(PcreData *pcre_data)
{
    if( pcre_data->options & SNORT_PCRE_RELATIVE )
        ParseError("PCRE unsupported configuration : both relative & uri options specified");

    if( pcre_data->options & SNORT_PCRE_RAWBYTES )
        ParseError("PCRE unsupported configuration : both rawbytes & uri options specified");
}

static void pcre_capture(
    SnortConfig* sc, const void *code, const void *extra)
{
    int tmp_ovector_size = 0;

    pcre_fullinfo((const pcre *)code, (const pcre_extra *)extra,
        PCRE_INFO_CAPTURECOUNT, &tmp_ovector_size);

    if (tmp_ovector_size > sc->pcre_ovector_size)
        sc->pcre_ovector_size = tmp_ovector_size;
}

static void pcre_check_anchored(PcreData *pcre_data)
{
    int rc;
    unsigned long int options = 0;

    if ((pcre_data == NULL) || (pcre_data->re == NULL) || (pcre_data->pe == NULL))
        return;

    rc = pcre_fullinfo(pcre_data->re, pcre_data->pe, PCRE_INFO_OPTIONS, (void *)&options);
    switch (rc)
    {
        /* pcre_fullinfo fails for the following:
         * PCRE_ERROR_NULL - the argument code was NULL
         *                   the argument where was NULL
         * PCRE_ERROR_BADMAGIC - the "magic number" was not found
         * PCRE_ERROR_BADOPTION - the value of what was invalid
         * so a failure here means we passed in bad values and we should
         * probably fatal error */

        case 0:
            /* This is the success code */
            break;

        case PCRE_ERROR_NULL:
            ParseError("pcre_fullinfo: code and/or where were NULL.");

        case PCRE_ERROR_BADMAGIC:
            ParseError("pcre_fullinfo: compiled code didn't have "
                       "correct magic.");

        case PCRE_ERROR_BADOPTION:
            ParseError("pcre_fullinfo: option type is invalid.");

        default:
            ParseError("pcre_fullinfo: Unknown error code.");
    }

    if ((options & PCRE_ANCHORED) && !(options & PCRE_MULTILINE))
    {
        /* This means that this pcre rule option shouldn't be reevaluted
         * even if any of it's relative children should fail to match.
         * It is anchored to the cursor set by the previous cursor setting
         * rule option */
        pcre_data->options |= SNORT_PCRE_ANCHORED;
    }
}

static void pcre_parse(
    SnortConfig* sc, char *data, PcreData *pcre_data, OptTreeNode*)
{
    const char *error;
    char *re, *free_me;
    char *opts;
    char delimit = '/';
    int erroffset;
    int compile_flags = 0;
    unsigned http = 0;

    if(data == NULL)
    {
        ParseError("pcre requires a regular expression");
    }

    free_me = SnortStrdup(data);
    re = free_me;

    /* get rid of starting and ending whitespace */
    while (isspace((int)re[strlen(re)-1])) re[strlen(re)-1] = '\0';
    while (isspace((int)*re)) re++;

    if(*re == '!') {
        pcre_data->options |= SNORT_PCRE_INVERT;
        re++;
        while(isspace((int)*re)) re++;
    }

    /* now we wrap the RE in double quotes.  stupid snort parser.... */
    if(*re != '"') {
        printf("It isn't \"\n");
        goto syntax;
    }
    re++;

    if(re[strlen(re)-1] != '"')
    {
        printf("It isn't \"\n");
        goto syntax;
    }

    /* remove the last quote from the string */
    re[strlen(re) - 1] = '\0';

    /* 'm//' or just '//' */

    if(*re == 'm')
    {
        re++;
        if(! *re) goto syntax;

        /* Space as a ending delimiter?  Uh, no. */
        if(isspace((int)*re)) goto syntax;
        /* using R would be bad, as it triggers RE */
        if(*re == 'R') goto syntax;

        delimit = *re;
    }
    else if(*re != delimit)
        goto syntax;

    pcre_data->expression = SnortStrdup(re);

    /* find ending delimiter, trim delimit chars */
    opts = strrchr(re, delimit);
    if (opts == NULL)
        goto syntax;

    if(!((opts - re) > 1)) /* empty regex(m||) or missing delim not OK */
        goto syntax;

    re++;
    *opts++ = '\0';

    /* process any /regex/ismxR options */
    while(*opts != '\0') {
        switch(*opts) {
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
        case 'B':  pcre_data->options |= SNORT_PCRE_RAWBYTES; break;
        case 'O':  pcre_data->options |= SNORT_OVERRIDE_MATCH_LIMIT; break;
        case 'U':  pcre_data->options |= SNORT_PCRE_HTTP_URI; http++; break;
        case 'P':  pcre_data->options |= SNORT_PCRE_HTTP_BODY;  http++; break;
        case 'H':  pcre_data->options |= SNORT_PCRE_HTTP_HEADER;  http++; break;
        case 'M':  pcre_data->options |= SNORT_PCRE_HTTP_METHOD;  http++; break;
        case 'C':  pcre_data->options |= SNORT_PCRE_HTTP_COOKIE;  http++; break;
        case 'I':  pcre_data->options |= SNORT_PCRE_HTTP_RAW_URI; http++; break;
        case 'D':  pcre_data->options |= SNORT_PCRE_HTTP_RAW_HEADER; http++; break;
        case 'K':  pcre_data->options |= SNORT_PCRE_HTTP_RAW_COOKIE; http++; break;
        case 'S':  pcre_data->options |= SNORT_PCRE_HTTP_STAT_CODE; http++; break;
        case 'Y':  pcre_data->options |= SNORT_PCRE_HTTP_STAT_MSG; http++; break;

        default:
            ParseError("unknown/extra pcre option encountered");
        }
        opts++;
    }

    if ( http > 1 )
        ParseWarning("at most one HTTP buffer may be indicated with pcre");

    if(pcre_data->options & (SNORT_PCRE_HTTP_BUFS))
        ValidatePcreHttpContentModifiers(pcre_data);

    /* now compile the re */
    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH, "pcre: compiling %s\n", re););
    pcre_data->re = pcre_compile(re, compile_flags, &error, &erroffset, NULL);

    if(pcre_data->re == NULL)
    {
        ParseError(": pcre compile of '%s' failed at offset "
                   "%d : %s", re, erroffset, error);
    }


    /* now study it... */
    pcre_data->pe = pcre_study(pcre_data->re, 0, &error);

    if (pcre_data->pe)
    {
        if ((ScPcreMatchLimit() != -1) && !(pcre_data->options & SNORT_OVERRIDE_MATCH_LIMIT))
        {
            if (pcre_data->pe->flags & PCRE_EXTRA_MATCH_LIMIT)
            {
                pcre_data->pe->match_limit = ScPcreMatchLimit();
            }
            else
            {
                pcre_data->pe->flags |= PCRE_EXTRA_MATCH_LIMIT;
                pcre_data->pe->match_limit = ScPcreMatchLimit();
            }
        }

#ifdef PCRE_EXTRA_MATCH_LIMIT_RECURSION
        if ((ScPcreMatchLimitRecursion() != -1) && !(pcre_data->options & SNORT_OVERRIDE_MATCH_LIMIT))
        {
            if (pcre_data->pe->flags & PCRE_EXTRA_MATCH_LIMIT_RECURSION)
            {
                pcre_data->pe->match_limit_recursion = ScPcreMatchLimitRecursion();
            }
            else
            {
                pcre_data->pe->flags |= PCRE_EXTRA_MATCH_LIMIT_RECURSION;
                pcre_data->pe->match_limit_recursion = ScPcreMatchLimitRecursion();
            }
        }
#endif
    }
    else
    {
        if (!(pcre_data->options & SNORT_OVERRIDE_MATCH_LIMIT) &&
             ((ScPcreMatchLimit() != -1) || (ScPcreMatchLimitRecursion() != -1)))
        {
            pcre_data->pe = (pcre_extra *)SnortAlloc(sizeof(pcre_extra));
            if (ScPcreMatchLimit() != -1)
            {
                pcre_data->pe->flags |= PCRE_EXTRA_MATCH_LIMIT;
                pcre_data->pe->match_limit = ScPcreMatchLimit();
            }

#ifdef PCRE_EXTRA_MATCH_LIMIT_RECURSION
            if (ScPcreMatchLimitRecursion() != -1)
            {
                pcre_data->pe->flags |= PCRE_EXTRA_MATCH_LIMIT_RECURSION;
                pcre_data->pe->match_limit_recursion = ScPcreMatchLimitRecursion();
            }
#endif
        }
    }

    if(error != NULL)
    {
        ParseError("pcre study failed : %s", error);
    }

    pcre_capture(sc, pcre_data->re, pcre_data->pe);
    pcre_check_anchored(pcre_data);

    free(free_me);
    return;

 syntax:
    free(free_me);

    ParseError("unable to parse pcre regex %s", data);
}

static IpsOption* pcre_ctor(
    SnortConfig* sc, char *data, OptTreeNode *otn)
{
    PcreData* pcre_data = (PcreData*)SnortAlloc(sizeof(PcreData));
    pcre_parse(sc, data, pcre_data, otn);
    return new PcreOption(pcre_data);
}

static void pcre_dtor(IpsOption* p)
{
    delete p;
}

static void pcre_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterOtnProfile(s_name, &pcrePerfStats, pcre_get_profile);
#endif
}

void pcre_tinit(SnortConfig* sc)
{
    SnortState* ss = sc->state + get_instance_id();
    ss->pcre_ovector = (int *) SnortAlloc(s_ovector_max*sizeof(int));
}

void pcre_tterm(SnortConfig* sc)
{
    SnortState* ss = sc->state + get_instance_id();

    if ( !ss->pcre_ovector )
        return;

    free(ss->pcre_ovector);
    ss->pcre_ovector = nullptr;
}

bool pcre_verify()
{
    /* The pcre_fullinfo() function can be used to find out how many
     * capturing subpatterns there are in a compiled pattern. The
     * smallest size for ovector that will allow for n captured
     * substrings, in addition to the offsets of the substring matched
     * by the whole pattern, is (n+1)*3.  */
    snort_conf->pcre_ovector_size += 1;
    snort_conf->pcre_ovector_size *= 3;

    if (snort_conf->pcre_ovector_size > s_ovector_max)
        s_ovector_max = snort_conf->pcre_ovector_size;

    return true;
}

static const IpsApi pcre_api =
{
    {
        PT_IPS_OPTION,
        s_name,
        IPSAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    OPT_TYPE_DETECTION,
    0, 0,
    pcre_ginit,
    nullptr,
    pcre_tinit,
    pcre_tterm,
    pcre_ctor,
    pcre_dtor,
    pcre_verify
};

const BaseApi* ips_pcre = &pcre_api.base;


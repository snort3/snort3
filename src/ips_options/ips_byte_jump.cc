/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 ** Copyright (C) 2002-2013 Sourcefire, Inc.
 ** Author: Martin Roesch
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

/* sp_byte_jump
 *
 * Purpose:
 *      Grab some number of bytes, convert them to their numeric
 *      representation, jump the doe_ptr up that many bytes (for
 *      further pattern matching/byte_testing).
 *
 *
 * Arguments:
 *      Required:
 *      <bytes_to_grab>: number of bytes to pick up from the packet
 *      <offset>: number of bytes into the payload to grab the bytes
 *      Optional:
 *      ["relative"]: offset relative to last pattern match
 *      ["big"]: process data as big endian (default)
 *      ["little"]: process data as little endian
 *      ["string"]: converted bytes represented as a string needing conversion
 *      ["hex"]: converted string data is represented in hexidecimal
 *      ["dec"]: converted string data is represented in decimal
 *      ["oct"]: converted string data is represented in octal
 *      ["align"]: round the number of converted bytes up to the next
 *                 32-bit boundry
 *      ["post_offset"]: number of bytes to adjust after applying
 *
 *   sample rules:
 *   alert udp any any -> any 32770:34000 (content: "|00 01 86 B8|"; \
 *       content: "|00 00 00 01|"; distance: 4; within: 4; \
 *       byte_jump: 4, 12, relative, align; \
 *       byte_test: 4, >, 900, 20, relative; \
 *       msg: "statd format string buffer overflow";)
 *
 * Effect:
 *
 *      Reads in the indicated bytes, converts them to an numeric
 *      representation and then jumps the doe_ptr up
 *      that number of bytes.  Returns 1 if the jump is in range (within the
 *      packet) and 0 if it's not.
 *
 * Comments:
 *
 * Any comments?
 *
 */

#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#include "snort_types.h"
#include "snort_bounds.h"
#include "detection/treenodes.h"
#include "protocols/packet.h"
#include "parser.h"
#include "snort_debug.h"
#include "util.h"
#include "mstring.h"
#include "extract.h"
#include "ips_byte_extract.h"
#include "sfhashfcn.h"
#include "snort.h"
#include "profiler.h"
#include "fpdetect.h"
#include "sfhashfcn.h"
#include "detection/detection_defines.h"
#include "detection/detection_util.h"
#include "framework/ips_option.h"

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats byteJumpPerfStats;

static const char* s_name = "byte_jump";

static PreprocStats* bj_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &byteJumpPerfStats;

    return nullptr;
}
#endif

typedef struct _ByteJumpData
{
    uint32_t bytes_to_grab;
    int32_t offset;
    uint8_t relative_flag;
    uint8_t data_string_convert_flag;
    uint8_t from_beginning_flag;
    uint8_t align_flag;
    int8_t endianess;
    uint32_t base;
    uint32_t multiplier;
    int32_t post_offset;
    int8_t offset_var;
} ByteJumpData;

class ByteJumpOption : public IpsOption
{
public:
    ByteJumpOption(const ByteJumpData& c) :
        IpsOption(s_name, RULE_OPTION_TYPE_BYTE_JUMP)
    { config = c; };

    ~ByteJumpOption() { };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    bool is_relative()
    { return (config.relative_flag == 1); };

    int eval(Packet*);

private:
    ByteJumpData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t ByteJumpOption::hash() const
{
    uint32_t a,b,c;
    const ByteJumpData *data = &config;

    a = data->bytes_to_grab;
    b = data->offset;
    c = data->base;

    mix(a,b,c);

    a += (data->relative_flag << 24 |
          data->data_string_convert_flag << 16 |
          data->from_beginning_flag << 8 |
          data->align_flag);
    b += data->endianess;
    c += data->multiplier;

    mix(a,b,c);

    a += data->post_offset;
    b += data->offset_var;

    mix(a,b,c);
    mix_str(a,b,c,get_name());

    final(a,b,c);

    return c;
}

bool ByteJumpOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(s_name, ips.get_name()) )
        return false;

    ByteJumpOption& rhs = (ByteJumpOption&)ips;
    ByteJumpData *left = (ByteJumpData *)&config;
    ByteJumpData *right = (ByteJumpData *)&rhs.config;

    if (( left->bytes_to_grab == right->bytes_to_grab) &&
        ( left->offset == right->offset) &&
        ( left->offset_var == right->offset_var) &&
        ( left->relative_flag == right->relative_flag) &&
        ( left->data_string_convert_flag == right->data_string_convert_flag) &&
        ( left->from_beginning_flag == right->from_beginning_flag) &&
        ( left->align_flag == right->align_flag) &&
        ( left->endianess == right->endianess) &&
        ( left->base == right->base) &&
        ( left->multiplier == right->multiplier) &&
        ( left->post_offset == right->post_offset))
    {
        return true;
    }

    return false;
}

int ByteJumpOption::eval(Packet *p)
{
    ByteJumpData *bjd = (ByteJumpData *)&config;
    int rval = DETECTION_OPTION_NO_MATCH;
    uint32_t value = 0;
    uint32_t jump_value = 0;
    uint32_t payload_bytes_grabbed = 0;
    uint32_t extract_offset;
    int32_t tmp = 0;
    int dsize;
    const uint8_t *base_ptr, *end_ptr, *start_ptr;
    uint8_t rst_doe_flags = 1;
    PROFILE_VARS;

    PREPROC_PROFILE_START(byteJumpPerfStats);

    if (Is_DetectFlag(FLAG_ALT_DETECT))
    {
        dsize = DetectBuffer.len;
        start_ptr = DetectBuffer.data;
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                    "Using Alternative Detect buffer!\n"););
    }
    else if(Is_DetectFlag(FLAG_ALT_DECODE))
    {
        dsize = DecodeBuffer.len;
        start_ptr = DecodeBuffer.data;
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                    "Using Alternative Decode buffer!\n"););
    }
    else
    {
        start_ptr = p->data;
        if(IsLimitedDetect(p))
            dsize = p->alt_dsize;
        else
            dsize = p->dsize;
    }

    DEBUG_WRAP(
            DebugMessage(DEBUG_PATTERN_MATCH,"[*] byte jump firing...\n");
            DebugMessage(DEBUG_PATTERN_MATCH,"payload starts at %p\n", start_ptr);
            );  /* END DEBUG_WRAP */

    /* save off whatever our ending pointer is */
    end_ptr = start_ptr + dsize;
    //base_ptr = start_ptr;

    /* Get values from byte_extract variables, if present. */
    if (bjd->offset_var >= 0 && bjd->offset_var < NUM_BYTE_EXTRACT_VARS)
    {
        GetByteExtractValue(&extract_offset, bjd->offset_var);
        bjd->offset = (int32_t) extract_offset;
    }

    if(bjd->relative_flag && doe_ptr)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "Checking relative offset!\n"););

        /* @todo: possibly degrade to use the other buffer, seems non-intuitive
         *  Because doe_ptr can be "end" in the last match,
         *  use end + 1 for upper bound
         *  Bound checked also after offset is applied
         *  (see byte_extract() and string_extract())
         */
        if(!inBounds(start_ptr, end_ptr + 1, doe_ptr))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                    "[*] byte jump bounds check failed..\n"););

            PREPROC_PROFILE_END(byteJumpPerfStats);
            return rval;
        }

        base_ptr = doe_ptr + bjd->offset;
        rst_doe_flags = 0;
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "checking absolute offset %d\n", bjd->offset););
        base_ptr = start_ptr + bjd->offset;
    }

    /* Both of the extraction functions contain checks to insure the data
     * is always inbounds */

    if(!bjd->data_string_convert_flag)
    {
        if(byte_extract(bjd->endianess, bjd->bytes_to_grab,
                        base_ptr, start_ptr, end_ptr, &value))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                    "Byte Extraction Failed\n"););

            PREPROC_PROFILE_END(byteJumpPerfStats);
            return rval;
        }

        payload_bytes_grabbed = bjd->bytes_to_grab;
    }
    else
    {
        payload_bytes_grabbed = tmp = string_extract(bjd->bytes_to_grab, bjd->base,
                                               base_ptr, start_ptr, end_ptr, &value);
        if (tmp < 0)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                    "Byte Extraction Failed\n"););

            PREPROC_PROFILE_END(byteJumpPerfStats);
            return rval;
        }

    }

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                            "grabbed %d of %d bytes, value = %08X\n",
                            payload_bytes_grabbed, bjd->bytes_to_grab, value););

    /* Adjust the jump_value (# bytes to jump forward) with the multiplier. */
    if (bjd->multiplier)
        jump_value = value * bjd->multiplier;
    else
        jump_value = value;

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                            "grabbed %d of %d bytes, after multiplier value = %08X\n",
                            payload_bytes_grabbed, bjd->bytes_to_grab, jump_value););


    /* if we need to align on 32-bit boundries, round up to the next
     * 32-bit value
     */
    if(bjd->align_flag)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                    "offset currently at %d\n", jump_value););
        if ((jump_value % 4) != 0)
        {
            jump_value += (4 - (jump_value % 4));
        }
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                    "offset aligned to %d\n", jump_value););
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                            "Grabbed %d bytes at offset %d, value = 0x%08X\n",
                            payload_bytes_grabbed, bjd->offset, jump_value););

    if(bjd->from_beginning_flag)
    {
        /* Reset base_ptr if from_beginning */
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "jumping from beginning %d bytes\n", jump_value););
        base_ptr = start_ptr;

        /* from base, push doe_ptr ahead "value" number of bytes */
        SetDoePtr((base_ptr + jump_value), DOE_BUF_STD);

    }
    else
    {
        UpdateDoePtr((base_ptr + payload_bytes_grabbed + jump_value), rst_doe_flags);
    }

    /* now adjust using post_offset -- before bounds checking */
    doe_ptr += bjd->post_offset;

    if(!inBounds(start_ptr, end_ptr, doe_ptr))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "tmp ptr is not in bounds %p\n", doe_ptr););
        PREPROC_PROFILE_END(byteJumpPerfStats);
        return rval;
    }
    else
    {
        rval = DETECTION_OPTION_MATCH;
    }

    PREPROC_PROFILE_END(byteJumpPerfStats);
    return rval;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static void byte_jump_parse(char *data, ByteJumpData *idx)
{
    char **toks;
    char *endp;
    int num_toks;
    char *cptr;
    int i =0;

    toks = mSplit(data, ",", 12, &num_toks, 0);

    if(num_toks < 2)
        ParseError("Bad arguments to byte_jump: %s", data);

    /* set how many bytes to process from the packet */
    idx->bytes_to_grab = strtoul(toks[0], &endp, 10);

    if(endp==toks[0])
    {
        ParseError("Unable to parse as byte value %s", toks[0]);
    }

    if(idx->bytes_to_grab > PARSELEN || idx->bytes_to_grab == 0)
    {
        ParseError("byte_jump can't process more than %d bytes!",
            PARSELEN);
    }

    /* set offset */
    if (isdigit(toks[1][0]) || toks[1][0] == '-')
    {
        idx->offset = strtol(toks[1], &endp, 10);
        idx->offset_var = -1;

        if(endp==toks[1])
        {
            ParseError("Unable to parse as offset %s", toks[1]);
        }
    }
    else
    {
        idx->offset_var = GetVarByName(toks[1]);
        if (idx->offset_var == BYTE_EXTRACT_NO_VAR)
        {
            ParseError("%s", BYTE_EXTRACT_INVALID_ERR_STR);
        }
    }

    i = 2;

    /* is it a relative offset? */
    if(num_toks > 2)
    {
        while(i < num_toks)
        {
            cptr = toks[i];

            while(isspace((int)*cptr)) {cptr++;}

            if(!strcasecmp(cptr, "relative"))
            {
                /* the offset is relative to the last pattern match */
                idx->relative_flag = 1;
            }
            else if(!strcasecmp(cptr, "from_beginning"))
            {
                idx->from_beginning_flag = 1;
            }
            else if(!strcasecmp(cptr, "string"))
            {
                /* the data will be represented as a string that needs
                 * to be converted to an int, binary is assumed otherwise
                 */
                idx->data_string_convert_flag = 1;
            }
            else if(!strcasecmp(cptr, "little"))
            {
                idx->endianess = ENDIAN_LITTLE;
            }
            else if(!strcasecmp(cptr, "big"))
            {
                /* this is the default */
                idx->endianess = ENDIAN_BIG;
            }
            else if(!strcasecmp(cptr, "hex"))
            {
                idx->base = 16;
            }
            else if(!strcasecmp(cptr, "dec"))
            {
                idx->base = 10;
            }
            else if(!strcasecmp(cptr, "oct"))
            {
                idx->base = 8;
            }
            else if(!strcasecmp(cptr, "align"))
            {
                idx->align_flag = 1;
            }
            else if(!strncasecmp(cptr, "multiplier ", 11))
            {
                /* Format of this option is multiplier xx.
                 * xx is a positive base 10 number.
                 */
                char *mval = &cptr[11];
                long factor = 0;
                int multiplier_len = strlen(cptr);
                if (multiplier_len > 11)
                {
                    factor = strtol(mval, &endp, 10);
                }
                if ((factor <= 0) || (endp != cptr + multiplier_len))
                {
                    ParseError("invalid length multiplier '%s'", cptr);
                }
                idx->multiplier = factor;
            }
            else if(!strncasecmp(cptr, "post_offset ", 12))
            {
                /* Format of this option is post_offset xx.
                 * xx is a positive or negative base 10 integer.
                 */
                char *mval = &cptr[12];
                int32_t factor = 0;
                int postoffset_len = strlen(cptr);
                if (postoffset_len > 12)
                {
                    factor = strtol(mval, &endp, 10);
                }
                if (endp != cptr + postoffset_len)
                {
                    ParseError("invalid post_offset '%s'", cptr);
                }
                idx->post_offset = factor;
            }
            // FIXIT allow byte order plugin here
            else
            {
                ParseError("unknown modifier '%s'", cptr);
            }
            i++;
        }
    }

    /* idx->base is only set if the parameter is specified */
    if(!idx->data_string_convert_flag && idx->base)
    {
        ParseError(
            "hex, dec and oct modifiers must be used in conjunction"
            " with the 'string' modifier");
    }

    mSplitFree(&toks, num_toks);
}

static IpsOption* byte_jump_ctor(
    SnortConfig*, char *data, OptTreeNode*)
{
    ByteJumpData idx;
    memset(&idx, 0, sizeof(idx));
    byte_jump_parse(data, &idx);
    return new ByteJumpOption(idx);
}

static void byte_jump_dtor(IpsOption* p)
{
    delete p;
}

static void byte_jump_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterOtnProfile(s_name, &byteJumpPerfStats, bj_get_profile);
#endif
}

static const IpsApi byte_jump_api =
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
    byte_jump_ginit,
    nullptr,
    nullptr,
    nullptr,
    byte_jump_ctor,
    byte_jump_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &byte_jump_api.base,
    nullptr
};
#else
const BaseApi* ips_byte_jump = &byte_jump_api.base;
#endif


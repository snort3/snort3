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

/* byte_test
 *
 * Purpose:
 *      Test a byte field against a specific value (with opcode).  Capable
 *      of testing binary values or converting represenative byte strings
 *      to their binary equivalent and testing them.
 *
 *
 * Arguments:
 *      Required:
 *      <bytes_to_convert>: number of bytes to pick up from the packet
 *      <opcode>: operation to perform to test the value (<,>,=,!)
 *      <value>: value to test the converted value against
 *      <offset>: number of bytes into the payload to start processing
 *      Optional:
 *      ["relative"]: offset relative to last pattern match
 *      ["big"]: process data as big endian (default)
 *      ["little"]: process data as little endian
 *      ["string"]: converted bytes represented as a string needing conversion
 *      ["hex"]: converted string data is represented in hexidecimal
 *      ["dec"]: converted string data is represented in decimal
 *      ["oct"]: converted string data is represented in octal
 *
 *   sample rules:
 *   alert udp $EXTERNAL_NET any -> $HOME_NET any \
 *      (msg:"AMD procedure 7 plog overflow "; \
 *      content: "|00 04 93 F3|"; \
 *      content: "|00 00 00 07|"; distance: 4; within: 4; \
 *      byte_test: 4,>, 1000, 20, relative;)
 *
 *   alert tcp $EXTERNAL_NET any -> $HOME_NET any \
 *      (msg:"AMD procedure 7 plog overflow "; \
 *      content: "|00 04 93 F3|"; \
 *      content: "|00 00 00 07|"; distance: 4; within: 4; \
 *      byte_test: 4, >,1000, 20, relative;)
 *
 * alert udp any any -> any 1234 \
 *      (byte_test: 4, =, 1234, 0, string, dec; \
 *      msg: "got 1234!";)
 *
 * alert udp any any -> any 1235 \
 *      (byte_test: 3, =, 123, 0, string, dec; \
 *      msg: "got 123!";)
 *
 * alert udp any any -> any 1236 \
 *      (byte_test: 2, =, 12, 0, string, dec; \
 *      msg: "got 12!";)
 *
 * alert udp any any -> any 1237 \
 *      (byte_test: 10, =, 1234567890, 0, string, dec; \
 *      msg: "got 1234567890!";)
 *
 * alert udp any any -> any 1238 \
 *      (byte_test: 8, =, 0xdeadbeef, 0, string, hex; \
 *      msg: "got DEADBEEF!";)
 *
 * Effect:
 *
 *      Reads in the indicated bytes, converts them to an numeric
 *      representation and then performs the indicated operation/test on
 *      the data using the value field.  Returns 1 if the operation is true,
 *      0 if it is not.
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
#include "extract.h"
#include "detection/treenodes.h"
#include "decode.h"
#include "parser.h"
#include "snort_debug.h"
#include "util.h"
#include "mstring.h"
#include "sfhashfcn.h"
#include "ips_byte_extract.h"
#include "snort.h"
#include "profiler.h"
#include "sfhashfcn.h"
#include "detection/detection_defines.h"
#include "detection/detection_util.h"
#include "fpdetect.h"
#include "framework/ips_option.h"

#define PARSELEN 10
#define TEXTLEN  (PARSELEN + 2)

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats byteTestPerfStats;

static const char* s_name = "byte_test";

static PreprocStats* bt_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &byteTestPerfStats;

    return nullptr;
}
#endif

// FIXIT cloned from sf_snort_plugin_api.h
#define CHECK_EQ            0
#define CHECK_NEQ           1
#define CHECK_LT            2
#define CHECK_GT            3
#define CHECK_LTE           4
#define CHECK_GTE           5
#define CHECK_AND           6
#define CHECK_XOR           7
#define CHECK_ALL           8
#define CHECK_ATLEASTONE    9
#define CHECK_NONE          10

#define BT_LESS_THAN            CHECK_LT
#define BT_EQUALS               CHECK_EQ
#define BT_GREATER_THAN         CHECK_GT
#define BT_AND                  CHECK_AND
#define BT_XOR                  CHECK_XOR
#define BT_GREATER_THAN_EQUAL   CHECK_GTE
#define BT_LESS_THAN_EQUAL      CHECK_LTE
#define BT_CHECK_ALL            CHECK_ALL
#define BT_CHECK_ATLEASTONE     CHECK_ATLEASTONE
#define BT_CHECK_NONE           CHECK_NONE

#define BIG    0
#define LITTLE 1

typedef struct _ByteTestData
{
    uint32_t bytes_to_compare;
    uint32_t cmp_value;
    uint32_t opcode;
    int32_t offset;
    uint8_t not_flag;
    uint8_t relative_flag;
    uint8_t data_string_convert_flag;
    int8_t endianess;
    uint32_t base;
    int8_t cmp_value_var;
    int8_t offset_var;
} ByteTestData;

class ByteTestOption : public IpsOption
{
public:
    ByteTestOption(const ByteTestData& c) :
        IpsOption(s_name, RULE_OPTION_TYPE_BYTE_TEST)
    { config = c; };

    ~ByteTestOption() { };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    bool is_relative()
    { return ( config.relative_flag == 1 ); };

    int eval(Packet*);

private:
    ByteTestData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t ByteTestOption::hash() const
{
    uint32_t a,b,c;
    const ByteTestData *data = (ByteTestData *)&config;

    a = data->bytes_to_compare;
    b = data->cmp_value;
    c = data->opcode;

    mix(a,b,c);

    a += data->offset;
    b += (data->not_flag << 24 |
          data->relative_flag << 16 |
          data->data_string_convert_flag << 8 |
          data->endianess);
    c += data->base;

    mix(a,b,c);

    a += data->cmp_value_var;
    b += data->offset_var;

    mix(a,b,c);
    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool ByteTestOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(s_name, ips.get_name()) )
        return false;

    ByteTestOption& rhs = (ByteTestOption&)ips;
    const ByteTestData *left = &config;
    const ByteTestData *right = &rhs.config;

    if (( left->bytes_to_compare == right->bytes_to_compare) &&
        ( left->cmp_value == right->cmp_value) &&
        ( left->opcode == right->opcode) &&
        ( left->offset == right->offset) &&
        ( left->not_flag == right->not_flag) &&
        ( left->relative_flag == right->relative_flag) &&
        ( left->data_string_convert_flag == right->data_string_convert_flag) &&
        ( left->endianess == right->endianess) &&
        ( left->base == right->base) &&
        ( left->cmp_value_var == right->cmp_value_var) &&
        ( left->offset_var == right->offset_var))
    {
        return true;
    }

    return false;
}

int ByteTestOption::eval(Packet *p)
{
    ByteTestData *btd = (ByteTestData *)&config;
    int rval = DETECTION_OPTION_NO_MATCH;
    uint32_t value = 0;
    int success = 0;
    int dsize;
    const char *base_ptr, *end_ptr, *start_ptr;
    int payload_bytes_grabbed;
    uint32_t extract_offset, extract_cmp_value;
    PROFILE_VARS;

    PREPROC_PROFILE_START(byteTestPerfStats);

    if (Is_DetectFlag(FLAG_ALT_DETECT))
    {
        dsize = DetectBuffer.len;
        start_ptr = (char *)DetectBuffer.data;
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                "Using Alternative Detect buffer!\n"););
    }
    else if(Is_DetectFlag(FLAG_ALT_DECODE))
    {
        dsize = DecodeBuffer.len;
        start_ptr = (char *)DecodeBuffer.data;
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                    "Using Alternative Decode buffer!\n"););
    }
    else
    {
        if(IsLimitedDetect(p))
            dsize = p->alt_dsize;
        else
            dsize = p->dsize;
        start_ptr = (char *) p->data;
    }

    base_ptr = start_ptr;
    end_ptr = start_ptr + dsize;

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                "[*] byte test firing...\npayload starts at %p\n", start_ptr););


    /* Get values from byte_extract variables, if present. */
    if (btd->cmp_value_var >= 0 && btd->cmp_value_var < NUM_BYTE_EXTRACT_VARS)
    {
        GetByteExtractValue(&extract_cmp_value, btd->cmp_value_var);
        btd->cmp_value = (int32_t) extract_cmp_value;
    }
    if (btd->offset_var >= 0 && btd->offset_var < NUM_BYTE_EXTRACT_VARS)
    {
        GetByteExtractValue(&extract_offset, btd->offset_var);
        btd->offset = (int32_t) extract_offset;
    }


    if(btd->relative_flag && doe_ptr)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "Checking relative offset!\n"););

        /* @todo: possibly degrade to use the other buffer, seems non-intuitive
         *  Because doe_ptr can be "end" in the last match,
         *  use end + 1 for upper bound
         *  Bound checked also after offset is applied
         *  (see byte_extract() and string_extract())
         */
        if(!inBounds((const uint8_t *)start_ptr, (const uint8_t *)end_ptr + 1, doe_ptr))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                    "[*] byte test bounds check failed..\n"););
            PREPROC_PROFILE_END(byteTestPerfStats);
            return rval;
        }

        base_ptr = (const char *)doe_ptr + btd->offset;
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                "checking absolute offset %d\n", btd->offset););
        base_ptr = start_ptr + btd->offset;
    }

    /* both of these functions below perform their own bounds checking within
     * byte_extract.c
     */

    if(!btd->data_string_convert_flag)
    {
        if(byte_extract(btd->endianess, btd->bytes_to_compare,
                        (const uint8_t *)base_ptr, (const uint8_t *)start_ptr, (const uint8_t *)end_ptr, &value))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                    "Byte Extraction Failed\n"););

            PREPROC_PROFILE_END(byteTestPerfStats);
            return rval;
        }
        payload_bytes_grabbed = (int)btd->bytes_to_compare;
    }
    else
    {
        payload_bytes_grabbed = string_extract(
                btd->bytes_to_compare, btd->base,
                (const uint8_t *)base_ptr, (const uint8_t *)start_ptr,
                (const uint8_t *)end_ptr, &value);

        if ( payload_bytes_grabbed < 0 )
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                                    "String Extraction Failed\n"););

            PREPROC_PROFILE_END(byteTestPerfStats);
            return rval;
        }

    }

    DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
        "Grabbed %d bytes at offset %d, value = 0x%08X(%u)\n",
        payload_bytes_grabbed, btd->offset, value, value); );

    switch(btd->opcode)
    {
        case BT_LESS_THAN: if(value < btd->cmp_value)
                               success = 1;
                           break;

        case BT_EQUALS: if(value == btd->cmp_value)
                            success = 1;
                        break;

        case BT_GREATER_THAN: if(value > btd->cmp_value)
                                  success = 1;
                              break;

        case BT_AND: if ((value & btd->cmp_value) > 0)
                         success = 1;
                     break;

        case BT_XOR: if ((value ^ btd->cmp_value) > 0)
                        success = 1;
                    break;

        case BT_GREATER_THAN_EQUAL: if (value >= btd->cmp_value)
                                        success = 1;
                                    break;

        case BT_LESS_THAN_EQUAL: if (value <= btd->cmp_value)
                                        success = 1;
                                 break;

        case BT_CHECK_ALL: if ((value & btd->cmp_value) == btd->cmp_value)
                               success = 1;
                           break;

        case BT_CHECK_ATLEASTONE: if ((value & btd->cmp_value) != 0)
                                      success = 1;
                                  break;

        case BT_CHECK_NONE: if ((value & btd->cmp_value) == 0)
                                success = 1;
                            break;
    }

    if (btd->not_flag)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                    "checking for not success...flag\n"););
        if (!success)
        {
            rval = DETECTION_OPTION_MATCH;
        }
    }
    else if (success)
    {
        rval = DETECTION_OPTION_MATCH;
    }

    /* if the test isn't successful, this function *must* return 0 */
    PREPROC_PROFILE_END(byteTestPerfStats);
    return rval;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static void byte_test_parse(char *data, ByteTestData *idx)
{
    char **toks;
    char *endp;
    int num_toks;
    char *cptr;
    int i =0;

    toks = mSplit(data, ",", 12, &num_toks, 0);

    if(num_toks < 4)
        ParseError("Bad arguments to byte_test: %s", data);

    /* set how many bytes to process from the packet */
    idx->bytes_to_compare = strtol(toks[0], &endp, 10);

    if(toks[0] == endp)
    {
        ParseError("Unable to parse as byte value %s", toks[0]);
    }

    if(*endp != '\0')
    {
        ParseError("byte_test option has bad value: %s.", toks[0]);
    }

    if(idx->bytes_to_compare > PARSELEN || idx->bytes_to_compare == 0)
    {
        ParseError("byte_test can't process more than 10 bytes");
    }

    cptr = toks[1];

    while(isspace((int)*cptr)) {cptr++;}

    if(*cptr == '!')
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PATTERN_MATCH,
                    "enabling not flag\n"););
       idx->not_flag = 1;
       cptr++;
    }

    if (idx->not_flag && strlen(cptr) == 0)
    {
        idx->opcode = BT_EQUALS;
    }
    else
    {
        /* set the opcode */
        switch(*cptr)
        {
            case '<': idx->opcode = BT_LESS_THAN;
                      cptr++;
                      if (*cptr == '=')
                          idx->opcode = BT_LESS_THAN_EQUAL;
                      else
                          cptr--;
                      break;

            case '=': idx->opcode = BT_EQUALS;
                      break;

            case '>': idx->opcode = BT_GREATER_THAN;
                      cptr++;
                      if (*cptr == '=')
                          idx->opcode = BT_GREATER_THAN_EQUAL;
                      else
                          cptr--;
                      break;

            case '&': idx->opcode = BT_AND;
                      break;

            case '^': idx->opcode = BT_XOR;
                      break;

            default: ParseError(
                "byte_test unknown opcode ('%c, %s')", *cptr, toks[1]);
        }
    }


    /* set the value to test against */
    if (isdigit(toks[2][0]) || toks[2][0] == '-')
    {
        idx->cmp_value = SnortStrtoul(toks[2], &endp, 0);
        idx->cmp_value_var = -1;

        if(toks[2] == endp)
        {
            ParseError("Unable to parse as comparison value %s", toks[2]);
        }

        if(*endp != '\0')
        {
            ParseError("byte_test option has bad comparison value: %s.", toks[2]);
        }

        if(errno == ERANGE)
        {
            printf("Bad range: %s\n", toks[2]);
        }
    }
    else
    {
        idx->cmp_value_var = GetVarByName(toks[2]);
        if (idx->cmp_value_var == BYTE_EXTRACT_NO_VAR)
        {
            ParseError("%s", BYTE_EXTRACT_INVALID_ERR_STR);
        }
    }

    if (isdigit(toks[3][0]) || toks[3][0] == '-')
    {
        /* set offset */
        idx->offset = strtol(toks[3], &endp, 10);
        idx->offset_var = -1;

        if(toks[3] == endp)
        {
            ParseError("Unable to parse as offset value %s", toks[3]);
        }

        if(*endp != '\0')
        {
            ParseError("byte_test option has bad offset: %s.", toks[3]);
        }
    }
    else
    {
        idx->offset_var = GetVarByName(toks[3]);
        if (idx->offset_var == BYTE_EXTRACT_NO_VAR)
        {
            ParseError("%s", BYTE_EXTRACT_INVALID_ERR_STR);
        }
    }


    i = 4;

    /* is it a relative offset? */
    if(num_toks > 4)
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
            else if(!strcasecmp(cptr, "string"))
            {
                /* the data will be represented as a string that needs
                 * to be converted to an int, binary is assumed otherwise
                 */
                idx->data_string_convert_flag = 1;
            }
            else if(!strcasecmp(cptr, "little"))
            {
                idx->endianess = LITTLE;
            }
            else if(!strcasecmp(cptr, "big"))
            {
                /* this is the default */
                idx->endianess = BIG;
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
            // FIXIT allow pluggable byte order func here (eg dce2)
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
            "with the 'string' modifier");
    }

    mSplitFree(&toks, num_toks);
}

static IpsOption* byte_test_ctor(
    SnortConfig*, char *data, OptTreeNode*)
{
    ByteTestData idx;
    memset(&idx, 0, sizeof(idx));
    byte_test_parse(data, &idx);
    return new ByteTestOption(idx);
}

static void byte_test_dtor(IpsOption* p)
{
    delete p;
}

static void byte_test_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterOtnProfile(s_name, &byteTestPerfStats, bt_get_profile);
#endif
}

static const IpsApi byte_test_api =
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
    byte_test_ginit,
    nullptr,
    nullptr,
    nullptr,
    byte_test_ctor,
    byte_test_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &byte_test_api.base,
    nullptr
};
#else
const BaseApi* ips_byte_test = &byte_test_api.base;
#endif


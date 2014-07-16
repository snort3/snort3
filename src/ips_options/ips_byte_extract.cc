/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 ** Copyright (C) 2010-2013 Sourcefire, Inc.
 ** Author: Ryan Jordan <ryan.jordan@sourcefire.com>
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

#include "ips_byte_extract.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snort_types.h"
#include "snort.h"
#include "parser.h"
#include "detection/detection_defines.h"
#include "detection_util.h"
#include "sfhashfcn.h"
#include "profiler.h"
#include "extract.h"
#include "fpdetect.h"
#include "framework/ips_option.h"
#include "framework/cursor.h"

#ifdef PERF_PROFILING
static THREAD_LOCAL ProfileStats byteExtractPerfStats;

static const char* s_name = "byte_extract";

static ProfileStats* be_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &byteExtractPerfStats;

    return nullptr;
}
#endif

#define MAX_BYTES_TO_GRAB 4

#define MIN_BYTE_EXTRACT_OFFSET -65535
#define MAX_BYTE_EXTRACT_OFFSET 65535
#define MIN_BYTE_EXTRACT_MULTIPLIER 1
#define MAX_BYTE_EXTRACT_MULTIPLIER 65535

typedef struct _ByteExtractData
{
    uint32_t bytes_to_grab;
    int32_t offset;
    uint8_t relative_flag;
    uint8_t data_string_convert_flag;
    uint8_t align;
    int8_t endianess;
    uint32_t base;
    uint32_t multiplier;
    int8_t var_number;
    char *name;
} ByteExtractData;

/* Storage for extracted variables */
static THREAD_LOCAL uint32_t extracted_values[NUM_BYTE_EXTRACT_VARS];
static THREAD_LOCAL char *variable_names[NUM_BYTE_EXTRACT_VARS];

class ByteExtractOption : public IpsOption
{
public:
    ByteExtractOption(const ByteExtractData& c) : IpsOption(s_name)
    { config = c; };

    ~ByteExtractOption()
    { free(config.name); };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    CursorActionType get_cursor_type() const
    { return CAT_ADJUST; };

    bool is_relative()
    { return (config.relative_flag == 1); };

    int eval(Cursor&, Packet*);

private:
    ByteExtractData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t ByteExtractOption::hash() const
{
    uint32_t a,b,c;
    const ByteExtractData *data = (ByteExtractData *)&config;

    a = data->bytes_to_grab;
    b = data->offset;
    c = data->base;

    mix(a,b,c);

    a += (data->relative_flag << 24 |
          data->data_string_convert_flag << 16 |
          data->align << 8 |
          data->endianess);
    b += data->multiplier;
    c += data->var_number;

    mix(a,b,c);
    mix_str(a,b,c,get_name());

    final(a,b,c);

    return c;
}

bool ByteExtractOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(s_name, ips.get_name()) )
        return false;

    ByteExtractOption& rhs = (ByteExtractOption&)ips;
    ByteExtractData *left = (ByteExtractData *)&config;
    ByteExtractData *right = (ByteExtractData *)&rhs.config;

    if ((left->bytes_to_grab == right->bytes_to_grab) &&
        (left->offset == right->offset) &&
        (left->relative_flag == right->relative_flag) &&
        (left->data_string_convert_flag == right->data_string_convert_flag) &&
        (left->align == right->align) &&
        (left->endianess == right->endianess) &&
        (left->base == right->base) &&
        (left->multiplier == right->multiplier) &&
        (left->var_number == right->var_number))
    {
        return true;
    }

    return false;
}

int ByteExtractOption::eval(Cursor& c, Packet *p)
{
    ByteExtractData *data = &config;
    int ret, bytes_read;
    uint32_t *value;

    PROFILE_VARS;
    PREPROC_PROFILE_START(byteExtractPerfStats);

    if (data == NULL || p == NULL)
    {
        PREPROC_PROFILE_END(byteExtractPerfStats);
        return DETECTION_OPTION_NO_MATCH;
    }

    const uint8_t* start = c.buffer();
    int dsize = c.size();

    const uint8_t* ptr = data->relative_flag ? c.start() : c.buffer();
    ptr += data->offset;

    const uint8_t* end = start + dsize;
    value = &(extracted_values[data->var_number]);

    /* check bounds */
    if (ptr < start || ptr >= end)
    {
        PREPROC_PROFILE_END(byteExtractPerfStats);
        return DETECTION_OPTION_NO_MATCH;
    }

    /* do the extraction */
    if (data->data_string_convert_flag == 0)
    {
        ret = byte_extract(data->endianess, data->bytes_to_grab, ptr, start, end, value);
        if (ret < 0)
        {
            PREPROC_PROFILE_END(byteExtractPerfStats);
            return DETECTION_OPTION_NO_MATCH;
        }
        bytes_read = data->bytes_to_grab;
    }
    else
    {
        ret = string_extract(data->bytes_to_grab, data->base, ptr, start, end, value);
        if (ret < 0)
        {
            PREPROC_PROFILE_END(byteExtractPerfStats);
            return DETECTION_OPTION_NO_MATCH;
        }
        bytes_read = ret;
    }

    /* mulitply */
    *value *= data->multiplier;

    /* align to next 32-bit or 16-bit boundary */
    if ((data->align == 4) && (*value % 4))
    {
        *value = *value + 4 - (*value % 4);
    }
    else if ((data->align == 2) && (*value % 2))
    {
        *value = *value + 2 - (*value % 2);
    }

    /* advance cursor */
    c.add_pos(bytes_read);

    /* this rule option always "matches" if the read is performed correctly */
    PREPROC_PROFILE_END(byteExtractPerfStats);
    return DETECTION_OPTION_MATCH;
}

static void init_var_names()
{
    for (int i = 0; i < NUM_BYTE_EXTRACT_VARS; i++)
    {
        variable_names[i] = NULL;
    }
}

static void clear_var_names()
{
    for (int i = 0; i < NUM_BYTE_EXTRACT_VARS; i++)
    {
        free(variable_names[i]);
        variable_names[i] = NULL;
    }
}

//-------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

/* Given a variable name, retrieve its index. For use by other options. */
int8_t GetVarByName(char *name)
{
    int i;

    if (name == NULL)
        return BYTE_EXTRACT_NO_VAR;

    for (i = 0; i < NUM_BYTE_EXTRACT_VARS; i++)
    {
        if (variable_names[i] != NULL && strcmp(variable_names[i], name) == 0)
            return i;
    }

    return BYTE_EXTRACT_NO_VAR;
}

/* If given an OptFpList with no byte_extracts, clear the variable_names array */
void ClearVarNames(OptFpList *fpl)
{
    while (fpl != NULL)
    {
        IpsOption* opt = (IpsOption*)fpl->context;

        if ( !strcmp(opt->get_name(), s_name) )
            return;

        fpl = fpl->next;
    }
    clear_var_names();
}

/* Add a variable's name to the variable_names array
   Returns: variable index
*/
int8_t AddVarNameToList(ByteExtractData *data)
{
    int i;

    for (i = 0; i < NUM_BYTE_EXTRACT_VARS; i++)
    {
        if (variable_names[i] == NULL)
        {
            variable_names[i] = SnortStrdup(data->name);
            break;
        }

        else if ( strcmp(variable_names[i], data->name) == 0 )
        {
            break;
        }
    }

    return i;
}

/* Setters & Getters for extracted values */
int GetByteExtractValue(uint32_t *dst, int8_t var_number)
{
    if (dst == NULL || var_number >= NUM_BYTE_EXTRACT_VARS)
        return BYTE_EXTRACT_NO_VAR;

    *dst = extracted_values[var_number];

    return 0;
}

int SetByteExtractValue(uint32_t value, int8_t var_number)
{
    if (var_number >= NUM_BYTE_EXTRACT_VARS)
        return BYTE_EXTRACT_NO_VAR;

    extracted_values[var_number] = value;

    return 0;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

/* Checks a ByteExtractData instance for errors. */
static bool ByteExtractVerify(ByteExtractData *data)
{
    if (data->bytes_to_grab > MAX_BYTES_TO_GRAB && data->data_string_convert_flag == 0)
    {
        ParseError("byte_extract rule option cannot extract more than %d bytes.",
                     MAX_BYTES_TO_GRAB);
    }

    if (data->bytes_to_grab > PARSELEN && data->data_string_convert_flag == 1)
    {
        ParseError("byte_extract rule cannot process more than %d bytes for "
                   "string extraction.",  PARSELEN);
    }

    if (data->offset < MIN_BYTE_EXTRACT_OFFSET || data->offset > MAX_BYTE_EXTRACT_OFFSET)
    {
        ParseError("byte_extract rule option has invalid offset. "
                   "Valid offsets are between %d and %d.",
                     MIN_BYTE_EXTRACT_OFFSET, MAX_BYTE_EXTRACT_OFFSET);
    }

    if (data->multiplier < MIN_BYTE_EXTRACT_MULTIPLIER || data->multiplier > MAX_BYTE_EXTRACT_MULTIPLIER)
    {
        ParseError("byte_extract rule option has invalid multiplier. "
                   "Valid multipliers are between %d and %d.",
                    MIN_BYTE_EXTRACT_MULTIPLIER, MAX_BYTE_EXTRACT_MULTIPLIER);
    }

    if (data->bytes_to_grab == 0)
        ParseError("byte_extract rule option extracts zero bytes. "
                   "'bytes_to_extract' must be 1 or greater.");

    if (data->align != 0 && data->align != 2 && data->align != 4)
        ParseError("byte_extract rule option has an invalid argument "
                   "to 'align'. Valid arguments are '2' and '4'.");

    if (data->offset < 0 && data->relative_flag == 0)
        ParseError("byte_extract rule option has a negative offset, but does "
                   "not use the 'relative' option.");

    if (data->name && isdigit(data->name[0]))
    {
        ParseError("byte_extract rule option has a name which starts with a digit. "
                   "Variable names must start with a letter.");
    }

    if (data->base && !data->data_string_convert_flag)
    {
        ParseError("byte_extract rule option has a string conversion type "
                   "(dec, hex, or oct) without the \"string\" "
                   "argument.");
    }

    return true;
}

static int byte_extract_parse(ByteExtractData *data, char *args)
{
    char *args_copy = SnortStrdup(args);
    char *endptr, *saveptr = args_copy;
    char *token = strtok_r(args_copy, ",", &saveptr);

    /* set defaults / sentinels */
    data->multiplier = 1;
    data->endianess = ENDIAN_NONE;

    /* first: bytes_to_extract */
    if (token)
    {
        data->bytes_to_grab = SnortStrtoul(token, &endptr, 10);
        if (*endptr != '\0')
            ParseError("byte_extract rule option has non-digits in the "
                    "'bytes_to_extract' field.");
        token = strtok_r(NULL, ",", &saveptr);
    }

    /* second: offset */
    if (token)
    {
        data->offset = SnortStrtoul(token, &endptr, 10);
        if (*endptr != '\0')
            ParseError("byte_extract rule option has non-digits in the "
                    "'offset' field.");
        token = strtok_r(NULL, ",", &saveptr);
    }

    /* third: variable name */
    if (token)
    {
        data->name = SnortStrdup(token);
        token = strtok_r(NULL, ",", &saveptr);
    }

    /* optional arguments */
    while (token)
    {
        if (strcmp(token, "relative") == 0)
        {
            data->relative_flag = 1;
        }

        else if (strncmp(token, "align ", 6) == 0)
        {
            char *value = (token+6);

            if (data->align == 0)
                data->align = (uint8_t)SnortStrtoul(value, &endptr, 10);
            else
                ParseError("byte_extract rule option includes the "
                        "'align' argument twice.");

            if (*endptr != '\0')
                ParseError("byte_extract rule option has non-digits in the "
                        "argument to 'align'. ");
        }

        else if (strcmp(token, "little") == 0)
        {
            if (data->endianess == ENDIAN_NONE)
                data->endianess = ENDIAN_LITTLE;
            else
                ParseError("byte_extract rule option specifies the "
                        "byte order twice. Use only one of 'big', 'little', "
                        "or 'dce'.");
        }

        else if (strcmp(token, "big") == 0)
        {
            if (data->endianess == ENDIAN_NONE)
                data->endianess = ENDIAN_BIG;
            else
                ParseError("byte_extract rule option specifies the "
                        "byte order twice. Use only one of 'big', 'little', "
                        "or 'dce'.");
        }

        else if (strncmp(token, "multiplier ", 11) == 0)
        {
            char *value = (token+11);
            if (value[0] == '\0')
                ParseError("byte_extract rule option has a 'multiplier' "
                        "argument with no value specified.");

            if (data->multiplier == 1)
            {
                data->multiplier = SnortStrtoul(value, &endptr, 10);

                if (*endptr != '\0')
                    ParseError("byte_extract rule option has non-digits in the "
                            "argument to 'multiplier'. ");
            }
            else
                ParseError("byte_extract rule option has multiple "
                        "'multiplier' arguments. Use only one.");
        }

        else if (strcmp(token, "string") == 0)
        {
            if (data->data_string_convert_flag == 0)
                data->data_string_convert_flag = 1;
            else
                ParseError("byte_extract rule option has multiple "
                        "'string' arguments. Use only one.");
        }

        else if (strcmp(token, "dec") == 0)
        {
            if (data->base == 0)
                data->base = 10;
            else
                ParseError("byte_extract rule option has multiple arguments "
                        "specifying the type of string conversion. Use only "
                        "one of 'dec', 'hex', or 'oct'.");
        }

        else if (strcmp(token, "hex") == 0)
        {
            if (data->base == 0)
                data->base = 16;
            else
                ParseError("byte_extract rule option has multiple arguments "
                        "specifying the type of string conversion. Use only "
                        "one of 'dec', 'hex', or 'oct'.");
        }

        else if (strcmp(token, "oct") == 0)
        {
            if (data->base == 0)
                data->base = 8;
            else
                ParseError("byte_extract rule option has multiple arguments "
                        "specifying the type of string conversion. Use only "
                        "one of 'dec', 'hex', or 'oct'.");
        }
        else
        {
            ParseError("byte_extract rule option has invalid argument '%s'.", token);
        }

        token = strtok_r(NULL, ",", &saveptr);
    }

    free(args_copy);

    /* Need to check this error before the sentinel gets replaced */
    if (data->endianess != ENDIAN_NONE && data->data_string_convert_flag == 1)
    {
        ParseError("byte_extract rule option can't have 'string' specified "
            "at the same time as a byte order ('big' or 'little').");
    }

    /* Replace sentinels with defaults */
    if (data->endianess == ENDIAN_NONE)
        data->endianess = ENDIAN_BIG;

    if (data->data_string_convert_flag && (data->base == 0))
        data->base = 10;

    /* At this point you could verify the data and return something. */
    return ByteExtractVerify(data);
}

static IpsOption* byte_extract_ctor(
    SnortConfig*, char *data, OptTreeNode* otn)
{
    ByteExtractData idx;
    memset(&idx, 0, sizeof(idx));

    ClearVarNames(otn->opt_func);

    byte_extract_parse(&idx, data);
    idx.var_number = AddVarNameToList(&idx);

    // FIXIT can this be handled by setting max_per_rule = 2?
    if (idx.var_number >= NUM_BYTE_EXTRACT_VARS)
    {
        ParseError("Rule has more than %d byte_extract variables.",
            NUM_BYTE_EXTRACT_VARS);
    }
    return new ByteExtractOption(idx);
}

static void byte_extract_dtor(IpsOption* p)
{
    delete p;
}

static void byte_extract_tinit(SnortConfig*)
{
    init_var_names();
}

static void byte_extract_tterm(SnortConfig*)
{
    clear_var_names();
}

void byte_extract_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterOtnProfile(s_name, be_get_profile);
#endif
}

static const IpsApi byte_extract_api =
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
    byte_extract_ginit,
    nullptr,
    byte_extract_tinit,
    byte_extract_tterm,
    byte_extract_ctor,
    byte_extract_dtor,
    nullptr
};

const BaseApi* ips_byte_extract = &byte_extract_api.base;


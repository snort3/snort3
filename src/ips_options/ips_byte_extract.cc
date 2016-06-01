//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2010-2013 Sourcefire, Inc.
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
// Author: Ryan Jordan <ryan.jordan@sourcefire.com>

#include "ips_byte_extract.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "extract.h"
#include "main/snort_types.h"
#include "parser/parser.h"
#include "detection/detection_defines.h"
#include "detection/detection_util.h"
#include "hash/sfhashfcn.h"
#include "profiler/profiler.h"
#include "framework/ips_option.h"
#include "framework/cursor.h"
#include "framework/parameter.h"
#include "framework/module.h"

static THREAD_LOCAL ProfileStats byteExtractPerfStats;

#define s_name "byte_extract"

#define s_help \
    "rule option to convert data to an integer variable"

#define MAX_BYTES_TO_GRAB 4

struct ByteExtractData
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
    char* name;
};

/* Storage for extracted variables */
static char* variable_names[NUM_BYTE_EXTRACT_VARS];
static THREAD_LOCAL uint32_t extracted_values[NUM_BYTE_EXTRACT_VARS];

class ByteExtractOption : public IpsOption
{
public:
    ByteExtractOption(const ByteExtractData& c) : IpsOption(s_name, RULE_OPTION_TYPE_BUFFER_USE)
    { config = c; }

    ~ByteExtractOption()
    { snort_free(config.name); }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    CursorActionType get_cursor_type() const override
    { return CAT_ADJUST; }

    bool is_relative() override
    { return (config.relative_flag == 1); }

    int eval(Cursor&, Packet*) override;

private:
    ByteExtractData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t ByteExtractOption::hash() const
{
    uint32_t a,b,c;
    const ByteExtractData* data = (ByteExtractData*)&config;

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

    finalize(a,b,c);

    return c;
}

bool ByteExtractOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    ByteExtractOption& rhs = (ByteExtractOption&)ips;
    ByteExtractData* left = (ByteExtractData*)&config;
    ByteExtractData* right = (ByteExtractData*)&rhs.config;

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

int ByteExtractOption::eval(Cursor& c, Packet* p)
{
    Profile profile(byteExtractPerfStats);

    ByteExtractData* data = &config;

    if (data == NULL || p == NULL)
        return DETECTION_OPTION_NO_MATCH;

    const uint8_t* start = c.buffer();
    int dsize = c.size();

    const uint8_t* ptr = data->relative_flag ? c.start() : c.buffer();
    ptr += data->offset;

    const uint8_t* end = start + dsize;
    uint32_t* value = &(extracted_values[data->var_number]);

    // check bounds
    if (ptr < start || ptr >= end)
        return DETECTION_OPTION_NO_MATCH;

    int8_t endian = data->endianess;
    if (data->endianess == ENDIAN_FUNC)
    {
        if (!p->endianness ||
            !p->endianness->get_offset_endianness(ptr - p->data, endian))
            return DETECTION_OPTION_NO_MATCH;
    }

    // do the extraction
    int ret = 0;
    int bytes_read = 0;

    if (data->data_string_convert_flag == 0)
    {
        ret = byte_extract(endian, data->bytes_to_grab, ptr, start, end, value);
        if (ret < 0)
            return DETECTION_OPTION_NO_MATCH;

        bytes_read = data->bytes_to_grab;
    }
    else
    {
        ret = string_extract(data->bytes_to_grab, data->base, ptr, start, end, value);
        if (ret < 0)
            return DETECTION_OPTION_NO_MATCH;

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
        snort_free(variable_names[i]);
        variable_names[i] = NULL;
    }
}

//-------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

/* Given a variable name, retrieve its index. For use by other options. */
int8_t GetVarByName(const char* name)
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
static void ClearVarNames(OptFpList* fpl)
{
    while ( fpl )
    {
        if ( !strcmp(fpl->ips_opt->get_name(), s_name) )
            return;

        fpl = fpl->next;
    }
    clear_var_names();
}

/* Add a variable's name to the variable_names array
   Returns: variable index
*/
static int8_t AddVarNameToList(ByteExtractData* data)
{
    int i;

    for (i = 0; i < NUM_BYTE_EXTRACT_VARS; i++)
    {
        if (variable_names[i] == NULL)
        {
            variable_names[i] = snort_strdup(data->name);
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
int GetByteExtractValue(uint32_t* dst, int8_t var_number)
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
static bool ByteExtractVerify(ByteExtractData* data)
{
    if (data->bytes_to_grab > MAX_BYTES_TO_GRAB && data->data_string_convert_flag == 0)
    {
        ParseError("byte_extract rule option cannot extract more than %d bytes.",
            MAX_BYTES_TO_GRAB);
        return false;
    }

    if (data->bytes_to_grab > PARSELEN && data->data_string_convert_flag == 1)
    {
        ParseError("byte_extract rule cannot process more than %d bytes for "
            "string extraction.",  PARSELEN);
        return false;
    }

    if (data->align != 0 && data->align != 2 && data->align != 4)
    {
        ParseError("byte_extract rule option has an invalid argument "
            "to 'align'. Valid arguments are '2' and '4'.");
        return false;
    }

    if (data->offset < 0 && data->relative_flag == 0)
    {
        ParseError("byte_extract rule option has a negative offset, but does "
            "not use the 'relative' option.");
        return false;
    }

    if (data->name && isdigit(data->name[0]))
    {
        ParseError("byte_extract rule option has a name which starts with a digit. "
            "Variable names must start with a letter.");
        return false;
    }

    if (data->base && !data->data_string_convert_flag)
    {
        ParseError("byte_extract rule option has a string conversion type "
            "(dec, hex, or oct) without the \"string\" "
            "argument.");
        return false;
    }
    unsigned e1 = ffs(data->endianess);
    unsigned e2 = ffs(data->endianess >> e1);

    if ( e1 && e2 )
    {
        ParseError("byte_extract rule option has multiple arguments "
            "specifying endianness. Use only "
            "one of 'big', 'little', or 'dce'.");
        return false;
    }
    return true;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~count", Parameter::PT_INT, "1:10", nullptr,
      "number of bytes to pick up from the buffer" },

    { "~offset", Parameter::PT_INT, "-65535:65535", nullptr,
      "number of bytes into the buffer to start processing" },

    { "~name", Parameter::PT_STRING, nullptr, nullptr,
      "name of the variable that will be used in other rule options" },

    { "relative", Parameter::PT_IMPLIED, nullptr, nullptr,
      "offset from cursor instead of start of buffer" },

    { "multiplier", Parameter::PT_INT, "1:65535", "1",
      "scale extracted value by given amount" },

    { "align", Parameter::PT_INT, "0:4", "0",
      "round the number of converted bytes up to the next 2- or 4-byte boundary" },

    { "big", Parameter::PT_IMPLIED, nullptr, nullptr,
      "big endian" },

    { "little", Parameter::PT_IMPLIED, nullptr, nullptr,
      "little endian" },

    { "dce", Parameter::PT_IMPLIED, nullptr, nullptr,
      "dcerpc2 determines endianness" },

    { "string", Parameter::PT_IMPLIED, nullptr, nullptr,
      "convert from string" },

    { "hex", Parameter::PT_IMPLIED, nullptr, nullptr,
      "convert from hex string" },

    { "oct", Parameter::PT_IMPLIED, nullptr, nullptr,
      "convert from octal string" },

    { "dec", Parameter::PT_IMPLIED, nullptr, nullptr,
      "convert from decimal string" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class ExtractModule : public Module
{
public:
    ExtractModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &byteExtractPerfStats; }

    ByteExtractData data;
};

bool ExtractModule::begin(const char*, int, SnortConfig*)
{
    memset(&data, 0, sizeof(data));
    data.multiplier = 1;
    return true;
}

bool ExtractModule::end(const char*, int, SnortConfig*)
{
    return ByteExtractVerify(&data);
}

bool ExtractModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("~count") )
        data.bytes_to_grab = v.get_long();

    else if ( v.is("~offset") )
        data.offset = v.get_long();

    else if ( v.is("~name") )
        data.name = snort_strdup(v.get_string());

    else if ( v.is("relative") )
        data.relative_flag = 1;

    else if ( v.is("align") )
        data.align = v.get_long();

    else if ( v.is("multiplier") )
        data.multiplier = v.get_long();

    else if ( v.is("big") )
        data.endianess |= ENDIAN_BIG;

    else if ( v.is("little") )
        data.endianess |= ENDIAN_LITTLE;

    else if ( v.is("dce") )
        data.endianess |= ENDIAN_FUNC;

    else if ( v.is("string") )
    {
        data.data_string_convert_flag = 1;
        data.base = 10;
    }
    else if ( v.is("dec") )
        data.base = 10;

    else if ( v.is("hex") )
        data.base = 16;

    else if ( v.is("oct") )
        data.base = 8;

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new ExtractModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* byte_extract_ctor(Module* p, OptTreeNode* otn)
{
    ExtractModule* m = (ExtractModule*)p;
    ByteExtractData& data = m->data;

    ClearVarNames(otn->opt_func);
    data.var_number = AddVarNameToList(&data);

    if (data.var_number >= NUM_BYTE_EXTRACT_VARS)
    {
        ParseError("Rule has more than %d byte_extract variables.",
            NUM_BYTE_EXTRACT_VARS);
        return nullptr;
    }
    return new ByteExtractOption(data);
}

static void byte_extract_dtor(IpsOption* p)
{
    delete p;
}

static void byte_extract_init(SnortConfig*)
{
    init_var_names();
}

static void byte_extract_term(SnortConfig*)
{
    clear_var_names();
}

static const IpsApi byte_extract_api =
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
    NUM_BYTE_EXTRACT_VARS, 0,
    byte_extract_init,
    byte_extract_term,
    nullptr,  // tinit
    nullptr,  // tterm
    byte_extract_ctor,
    byte_extract_dtor,
    nullptr
};

const BaseApi* ips_byte_extract = &byte_extract_api.base;


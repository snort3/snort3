//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

#include <array>
#include <cassert>

#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hashes.h"
#include "hash/hashfcn.h"
#include "log/messages.h"
#include "parser/parse_utils.h"
#include "profiler/profiler.h"

#include "extract.h"

using namespace snort;

enum HashPsIdx
{
    HPI_MD5, HPI_SHA256, HPI_SHA512, HPI_MAX
};

static THREAD_LOCAL std::array<ProfileStats, HPI_MAX> hash_ps;

struct HashMatchData
{
    std::string hash;
    unsigned length;
    unsigned offset;
    int offset_var;
    bool relative;
    bool negated;

    HashMatchData();
};

HashMatchData::HashMatchData()
{
    length = offset = 0;
    offset_var = IPS_OPTIONS_NO_VAR;
    relative = negated = false;
}

typedef void (* HashFunc)(const unsigned char* data, size_t size, unsigned char* digest);

class HashOption : public IpsOption
{
public:
    HashOption(const char* s, HashPsIdx hpi, HashMatchData* c, HashFunc f, unsigned n) :
        IpsOption(s, RULE_OPTION_TYPE_BUFFER_USE)
    { config = c; hashf = f; size = n; idx = hpi; assert(n <= MAX_HASH_SIZE); }

    ~HashOption() override { delete config; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    CursorActionType get_cursor_type() const override
    { return CAT_ADJUST; }

    bool is_relative() override
    { return config->relative; }

    EvalStatus eval(Cursor&, Packet*) override;
    int match(Cursor&);

private:
    HashMatchData* config;
    HashFunc hashf;
    unsigned size;
    HashPsIdx idx;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t HashOption::hash() const
{
    uint32_t a,b,c;
    const HashMatchData* hmd = config;

    a = hmd->negated;
    b = hmd->relative;
    c = size;

    mix_str(a,b,c,hmd->hash.c_str());

    a += hmd->length;
    b += hmd->offset;
    c += hmd->offset_var;

    mix_str(a,b,c,get_name());
    finalize(a,b,c);

    return c;
}

bool HashOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const HashOption& rhs = (const HashOption&)ips;

    if (
        config->hash == rhs.config->hash &&
        config->length == rhs.config->length &&
        config->offset == rhs.config->offset &&
        config->offset_var == rhs.config->offset_var &&
        config->negated == rhs.config->negated &&
        config->relative == rhs.config->relative
        )
        return true;

    return false;
}

//-------------------------------------------------------------------------
// runtime functions
//-------------------------------------------------------------------------

int HashOption::match(Cursor& c)
{
    int offset;

    /* Get byte_extract variables */
    if (config->offset_var >= 0 && config->offset_var < NUM_IPS_OPTIONS_VARS)
    {
        uint32_t extract;
        GetVarValueByIndex(&extract, config->offset_var);
        offset = (int)extract;
    }
    else
        offset = config->offset;

    int pos = c.get_delta();

    if ( !pos )
    {
        if ( config->relative )
            pos = c.get_pos();

        pos += offset;
    }

    // FIXIT-H should fail if offset is out of bounds
    // same for content and possibly others too
    if ( pos < 0 )
        pos = 0;

    // If the pattern size is greater than the amount of data we have to
    // search, there's no way we can match, but return 0 here for the
    // case where the match is inverted and there is at least some data.
    if ( config->length > c.size() - pos )
    {
        if ( config->negated )
            return 0;

        return -1;
    }

    const uint8_t* base = c.buffer() + pos;
    unsigned char buf[MAX_HASH_SIZE];
    hashf(base, config->length, buf);
    int found = memcmp(buf, config->hash.c_str(), size);

    if ( !found )
    {
        c.set_pos(pos + config->length);
        return 1;
    }

    return 0;
}

IpsOption::EvalStatus HashOption::eval(Cursor& c, Packet*)
{
    Profile profile(hash_ps[idx]);

    int found = match(c);

    if ( found == -1 )
    {
        /* On error, mark as not found.  This is necessary to handle !content
           cases.  In that case, a search that is outside the given buffer will
           return 0, and !0 is 1, so a !content out of bounds will return true,
           which is not what we want.  */
        found = 0;
    }

    else
        found ^= config->negated;

    if ( found )
        return MATCH;

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// parsing methods
//-------------------------------------------------------------------------

static void parse_hash(HashMatchData* hmd, const char* rule)
{
    parse_byte_code(rule, hmd->negated, hmd->hash);
}

// FIXIT-L refactor for general use?
static void parse_offset(HashMatchData* hmd, const char* data)
{
    if (data == nullptr)
    {
        ParseError("missing argument to 'offset' option");
        return;
    }

    if (isdigit(data[0]) || data[0] == '-')
    {
        hmd->offset = parse_int(data, "offset");
        hmd->offset_var = IPS_OPTIONS_NO_VAR;
    }
    else
    {
        hmd->offset_var = GetVarByName(data);

        if (hmd->offset_var == IPS_OPTIONS_NO_VAR)
            ParseError(INVALID_VAR_ERR_STR, "content offset", data);
    }
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~hash", Parameter::PT_STRING, nullptr, nullptr,
      "data to match" },

    { "length", Parameter::PT_INT, "1:65535", nullptr,
      "number of octets in plain text" },

    { "offset", Parameter::PT_STRING, nullptr, nullptr,
      "var or number of bytes from start of buffer to start search" },

    { "relative", Parameter::PT_IMPLIED, nullptr, "false",
      "offset from cursor instead of start of buffer" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "payload rule option for hash matching"

class HashModule : public Module
{
public:
    HashModule(const char* s, HashPsIdx hpi) :
        Module(s, s_help, s_params)
    { hmd = nullptr; idx = hpi; }

    ~HashModule() override
    { delete hmd; }

    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &hash_ps[idx]; }

    HashMatchData* get_data();

    Usage get_usage() const override
    { return DETECT; }

private:
    HashMatchData* hmd;
    HashPsIdx idx;
};

HashMatchData* HashModule::get_data()
{
    HashMatchData* tmp = hmd;
    hmd = nullptr;
    return tmp;
}

bool HashModule::begin(const char*, int, SnortConfig*)
{
    assert(!hmd);
    hmd = new HashMatchData;
    return true;
}

bool HashModule::end(const char*, int, SnortConfig*)
{
    if ( !hmd->length )
        ParseError("%s requires length parameter", get_name());

    return true;
}

bool HashModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("~hash") )
        parse_hash(hmd, v.get_string());

    else if ( v.is("offset") )
        parse_offset(hmd, v.get_string());

    else if ( v.is("relative") )
        hmd->relative = true;

    else if ( v.is("length") )
        hmd->length = v.get_long();

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// shared methods
//-------------------------------------------------------------------------

static void mod_dtor(Module* m)
{
    delete m;
}

static void opt_dtor(IpsOption* p)
{
    delete p;
}

//-------------------------------------------------------------------------
// md5 methods
//-------------------------------------------------------------------------

#undef IPS_OPT
#define IPS_OPT "md5"

static Module* md5_mod_ctor()
{
    return new HashModule(IPS_OPT, HPI_MD5);
}

static IpsOption* md5_opt_ctor(Module* p, OptTreeNode*)
{
    HashModule* m = (HashModule*)p;
    HashMatchData* hmd = m->get_data();
    return new HashOption(IPS_OPT, HPI_MD5, hmd, md5, MD5_HASH_SIZE);
}

static const IpsApi md5_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        IPS_OPT,
        s_help,
        md5_mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, 0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    md5_opt_ctor,
    opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// sha256 methods
//-------------------------------------------------------------------------

#undef IPS_OPT
#define IPS_OPT "sha256"

static Module* sha256_mod_ctor()
{
    return new HashModule(IPS_OPT, HPI_SHA256);
}

static IpsOption* sha256_opt_ctor(Module* p, OptTreeNode*)
{
    HashModule* m = (HashModule*)p;
    HashMatchData* hmd = m->get_data();
    return new HashOption(IPS_OPT, HPI_SHA256, hmd, sha256, SHA256_HASH_SIZE);
}

static const IpsApi sha256_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        IPS_OPT,
        s_help,
        sha256_mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, 0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    sha256_opt_ctor,
    opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// sha512 methods
//-------------------------------------------------------------------------

#undef IPS_OPT
#define IPS_OPT "sha512"

static Module* sha512_mod_ctor()
{
    return new HashModule(IPS_OPT, HPI_SHA512);
}

static IpsOption* sha512_opt_ctor(Module* p, OptTreeNode*)
{
    HashModule* m = (HashModule*)p;
    HashMatchData* hmd = m->get_data();
    return new HashOption(IPS_OPT, HPI_SHA512, hmd, sha512, SHA512_HASH_SIZE);
}

static const IpsApi sha512_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        IPS_OPT,
        s_help,
        sha512_mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, 0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    sha512_opt_ctor,
    opt_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// plugins
//-------------------------------------------------------------------------

// can't be linked dynamically yet
//#ifdef BUILDING_SO
//SO_PUBLIC const BaseApi* snort_plugins[] =
//{
//    &md5_api.base,
//    &sha256_api.base,
//    &sha512_api.base,
//    nullptr
//};
//#else
const BaseApi* ips_md5 = &md5_api.base;
const BaseApi* ips_sha256 = &sha256_api.base;
const BaseApi* ips_sha512 = &sha512_api.base;
//#endif


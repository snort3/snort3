//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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
// ips_file_type.cc author Victor Roemer <vroemer@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/ips_option.h"
#include "framework/module.h"
#include "file_api/file_flows.h"
#include "file_api/file_identifier.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

using namespace snort;

#define s_name "file_type"

static THREAD_LOCAL ProfileStats fileTypePerfStats;

class FileTypeOption : public IpsOption
{
public:
    FileTypeOption(FileTypeBitSet&);

    CursorActionType get_cursor_type() const override
    { return CAT_NONE; }

    EvalStatus eval(Cursor&, Packet*) override;

    FileTypeBitSet types;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

FileTypeOption::FileTypeOption(FileTypeBitSet& t) : IpsOption(s_name)
{
    types = t;
}

IpsOption::EvalStatus FileTypeOption::eval(Cursor&, Packet* pkt)
{
    Profile profile(fileTypePerfStats);

    if (!pkt->flow)
        return NO_MATCH;

    FileFlows* files = FileFlows::get_file_flows(pkt->flow);

    if (!files)
        return NO_MATCH;

    FileContext* file = files->get_current_file_context();

    if (!file)
        return NO_MATCH;

    uint32_t current_type = file->get_file_type();

    if (current_type < types.size() and types[current_type] )
        return MATCH;

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~", Parameter::PT_STRING, nullptr, nullptr,
        "list of file type IDs to match" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};


#define s_help \
    "rule option to check file type"

class FileTypeModule : public Module
{
public:
    FileTypeModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &fileTypePerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    FileTypeBitSet types;

private:
    bool parse_type_and_version(std::string& token);
};

bool FileTypeModule::begin(const char*, int, SnortConfig*)
{
    types.reset();

    return true;
}

bool FileTypeModule::set(const char*, Value& v, SnortConfig*)
{
    if ( !v.is("~") )
        return false;

    v.set_first_token();
    std::string tok;

    while ( v.get_next_token(tok) )
    {
        if ( tok[0] == '"' )
            tok.erase(0, 1);

        if ( tok[tok.length()-1] == '"' )
            tok.erase(tok.length()-1, 1);

        if (! parse_type_and_version(tok) )
            return false;
    }
    return true;
}

// Parse a file_type token and add the rule ID associated with the type
// into the set of file types to match.
//
// The file_type token can have the following format where TYPENAME and
// VER? are strings:
//
// TYPENAME     -- Type by itself will match all versions of that type.
// TYPENAME,VER1 -- Match type and version
// TYPENAME,VER1,VER2,... -- Match type and any of the specified versions.
//
//    Multiple types are separated by spaces:
// TYPE1,VER1 TYPE2 TYPE3,VER1,VER2 -- Match any of these types
//
bool FileTypeModule::parse_type_and_version(std::string& token)
{
    std::istringstream stream(token);
    std::string type_name;
    std::string version;
    FileTypeBitSet ids_set;

    if(!std::getline(stream, type_name, ','))
        return false;

    if(!std::getline(stream, version, ','))
    {
        // Match all versions of this type.
        get_magic_rule_ids_from_type(type_name, "", ids_set);
        if(ids_set.none())
        {
            ParseError("Invalid file_type type '%s'. Not found in file_rules.", type_name.c_str());
            return false;
        }

        types |= ids_set;
        return true;
    }

    get_magic_rule_ids_from_type(type_name, version, ids_set);
    if(ids_set.none())
    {
        ParseError("Invalid file_type type '%s' or version '%s'. Not found in file_rules.", type_name.c_str(), version.c_str());
        return false;
    }

    types |= ids_set;

    while(std::getline(stream, version, ','))
    {
        get_magic_rule_ids_from_type(type_name, version, ids_set);
        if(ids_set.none())
        {
            ParseError("Invalid file_type type '%s' or version '%s'. Not found in file_rules.", type_name.c_str(), version.c_str());
            return false;
        }

        types |= ids_set;
    }

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new FileTypeModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* file_type_ctor(Module* m, OptTreeNode*)
{
    FileTypeModule* mod = (FileTypeModule*)m;
    return new FileTypeOption(mod->types);
}

static void file_type_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi file_type_api =
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
    file_type_ctor,
    file_type_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_file_type[] =
#endif
{
    &file_type_api.base,
    nullptr
};


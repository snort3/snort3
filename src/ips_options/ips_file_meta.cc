//--------------------------------------------------------------------------
// Copyright (C) 2022-2024 Cisco and/or its affiliates. All rights reserved.
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

// Author: Bhargava Jandhyala <bjandhya@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <unordered_map>

#include "detection/detection_engine.h"
#include "detection/treenodes.h"
#include "file_api/file_flows.h"
#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "main/thread_config.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

using namespace snort;

#define s_name "file_meta"

//--------------------------------------------------------------------------
// file_meta option config
//--------------------------------------------------------------------------

struct FileMetaData
{
    uint32_t file_id = 0;
    std::string file_type;
    std::string category;
    std::string version;
    std::vector<std::string> groups;
};

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "type", Parameter::PT_STRING, nullptr, nullptr,
      "file type to set" },

    { "id", Parameter::PT_INT, "1:1023", nullptr,
      "file type id" },

    { "category", Parameter::PT_STRING, nullptr, nullptr,
      "file type category" },

    { "group", Parameter::PT_STRING, nullptr, nullptr,
      "comma separated list of groups associated with file type" },

    { "version", Parameter::PT_STRING, nullptr, nullptr,
      "file type version" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to set file metadata (file type and id)"

class FileMetaModule : public Module
{
public:
    FileMetaModule() : Module(s_name, s_help, s_params) { }
    bool set(const char*, Value&, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    Usage get_usage() const override
    {
        return DETECT;
    }

public:
    FileMetaData fmc;
};

bool FileMetaModule::set(const char*, Value& v, SnortConfig*)
{
    if (v.is("type"))
    {
        fmc.file_type = v.get_string();
    }
    else if (v.is("id"))
    {
        fmc.file_id = v.get_uint32();
    }
    else if (v.is("category"))
    {
        fmc.category = v.get_string();
    }
    else if (v.is("group"))
    {
        std::istringstream stream(v.get_string());
        std::string tmpstr;
        while (std::getline(stream, tmpstr, ','))
        {
            fmc.groups.emplace_back(tmpstr);
        }
    }
    else if (v.is("version"))
        fmc.version = v.get_string();
    else
        return false;

    return true;
}

bool FileMetaModule::end(const char*, int, SnortConfig* sc)
{
    set_rule_id_from_type(sc, fmc.file_id, fmc.file_type,fmc.category, fmc.version, fmc.groups);
    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new FileMetaModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* file_meta_ctor(Module* p, OptTreeNode* otn)
{
    FileMetaModule* m = (FileMetaModule*)p;
    otn->sigInfo.file_id = m->fmc.file_id;
    return nullptr;
}

static const IpsApi file_meta_api =
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
    OPT_TYPE_META,
    1,
    PROTO_BIT__NONE,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    file_meta_ctor,
    nullptr,
    nullptr
};

const BaseApi* ips_file_meta = &file_meta_api.base;


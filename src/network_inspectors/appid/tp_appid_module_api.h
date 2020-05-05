//--------------------------------------------------------------------------
// Copyright (C) 2018-2020 Cisco and/or its affiliates. All rights reserved.
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

// tp_appid_module_api.h author Silviu Minut <sminut@cisco.com>

#ifndef TP_APPID_MODULE_API_H
#define TP_APPID_MODULE_API_H

#include <vector>
#include <string>
#include "tp_appid_types.h"

#define THIRD_PARTY_APPID_API_VERSION 5

class ThirdPartyConfig
{
public:
    uint32_t chp_body_collection_max = 0;
    bool ftp_userid_disabled = false;
    bool chp_body_collection_disabled = false;
    bool tp_allow_probes = false;
    std::string tp_appid_config;
    bool tp_appid_stats_enable = false;
    bool tp_appid_config_dump = false;
};

class ThirdPartyAppIdContext
{
public:
    ThirdPartyAppIdContext(uint32_t ver, const char* mname, ThirdPartyConfig& config)
        : version(ver), name(mname), cfg(config) { }

    virtual ~ThirdPartyAppIdContext() { }

    uint32_t api_version() const { return version; }
    const std::string& module_name() const { return name; }

    virtual int tinit() = 0;
    virtual int tfini() = 0;

    virtual const ThirdPartyConfig& get_config() const { return cfg; }

protected:
    const uint32_t version;
    const std::string name;
    ThirdPartyConfig cfg;

private:
    // No implicit constructor as derived classes need to provide
    // version and name.
    ThirdPartyAppIdContext() : version(0), name("") { }
};

#endif

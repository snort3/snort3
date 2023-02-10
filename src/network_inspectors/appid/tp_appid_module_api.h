//--------------------------------------------------------------------------
// Copyright (C) 2018-2023 Cisco and/or its affiliates. All rights reserved.
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
#include "main/thread.h"
#include "tp_appid_types.h"

#define THIRD_PARTY_APPID_API_VERSION 6

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
        : api_version(ver), name(mname), cfg(config)
    {
        version = next_version++;
    }

    uint32_t get_version() const
    {
        return version;
    }

    virtual ~ThirdPartyAppIdContext() = default;

    uint32_t get_api_version() const { return api_version; }
    const std::string& module_name() const { return name; }

    virtual int tinit() = 0;
    virtual bool tfini(bool is_idling = false) = 0;

    virtual const ThirdPartyConfig& get_config() const { return cfg; }

    static void set_tp_reload_in_progress(bool value) { tp_reload_in_progress = value; }
    static bool get_tp_reload_in_progress() { return tp_reload_in_progress; }

    virtual const std::string& get_user_config() const = 0;

protected:
    const uint32_t api_version;
    const std::string name;
    ThirdPartyConfig cfg;

private:
    // No implicit constructor as derived classes need to provide
    // version and name.
    ThirdPartyAppIdContext() : api_version(0), name(""), version(0) { }
    uint32_t version;
    static THREAD_LOCAL bool tp_reload_in_progress;
    // Increments when a new third-party context is loaded
    SO_PUBLIC static uint32_t next_version;
};

#endif

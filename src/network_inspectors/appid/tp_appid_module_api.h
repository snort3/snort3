//--------------------------------------------------------------------------
// Copyright (C) 2018-2018 Cisco and/or its affiliates. All rights reserved.
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

#define THIRD_PARTY_APP_ID_API_VERSION 1

class ThirdPartyConfig
{
public:
    unsigned chp_body_collection_max;
    unsigned ftp_userid_disabled : 1;
    unsigned chp_body_collection_disabled : 1;
    unsigned tp_allow_probes : 1;
    unsigned http_upgrade_reporting_enabled : 1;
    unsigned http_response_version_enabled : 1;
    std::string tp_appid_config;
    std::vector<std::string> xff_fields;
    std::vector<std::string> old_xff_fields;

    ThirdPartyConfig()
    {
        getXffFields();
    }

    void getXffFields()
    {
        xff_fields.clear();
        xff_fields.push_back(HTTP_XFF_FIELD_X_FORWARDED_FOR);
        xff_fields.push_back(HTTP_XFF_FIELD_TRUE_CLIENT_IP);
    }
};

class ThirdPartyAppIDModule
{
public:

    /* ThirdPartyAppIdConfig tpac; */

    ThirdPartyAppIDModule(uint32_t ver, const char* mname)
        : version(ver), name(mname) { }

    virtual ~ThirdPartyAppIDModule() { }

    uint32_t api_version() const { return version; }
    const std::string& module_name() const { return name; }

    virtual int pinit(ThirdPartyConfig&) = 0;
    virtual int pfini() = 0;

    virtual int tinit() = 0;
    virtual int tfini() = 0;

    virtual int reconfigure(const ThirdPartyConfig&) = 0;
    virtual int print_stats() = 0;
    virtual int reset_stats() = 0;

private:

    // No implicit constructor as derived classes need to provide
    // version and name.
    ThirdPartyAppIDModule() : version(0), name("") { }

    const uint32_t version;
    const std::string name;
};

// Function pointer to object factory that returns a pointer to a newly
// created object of a derived class.
// This needs to be exported (SO_PUBLIC) by any third party .so library.
// Must return NULL if it fails to create the object.
typedef ThirdPartyAppIDModule* (* CreateThirdPartyAppIDModule_t)();

#endif


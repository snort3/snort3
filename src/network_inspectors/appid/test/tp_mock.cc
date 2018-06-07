//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

// tp_mock.cc author Silviu Minut <sminut@cisco.com>

// Standalone compilation:
// g++ -g -Wall -I.. -I/path/to/snort3/src -c tp_mock.cc
// g++ -std=c++11 -g -Wall -I.. -I/path/to/snort3/src -shared -fPIC -o libtp_mock.so tp_mock.cc
// As a module (dynamically loaded)  - see CMakeLists.txt

#include <iostream>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "main/snort_types.h"

#include "tp_appid_module_api.h"
#include "tp_appid_session_api.h"

#define WhereMacro __FILE__ << ": " << __FUNCTION__ << ": " << __LINE__

using namespace std;

class ThirdPartyAppIDModuleImpl : public ThirdPartyAppIDModule
{
public:
    ThirdPartyAppIDModuleImpl(uint32_t ver, const char* mname)
        : ThirdPartyAppIDModule(ver, mname)
    {
        cerr << WhereMacro << endl;
    }

    ~ThirdPartyAppIDModuleImpl()
    {
        cerr << WhereMacro << endl;
    }

    // Hack: use cfg to manipulate pinit to return 1, so we can hit the
    // if (ret != 0) case in tp_lib_handler.cc.
    int pinit(ThirdPartyConfig& cfg)
    {
        cerr << WhereMacro << endl;
        return cfg.tp_appid_config.empty() ? 1 : 0;
    }

    int tinit() { return 0; }
    int reconfigure(const ThirdPartyConfig&) { return 0; }
    int pfini()
    {
        cerr << WhereMacro << endl;
        return 0;
    }

    int tfini() { return 0; }
    int print_stats() { return 0; }
    int reset_stats() { return 0; }
};

class ThirdPartyAppIDSessionImpl : public ThirdPartyAppIDSession
{
public:

    bool reset() { return 1; }
    bool process(const snort::Packet&, AppidSessionDirection, vector<AppId>&,
        ThirdPartyAppIDAttributeData&) { return 1; }

    int disable_flags(uint32_t) { return 0; }
    TPState get_state() { return state; }
    void set_state(TPState s) { state=s; }
    void clear_attr(TPSessionAttr attr) { flags &= ~attr; }
    void set_attr(TPSessionAttr attr) { flags |= attr; }
    unsigned get_attr(TPSessionAttr attr) { return flags & attr; }

private:
    unsigned flags = 0;
};

// Object factories to create module and session.
// This is the only way for outside callers to create module and session
// once the .so has been loaded.
extern "C"
{
    SO_PUBLIC ThirdPartyAppIDModuleImpl* create_third_party_appid_module();
    SO_PUBLIC ThirdPartyAppIDSessionImpl* create_third_party_appid_session();

    SO_PUBLIC ThirdPartyAppIDModuleImpl* create_third_party_appid_module()
    {
        return new ThirdPartyAppIDModuleImpl(1,"foobar");
    }

    SO_PUBLIC ThirdPartyAppIDSessionImpl* create_third_party_appid_session()
    {
        return new ThirdPartyAppIDSessionImpl;
    }
}


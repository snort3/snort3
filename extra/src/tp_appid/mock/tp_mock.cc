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

// Brief description:
//
// Minimalist example of an implementation of a third party library for appid
// detection.
// Snort interacts with this library via 3 classes:
// 1) TPLibHandler - to load the third party library.
// 2) ThirdPartyAppIDModule - to initialize and clean-up whatever we might need
// 3) ThirdPartyAppIDSession - for the actual information extracted from packets
// The third party library must provide implementations to the abstract classes
// ThirdPartyAppIDModule and ThirdPartyAppIDSession and must also implement the
// object factory functions returning pointers to the derived classes.
//
//
// Standalone compilation:
// g++ -g -Wall -I/path/to/snort3/src -c tp_mock.cc
// g++ -std=c++11 -g -Wall -I/path/to/snort3/src -shared -fPIC -o libtp_mock.so tp_mock.cc
// As a module (dynamically loaded)  - see CMakeLists.txt

#include <iostream>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "main/snort_types.h"

#include "network_inspectors/appid/tp_appid_module_api.h"
#include "network_inspectors/appid/tp_appid_session_api.h"

#define THIRD_PARTY_APPID_MODULE_NAME "NAVL"

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

    int pinit(ThirdPartyConfig& config)
    {
        cerr << WhereMacro
             << ": main thread initialization, possibly load other libraries." << endl;
        return 0;
    }

    int tinit()
    {
        cerr << WhereMacro << ": per worker thread initialization." << endl;
        return 0;
    }

    int reconfigure(const ThirdPartyConfig& config)
    {
        cerr << WhereMacro << ": do not call pinit() during reconfigure." << endl;
        return 0;
    }

    int pfini()
    {
        cerr << WhereMacro << ": main thread clean-up." << endl;
        return 0;
    }

    int tfini()
    {
        cerr << WhereMacro << ": per worker-thread clean-up." << endl;
        return 0;
    }

    int print_stats() { return 0; }
    int reset_stats() { return 0; }
};

class ThirdPartyAppIDSessionImpl : public ThirdPartyAppIDSession
{
public:

    bool reset() { return 1; }
    bool process(const snort::Packet&,
        AppidSessionDirection direction,
        vector<AppId>& proto_list,
        ThirdPartyAppIDAttributeData& attribute_data)
    {
        cerr << WhereMacro
             << ": third party packet parsing and appid processing." << endl;
        return 1;
    }

    int disable_flags(uint32_t session_flags) { return 0; }
    TPState get_state() { return state; }
    void set_state(TPState s) { state=s; }
    void clear_attr(TPSessionAttr attr) { flags &= ~attr; }
    void set_attr(TPSessionAttr attr) { flags |= attr; }
    unsigned get_attr(TPSessionAttr attr) { return flags & attr; }

private:
    unsigned flags=0;
};

// Object factories to create module and session.
// This is the only way for outside callers to create module and session
// once the .so has been loaded.
extern "C"
{
    SO_PUBLIC ThirdPartyAppIDModuleImpl* create_third_party_appid_module()
    {
        return new ThirdPartyAppIDModuleImpl(1,"third party");
    }
}

extern "C"
{
    SO_PUBLIC ThirdPartyAppIDSessionImpl* create_third_party_appid_session()
    {
        return new ThirdPartyAppIDSessionImpl;
    }
}


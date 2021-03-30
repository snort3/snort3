//--------------------------------------------------------------------------
// Copyright (C) 2016-2021 Cisco and/or its affiliates. All rights reserved.
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
// g++ -std=c++14 -g -Wall -I.. -I/path/to/snort3/src -shared -fPIC -o libtp_mock.so tp_mock.cc
// As a module (dynamically loaded)  - see CMakeLists.txt

#include <iostream>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "main/snort_types.h"

#include "tp_appid_module_api.h"
#include "tp_appid_session_api.h"

#define WhereMacro __FILE__ << ": " << __FUNCTION__ << ": " << __LINE__

using namespace snort;
using namespace std;

uint32_t ThirdPartyAppIdContext::next_version = 0;

class ThirdPartyAppIdContextImpl : public ThirdPartyAppIdContext
{
public:
    ThirdPartyAppIdContextImpl(uint32_t ver, const char* mname, ThirdPartyConfig& config)
        : ThirdPartyAppIdContext(ver, mname, config)
    {
        cerr << WhereMacro << endl;
    }

    ~ThirdPartyAppIdContextImpl() override
    {
        cerr << WhereMacro << endl;
    }

    int tinit() override { return 0; }
    bool tfini(bool) override { return false; }
    const string& get_user_config() const override { return user_config; }

private:
    const string user_config = "";
};

class ThirdPartyAppIdSessionImpl : public ThirdPartyAppIdSession
{
public:
    ThirdPartyAppIdSessionImpl(ThirdPartyAppIdContext& ctxt)
      : ThirdPartyAppIdSession(ctxt)
    { }
    void reset() override { }
    void delete_with_ctxt() override { delete this; }
    TPState process(const Packet&, AppidSessionDirection, vector<AppId>&,
        ThirdPartyAppIDAttributeData&) override { return TP_STATE_INIT; }

    int disable_flags(uint32_t) override { return 0; }
    TPState get_state() override { return state; }
    void set_state(TPState s) override { state=s; }
    void clear_attr(TPSessionAttr attr) override { flags &= ~attr; }
    void set_attr(TPSessionAttr attr) override { flags |= attr; }
    unsigned get_attr(TPSessionAttr attr) override { return flags & attr; }

private:
    unsigned flags = 0;
};

// Object factories to create module and session.
// This is the only way for outside callers to create module and session
// once the .so has been loaded.
extern "C"
{
    SO_PUBLIC ThirdPartyAppIdContextImpl* tp_appid_create_ctxt(ThirdPartyConfig& config)
    {
        return new ThirdPartyAppIdContextImpl(THIRD_PARTY_APPID_API_VERSION,"foobar", config);
    }

    SO_PUBLIC ThirdPartyAppIdSessionImpl* tp_appid_create_session(ThirdPartyAppIdContext& ctxt)
    {
        return new ThirdPartyAppIdSessionImpl(ctxt);
    }

    SO_PUBLIC int tp_appid_pfini()
    {
        return 0;
    }

    SO_PUBLIC int tp_appid_tfini()
    {
        return 0;
    }
}


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
// user_module.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "user_module.h"

#include "stream_user.h"

using namespace snort;
using namespace std;

Trace TRACE_NAME(stream_user);

//-------------------------------------------------------------------------
// stream_user module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "session_timeout", Parameter::PT_INT, "1:86400", "30",
      "session tracking timeout" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

StreamUserModule::StreamUserModule() :
    Module(MOD_NAME, MOD_HELP, s_params, false, &TRACE_NAME(stream_user))
{
    config = nullptr;
}

StreamUserModule::~StreamUserModule()
{
    if ( config )
        delete config;
}

StreamUserConfig* StreamUserModule::get_data()
{
    StreamUserConfig* temp = config;
    config = nullptr;
    return temp;
}

bool StreamUserModule::set(const char* fqn, Value& v, SnortConfig* sc)
{
    if ( v.is("session_timeout") )
        config->session_timeout = v.get_long();

    else
        return Module::set(fqn, v, sc);

    return true;
}

bool StreamUserModule::begin(const char*, int, SnortConfig*)
{
    if ( !config )
        config = new StreamUserConfig;

    return true;
}

bool StreamUserModule::end(const char*, int, SnortConfig*)
{
    return true;
}


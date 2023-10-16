//--------------------------------------------------------------------------
// Copyright (C) 2015-2023 Cisco and/or its affiliates. All rights reserved.
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
#include "trace/trace.h"

using namespace snort;
using namespace std;

THREAD_LOCAL const Trace* stream_user_trace = nullptr;

//-------------------------------------------------------------------------
// stream_user module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "session_timeout", Parameter::PT_INT, "1:max31", "60",
      "session tracking timeout" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

StreamUserModule::StreamUserModule() : Module(MOD_NAME, MOD_HELP, s_params)
{ config = nullptr; }

StreamUserModule::~StreamUserModule()
{ delete config; }

StreamUserConfig* StreamUserModule::get_data()
{
    StreamUserConfig* temp = config;
    config = nullptr;
    return temp;
}

void StreamUserModule::set_trace(const Trace* trace) const
{ stream_user_trace = trace; }

const TraceOption* StreamUserModule::get_trace_options() const
{
#ifndef DEBUG_MSGS
    return nullptr;
#else
    static const TraceOption stream_user_trace_options(nullptr, 0, nullptr);
    return &stream_user_trace_options;
#endif
}

bool StreamUserModule::set(const char*, Value& v, SnortConfig*)
{
    assert(v.is("session_timeout"));
    config->session_timeout = v.get_uint32();
    return true;
}

bool StreamUserModule::begin(const char*, int, SnortConfig*)
{
    if ( !config )
        config = new StreamUserConfig;

    return true;
}


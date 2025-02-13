//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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
// user_module.h author Russ Combs <rucombs@cisco.com>

#ifndef USER_MODULE_H
#define USER_MODULE_H

#include "framework/module.h"

namespace snort
{
class Trace;
struct SnortConfig;
}

extern THREAD_LOCAL const snort::Trace* stream_user_trace;
extern THREAD_LOCAL snort::ProfileStats user_perf_stats;

//-------------------------------------------------------------------------
// stream_user module
//-------------------------------------------------------------------------

#define MOD_NAME "stream_user"
#define MOD_HELP "stream inspector for user flow tracking and reassembly "

struct StreamUserConfig;

class StreamUserModule : public snort::Module
{
public:
    StreamUserModule();
    ~StreamUserModule() override;

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool begin(const char*, int, snort::SnortConfig*) override;

    Usage get_usage() const override
    { return INSPECT; }

    bool is_bindable() const override
    { return true; }

    StreamUserConfig* get_data();

    void set_trace(const snort::Trace*) const override;
    const snort::TraceOption* get_trace_options() const override;

private:
    StreamUserConfig* config;
};

#endif


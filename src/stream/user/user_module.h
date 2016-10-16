//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

struct SnortConfig;

#if 0
extern const PegInfo user_pegs[];
extern THREAD_LOCAL struct UserStats user_stats;
#endif

extern THREAD_LOCAL ProfileStats user_perf_stats;

extern Trace TRACE_NAME(stream_user);

//-------------------------------------------------------------------------
// stream_user module
//-------------------------------------------------------------------------

#define MOD_NAME "stream_user"
#define MOD_HELP "stream inspector for user flow tracking and reassembly "

struct StreamUserConfig;

class StreamUserModule : public Module
{
public:
    StreamUserModule();
    ~StreamUserModule();

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

#if 0
    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
#endif

    StreamUserConfig* get_data();

private:
    StreamUserConfig* config;
};

#endif


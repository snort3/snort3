//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

// perf_module.h author Russ Combs <rucombs@cisco.com>

#ifndef PERF_MODULE_H
#define PERF_MODULE_H

#include "perf.h"
#include "framework/module.h"

#define PERF_NAME "perf_monitor"
#define PERF_HELP "performance monitoring and flow statistics collection"

extern THREAD_LOCAL SimpleStats pmstats;
extern THREAD_LOCAL ProfileStats perfmonStats;

/* The Module Class for incorporation into Snort++ */
class PerfMonModule : public Module
{
public:
    PerfMonModule();

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    ProfileStats* get_profile() const override;

    void get_config(SFPERF&);

private:
    SFPERF config;
};

#endif


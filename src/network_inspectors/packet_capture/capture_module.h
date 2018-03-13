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

// capture_module.h author Carter Waxman <cwaxman@cisco.com>

#ifndef CAPTURE_MODULE_H
#define CAPTURE_MODULE_H

#include "framework/module.h"

#define CAPTURE_NAME "packet_capture"
#define CAPTURE_HELP "raw packet dumping facility"

struct CaptureConfig
{
    bool enabled;
    std::string filter;
};

struct CaptureStats
{
    PegCount checked;
    PegCount matched;
};

class CaptureModule : public snort::Module
{
public:
    CaptureModule();

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    snort::ProfileStats* get_profile() const override;
    const snort::Command* get_commands() const override;
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;

    void get_config(CaptureConfig&);

    Usage get_usage() const override
    { return GLOBAL; }

private:
    CaptureConfig config;
};

extern THREAD_LOCAL CaptureStats cap_count_stats;
extern THREAD_LOCAL snort::ProfileStats cap_prof_stats;

#endif


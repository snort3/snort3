//--------------------------------------------------------------------------
// Copyright (C) 2016-2024 Cisco and/or its affiliates. All rights reserved.
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

// sfdaq_module.h author Michael Altizer <mialtize@cisco.com>

#ifndef SFDAQ_MODULE_H
#define SFDAQ_MODULE_H

#include <daq_common.h>

#include "framework/module.h"

namespace snort
{
struct SnortConfig;
}
struct SFDAQConfig;
struct SFDAQModuleConfig;

class SFDAQModule : public snort::Module
{
public:
    SFDAQModule();

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    void prep_counts(bool dump_stats) override;
    void reset_stats() override;

    bool counts_need_prep() const override
    { return true; }

    Usage get_usage() const override
    { return GLOBAL; }

private:
    SFDAQConfig* config;
    SFDAQModuleConfig* module_config;
};

struct DAQStats
{
    PegCount pcaps;
    PegCount received;
    PegCount analyzed;
    PegCount dropped;
    PegCount filtered;
    PegCount outstanding;
    PegCount outstanding_max;
    PegCount injected;
    PegCount verdicts[MAX_DAQ_VERDICT];
    PegCount internal_blacklist;
    PegCount internal_whitelist;
    PegCount skipped;
    PegCount idle;
    PegCount rx_bytes;
    PegCount expected_flows;
    PegCount retries_queued;
    PegCount retries_dropped;
    PegCount retries_processed;
    PegCount retries_discarded;
    PegCount sof_messages;
    PegCount eof_messages;
    PegCount other_messages;
};

extern THREAD_LOCAL DAQStats daq_stats;

#endif

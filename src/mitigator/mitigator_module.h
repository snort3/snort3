//--------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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
// mitigator_module.h author Oleksandr Fatieiev <ofatieie@cisco.com>

#ifndef MITIGATOR_MODULE_H
#define MITIGATOR_MODULE_H

#include <mutex>

#include "framework/module.h"
#include "main/analyzer_command.h"

namespace snort
{

class ACMitigateCrash : public snort::AnalyzerCommand
{
public:
    explicit ACMitigateCrash(ControlConn* conn, std::vector<std::string>&& new_modules, bool new_enabled)
        : AnalyzerCommand(conn), modules{std::move(new_modules)}, enabled{new_enabled}
    { }
    bool execute(Analyzer&) override;
    const char* stringify() override { return "MITIGATE_CRASH"; }
    ~ACMitigateCrash() override;
private:
    std::once_flag once;
    std::vector<std::string> modules;
    bool enabled;
};

struct SO_PUBLIC MitigatorStats
{
    PegCount signals_received;
    PegCount actions_ignore;
    PegCount actions_drop;
    PegCount actions_block;
};

extern const PegInfo mitigator_pegs[];
extern THREAD_LOCAL SO_PUBLIC MitigatorStats mitigator_stats;

class MitigatorModule : public Module
{
public:
    MitigatorModule();

    bool set(const char*, Value&, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    const Command* get_commands() const override;
    const snort::RuleMap* get_rules() const override;
    unsigned get_gid() const override;
    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    Usage get_usage() const override { return GLOBAL; }

private:
    void generate_params();

private:
    std::vector<std::vector<Parameter>> module_ranges;
};

} // namespace snort

#endif

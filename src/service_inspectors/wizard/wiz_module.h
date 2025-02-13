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

// wiz_module.cc author Russ Combs <rucombs@cisco.com>

#ifndef WIZ_MODULE_H
#define WIZ_MODULE_H

// wizard management interface

#include "framework/module.h"

#include "magic.h"

#define WIZ_NAME "wizard"
#define WIZ_HELP "inspector that implements port-independent protocol identification"

namespace snort
{
class Trace;
}

extern const PegInfo wiz_pegs[];
extern THREAD_LOCAL struct WizStats tstats;
extern THREAD_LOCAL snort::ProfileStats wizPerfStats;
extern THREAD_LOCAL const snort::Trace* wizard_trace;

class MagicBook;
class CurseBook;

class WizardModule : public snort::Module
{
public:
    WizardModule();
    ~WizardModule() override;

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    snort::ProfileStats* get_profile() const override;

    MagicBook* get_book(bool c2s, bool hex);
    CurseBook* get_curse_book();

    uint16_t get_max_search_depth() const
    { return max_search_depth; }

    Usage get_usage() const override
    { return INSPECT; }

    bool is_bindable() const override
    { return true; }

    void set_trace(const snort::Trace*) const override;
    const snort::TraceOption* get_trace_options() const override;

private:
    std::string service;
    std::vector<std::string> c2s_patterns;
    std::vector<std::string> s2c_patterns;
    bool c2s = false;

    MagicBook* c2s_hexes = nullptr;
    MagicBook* s2c_hexes = nullptr;

    MagicBook* c2s_spells = nullptr;
    MagicBook* s2c_spells = nullptr;

    CurseBook* curses = nullptr;
    uint16_t max_search_depth = 0;

    MagicBook::ArcaneType proto = MagicBook::ArcaneType::MAX;
};

#endif


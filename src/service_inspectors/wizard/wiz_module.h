//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#define WIZ_NAME "wizard"
#define WIZ_HELP "inspector that implements port-independent protocol identification"

extern const PegInfo wiz_pegs[];
extern THREAD_LOCAL struct WizStats tstats;
extern THREAD_LOCAL snort::ProfileStats wizPerfStats;

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

    Usage get_usage() const override
    { return INSPECT; }

private:
    void add_spells(MagicBook*, std::string&);

private:
    bool hex;
    bool c2s;
    std::string service;
    std::vector<std::string> spells;

    MagicBook* c2s_hexes;
    MagicBook* s2c_hexes;

    MagicBook* c2s_spells;
    MagicBook* s2c_spells;

    CurseBook* curses;
};

#endif


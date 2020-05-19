//--------------------------------------------------------------------------
// Copyright (C) 2014-2020 Cisco and/or its affiliates. All rights reserved.
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
// swapper.h author Russ Combs <rucombs@cisco.com>

#ifndef SWAPPER_H
#define SWAPPER_H

// used to make thread local, pointer-based config swaps by packet threads

namespace snort
{
struct SnortConfig;
}

class Analyzer;
struct HostAttributesTable;

class Swapper
{
public:
    Swapper(snort::SnortConfig*, HostAttributesTable*);
    Swapper(const snort::SnortConfig* sold, snort::SnortConfig* snew);

    Swapper(const snort::SnortConfig* sold, snort::SnortConfig* snew,
        HostAttributesTable*, HostAttributesTable*);

    Swapper(HostAttributesTable*, HostAttributesTable*);
    ~Swapper();

    void apply(Analyzer&);
    snort::SnortConfig* get_new_conf() { return new_conf; }

    static bool get_reload_in_progress() { return reload_in_progress; }
    static void set_reload_in_progress(bool rip) { reload_in_progress = rip; }

private:
    const snort::SnortConfig* old_conf;
    snort::SnortConfig* new_conf;

    HostAttributesTable* old_attribs;
    HostAttributesTable* new_attribs;

    static bool reload_in_progress;
};

#endif


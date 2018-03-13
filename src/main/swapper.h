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
// swapper.h author Russ Combs <rucombs@cisco.com>

#ifndef SWAPPER_H
#define SWAPPER_H

// used to make thread local, pointer-based config swaps by packet threads

namespace snort
{
struct SnortConfig;
}

struct tTargetBasedConfig;

class Swapper
{
public:
    Swapper(snort::SnortConfig*, tTargetBasedConfig*);
    Swapper(snort::SnortConfig*, snort::SnortConfig*);
    Swapper(snort::SnortConfig*, snort::SnortConfig*, tTargetBasedConfig*, tTargetBasedConfig*);
    Swapper(tTargetBasedConfig*, tTargetBasedConfig*);
    ~Swapper();

    void apply();

    static bool get_reload_in_progress() { return reload_in_progress; }
    static void set_reload_in_progress(bool rip) { reload_in_progress = rip; }

private:
    snort::SnortConfig* old_conf;
    snort::SnortConfig* new_conf;

    tTargetBasedConfig* old_attribs;
    tTargetBasedConfig* new_attribs;

    static bool reload_in_progress;
};

#endif


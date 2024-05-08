//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

#include "main/snort_types.h"

namespace snort
{
struct SnortConfig;
}

class Analyzer;

class Swapper
{
public:
    Swapper(snort::SnortConfig*);
    Swapper(const snort::SnortConfig* sold, snort::SnortConfig* snew);
    Swapper();
    ~Swapper();

    void apply(Analyzer&);
    void finish(Analyzer&);
    snort::SnortConfig* get_new_conf() { return new_conf; }

private:
    const snort::SnortConfig* old_conf;
    snort::SnortConfig* new_conf;
};

#endif


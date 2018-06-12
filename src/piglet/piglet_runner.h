//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
// piglet_runner.h author Joel Cornett <jocornet@cisco.com>

#ifndef PIGLET_RUNNER_H
#define PIGLET_RUNNER_H

// Test runner

#include <vector>

namespace Piglet
{
struct Chunk;
struct Test;
struct Output;

struct Summary
{
    unsigned passed = 0;
    unsigned failed = 0;
    unsigned errors = 0;

    inline unsigned total() const
    { return passed + failed + errors; }
};

class Runner
{
public:
    static bool run_all(const struct Output&);

    // FIXIT-L this method should be hidden
    static bool run_all(const struct Output&, const std::vector<Chunk>&);

private:
    static void run(const struct Output&, Test&, unsigned);
};
} // namespace Piglet

#endif


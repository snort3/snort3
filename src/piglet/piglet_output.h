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
// piglet_output.h author Joel Cornett <jocornet@cisco.com>

#ifndef PIGLET_OUTPUT_H
#define PIGLET_OUTPUT_H

// Output handling for piglet tests

#include <vector>

namespace Piglet
{
struct Chunk;
struct Test;
struct Summary;
}

namespace Piglet
{
struct Output
{
    using SuiteHeaderCallback = void (*)(const std::vector<Chunk>&);
    using SuiteResultCallback = void (*)(const Summary&);
    using TestHeaderCallback = void (*)(const Test&, unsigned);
    using TestResultCallback = void (*)(const Test&, unsigned);

    SuiteHeaderCallback on_suite_start;
    SuiteResultCallback on_suite_end;
    TestHeaderCallback on_test_start;
    TestResultCallback on_test_end;
};

// -----------------------------------------------------------------------------
// Builtin Output structs
// -----------------------------------------------------------------------------
extern const struct Output unit_test_output;
extern const struct Output pretty_output;
extern const struct Output verbose_output;
}

#endif

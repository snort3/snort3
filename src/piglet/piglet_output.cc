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
// piglet_output.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "piglet_output.h"

#include "piglet_runner.h"
#include "piglet_utils.h"

static inline double calc_percent(unsigned n, unsigned total)
{
    if ( total )
        return static_cast<double>(n) / total * 100;
    else
        return 0;
}

static inline char get_result_short(Piglet::Test::Result result)
{
    switch ( result )
    {
        case Piglet::Test::PASSED:
            return 'P';

        case Piglet::Test::FAILED:
            return 'F';

        case Piglet::Test::ERROR:
            return 'E';

        default:
            return '?';
    }
}

static inline const char* get_result_long(Piglet::Test::Result result)
{
    switch ( result )
    {
        case Piglet::Test::PASSED:
            return "Passed";

        case Piglet::Test::FAILED:
            return "Failed";

        case Piglet::Test::ERROR:
            return "Error";

        default:
            return "?";
    }
}

namespace Piglet
{
// -----------------------------------------------------------------------------
// Builtin Output structs
// -----------------------------------------------------------------------------
const struct Output unit_test_output =
{
    [](const std::vector<Chunk>& chunks) -> void
    { printf("Running suite: piglet (%zu tests)\n", chunks.size()); },

    [](const Summary& sum) -> void
    {
        printf(
            "%f: Checks: %u, Failures: %u, Errors: %u\n",
            calc_percent(sum.passed, sum.total()),
            sum.total(), sum.failed, sum.errors
        );
    },

    nullptr,

    [](const Test& t, unsigned i) -> void
    {
        printf(
            "%s:%c:piglet:(%s::%s):%u: %s\n",
            t.chunk->filename.c_str(), get_result_short(t.result),
            t.type.c_str(), t.name.c_str(), i, get_result_long(t.result)
        );
    }
};

const struct Output pretty_output =  // FIXIT-L don't want to include this
{
    [](const std::vector<Chunk>&) -> void
    {
        printf("\n\x1b[35m======\x1b[0m\n");
        printf("\x1b[35mPIGLET\x1b[0m\n");
        printf("\x1b[35m======\x1b[0m\n\n");
    },
    [](const Summary& sum) -> void
    {
        printf("================\n");

        if ( sum.failed || sum.errors )
            printf("[\x1b[31mFAIL\x1b[0m] ");
        else
            printf("[\x1b[32mPASS\x1b[0m] ");

        printf("%.2f%%", calc_percent(sum.passed, sum.total()));

        if ( sum.failed || sum.errors )
        {
            printf(
                " - Passed: \x1b[32m%u\x1b[0m, "
                "Failed: \x1b[31m%u\x1b[0m, "
                "Errors: \x1b[33m%u\x1b[0m",
                sum.passed, sum.failed, sum.errors
            );
        }

        printf("\n");
    },
    [](const Test& t, unsigned i) -> void
    {
        printf(
            "%u) \x1b[34m%s::%s\x1b[0m: %s\n",
            i, t.type.c_str(), t.name.c_str(), t.chunk->filename.c_str()
        );
    },
    [](const Test& t, unsigned) -> void
    {
        switch ( t.result )
        {
            case Test::PASSED:
                printf("\x1b[32mPASS\x1b[0m");
                break;
            case Test::FAILED:
                printf("\x1b[31mFAIL\x1b[0m");
                break;
            case Test::ERROR:
                printf("\x1b[33mERROR\x1b[0m");
                break;
            default:
                printf("NA");
                break;
        }

        printf("\n");

        if ( t.result != Test::PASSED )
        {
            printf("\x1b[35m");
            for ( const auto& m : t.messages )
                printf("    %s\n", m.c_str());

            printf("\x1b[0m");
        }
    }
};

const struct Output verbose_output =
{
    [](const std::vector<Chunk>& chunks) -> void
    {
        if ( chunks.size() == 1 )
            printf("=== PIGLET (1 test)\n");
        else
            printf("=== PIGLET (%zu tests)\n", chunks.size());
    },

    [](const Summary& sum) -> void
    {
        printf("=========================================\n");
        printf(
            "%0.f%% - passed: %u/%u, failed: %u, errors: %u\n",
            calc_percent(sum.passed, sum.total()),
            sum.passed, sum.total(), sum.failed, sum.errors
        );
    },

    [](const Test& t, unsigned i) -> void
    {
        printf(
            "[%u] - %s::%s - %s\n",
            i, t.type.c_str(), t.name.c_str(), t.chunk->filename.c_str()
        );
    },

    [](const Test& t, unsigned) -> void
    {
        for ( const auto& msg : t.messages )
            printf("    %s\n", msg.c_str());

        printf("  %s\n", get_result_long(t.result));
    }
};
}

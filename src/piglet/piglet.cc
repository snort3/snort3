//--------------------------------------------------------------------------
// Copyright (C) 2015-2015 Cisco and/or its affiliates. All rights reserved.
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
// piglet.cc author Joel Cornett <jocornet@cisco.com>

#include "piglet.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <iostream>
#include <chrono>

#include "main/snort_config.h"

#include "piglet_manager.h"
#include "piglet_runner.h"

namespace Piglet
{
using namespace std;

enum class Result
{
    PASSED = 0,
    FAILED,
    ERROR
};

using output_function = void (*)(Result, Test&, int);
using result_function = int (*)(int, int, int);

inline Result get_result(Test& t)
{
    if ( t.error )
        return Result::ERROR;

    if ( t.result )
        return Result::PASSED;

    return Result::FAILED;
}

void unit_tests_output_fn(Result r, Test& t, int idx)
{
    cout << t.chunk->filename << "::";
    switch ( r )
    {
    case Result::PASSED:
        cout << "P";
        break;

    case Result::FAILED:
        cout << "F";
        break;

    case Result::ERROR:
        cout << "E";
        break;
    }

    cout << ":" << t.type << "-" << t.target;
    cout << ":" << t.name;
    cout << ":" << idx << ": ";

    if ( r == Result::PASSED )
        cout << "Passed";

    else if ( t.messages.size() > 0 )
        cout << t.messages[t.messages.size() - 1];

    else if ( r == Result::FAILED )
        cout << "Failed";

    else
        cout << "Error";

    cout << endl;
}

int unit_tests_result_fn(int total, int failed, int error)
{
    float percent;

    if ( total == 0 )
        percent = 0;
    else
        percent = float(total - failed - error) / total * 100;

    cout << percent << "%: ";
    cout << "Checks: " << total << ": ";
    cout << "Failures: " << failed << ": ";
    cout << "Errors: " << error << endl;

    if ( error )
        return 2;

    if ( failed )
        return 1;

    return 0;
}

void verbose_output_fn(Result r, Test& t, int idx)
{
    string err_string;
    switch ( r )
    {
    case Result::PASSED:
        err_string = "PASS";
        break;

    case Result::FAILED:
        err_string = "FAIL";
        break;

    case Result::ERROR:
        err_string = "ERROR";
        break;
    }

    cout << idx << ": [" << err_string << "] " << t.name << endl;
    cout << "  " << t.type << ", " << t.target << endl;
    cout << "  file: " << t.chunk->filename << endl;

    chrono::microseconds d =
        chrono::duration_cast<chrono::microseconds>(t.timer.delta());

    cout << "  time: " << d.count() << endl;

    if ( t.messages.size() )
    {
        cout << "  errors: " << endl;

        for ( auto m : t.messages )
            cout << "  - " << m << endl;
    }
}

int run_tests(
    const vector<Chunk>& chunks,
    result_function r_fn,
    output_function o_fn = nullptr
    )
{
    int failed = 0,
        error = 0,
        total = 0;

    for ( auto chunk : chunks )
    {
        auto test = Runner::run(chunk);
        auto result = get_result(test);

        total++;
        switch ( result )
        {
        case Result::FAILED:
            failed++;
            break;

        case Result::ERROR:
            error++;
            break;

        case Result::PASSED:
            break; // noop
        }

        if ( o_fn )
            o_fn(result, test, total);
    }

    return r_fn(total, failed, error);
}

int Main::piglet()
{
    cout << "Running suite(s): piglet\n";
    // FIXIT-M: Allow user selection of output/result functions
    return run_tests(Manager::get_chunks(), unit_tests_result_fn, verbose_output_fn);
}

bool Main::run_in_piglet_mode()
{ return snort_conf->run_flags & RUN_FLAG__PIGLET; }
} // namespace Piglet


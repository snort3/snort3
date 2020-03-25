//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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
// trace.cc author Serhii Vlasiuk <svlasiuk@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "trace.h"

using namespace snort;

static const TraceOptionString default_trace_option[] =
{
    { "all", DEFAULT_TRACE_OPTION }
};
static const size_t default_trace_size = (sizeof(default_trace_option) / sizeof(TraceOptionString));

Trace::Trace(const char* name, const TraceOptionString* trace_options, size_t size)
{
    assert(trace_options);
    mod_name = name;
    options = trace_options;
    option_levels.resize(size, 0);
    config_options.resize(size, false);
}

Trace::Trace(const char* name)
{
    mod_name = name;
    options = default_trace_option;
    option_levels.resize(default_trace_size, 0);
    config_options.resize(default_trace_size, false);
}

bool Trace::set(const snort::Value& v)
{
    size_t size = option_levels.size();
    if ( v.is("all") )
    {
        for ( size_t index = 0; index < size; ++index )
            if ( !config_options[index] )
                option_levels[index] = v.get_uint8();
        return true;
    }

    for ( size_t index = 0; index < size; ++index )
    {
        if ( v.is(option_name(index)) )
        {
            TraceOption trace_option = options[index].option;

            option_levels[trace_option] = v.get_uint8();
            config_options[trace_option] = true;
            return true;
        }
    }
    return false;
}

void Trace::reset()
{
    std::fill(option_levels.begin(), option_levels.end(), 0);
    std::fill(config_options.begin(), config_options.end(), false);
}

void Trace::enable()
{
    option_levels[DEFAULT_TRACE_OPTION] = DEFAULT_LOG_LEVEL;
}

#ifdef UNIT_TEST

#include <catch/snort_catch.h>

//-------------------------------------------------------------------------
// Set trace option tests
//-------------------------------------------------------------------------


#define LOG_LEVEL_TEST 1

TEST_CASE("Trace - single trace value", "[trace]")
{
    Trace test_trace("test");

    Parameter p("all", Parameter::PT_INT, "0:255", "0", "enabling traces in module");
    Value trace_val((double)1);
    trace_val.set(&p);

    bool result = test_trace.set(trace_val);
    CHECK( result == true );
    CHECK( test_trace.option_levels[DEFAULT_TRACE_OPTION] == LOG_LEVEL_TEST );
}

TEST_CASE("Trace - multiple trace values", "[trace]")
{
    enum
    {
        TEST_TRACE_DETECTION_ENGINE = 0,
        TEST_TRACE_RULE_VARS,
        TEST_TRACE_OPTION_TREE,
        TEST_TRACE_TAG,
    };
    const TraceOptionString test_trace_values[] =
    {
        { "detect_engine", TEST_TRACE_DETECTION_ENGINE },
        { "rule_vars",     TEST_TRACE_RULE_VARS },
        { "opt_tree",      TEST_TRACE_OPTION_TREE },
        { "tag",           TEST_TRACE_TAG }
    };

    Trace test_trace("test", test_trace_values,
        (sizeof(test_trace_values) / sizeof(TraceOptionString)));

    Parameter p1("detect_engine", Parameter::PT_INT, "0:255", "0", "p1");
    Parameter p2("rule_vars", Parameter::PT_INT, "0:255", "0", "p2");
    Parameter p3("opt_tree", Parameter::PT_INT, "0:255", "0", "p3");
    Parameter p4("tag", Parameter::PT_INT, "0:255", "0", "p4");
    Value trace_val("trace");
    trace_val.set(&p1);
    trace_val.set_enum(1);

    bool result = test_trace.set(trace_val);
    CHECK( result == true );
    CHECK( test_trace.option_levels[TEST_TRACE_DETECTION_ENGINE] == LOG_LEVEL_TEST );

    trace_val.set(&p2);
    result = test_trace.set(trace_val);
    CHECK( result == true );
    CHECK( test_trace.option_levels[TEST_TRACE_DETECTION_ENGINE] == LOG_LEVEL_TEST );
    CHECK( test_trace.option_levels[TEST_TRACE_RULE_VARS] == LOG_LEVEL_TEST );

    trace_val.set(&p3);
    result = test_trace.set(trace_val);
    CHECK( result == true );
    CHECK( test_trace.option_levels[TEST_TRACE_DETECTION_ENGINE] == LOG_LEVEL_TEST );
    CHECK( test_trace.option_levels[TEST_TRACE_RULE_VARS] == LOG_LEVEL_TEST );
    CHECK( test_trace.option_levels[TEST_TRACE_OPTION_TREE] == LOG_LEVEL_TEST );

    trace_val.set(&p4);
    result = test_trace.set(trace_val);
    CHECK( result == true );
    CHECK( test_trace.option_levels[TEST_TRACE_DETECTION_ENGINE] == LOG_LEVEL_TEST );
    CHECK( test_trace.option_levels[TEST_TRACE_RULE_VARS] == LOG_LEVEL_TEST );
    CHECK( test_trace.option_levels[TEST_TRACE_OPTION_TREE] == LOG_LEVEL_TEST );
    CHECK( test_trace.option_levels[TEST_TRACE_TAG] == LOG_LEVEL_TEST );
}

TEST_CASE("Trace - incorrect trace value", "[trace]")
{
    Trace test_trace("test");
    Parameter p("test", Parameter::PT_INT, "0:255", "0", "p");
    Value trace_val("trace");
    trace_val.set(&p);
    trace_val.set_enum(1);

    bool result = test_trace.set(trace_val);
    CHECK( result == false );
    CHECK( test_trace.option_levels[DEFAULT_TRACE_OPTION] == TraceLevel(0) );
}

#endif // UNIT_TEST


//--------------------------------------------------------------------------
// Copyright (C) 2014-2020 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snort_debug.h"

#include <cstring>

#include "trace/trace_log_api.h"
#include "utils/safec.h"

#define STD_BUF_SIZE 1024

namespace snort
{
template <void (log_func)(const char*, const char*, uint8_t, const char*)>
void trace_vprintf(const char* name, TraceLevel log_level,
    const char* trace_option, const char* fmt, va_list ap)
{
    char buf[STD_BUF_SIZE];
    vsnprintf(buf, sizeof(buf), fmt, ap);

    log_func(buf, name, log_level, trace_option);
}

void trace_vprintf(const char* name, TraceLevel log_level,
    const char* trace_option, const char* fmt, va_list ap)
{
    trace_vprintf<TraceLogApi::log>(name, log_level, trace_option, fmt, ap);
}
}

#ifdef UNIT_TEST
#include <catch/snort_catch.h>

#ifdef DEBUG_MSGS

using namespace snort;

//stringify the expansion of the macro
#define sx(code) sm(code)

//stringify the macro
#define sm(code) #code

struct TestCase
{
    const char* test;
    const char* expected;
};

static char testing_dump[STD_BUF_SIZE];

void test_log(const char* log_msg, const char* name,
    uint8_t log_level, const char* trace_option)
{
    snprintf(testing_dump, sizeof(testing_dump), "%s:%s:%d: %s",
        name, trace_option, log_level, log_msg);
}

TEST_CASE("macros", "[trace]")
{
    TestCase cases[] =
    {
        {
            sx(debug_log(1, testing, "my message")),
            "trace_print<snort::trace_vprintf>(1, testing, \"my message\")"
        },
        {
            sx(debug_log(testing, my_flags, "my message")),
            "trace_print<snort::trace_vprintf>(testing, my_flags, \"my message\")"
        },
        {
            sx(debug_logf(1, testing, "%s %s", "my", "message")),
            "trace_printf<snort::trace_vprintf>(1, testing, \"%s %s\", \"my\", \"message\")"
        },
        {
            sx(debug_logf(testing, my_flags, "%s %s", "my", "message")),
            "trace_printf<snort::trace_vprintf>(testing, my_flags, \"%s %s\", \"my\", \"message\")"
        }
    };

    CHECK( !strcmp(cases[0].expected, cases[0].test) );
    CHECK( !strcmp(cases[1].expected, cases[1].test) );
    CHECK( !strcmp(cases[2].expected, cases[2].test) );
    CHECK( !strcmp(cases[3].expected, cases[3].test) );
}

#undef trace_print
#undef trace_printf

//These templates expand to replace the default expansion of trace_vprintf.
//This custom expansion replaces log_func (expands to TraceLogApi::log())
//with test_log for capturing what would be passed to the console.
#define trace_print trace_print<trace_vprintf<test_log>>
#define trace_printf trace_printf<trace_vprintf<test_log>>

enum
{
    TEST_TRACE_OPTION1 = 0,
    TEST_TRACE_OPTION2,
    TEST_TRACE_OPTION3,
    TEST_TRACE_OPTION4,
    TEST_TRACE_OPTION5,
};

const TraceOptionString test_trace_values[] =
{
    { "option1", TEST_TRACE_OPTION1 },
    { "option2", TEST_TRACE_OPTION2 },
    { "option3", TEST_TRACE_OPTION3 },
    { "option4", TEST_TRACE_OPTION4 },
    { "option5", TEST_TRACE_OPTION5 },
};

TEST_CASE("Trace logging", "[trace]")
{
    SECTION("trace all=0")
    {
        Trace test("test");

        Parameter p("all", Parameter::PT_INT, "0:255", "0", "enable traces in module");
        Value trace_val((double)0);
        trace_val.set(&p);

        test.set(trace_val);

        testing_dump[0] = '\0';
        debug_log(test, "my message");
        CHECK( testing_dump[0] == '\0' );
    }
    SECTION("debug_log")
    {
        Trace test("test");

        Parameter p("all", Parameter::PT_INT, "0:255", "0", "enable traces in module");
        Value trace_val((double)1);
        trace_val.set(&p);

        test.set(trace_val);

        testing_dump[0] = '\0';
        debug_log(test, "my message");
        CHECK( !strcmp(testing_dump, "test:all:1: my message") );

        Parameter p_all("all", Parameter::PT_INT, "0:255", "0", "p_all");
        Parameter p1("option1", Parameter::PT_INT, "0:255", "0", "p1");
        Parameter p2("option3", Parameter::PT_INT, "0:255", "0", "p2");
        Value trace_val1("trace");

        Trace testing_opt("testing_opt", test_trace_values,
            (sizeof(test_trace_values) / sizeof(TraceOptionString)));

        // set log_level = 1 for TEST_TRACE_OPTION1
        trace_val1.set(&p1);
        trace_val1.set_enum(1);
        testing_opt.set(trace_val1);

        // set log_level = 5 for TEST_TRACE_OPTION3
        trace_val1.set(&p2);
        trace_val1.set_enum(5);
        testing_opt.set(trace_val1);

        // set log_level = 2 for TEST_TRACE_OPTION2, TEST_TRACE_OPTION4, TEST_TRACE_OPTION5
        trace_val1.set(&p_all);
        trace_val1.set_enum(2);
        testing_opt.set(trace_val1);

        testing_dump[0] = '\0';
        debug_log(testing_opt, TEST_TRACE_OPTION1, "my other masked message");
        CHECK( !strcmp(testing_dump, "testing_opt:option1:1: my other masked message") );

        testing_dump[0] = '\0';
        debug_log(3, testing_opt, TEST_TRACE_OPTION2, "log option2 message");
        CHECK( testing_dump[0] == '\0' );

        testing_dump[0] = '\0';
        debug_log(testing_opt, TEST_TRACE_OPTION2, "log option2 message");
        CHECK( !strcmp(testing_dump, "testing_opt:option2:1: log option2 message") );

        testing_dump[0] = '\0';
        debug_log(6, testing_opt, TEST_TRACE_OPTION3, "log option3 message");
        CHECK( testing_dump[0] == '\0' );

        testing_dump[0] = '\0';
        debug_log(3, testing_opt, TEST_TRACE_OPTION3, "log option3 message");
        CHECK( !strcmp(testing_dump, "testing_opt:option3:3: log option3 message") );

        testing_dump[0] = '\0';
        debug_log(2, testing_opt, TEST_TRACE_OPTION4, "log option4 message");
        CHECK( !strcmp(testing_dump, "testing_opt:option4:2: log option4 message") );

        testing_dump[0] = '\0';
        debug_log(4, testing_opt, TEST_TRACE_OPTION5, "log option5 message");
        CHECK( testing_dump[0] == '\0' );
    }
    SECTION("debug_logf")
    {
        Trace test("test");

        Parameter p("all", Parameter::PT_INT, "0:255", "0", "enable traces in module");
        Value trace_val((double)1);
        trace_val.set(&p);
        test.set(trace_val);

        testing_dump[0] = '\0';
        debug_logf(test, "%s %s", "my", "message");
        CHECK( !strcmp(testing_dump, "test:all:1: my message") );

        Parameter p_all("all", Parameter::PT_INT, "0:255", "0", "p_all");
        Parameter p1("option1", Parameter::PT_INT, "0:255", "0", "p1");
        Parameter p2("option3", Parameter::PT_INT, "0:255", "0", "p2");
        Value trace_val1("trace");

        Trace testing_opt("testing_opt", test_trace_values,
            (sizeof(test_trace_values) / sizeof(TraceOptionString)));

        // set log_level = 1 for TEST_TRACE_OPTION1
        trace_val1.set(&p1);
        trace_val1.set_enum(1);
        testing_opt.set(trace_val1);

        // set log_level = 5 for TEST_TRACE_OPTION3
        trace_val1.set(&p2);
        trace_val1.set_enum(5);
        testing_opt.set(trace_val1);

        // set log_level = 3 for TEST_TRACE_OPTION2, TEST_TRACE_OPTION4, TEST_TRACE_OPTION5
        trace_val1.set(&p_all);
        trace_val1.set_enum(3);
        testing_opt.set(trace_val1);

        testing_dump[0] = '\0';
        debug_logf(testing_opt, TEST_TRACE_OPTION1, "%s %s %s", "log", "option1", "message");
        CHECK( !strcmp(testing_dump, "testing_opt:option1:1: log option1 message") );

        testing_dump[0] = '\0';
        debug_logf(testing_opt, TEST_TRACE_OPTION2, "%s %s %s", "log", "option2", "message");
        CHECK( !strcmp(testing_dump, "testing_opt:option2:1: log option2 message") );

        testing_dump[0] = '\0';
        debug_logf(4, testing_opt, TEST_TRACE_OPTION2, "%s %s %s", "log", "option2", "message");
        CHECK( testing_dump[0] == '\0' );

        testing_dump[0] = '\0';
        debug_logf(3, testing_opt, TEST_TRACE_OPTION3, "%s %s %s", "log", "option3", "message");
        CHECK( !strcmp(testing_dump, "testing_opt:option3:3: log option3 message") );

        testing_dump[0] = '\0';
        debug_logf(6, testing_opt, TEST_TRACE_OPTION3, "%s %s %s", "log", "option3", "message");
        CHECK( testing_dump[0] == '\0' );

        testing_dump[0] = '\0';
        debug_logf(2, testing_opt, TEST_TRACE_OPTION4, "%s %s %s", "log", "option4", "message");
        CHECK( !strcmp(testing_dump, "testing_opt:option4:2: log option4 message") );

        testing_dump[0] = '\0';
        debug_logf(4, testing_opt, TEST_TRACE_OPTION5, "%s %s %s", "log", "option5", "message");
        CHECK( testing_dump[0] == '\0' );
    }
    SECTION("safety")
    {
        Trace test("test");

        Parameter p("all", Parameter::PT_INT, "0:255", "0", "enable traces in module");
        Value trace_val((double)1);
        trace_val.set(&p);

        test.set(trace_val);

        char message[STD_BUF_SIZE + 1];

        for( int i = 0; i < STD_BUF_SIZE; i++ )
            message[i] = 'A';
        message[STD_BUF_SIZE] = '\0';

        testing_dump[0] = '\0';
        debug_log(test, message);
        CHECK( (strlen(testing_dump) == STD_BUF_SIZE - 1) );

        Trace testing_opt("testing_opt", test_trace_values,
            (sizeof(test_trace_values) / sizeof(TraceOptionString)));

        Parameter p1("option3", Parameter::PT_INT, "0:255", "0", "p1");
        Value trace_val1("trace");
        trace_val1.set(&p1);
        trace_val1.set_enum(5);
        testing_opt.set(trace_val1);

        testing_dump[0] = '\0';
        debug_log(3, testing_opt, TEST_TRACE_OPTION3, message);
        CHECK( (strlen(testing_dump) == STD_BUF_SIZE - 1) );

        testing_dump[0] = '\0';
        debug_log(6, testing_opt, TEST_TRACE_OPTION3, message);
        CHECK( (strlen(testing_dump) == 0) );
    }
}

#endif  // DEBUG_MSGS

#endif  // UNIT_TEST


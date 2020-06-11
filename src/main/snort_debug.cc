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

#include "trace/trace_api.h"
#include "utils/safec.h"

#define STD_BUF_SIZE 1024

namespace snort
{
template <void (log_func)(const char*, const char*, uint8_t, const char*, const Packet*)>
void trace_vprintf(const char* name, TraceLevel log_level,
    const char* trace_option, const Packet* p, const char* fmt, va_list ap)
{
    char buf[STD_BUF_SIZE];
    vsnprintf(buf, sizeof(buf), fmt, ap);

    log_func(buf, name, log_level, trace_option, p);
}

void trace_vprintf(const char* name, TraceLevel log_level,
    const char* trace_option, const Packet* p, const char* fmt, va_list ap)
{
    trace_vprintf<TraceApi::log>(name, log_level, trace_option, p, fmt, ap);
}
}

#ifdef UNIT_TEST
#include <catch/snort_catch.h>

#ifdef DEBUG_MSGS

#include "framework/module.h"

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

static void test_log(const char* log_msg, const char* name,
    uint8_t log_level, const char* trace_option, const snort::Packet*)
{
    snprintf(testing_dump, sizeof(testing_dump), "%s:%s:%d: %s",
        name, trace_option, log_level, log_msg);
}

TEST_CASE("macros", "[trace]")
{
    TestCase cases[] =
    {
        {
            sx(debug_log(1, test_trace, "my message")),
            "trace_print<snort::trace_vprintf>(1, test_trace, \"my message\")"
        },
        {
            sx(debug_log(test_trace, my_flags, "my message")),
            "trace_print<snort::trace_vprintf>(test_trace, my_flags, \"my message\")"
        },
        {
            sx(debug_logf(1, test_trace, "%s %s", "my", "message")),
            "trace_printf<snort::trace_vprintf>(1, test_trace, \"%s %s\", \"my\", \"message\")"
        },
        {
            sx(debug_logf(test_trace, my_flags, "%s %s", "my", "message")),
            "trace_printf<snort::trace_vprintf>(test_trace, my_flags, \"%s %s\", \"my\", \"message\")"
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
//This custom expansion replaces log_func (expands to TraceApi::log())
//with test_log for capturing what would be passed to the console.
#define trace_print trace_print<trace_vprintf<test_log>>
#define trace_printf trace_printf<trace_vprintf<test_log>>

class TraceTestModule : public Module
{
public:
    TraceTestModule(const char* name, const TraceOption* trace_options) :
        Module(name, "trace_test_help"), test_trace_options(trace_options)
    { }

    virtual const TraceOption* get_trace_options() const
    { return test_trace_options; }

private:
    const TraceOption* test_trace_options;
};

TEST_CASE("debug_log, debug_logf", "[trace]")
{
    enum
    {
        TEST_TRACE_OPTION1 = 0,
        TEST_TRACE_OPTION2,
        TEST_TRACE_OPTION3,
        TEST_TRACE_OPTION4,
        TEST_TRACE_OPTION5,
    };

    const TraceOption test_trace_values[] =
    {
        { "option1", TEST_TRACE_OPTION1, "help_option1" },
        { "option2", TEST_TRACE_OPTION2, "help_option2" },
        { "option3", TEST_TRACE_OPTION3, "help_option3" },
        { "option4", TEST_TRACE_OPTION4, "help_option4" },
        { "option5", TEST_TRACE_OPTION5, "help_option5" },

        { nullptr, 0, nullptr },
    };

    TraceOption test_trace_options(nullptr, 0, nullptr);
    TraceTestModule trace_test_module("test_module", &test_trace_options);
    Trace test_trace(trace_test_module);

    TraceTestModule trace_test_module_opt("test_opt_module", test_trace_values);
    Trace test_opt_trace(trace_test_module_opt);

    test_trace.set("all", 0);

    testing_dump[0] = '\0';
    debug_log(&test_trace, nullptr, "my message");
    CHECK( testing_dump[0] == '\0' );

    test_trace.set("all", 1);
    test_opt_trace.set("option1", 1);
    test_opt_trace.set("option2", 2);
    test_opt_trace.set("option3", 3);
    test_opt_trace.set("option4", 2);
    test_opt_trace.set("option5", 2);

    char message[STD_BUF_SIZE + 1];
    for( int i = 0; i < STD_BUF_SIZE; i++ )
        message[i] = 'A';
    message[STD_BUF_SIZE] = '\0';

    testing_dump[0] = '\0';
    debug_log(&test_trace, nullptr, message);
    CHECK( (strlen(testing_dump) == STD_BUF_SIZE - 1) );

    testing_dump[0] = '\0';
    debug_log(3, &test_opt_trace, TEST_TRACE_OPTION3, nullptr, message);
    CHECK( (strlen(testing_dump) == STD_BUF_SIZE - 1) );

    testing_dump[0] = '\0';
    debug_log(6, &test_opt_trace, TEST_TRACE_OPTION3, nullptr, message);
    CHECK( (strlen(testing_dump) == 0) );

    testing_dump[0] = '\0';
    debug_log(&test_trace, nullptr, "my message"); 
    CHECK( !strcmp(testing_dump, "test_module:all:1: my message") );

    testing_dump[0] = '\0';
    debug_logf(&test_trace, nullptr, "%s %s", "my", "message");
    CHECK( !strcmp(testing_dump, "test_module:all:1: my message") );

    testing_dump[0] = '\0';
    debug_log(&test_opt_trace, TEST_TRACE_OPTION1, nullptr, "log option1 message");
    CHECK( !strcmp(testing_dump, "test_opt_module:option1:1: log option1 message") );

    testing_dump[0] = '\0';
    debug_logf(&test_opt_trace, TEST_TRACE_OPTION1, nullptr, "%s %s %s", "log", "option1", "message");
    CHECK( !strcmp(testing_dump, "test_opt_module:option1:1: log option1 message") );

    testing_dump[0] = '\0';
    debug_log(3, &test_opt_trace, TEST_TRACE_OPTION2, nullptr, "log option2 message");
    CHECK( testing_dump[0] == '\0' );

    testing_dump[0] = '\0';
    debug_log(&test_opt_trace, TEST_TRACE_OPTION2, nullptr, "log option2 message");
    CHECK( !strcmp(testing_dump, "test_opt_module:option2:1: log option2 message") );

    testing_dump[0] = '\0';
    debug_logf(&test_opt_trace, TEST_TRACE_OPTION2, nullptr, "%s %s %s", "log", "option2", "message");
    CHECK( !strcmp(testing_dump, "test_opt_module:option2:1: log option2 message") );

    testing_dump[0] = '\0';
    debug_log(6, &test_opt_trace, TEST_TRACE_OPTION3, nullptr, "log option3 message");
    CHECK( testing_dump[0] == '\0' );

    testing_dump[0] = '\0';
    debug_log(3, &test_opt_trace, TEST_TRACE_OPTION3, nullptr, "log option3 message");
    CHECK( !strcmp(testing_dump, "test_opt_module:option3:3: log option3 message") );

    testing_dump[0] = '\0';
    debug_logf(3, &test_opt_trace, TEST_TRACE_OPTION3, nullptr, "%s %s %s", "log", "option3", "message");
    CHECK( !strcmp(testing_dump, "test_opt_module:option3:3: log option3 message") );

    testing_dump[0] = '\0';
    debug_log(2, &test_opt_trace, TEST_TRACE_OPTION4, nullptr, "log option4 message");
    CHECK( !strcmp(testing_dump, "test_opt_module:option4:2: log option4 message") );

    testing_dump[0] = '\0';
    debug_logf(2, &test_opt_trace, TEST_TRACE_OPTION4, nullptr, "%s %s %s", "log", "option4", "message");
    CHECK( !strcmp(testing_dump, "test_opt_module:option4:2: log option4 message") );

    testing_dump[0] = '\0';
    debug_log(4, &test_opt_trace, TEST_TRACE_OPTION5, nullptr, "log option5 message");
    CHECK( testing_dump[0] == '\0' );
}

#endif // DEBUG_MSGS

#endif // UNIT_TEST


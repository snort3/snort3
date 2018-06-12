//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#include <syslog.h>

#include <cstring>

#include "log/messages.h"
#include "utils/safec.h"

#include "snort_config.h"

using namespace snort;

bool trace_enabled(Trace mask, Trace flags)
{ return mask & flags; }

bool trace_enabled(Trace mask)
{ return mask; }

template <int (output)(const char*, FILE*)>
static inline void trace_vprintf(const char* name, Trace mask, const char* file, int line,
    Trace flags, const char* fmt, va_list ap)
{
    if ( !trace_enabled(mask, flags) )
        return;

    char buf[STD_BUF];
    int buf_len = sizeof(buf);
    char* buf_ptr = buf;
    int size;

    if (name)
    {   
        size = snprintf(buf, buf_len, "%s: ", name);
        if ( size >= buf_len )
            size = buf_len - 1;
        if ( size > 0 )
        {
            buf_ptr += size;
            buf_len -= size;
        }
    }

    if ( file )
    {
        size = snprintf(buf_ptr, buf_len, "%s:%d: ", file, line);
        if ( size >= buf_len )
            size = buf_len - 1;
        if ( size > 0 )
        {
            buf_ptr += size;
            buf_len -= size;
        }
    }

    vsnprintf(buf_ptr, buf_len, fmt, ap);

    if ( snort::SnortConfig::get_conf() and snort::SnortConfig::log_syslog() )
        syslog(LOG_DAEMON | LOG_DEBUG, "%s", buf);
    else
        output(buf, stdout);
}

void trace_vprintf(const char* name, Trace mask, const char* file, int line,
    Trace flags, const char* fmt, va_list ap)
{
    trace_vprintf<fputs>(name, mask, file, line, flags, fmt, ap);
}

#ifdef UNIT_TEST
#include <catch/snort_catch.h>

//stringify the expansion of the macro
#define sx(code) sm(code)

//stringify the macro
#define sm(code) #code

#define TRACE_SECTION_1 0x0000000000000001
#define TRACE_SECTION_2 0x0000000000000002
#define TRACE_SECTION_3 0x0000000000000004
#define TRACE_SECTION_4 0x0000000000000008

struct TestCase
{
    const char* test;
    const char* expected;
};

static char testing_dump[STD_BUF];
static int test_fputs(const char* str, FILE*)
{
    memcpy_s(testing_dump, STD_BUF, str, STD_BUF);

    return 0;
}

TEST_CASE("macros", "[trace]")
{
    TestCase cases[] =
    {
        {
            sx(trace_log(testing, "my message")),
            "trace_print<trace_vprintf>(\"testing\", testing_trace, nullptr, 0, \"my message\")"
        },
        {
            sx(trace_log(testing, my_flags, "my message")),
            "trace_print<trace_vprintf>(\"testing\", testing_trace, nullptr, 0, my_flags, \"my message\")"
        },
        {
            sx(trace_logf(testing, "%s %s", "my", "message")),
            "trace_printf<trace_vprintf>(\"testing\", testing_trace, nullptr, 0, \"%s %s\", \"my\", \"message\")"
        },
        {
            sx(trace_logf(testing, my_flags, "%s %s", "my", "message")),
            "trace_printf<trace_vprintf>(\"testing\", testing_trace, nullptr, 0, my_flags, \"%s %s\", \"my\", \"message\")"
        },
        {
            sx(trace_debug(testing, "my message")), "trace_print<trace_vprintf>(\"testing\", testing_trace, " sx(__FILE__) ", " sx(__LINE__) ", \"my message\")"
        },
        {
            sx(trace_debug(testing, my_flags, "my message")), "trace_print<trace_vprintf>(\"testing\", testing_trace, " sx(__FILE__) ", " sx(__LINE__) ", my_flags, \"my message\")"
        },
        {
            sx(trace_debugf(testing, "%s %s", "my", "message")), "trace_printf<trace_vprintf>(\"testing\", testing_trace, " sx(__FILE__) ", " sx(__LINE__) ", \"%s %s\", \"my\", \"message\")"
        },
        {
            sx(trace_debugf(testing, my_flags, "%s %s", "my", "message")), "trace_printf<trace_vprintf>(\"testing\", testing_trace, " sx(__FILE__) ", " sx(__LINE__) ", my_flags, \"%s %s\", \"my\", \"message\")"
        }
    };

    CHECK( !strcmp(cases[0].expected, cases[0].test) );
    CHECK( !strcmp(cases[1].expected, cases[1].test) );
    CHECK( !strcmp(cases[2].expected, cases[2].test) );
    CHECK( !strcmp(cases[3].expected, cases[3].test) );
    CHECK( !strcmp(cases[4].expected, cases[4].test) );
    CHECK( !strcmp(cases[5].expected, cases[5].test) );
    CHECK( !strcmp(cases[6].expected, cases[6].test) );
    CHECK( !strcmp(cases[7].expected, cases[7].test) );
}

#undef trace_print
#undef trace_printf

//These templates expand to replace the default expansion of trace_vprintf.
//This custom expansion replaces output (expands to fputs in snort_debug.h macros)
//with test_fputs for capturing what would be passed to the console.
#define trace_print trace_print<trace_vprintf<test_fputs>>
#define trace_printf trace_printf<trace_vprintf<test_fputs>>

TEST_CASE("trace_log", "[trace]")
{
    Trace TRACE_NAME(testing) = TRACE_SECTION_2 | TRACE_SECTION_3;

    testing_dump[0] = '\0';
    trace_log(testing, "my message");
    CHECK( !strcmp(testing_dump, "testing: my message") );

    testing_dump[0] = '\0';
    trace_log(testing, TRACE_SECTION_1, "my masked message");
    CHECK( testing_dump[0] == '\0' );

    testing_dump[0] = '\0';
    trace_log(testing, TRACE_SECTION_2, "my other masked message");
    CHECK( !strcmp(testing_dump, "testing: my other masked message") );
}

TEST_CASE("trace_logf", "[trace]")
{
    Trace TRACE_NAME(testing) = TRACE_SECTION_2 | TRACE_SECTION_3;

    testing_dump[0] = '\0';
    trace_logf(testing, "%s %s", "my", "message");
    CHECK( !strcmp(testing_dump, "testing: my message") );

    testing_dump[0] = '\0';
    trace_logf(testing, TRACE_SECTION_1, "%s %s %s", "my", "masked", "message");
    CHECK( testing_dump[0] == '\0' );

    testing_dump[0] = '\0';
    trace_logf(testing, TRACE_SECTION_2, "%s %s %s %s", "my", "other", "masked", "message");
    CHECK( !strcmp(testing_dump, "testing: my other masked message") );
}

TEST_CASE("trace_debug", "[trace]")
{
    Trace TRACE_NAME(testing) = TRACE_SECTION_2 | TRACE_SECTION_3;

    testing_dump[0] = '\0';
    trace_debug(testing, "my message"); CHECK( !strcmp(testing_dump, "testing: " __FILE__ ":" sx(__LINE__) ": my message") );

    testing_dump[0] = '\0';
    trace_debug(testing, TRACE_SECTION_1, "my masked message");
    CHECK( testing_dump[0] == '\0' );

    testing_dump[0] = '\0';
    trace_debug(testing, TRACE_SECTION_2, "my other masked message"); CHECK( !strcmp(testing_dump, "testing: " __FILE__ ":" sx(__LINE__) ": my other masked message") );
}

TEST_CASE("trace_debugf", "[trace]")
{
    Trace TRACE_NAME(testing) = TRACE_SECTION_2 | TRACE_SECTION_3;

    testing_dump[0] = '\0';
    trace_debugf(testing, "%s %s", "my", "message"); CHECK( !strcmp(testing_dump, "testing: " __FILE__ ":" sx(__LINE__) ": my message") );

    testing_dump[0] = '\0';
    trace_debugf(testing, TRACE_SECTION_1, "%s %s %s", "my", "masked", "message");
    CHECK( testing_dump[0] == '\0' );

    testing_dump[0] = '\0';
    trace_debugf(testing, TRACE_SECTION_2, "%s %s %s %s", "my", "other", "masked", "message"); CHECK( !strcmp(testing_dump, "testing: " __FILE__ ":" sx(__LINE__) ": my other masked message") );
}

TEST_CASE("safety", "[trace]")
{
    Trace TRACE_NAME(testing) = TRACE_SECTION_2 | TRACE_SECTION_3;
    char message[STD_BUF + 1];

    for( int i = 0; i < STD_BUF; i++ )
        message[i] = 'A';
    message[STD_BUF] = '\0';

    testing_dump[0] = '\0';
    trace_log(testing, message);
    CHECK( (strlen(testing_dump) == STD_BUF - 1) );
}

#endif


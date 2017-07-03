//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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

#include "messages.h"

#include <syslog.h>

#include <cassert>
#include <cstdarg>
#include <cstring>

#include "main/snort_config.h"
#include "parser/parser.h"
#include "time/packet_time.h"
#include "utils/util_cstring.h"

#ifdef UNIT_TEST
#include "catch/catch.hpp"
#endif

static int already_fatal = 0;

static unsigned parse_errors = 0;
static unsigned parse_warnings = 0;

unsigned get_parse_errors()
{
    unsigned tmp = parse_errors;
    parse_errors = 0;
    return tmp;
}

unsigned get_parse_warnings()
{
    unsigned tmp = parse_warnings;
    parse_warnings = 0;
    return tmp;
}

static void log_message(const char* type, const char* msg)
{
    const char* file_name;
    unsigned file_line;
    get_parse_location(file_name, file_line);

    if ( file_line )
        LogMessage("%s: %s:%d %s\n", type, file_name, file_line, msg);
    else
        LogMessage("%s: %s\n", type, msg);
}

void ParseMessage(const char* format, ...)
{
    char buf[STD_BUF+1];
    va_list ap;

    va_start(ap, format);
    vsnprintf(buf, STD_BUF, format, ap);
    va_end(ap);

    buf[STD_BUF] = '\0';
    log_message("INFO", buf);
}

void ParseWarning(WarningGroup wg, const char* format, ...)
{
    if ( !(snort_conf->warning_flags & (1 << wg)) )
        return;

    char buf[STD_BUF+1];
    va_list ap;

    va_start(ap, format);
    vsnprintf(buf, STD_BUF, format, ap);
    va_end(ap);

    buf[STD_BUF] = '\0';
    log_message("WARNING", buf);

    parse_warnings++;
}

void ParseError(const char* format, ...)
{
    char buf[STD_BUF+1];
    va_list ap;

    va_start(ap, format);
    vsnprintf(buf, STD_BUF, format, ap);
    va_end(ap);

    buf[STD_BUF] = '\0';
    log_message("ERROR", buf);

    parse_errors++;
}

NORETURN void ParseAbort(const char* format, ...)
{
    char buf[STD_BUF+1];
    va_list ap;

    va_start(ap, format);
    vsnprintf(buf, STD_BUF, format, ap);
    va_end(ap);

    buf[STD_BUF] = '\0';

    const char* file_name;
    unsigned file_line;
    get_parse_location(file_name, file_line);

    if ( file_line )
        FatalError("%s:%u %s\n", file_name, file_line, buf);
    else
        FatalError("%s\n", buf);
}

static void WriteLogMessage(FILE* fh, bool prefer_fh, const char* format, va_list& ap)
{
    char buf[STD_BUF+1];

    if ( snort_conf && !prefer_fh )
    {
        if ( SnortConfig::log_quiet() )
            return;

        if ( SnortConfig::log_syslog() )
        {
            vsnprintf(buf, STD_BUF, format, ap);
            buf[STD_BUF] = '\0';
            syslog(LOG_DAEMON | LOG_NOTICE, "%s", buf);
            return;
        }
    }
    vfprintf(fh, format, ap);
}

/*
 * Function: LogMessage(const char *, ...)
 *
 * Purpose: Print a message to stdout or with logfacility.
 *
 * Arguments: format => the formatted error string to print out
 *            ... => format commands/fillers
 *
 * Returns: void function
 */
void LogMessage(const char* format,...)
{
    va_list ap;
    va_start(ap, format);

    WriteLogMessage(stdout, false, format, ap);

    va_end(ap);
}

void LogMessage(FILE* fh, const char* format,...)
{
    va_list ap;
    va_start(ap, format);

    WriteLogMessage(fh, fh != stdout, format, ap);

    va_end(ap);
}

/*
 * Function: WarningMessage(const char *, ...)
 *
 * Purpose: Print a message to stderr or with logfacility.
 *
 * Arguments: format => the formatted error string to print out
 *            ... => format commands/fillers
 *
 * Returns: void function
 */
void WarningMessage(const char* format,...)
{
    char buf[STD_BUF+1];
    va_list ap;

    if ( snort_conf and SnortConfig::log_quiet() )
        return;

    va_start(ap, format);

    if ( snort_conf and SnortConfig::log_syslog() )
    {
        vsnprintf(buf, STD_BUF, format, ap);
        buf[STD_BUF] = '\0';
        syslog(LOG_DAEMON | LOG_WARNING, "%s", buf);
    }
    else
    {
        vfprintf(stderr, format, ap);
    }

    va_end(ap);
}

/*
 * Function: ErrorMessage(const char *, ...)
 *
 * Purpose: Print a message to stderr.
 *
 * Arguments: format => the formatted error string to print out
 *            ... => format commands/fillers
 *
 * Returns: void function
 */
void ErrorMessage(const char* format,...)
{
    char buf[STD_BUF+1];
    va_list ap;

    va_start(ap, format);

    if ( snort_conf and SnortConfig::log_syslog() )
    {
        vsnprintf(buf, STD_BUF, format, ap);
        buf[STD_BUF] = '\0';
        syslog(LOG_CONS | LOG_DAEMON | LOG_ERR, "%s", buf);
    }
    else
    {
        vfprintf(stderr, format, ap);
    }
    va_end(ap);
}

ThrottledErrorLogger::ThrottledErrorLogger(uint32_t dur) :
    throttle_duration { dur }
{ reset(); }

bool ThrottledErrorLogger::log(const char* format, ...)
{
    if ( !snort_conf )
        return false;

    if ( throttle() )
        return false;

    va_list ap;

    va_start(ap, format);
    int index = vsnprintf(buf, STD_BUF, format, ap);
    va_end(ap);

    if ( index && ( count > 1 ) )
        snprintf(&buf[index - 1], STD_BUF - index,
            " (suppressed " STDu64 " times in the last %d seconds).\n",
            count, delta);

    ErrorMessage("%s", buf);
    return true;
}

void ThrottledErrorLogger::reset()
{ count = 0; }

bool ThrottledErrorLogger::throttle()
{
    time_t cur = packet_time();
    bool result = false;

    if ( count++ )
    {
        delta = cur - last;
        result = (decltype(throttle_duration))delta < throttle_duration;

        if ( !result )
            count = 0;
    }

    last = cur;

    return result;
}

/*
 * Function: FatalError(const char *, ...)
 *
 * Purpose: When a fatal error occurs, this function prints the error message
 *          and cleanly shuts down the program
 *
 * Arguments: format => the formatted error string to print out
 *            ... => format commands/fillers
 *
 * Returns: void function
 */
NORETURN void FatalError(const char* format,...)
{
    char buf[STD_BUF+1];
    va_list ap;

    // -----------------------------
    // bail now if we are reentering
    if ( already_fatal )
        exit(1);
    else
        already_fatal = 1;
    // -----------------------------

    va_start(ap, format);
    vsnprintf(buf, STD_BUF, format, ap);
    va_end(ap);

    buf[STD_BUF] = '\0';

    if ( snort_conf and SnortConfig::log_syslog() )
    {
        syslog(LOG_CONS | LOG_DAEMON | LOG_ERR, "FATAL ERROR: %s", buf);
    }
    else
    {
        fprintf(stderr, "FATAL: %s", buf);
        fprintf(stderr,"Fatal Error, Quitting..\n");
    }

#if 0
    // FIXIT-M need to stop analyzers / workers
    // and they should handle the DAQ break / abort
    if ( SnortIsInitializing() )
    {
        DAQ_Abort();
        exit(1);
    }
    else
#endif
    {
        // FIXIT-M this makes no sense from main thread
        exit(EXIT_FAILURE);
    }
}

void log_safec_error(const char* msg, void*, int e)
{
    static THREAD_LOCAL unsigned safec_errors = 0;

    if ( ++safec_errors < 1000 )
        ErrorMessage("SafeC error %i: %s\n", e, msg);

    assert(false);
}

#ifdef UNIT_TEST

static void set_packet_time(time_t x)
{
    struct timeval t { x, 0 };
    packet_time_update(&t);
}

static bool check_message(const char* buffer, const char* msg)
{
    if ( strncmp(buffer, msg, strnlen(msg, STD_BUF)) != 0 )
    {
        INFO( buffer );
        return false;
    }

    return true;
}

TEST_CASE( "throttled error logger", "[ThrottledErrorLogger]" )
{
    uint32_t dur = 5;
    ThrottledErrorLogger logger(dur);

    set_packet_time(0);

    SECTION( "1st message" )
    {
        const char msg[] = "first message";
        REQUIRE( logger.log("%s\n", msg) );

        CHECK( check_message(logger.last_message(), msg) );
    }

    SECTION( "2nd message within 1 second" )
    {
        const char msg[] = "second message";
        logger.log(" ");

        REQUIRE_FALSE( logger.log("%s\n", msg) );
    }

    SECTION( "0 duration" )
    {
        logger.throttle_duration = 0;
        const char msg[] = "zero duration";

        logger.log(" "); // trigger throttling
        REQUIRE( logger.log("%s\n", msg) );

        CHECK( check_message(logger.last_message(), msg) );
    }

    SECTION( "message @ duration" )
    {
        const char msg[] = "at duration";
        logger.log(" "); // trigger throttling

        set_packet_time(dur - 1);
        CHECK_FALSE( logger.log("%s\n", msg) );
    }

    SECTION( "message after duration" )
    {
        const char msg[] = "after duration";
        logger.log(" "); // trigger throttling

        set_packet_time(dur);
        REQUIRE( logger.log("%s\n", msg) );

        CHECK( check_message(logger.last_message(), msg) );
    }

    SECTION( "reversed packet time" )
    {
        const char msg[] = "reversed packet time";

        set_packet_time(10);
        logger.log(" ");

        set_packet_time(4);
        REQUIRE( logger.log("%s\n", msg) );

        CHECK( check_message(logger.last_message(), msg) );
    }
}

#endif

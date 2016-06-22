//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "log/messages.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <dirent.h>
#include <fnmatch.h>

#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <pcap.h>
#include <string.h>
#include <grp.h>
#include <pwd.h>
#include <netdb.h>
#include <limits.h>
#include <fcntl.h>

#include "main/snort_config.h"
#include "main/snort_debug.h"
#include "packet_io/sfdaq.h"
#include "parser/parser.h"
#include "time/packet_time.h"
#include "time/timersub.h"
#include "sfip/sf_ip.h"

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

void ParseMessage(const char* format, ...)
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

   // FIXIT-L use same format filename/linenum as ParseWarning ( %s(%d) vs $s:%d )
   if ( file_name )
        LogMessage("%s(%d) %s\n", file_name, file_line, buf);
    else
        LogMessage("%s\n", buf);
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

    const char* file_name;
    unsigned file_line;
    get_parse_location(file_name, file_line);

    // FIXIT-L Why `file_line` here and `file_name` in ParseMessage?
    if ( file_line )
        LogMessage("WARNING: %s:%d %s\n", file_name, file_line, buf);
    else
        LogMessage("WARNING: %s\n", buf);

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

    const char* file_name;
    unsigned file_line;
    get_parse_location(file_name, file_line);

    if (file_line )
        LogMessage("ERROR: %s:%d %s\n", file_name, file_line, buf);
    else
        LogMessage("ERROR: %s\n", buf);

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

    // FIXIT-L Refer to ParseMessage above.
    if ( file_name )
        FatalError("%s(%u) %s\n", file_name, file_line, buf);
    else
        FatalError("%s\n", buf);
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
    char buf[STD_BUF+1];
    va_list ap;

    if ( !snort_conf )
    {
        va_start(ap, format);
        vfprintf(stdout, format, ap);
        va_end(ap);
        return;
    }
    if ( SnortConfig::log_quiet() )
        return;

    va_start(ap, format);

    if ( SnortConfig::log_syslog() )
    {
        vsnprintf(buf, STD_BUF, format, ap);
        buf[STD_BUF] = '\0';
        syslog(LOG_DAEMON | LOG_NOTICE, "%s", buf);
    }
    else
    {
        vfprintf(stdout, format, ap);
    }

    va_end(ap);
}

void LogMessage(FILE* fh, const char* format,...)
{
    if ( snort_conf &&
        ( !SnortConfig::log_quiet() || fh != stdout ))
    {
        va_list ap;

        va_start(ap, format);
        vfprintf(fh, format, ap);
        va_end(ap);
    }
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

void PrintPacketData(const uint8_t* data, const uint32_t len)
{
    uint32_t i, j;
    uint32_t total_len = 0;
    uint8_t hex_buf[16];
    uint8_t char_buf[16];
    const char* length_chars =
        "       0  1  2  3  4  5  6  7   8  9 10 11 12 13 14 15\n"
        "------------------------------------------------------\n";

    LogMessage("%s", length_chars);

    for (i = 0; i <= len; i++)
    {
        if ((i%16 == 0) && (i != 0))
        {
            LogMessage("%04x  ", total_len);
            total_len += 16;

            for (j = 0; j < 16; j++)
            {
                LogMessage("%02x ", hex_buf[j]);
                if (j == 7)
                    LogMessage(" ");
            }

            LogMessage(" ");

            for (j = 0; j < 16; j++)
            {
                LogMessage("%c", char_buf[j]);
                if (j == 7)
                    LogMessage(" ");
            }

            LogMessage("\n");
        }

        if (i == len)
            break;

        hex_buf[i%16] = data[i];

        if (isprint((int)data[i]))
            char_buf[i%16] = data[i];
        else
            char_buf[i%16] = '.';
    }

    if ((i-total_len) > 0)
    {
        LogMessage("%04x  ", total_len);

        for (j = 0; j < i-total_len; j++)
        {
            LogMessage("%02x ", hex_buf[j]);
            if (j == 7)
                LogMessage(" ");
        }

        if (j < 8)
            LogMessage(" ");
        LogMessage("%*s", (16-j)*3, "");
        LogMessage(" ");

        for (j = 0; j < i-total_len; j++)
        {
            LogMessage("%c", char_buf[j]);
            if (j == 7)
                LogMessage(" ");
        }
    }

    LogMessage("\n");
}

char* ObfuscateIpToText(const sfip_t* ip)
{
    static THREAD_LOCAL char ip_buf1[INET6_ADDRSTRLEN];
    static THREAD_LOCAL char ip_buf2[INET6_ADDRSTRLEN];
    static THREAD_LOCAL int buf_num = 0;
    int buf_size = INET6_ADDRSTRLEN;
    char* ip_buf;

    if (buf_num)
        ip_buf = ip_buf2;
    else
        ip_buf = ip_buf1;

    buf_num ^= 1;
    ip_buf[0] = 0;

    if (ip == NULL)
        return ip_buf;

    if (!sfip_is_set(snort_conf->obfuscation_net))
    {
        if (ip->is_ip6())
            SnortSnprintf(ip_buf, buf_size, "x:x:x:x::x:x:x:x");
        else
            SnortSnprintf(ip_buf, buf_size, "xxx.xxx.xxx.xxx");
    }
    else
    {
        sfip_t tmp;
        char* tmp_buf;

        sfip_copy(tmp, ip);

        if (sfip_is_set(snort_conf->homenet))
        {
            if (sfip_contains(&snort_conf->homenet, &tmp) == SFIP_CONTAINS)
                sfip_obfuscate(&snort_conf->obfuscation_net, &tmp);
        }
        else
        {
            sfip_obfuscate(&snort_conf->obfuscation_net, &tmp);
        }

        tmp_buf = sfip_to_str(&tmp);
        SnortSnprintf(ip_buf, buf_size, "%s", tmp_buf);
    }

    return ip_buf;
}

// FIXIT-M add throttling so we don't spam syslog
void log_safec_error(const char* msg, void*, int e)
{
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

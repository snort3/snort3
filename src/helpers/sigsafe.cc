//--------------------------------------------------------------------------
// Copyright (C) 2020-2023 Cisco and/or its affiliates. All rights reserved.
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
// sigsafe.cc author Michael Altizer <mialtize@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sigsafe.h"

#include <unistd.h>

#include <cassert>
#include <cstdarg>
#include <cstring>

/*
 * Signal safety of functions called from here (POSIX async-signal-safe requirement):
 *  strlen              POSIX.1-2016
 *  write               POSIX.1-2001
 */

static int sigsafe_format_uint64_dec(uint64_t num, char* buf, size_t buf_len)
{
    uint64_t divisor;
    size_t len, i;

    // ceil(log10(0xFFFFFFFFFFFFFFFF)) = 20 + 1 for '\0'
    if (buf_len > 21)
        buf_len = 21;

    for (len = 1, divisor = 10;
         len < buf_len - 1 && num / divisor;
         len++, divisor *= 10);

    for (i = len, divisor = 1; i > 0; i--, divisor *= 10)
        buf[i - 1] = '0' + ((num / divisor) % 10);

    buf[len] = '\0';
    return len;
}

static int sigsafe_format_uint64_hex(uint64_t num, char* buf, size_t buf_len)
{
    uint64_t divisor;
    size_t len, i;

    // log16(0xFFFFFFFFFFFFFFFF) = 16 + 1 for '\0'
    if (buf_len > 17)
        buf_len = 17;

    for (len = 1, divisor = 0x10;
         len < buf_len - 1 && num / divisor;
         len++, divisor *= 0x10);

    for (i = len, divisor = 1; i > 0; i--, divisor *= 0x10)
    {
        int val = (num / divisor) % 0x10;

        if (val < 10)
            buf[i - 1] = '0' + val;
        else
            buf[i - 1] = 'a' + val - 10;
    }

    buf[len] = '\0';
    return len;
}

static void sigsafe_vsnprintf(char* str, size_t size, const char* format, va_list ap)
{
    size_t fmt_idx = 0;
    size_t str_idx = 0;
    size_t fmt_len = strlen(format);
    char number[32];
    const char* string_arg;
    int64_t i64_arg;
    uint64_t u64_arg;
    size_t arg_len;
    bool negative;

    if (size == 0)
        return;

    for (; fmt_idx < fmt_len && str_idx < size - 1; fmt_idx++)
    {
        if (format[fmt_idx] != '%')
        {
            str[str_idx++] = format[fmt_idx];
            continue;
        }
        if (++fmt_idx >= fmt_len)
            break;

        bool zpad = false;
        if (format[fmt_idx] == '0')
        {
            zpad = true;
            if (++fmt_idx >= fmt_len)
                break;
        }

        size_t min_width = 0;
        if (format[fmt_idx] >= '1' && format[fmt_idx] <= '9')
        {
            while (format[fmt_idx] >= '0' && format[fmt_idx] <= '9')
            {
                min_width = min_width * 10 + (format[fmt_idx] - '0');
                if (++fmt_idx >= fmt_len)
                    break;
            }
            if (fmt_idx >= fmt_len)
                break;
        }

        switch(format[fmt_idx])
        {
            case 'd':
                i64_arg = va_arg(ap, int64_t);
                if (i64_arg < 0)
                {
                    negative = true;
                    u64_arg = -i64_arg;
                }
                else
                {
                    negative = false;
                    u64_arg = i64_arg;
                }
                arg_len = sigsafe_format_uint64_dec(u64_arg, number, sizeof(number));
                if (arg_len < min_width)
                {
                    for (size_t padding = arg_len; padding < min_width && str_idx < size - 1; padding++)
                    {
                        if (negative && ((padding == arg_len && zpad) || (padding + 1 == min_width && !zpad)))
                            str[str_idx++] = '-';
                        else
                            str[str_idx++] = zpad ? '0' : ' ';
                    }
                }
                else if (negative && str_idx < size - 1)
                    str[str_idx++] = '-';
                for (size_t arg_idx = 0; arg_idx < arg_len && str_idx < size - 1; arg_idx++)
                    str[str_idx++] = number[arg_idx];
                break;

            case 'u':
                u64_arg = va_arg(ap, uint64_t);
                arg_len = sigsafe_format_uint64_dec(u64_arg, number, sizeof(number));
                for (size_t padding = arg_len; padding < min_width && str_idx < size - 1; padding++)
                    str[str_idx++] = zpad ? '0' : ' ';
                for (size_t arg_idx = 0; arg_idx < arg_len && str_idx < size - 1; arg_idx++)
                    str[str_idx++] = number[arg_idx];
                break;

            case 's':
                string_arg = va_arg(ap, const char*);
                if (!string_arg)
                    string_arg = "(null)";
                arg_len = strlen(string_arg);
                for (size_t padding = arg_len; padding < min_width && str_idx < size - 1; padding++)
                    str[str_idx++] = ' ';
                for (size_t arg_idx = 0; arg_idx < arg_len && str_idx < size - 1; arg_idx++)
                    str[str_idx++] = string_arg[arg_idx];
                break;

            case 'x':
                u64_arg = va_arg(ap, uint64_t);
                arg_len = sigsafe_format_uint64_hex(u64_arg, number, sizeof(number));
                for (size_t padding = arg_len; padding < min_width && str_idx < size - 1; padding++)
                    str[str_idx++] = zpad ? '0' : ' ';
                for (size_t arg_idx = 0; arg_idx < arg_len && str_idx < size - 1; arg_idx++)
                    str[str_idx++] = number[arg_idx];
                break;

            default:
                break;
        }
    }

    str[str_idx] = '\0';
}

static void sigsafe_snprintf(char* str, size_t size, const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    sigsafe_vsnprintf(str, size, format, ap);
    va_end(ap);
}

SigSafePrinter::SigSafePrinter(char *buf, size_t size) : buf(buf), buf_size(size)
{
    buf[0] = '\0';
}

void SigSafePrinter::write_string(const char* str)
{
    size_t len = strlen(str);
    if (fd >= 0)
        (void) write(fd, str, len);
    else if (buf)
    {
        if (len > buf_size - buf_idx - 1)
            len = buf_size - buf_idx - 1;
        strncpy(buf + buf_idx, str, len);
        buf_idx += len;
        buf[buf_idx] = '\0';
    }
}

void SigSafePrinter::hex_dump(const uint8_t* data, unsigned len)
{
    char line[41];
    unsigned lidx = 0;

    for (unsigned i = 0; i < len; i++)
    {
        if (i > 0)
        {
            if (i % 16 == 0)
            {
                line[lidx++] = '\n';
                line[lidx] = '\0';
                write_string(line);
                lidx = 0;
            }
            else if (i % 2 == 0)
                line[lidx++] = ' ';
        }
        sigsafe_snprintf(line + lidx, sizeof(line) - lidx, "%02x", (uint64_t) data[i]);
        lidx += 2;
    }
    if (lidx)
    {
        line[lidx++] = '\n';
        line[lidx] = '\0';
        write_string(line);
    }
}

void SigSafePrinter::printf(const char *format, ...)
{
    char fmt_buf[1024];
    va_list ap;
    va_start(ap, format);
    sigsafe_vsnprintf(fmt_buf, sizeof(fmt_buf), format, ap);
    va_end(ap);
    write_string(fmt_buf);
}

#ifdef CATCH_TEST_BUILD

#include <cinttypes>

#include "catch/catch.hpp"

TEST_CASE("sigsafe printer", "[SigsafePrinter]")
{
    using Catch::Matchers::Equals;

    uint64_t unsigned_tests[] =
    {
        0,                  // Zero
        5,                  // Single digit number
        12,                 // Two digit decimal number
        37,                 // Two digit hex number
        0xC90B2,            // Large < 32 bit number
        0x15D027BF211B37A,  // Large > 32 bit number
        0xFFFFFFFFFFFFFFFF, // Maximum 64-bit number
    };
    int64_t signed_tests[] =
    {
        0,                      // Zero
        5,                      // Single digit number
        12,                     // Two digit decimal number
        37,                     // Two digit hex number
        0xC90B2,                // Large < 32 bit number
        0x15D027BF211B37A,      // Large > 32 bit number
        0x7FFFFFFFFFFFFFFF,     // Maximum 64-bit signed number
        -1,                     // Single digit number
        -12,                    // Two digit decimal number
        -0xC90B2,               // Large < 32 bit number
        -0x15D027BF211B37A,     // Large > 32 bit number
        -0x7FFFFFFFFFFFFFFF,    // Maximum 64-bit signed number
    } ;
    char expected[1024];
    char actual[1024];
    SECTION("unsigned decimal")
    {
        for (size_t i = 0; i < sizeof(unsigned_tests) / sizeof(*unsigned_tests); i++)
        {
            snprintf(expected, sizeof(expected), "%" PRIu64, unsigned_tests[i]);
            SigSafePrinter(actual, sizeof(actual)).printf("%u", unsigned_tests[i]);
            CHECK_THAT(expected, Equals(actual));
        }
    }
    SECTION("padded unsigned decimal")
    {
        for (size_t i = 0; i < sizeof(unsigned_tests) / sizeof(*unsigned_tests); i++)
        {
            snprintf(expected, sizeof(expected), "%32" PRIu64, unsigned_tests[i]);
            SigSafePrinter(actual, sizeof(actual)).printf("%32u", unsigned_tests[i]);
            CHECK_THAT(expected, Equals(actual));
        }
    }
    SECTION("0-padded unsigned decimal")
    {
        for (size_t i = 0; i < sizeof(unsigned_tests) / sizeof(*unsigned_tests); i++)
        {
            snprintf(expected, sizeof(expected), "%032" PRIu64, unsigned_tests[i]);
            SigSafePrinter(actual, sizeof(actual)).printf("%032u", unsigned_tests[i]);
            CHECK_THAT(expected, Equals(actual));
        }
    }
    SECTION("signed decimal")
    {
        for (size_t i = 0; i < sizeof(signed_tests) / sizeof(*signed_tests); i++)
        {
            snprintf(expected, sizeof(expected), "%" PRId64, signed_tests[i]);
            SigSafePrinter(actual, sizeof(actual)).printf("%d", signed_tests[i]);
            CHECK_THAT(expected, Equals(actual));
        }
    }
    SECTION("padded signed decimal")
    {
        for (size_t i = 0; i < sizeof(signed_tests) / sizeof(*signed_tests); i++)
        {
            snprintf(expected, sizeof(expected), "%32" PRId64, signed_tests[i]);
            SigSafePrinter(actual, sizeof(actual)).printf("%32d", signed_tests[i]);
            CHECK_THAT(expected, Equals(actual));
        }
    }
    SECTION("0-padded signed decimal")
    {
        for (size_t i = 0; i < sizeof(signed_tests) / sizeof(*signed_tests); i++)
        {
            snprintf(expected, sizeof(expected), "%032" PRId64, signed_tests[i]);
            SigSafePrinter(actual, sizeof(actual)).printf("%032d", signed_tests[i]);
            CHECK_THAT(expected, Equals(actual));
        }
    }
    SECTION("hex")
    {
        for (size_t i = 0; i < sizeof(unsigned_tests) / sizeof(*unsigned_tests); i++)
        {
            snprintf(expected, sizeof(expected), "%" PRIx64, unsigned_tests[i]);
            SigSafePrinter(actual, sizeof(actual)).printf("%x", unsigned_tests[i]);
            CHECK_THAT(expected, Equals(actual));
        }
    }
    SECTION("padded hex")
    {
        for (size_t i = 0; i < sizeof(unsigned_tests) / sizeof(*unsigned_tests); i++)
        {
            snprintf(expected, sizeof(expected), "%2" PRIx64, unsigned_tests[i]);
            SigSafePrinter(actual, sizeof(actual)).printf("%2x", unsigned_tests[i]);
            CHECK_THAT(expected, Equals(actual));
        }
    }
    SECTION("0-padded hex")
    {
        for (size_t i = 0; i < sizeof(unsigned_tests) / sizeof(*unsigned_tests); i++)
        {
            snprintf(expected, sizeof(expected), "%02" PRIx64, unsigned_tests[i]);
            SigSafePrinter(actual, sizeof(actual)).printf("%02x", unsigned_tests[i]);
            CHECK_THAT(expected, Equals(actual));
        }
    }
    SECTION("string")
    {
        snprintf(expected, sizeof(expected), "%s", "foobar");
        SigSafePrinter(actual, sizeof(actual)).printf("%s", "foobar");
        CHECK_THAT(expected, Equals(actual));
    }
    SECTION("null string")
    {
        const char* nullstr = nullptr;
        // cppcheck-suppress nullPointer
        snprintf(expected, sizeof(expected), "%s", nullstr);
        SigSafePrinter(actual, sizeof(actual)).printf("%s", nullstr);
        CHECK_THAT(expected, Equals(actual));
    }
    SECTION("padded string")
    {
        snprintf(expected, sizeof(expected), "%32s", "foobar");
        SigSafePrinter(actual, sizeof(actual)).printf("%32s", "foobar");
        CHECK_THAT(expected, Equals(actual));
    }
    SECTION("all together now")
    {
        for (size_t i = 0; i < sizeof(unsigned_tests) / sizeof(*unsigned_tests); i++)
        {
            snprintf(expected, sizeof(expected), "%" PRIu64 " is %" PRIx64 " in %s!",
                    unsigned_tests[i], unsigned_tests[i], "hex");
            SigSafePrinter(actual, sizeof(actual)).printf("%u is %x in %s!",
                    unsigned_tests[i], unsigned_tests[i], "hex");
            CHECK_THAT(expected, Equals(actual));
        }
    }
    SECTION("unrecognized conversion specifiers")
    {
        char format[32];
        snprintf(expected, sizeof(expected), "Nothing to see here: .");
        for (char c = 'A'; c < 'z'; c++)
        {
            if (c == 'd' || c == 's' || c == 'u' || c == 'x')
                continue;
            snprintf(format, sizeof(format), "Nothing to see here: %%%c.", c);
            SigSafePrinter(actual, sizeof(actual)).printf(format, 0xDEADBEEF);
            CHECK_THAT(expected, Equals(actual));
        }
    }
    SECTION("hexdump")
    {
        uint8_t data[32];
        unsigned offset = 0;
        for (unsigned i = 0; i < sizeof(data); i++)
        {
            data[i] = i;
            if (i > 0)
            {
                if (i % 16 == 0)
                    offset += snprintf(expected + offset, sizeof(expected) - offset, "\n");
                else if (i % 2 == 0)
                    offset += snprintf(expected + offset, sizeof(expected) - offset, " ");
            }
            offset += snprintf(expected + offset, sizeof(expected) - offset, "%02x", data[i]);
        }
        snprintf(expected + offset, sizeof(expected) - offset, "\n");
        SigSafePrinter(actual, sizeof(actual)).hex_dump(data, sizeof(data));
        CHECK_THAT(expected, Equals(actual));
    }
}

#endif


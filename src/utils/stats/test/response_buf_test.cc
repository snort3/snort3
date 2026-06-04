//--------------------------------------------------------------------------
// Copyright (C) 2026 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstdarg>
#include <cstdio>
#include <ostream>
#include <string>

#include "catch/catch.hpp"

#include "control/control.h"

#include "../response_buf.h"

using namespace snort;

static std::string responded;
static std::string logged;
static bool respond_result = true;

static void append_format(std::string& out, const char* format, va_list& args)
{
    char buffer[4096];
    vsnprintf(buffer, sizeof(buffer), format, args);
    out += buffer;
}

static void reset_output()
{
    responded.clear();
    logged.clear();
    respond_result = true;
}

ControlConn::ControlConn(int fd_arg, bool local_arg) : shell(nullptr), fd(fd_arg), local(local_arg)
{ }

ControlConn::~ControlConn() = default;

bool ControlConn::respond(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    append_format(responded, format, args);
    va_end(args);
    return respond_result;
}

namespace snort
{
void LogMessage(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    append_format(logged, format, args);
    va_end(args);
}
}

static void write_response(ControlConn* ctrlcon, const char* text)
{
    StatsResponseBuf buffer(ctrlcon);
    std::ostream out(&buffer);
    out << text;
}

class TestStatsResponseBuf : public StatsResponseBuf
{
public:
    using StatsResponseBuf::StatsResponseBuf;
    using StatsResponseBuf::overflow;
};

// cppcheck-suppress syntaxError
TEST_CASE("stats response buffer logs when no control connection exists", "[stats_response_buf]")
{
    reset_output();

    write_response(nullptr, "abc");

    CHECK(responded.empty());
    CHECK(logged == "abc");
}

TEST_CASE("stats response buffer responds to local control connections", "[stats_response_buf]")
{
    reset_output();
    ControlConn ctrlcon(-1, true);

    write_response(&ctrlcon, "abc");

    CHECK(responded == "abc");
    CHECK(logged.empty());
}

TEST_CASE("stats response buffer responds to remote control connections without logging", "[stats_response_buf]")
{
    reset_output();
    ControlConn ctrlcon(-1, false);

    write_response(&ctrlcon, "abc");

    CHECK(responded == "abc");
    CHECK(logged.empty());
}

TEST_CASE("stats response buffer handles eof overflow", "[stats_response_buf]")
{
    reset_output();

    TestStatsResponseBuf buffer(nullptr);

    CHECK(buffer.overflow(TestStatsResponseBuf::traits_type::eof()) !=
        TestStatsResponseBuf::traits_type::eof());
    CHECK(responded.empty());
    CHECK(logged.empty());
}

TEST_CASE("stats response buffer reports full-buffer flush failure", "[stats_response_buf]")
{
    reset_output();
    respond_result = false;
    ControlConn ctrlcon(-1, true);

    StatsResponseBuf buffer(&ctrlcon);
    std::ostream out(&buffer);
    out << std::string(1024, 'x');

    CHECK(out.bad());
    CHECK(responded == std::string(1023, 'x'));
    CHECK(logged.empty());
}

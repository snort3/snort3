//--------------------------------------------------------------------------
// Copyright (C) 2020-2025 Cisco and/or its affiliates. All rights reserved.
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
// json_stream.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "json_stream.h"

#include <cassert>
#include <cctype>
#include <cstring>
#include <iomanip>

using namespace snort;

void JsonStream::open(const char* key)
{
    split();

    if ( key )
        out << std::quoted(key) << ": ";

    out << "{ ";
    sep = false;
    ++level;
}

void JsonStream::close()
{
    out << " }";
    sep = true;
    assert(level > 0);

    if ( --level == 0 and !level_array )
    {
        out << std::endl;
        sep = false;
    }
}

void JsonStream::open_array(const char* key)
{
    split();

    if ( key )
        out << std::quoted(key) << ": ";

    out << "[ ";
    sep = false;
    level_array++;
}

void JsonStream::close_array()
{
    out << " ]";
    sep = true;
    assert(level_array > 0);

    if ( --level_array == 0 and !level )
    {
        out << std::endl;
        sep = false;
    }
}

void JsonStream::put(const char* key)
{
    split();

    if ( key )
        out << std::quoted(key) << ": ";

    out << "null";
}

void JsonStream::put(const char* key, int64_t val)
{
    split();

    if ( key )
        out << std::quoted(key) << ": ";

    out << val;
}

void JsonStream::uput(const char* key, uint64_t val)
{
    split();

    if ( key )
        out << std::quoted(key) << ": ";

    out << val;
}

void JsonStream::put(const char* key, const char* val)
{
    if (val and val[0] == '\0')
        return;

    split();

    if ( key )
        out << std::quoted(key) << ": ";

    if (val)
        put_escaped(val, strlen(val));
    else
        out << "null";
}

void JsonStream::put(const char* key, const std::string& val)
{
    if ( val.empty() )
        return;

    split();

    if ( key )
        out << std::quoted(key) << ": ";

    put_escaped(val.c_str(), val.size());
}

void JsonStream::put(const char* key, double val, int precision)
{
    split();

    if ( key )
        out << std::quoted(key) << ": ";

    out.precision(precision);
    out << std::fixed << val;
}

void JsonStream::put_true(const char* key)
{
    split();

    if ( key )
        out << std::quoted(key) << ": ";

    out << "true";
}

void JsonStream::put_false(const char* key)
{
    split();

    if ( key )
        out << std::quoted(key) << ": ";

    out << "false";
}

void JsonStream::split()
{
    if ( sep )
        out << ", ";
    else
        sep = true;
}

void JsonStream::put_eol()
{
    out << std::endl;
}

void JsonStream::put_escaped(const char* v, size_t len)
{
    char* buf = new char[2 * len + 2];
    char* dst = buf;

    *dst++ = '\"';

    while (len--)
    {
        char c = *v++;

        switch (c)
        {
        case '\\': *dst++ = '\\'; *dst++ = '\\'; break;
        case '\"': *dst++ = '\\'; *dst++ = '"'; break;
        case '\b': *dst++ = '\\'; *dst++ = 'b'; break;
        case '\f': *dst++ = '\\'; *dst++ = 'f'; break;
        case '\n': *dst++ = '\\'; *dst++ = 'n'; break;
        case '\r': *dst++ = '\\'; *dst++ = 'r'; break;
        case '\t': *dst++ = '\\'; *dst++ = 't'; break;
        default:
            if (isprint(c))
                *dst++ = c;
            else
            {
                out.write(buf, dst - buf);
                dst = buf;
                out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (0xFF & c);
            }
        }
    }

    *dst++ = '\"';
    out.write(buf, dst - buf);

    delete[] buf;
}

#ifdef UNIT_TEST

#include "catch/snort_catch.h"

class JsonStreamTest : public JsonStream
{
public:
    JsonStreamTest() : JsonStream(oss), oss() { }

    void check_escaping(const char* f, const char* input, size_t i_len, const std::string& expected)
    {
        oss.str(std::string());
        put(f, std::string(input, i_len));
        CHECK(oss.str() == expected);
    }

private:
    std::ostringstream oss;
};

TEST_CASE_METHOD(JsonStreamTest, "escape: special chars", "[Json_Stream]")
{
    const char* field = "Special characters";
    const char* value = "\" \\ \b \f \n \r \t";
    size_t len = strlen(value);

    std::string expected = "\"Special characters\": \"\\\" \\\\ \\b \\f \\n \\r \\t\"";
    check_escaping(field, value, len, expected);
}

TEST_CASE_METHOD(JsonStreamTest, "escape: non printable chars", "[Json_Stream]")
{
    // __STRDUMP_DISABLE__
    const char* field = "Non printable";
    const char* value = "\x01\x02\x03";
    size_t len = strlen(value);

    std::string expected = "\"Non printable\": \"\\u0001\\u0002\\u0003\"";
    check_escaping(field, value, len, expected);
    // __STRDUMP_ENABLE__
}

TEST_CASE_METHOD(JsonStreamTest, "escape: printable chars", "[Json_Stream]")
{
    const char* field = "Printable characters";
    const char* value = "ABC abc 123";
    size_t len = strlen(value);

    std::string expected = "\"Printable characters\": \"ABC abc 123\"";
    check_escaping(field, value, len, expected);
}

TEST_CASE_METHOD(JsonStreamTest, "escape: mixed chars", "[Json_Stream]")
{
    // __STRDUMP_DISABLE__
    const char* field = "Mixed";
    const char* value = "ABC \x01 \" \\ \b \f \n \r \t 123";
    size_t len = strlen(value);

    std::string expected = "\"Mixed\": \"ABC \\u0001 \\\" \\\\ \\b \\f \\n \\r \\t 123\"";
    check_escaping(field, value, len, expected);
    // __STRDUMP_ENABLE__
}

TEST_CASE_METHOD(JsonStreamTest, "escape: empty string", "[Json_Stream]")
{
    const char* field = "Empty string";
    const char* value = "";
    size_t len = strlen(value);

    std::string expected = "";
    check_escaping(field, value, len, expected);
}

#endif


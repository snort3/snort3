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

static inline size_t str_esc_pos(const char* str, size_t len)
{
    for (size_t i = 0; i < len; ++i)
    {
        switch (str[i])
        {
        case '\\':
        case '\"':
        case '\b':
        case '\f':
        case '\n':
        case '\r':
        case '\t':
            return i;
        default:
            if (!isprint(str[i]))
                return i;
        }
    }

    return len;
}

void escape_json_append(std::string& out, const char* v, size_t len)
{
    if (!v or len == 0)
        return;

    size_t pos = str_esc_pos(v, len);

    if (pos != 0)
        out.append(v, pos);

    if (pos == len)
        return;

    len -= pos;
    v += pos;

    out.reserve(out.size() + 2 * len);

    while (len--)
    {
        const unsigned char c = *v++;

        switch (c)
        {
        case '\\': out.push_back('\\'); out.push_back('\\'); break;
        case '\"': out.push_back('\\'); out.push_back('"'); break;
        case '\b': out.push_back('\\'); out.push_back('b'); break;
        case '\f': out.push_back('\\'); out.push_back('f'); break;
        case '\n': out.push_back('\\'); out.push_back('n'); break;
        case '\r': out.push_back('\\'); out.push_back('r'); break;
        case '\t': out.push_back('\\'); out.push_back('t'); break;
        default:
            if (isprint(c))
                out.push_back(c);
            else
            {
                char buf[7];
                std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned int>(0xFF & c));
                out.append(buf);
            }
        }
    }
}

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
    {
        std::string escaped;
        escape_json_append(escaped, val, strlen(val));
        out << '"' << escaped << '"';
    }
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

    std::string escaped;
    escape_json_append(escaped, val.c_str(), val.size());
    out << '"' << escaped << '"';
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

#ifdef UNIT_TEST

#include <sstream>

#include "catch/snort_catch.h"

class JsonStreamTest : public JsonStream
{
public:
    JsonStreamTest() : JsonStream(oss), oss() { }

    void check_escaping(const char* f, const char* input, size_t i_len, const std::string& expected)
    {
        oss.str(std::string());
        auto flags_before = oss.flags();
        auto precision_before = oss.precision();
        auto width_before = oss.width();

        put(f, std::string(input, i_len));
        CHECK(oss.str() == expected);
        CHECK(oss.flags() == flags_before);
        CHECK(oss.precision() == precision_before);
        CHECK(oss.width() == width_before);
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

TEST_CASE_METHOD(JsonStreamTest, "escape: no escaping", "[Json_Stream]")
{
    const char* field = "Normal string";
    const char* value = "foobar";
    size_t len = strlen(value);

    std::string expected = "\"Normal string\": \"foobar\"";
    check_escaping(field, value, len, expected);
}

#endif


//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
// nhttp_module.cc author Tom Peters <thopeter@cisco.com>

#include <string.h>
#include <sys/types.h>

#include "nhttp_uri_norm.h"
#include "nhttp_module.h"

using namespace NHttpEnums;

const Parameter NHttpModule::nhttp_params[] =
{
    { "request_depth", Parameter::PT_INT, "-1:", "-1",
          "maximum request message body bytes to examine (-1 no limit)" },
    { "response_depth", Parameter::PT_INT, "-1:", "-1",
          "maximum response message body bytes to examine (-1 no limit)" },
    { "unzip", Parameter::PT_BOOL, nullptr, "true", "decompress gzip and deflate message bodies" },
    { "bad_characters", Parameter::PT_BIT_LIST, "255", nullptr,
          "alert when any of specified bytes are present in URI after percent decoding" },
    { "ignore_unreserved", Parameter::PT_STRING, "(optional)", nullptr,
          "do not alert when the specified unreserved characters are percent-encoded in a URI."
          "Unreserved characters are 0-9, a-z, A-Z, period, underscore, tilde, and minus." },
    { "backslash_to_slash", Parameter::PT_BOOL, nullptr, "false",
          "replace \\ with / when normalizing URIs" },
    { "plus_to_space", Parameter::PT_BOOL, nullptr, "true",
          "replace + with <sp> when normalizing URIs" },
    { "simplify_path", Parameter::PT_BOOL, nullptr, "true",
          "reduce URI directory path to simplest form" },
#ifdef REG_TEST
    { "test_input", Parameter::PT_BOOL, nullptr, "false", "read HTTP messages from text file" },
    { "test_output", Parameter::PT_BOOL, nullptr, "false", "print out HTTP section data" },
    { "print_amount", Parameter::PT_INT, "1:1000000", "1200",
          "number of characters to print from a Field" },
#endif
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

bool NHttpModule::begin(const char*, int, SnortConfig*)
{
    return true;
}

bool NHttpModule::set(const char*, Value& val, SnortConfig*)
{
    if (val.is("request_depth"))
    {
        params.request_depth = val.get_long();
    }
    else if (val.is("response_depth"))
    {
        params.response_depth = val.get_long();
    }
    else if (val.is("unzip"))
    {
        params.unzip = val.get_bool();
    }
    else if (val.is("bad_characters"))
    {
        val.get_bits(params.uri_param.bad_characters);
    }
    else if (val.is("ignore_unreserved"))
    {
        const char* ignore = val.get_string();
        while (*ignore != '\0')
        {
            params.uri_param.unreserved_char[*(ignore++)] = false;
        }
    }
    else if (val.is("backslash_to_slash"))
    {
        params.uri_param.backslash_to_slash = val.get_bool();
        params.uri_param.uri_char[(uint8_t)'\\'] = val.get_bool() ? CHAR_SUBSTIT : CHAR_NORMAL;
    }
    else if (val.is("plus_to_space"))
    {
        params.uri_param.plus_to_space = val.get_bool();
        params.uri_param.uri_char[(uint8_t)'+'] = val.get_bool() ? CHAR_SUBSTIT : CHAR_NORMAL;
    }
    else if (val.is("simplify_path"))
    {
        params.uri_param.simplify_path = val.get_bool();
        params.uri_param.uri_char[(uint8_t)'/'] = val.get_bool() ? CHAR_PATH : CHAR_NORMAL;
        params.uri_param.uri_char[(uint8_t)'.'] = val.get_bool() ? CHAR_PATH : CHAR_NORMAL;
    }
#ifdef REG_TEST
    else if (val.is("test_input"))
    {
        params.test_input = val.get_bool();
    }
    else if (val.is("test_output"))
    {
        params.test_output = val.get_bool();
    }
    else if (val.is("print_amount"))
    {
        params.print_amount = val.get_long();
    }
#endif
    else
    {
        return false;
    }
    return true;
}

// Some values in these tables may be changed by configuration parameters.
NHttpParaList::UriParam::UriParam() :
  // Characters that should not be percent-encoded
  // 0-9, a-z, A-Z, tilde, period, underscore, and minus
  // Initializer string for std::bitset is in reverse order. The first character is element 255
  // and the last is element 0.
  unreserved_char { std::string(
      "00000000" "00000000" "00000000" "00000000"
      "00000000" "00000000" "00000000" "00000000"
      "00000000" "00000000" "00000000" "00000000"
      "00000000" "00000000" "00000000" "00000000"
      "01000111" "11111111" "11111111" "11111110"
      "10000111" "11111111" "11111111" "11111110"
      "00000011" "11111111" "01100000" "00000000"
      "00000000" "00000000" "00000000" "00000000" ) },

  uri_char {
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,

    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_PERCENT,   CHAR_NORMAL,    CHAR_NORMAL,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_SUBSTIT,   CHAR_NORMAL,    CHAR_NORMAL,    CHAR_PATH,      CHAR_PATH,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,

    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_PATH,      CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,

    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,

    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,

    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,

    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,

    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT
  }
{}


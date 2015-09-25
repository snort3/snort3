//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

#include "nhttp_module.h"

const Parameter NHttpModule::nhttp_params[] =
{
    { "request_depth", Parameter::PT_INT, "-1:", "-1",
          "maximum request message body bytes to examine (-1 no limit)" },
    { "response_depth", Parameter::PT_INT, "-1:", "-1",
          "maximum response message body bytes to examine (-1 no limit)" },
#ifdef REG_TEST
    { "test_input", Parameter::PT_BOOL, nullptr, "false", "read HTTP messages from text file" },
    { "test_output", Parameter::PT_BOOL, nullptr, "false", "print out HTTP section data" },
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
#ifdef REG_TEST
    else if (val.is("test_input"))
    {
        params.test_input = val.get_bool();
    }
    else if (val.is("test_output"))
    {
        params.test_output = val.get_bool();
    }
#endif
    else
    {
        return false;
    }
    return true;
}


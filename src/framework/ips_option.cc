//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// ips_option.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ips_option.h"

#include <cstring>

#include "hash/hashfcn.h"

using namespace snort;

static const char* s_buffer = nullptr;

void IpsOption::set_buffer(const char* s)
{ s_buffer = s; }

//-------------------------------------------------------------------------

IpsOption::IpsOption(const char* s, option_type_t t)
{
    name = s;
    type = t;

    switch ( t )
    {
    case RULE_OPTION_TYPE_BUFFER_SET: buffer = s_buffer = s; break;
    case RULE_OPTION_TYPE_CONTENT:
    case RULE_OPTION_TYPE_BUFFER_USE: buffer = s_buffer; break;
    default: buffer = "n/a";
    }
}

uint32_t IpsOption::hash() const
{
    uint32_t a = 0, b = 0, c = 0;
    mix_str(a, b, c, get_name());
    mix_str(a, b, c, get_buffer());
    finalize(a, b, c);
    return c;
}

bool IpsOption::operator==(const IpsOption& ips) const
{
    return !strcmp(get_name(), ips.get_name()) and
        !strcmp(get_buffer(), ips.get_buffer());
}


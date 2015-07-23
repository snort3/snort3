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
// ips_option.cc author Russ Combs <rucombs@cisco.com>

#include "ips_option.h"

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "hash/sfhashfcn.h"

//-------------------------------------------------------------------------

uint32_t IpsOption::hash() const
{
    uint32_t a=0, b=0, c=0;
    mix_str(a,b,c,get_name());
    final(a,b,c);
    return c;
}

bool IpsOption::operator==(const IpsOption& ips) const
{ return !strcmp(get_name(), ips.get_name()); }


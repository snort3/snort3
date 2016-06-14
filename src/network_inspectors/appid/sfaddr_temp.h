//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// sfaddr_temp.h author Sourcefire Inc.

#ifndef SFADDR_TEMP_H
#define SFADDR_TEMP_H

#include "protocols/ipv6.h"

#define WORKAROUND_UNTIL_SFIP_CHANGES_FROM_SNORT299_ARE_PORTED_TO_SNORT3
#ifdef WORKAROUND_UNTIL_SFIP_CHANGES_FROM_SNORT299_ARE_PORTED_TO_SNORT3

#define sfaddr_get_ip4_value(x) (0)
#define sfaddr_get_ptr(x) (0)
#define sfip_fast_eq6(x,y) (0)
#define sfip_fast_equals_raw(x, y) (0)
#define sfaddr_family(x)  ((x)->family)

#endif

#endif

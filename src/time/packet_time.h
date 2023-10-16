//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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

#ifndef PACKET_TIME_H
#define PACKET_TIME_H

#include <sys/time.h>

#include "main/snort_types.h"

namespace snort
{
SO_PUBLIC void packet_gettimeofday(struct timeval* tv);
SO_PUBLIC time_t packet_time();
SO_PUBLIC int64_t timersub_ms(const struct timeval* end, const struct timeval* start);
}

void packet_time_update(const struct timeval* cur_tv);
uint32_t packet_first_time();

#endif


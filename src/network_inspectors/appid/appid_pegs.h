//--------------------------------------------------------------------------
// Copyright (C) 2019-2021 Cisco and/or its affiliates. All rights reserved.
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

// appid_pegs.h author Silviu Minut <sminut@cisco.com>

#ifndef APPID_PEGS_H
#define APPID_PEGS_H

#include "framework/counts.h"

struct AppIdStats
{
    PegCount packets;
    PegCount processed_packets;
    PegCount ignored_packets;
    PegCount total_sessions;
    PegCount appid_unknown;
    PegCount service_cache_prunes;
    PegCount service_cache_adds;
    PegCount service_cache_removes;
    PegCount odp_reload_ignored_pkts;
    PegCount tp_reload_ignored_pkts;
};

#endif

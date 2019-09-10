//--------------------------------------------------------------------------
// Copyright (C) 2014-2019 Cisco and/or its affiliates. All rights reserved.
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

// rna_logger.h author Masud Hasan <mashasan@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rna_logger.h"

#include "managers/event_manager.h"
#include "protocols/packet.h"
#include "rna_logger_common.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

bool RnaLogger::log(uint16_t type, uint16_t subtype, const Packet* p, RnaTracker* ht,
    const struct in6_addr* src_ip, const u_int8_t* src_mac, uint32_t event_time,
    void* cond_var)
{
    if ( !enabled )
        return false;

    RnaLoggerEvent rle(type, subtype, ht, src_mac);
    if ( src_ip and (!IN6_IS_ADDR_V4MAPPED(src_ip) or src_ip->s6_addr32[3]) )
        rle.ip = src_ip;
    else
        rle.ip = nullptr;

    if (ht)
    {
        (*ht)->update_last_event(event_time);
        if (type == RNA_EVENT_CHANGE && subtype == CHANGE_HOST_UPDATE)
            rle.cond_var = cond_var;
    }

    EventManager::call_loggers(nullptr, const_cast<Packet*>(p), "RNA", &rle);
    return true;
}

#ifdef UNIT_TEST
TEST_CASE("RNA logger", "[rna_logger]")
{
    SECTION("Checking enabled flag")
    {
        RnaLogger logger1(false);
        CHECK(logger1.log(0, 0, 0, 0, 0, 0) == false);

        RnaLogger logger2(true);
        CHECK(logger2.log(0, 0, 0, 0, 0, 0) == true);
    }
}
#endif

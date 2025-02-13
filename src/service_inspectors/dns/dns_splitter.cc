//--------------------------------------------------------------------------
// Copyright (C) 2021-2025 Cisco and/or its affiliates. All rights reserved.
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
// dns_splitter.cc author Brandon Stultz <brastult@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dns_splitter.h"

#include <cassert>

#include "log/messages.h"
#include "protocols/packet.h"

#include "dns.h"
#include "dns_module.h"

using namespace snort;

StreamSplitter::Status DnsSplitter::scan(
    Packet* p, const uint8_t* data, uint32_t len,
    uint32_t, uint32_t* fp)
{
    assert(len > 0);

    DNSData udp_session_data;
    bool from_server = p->is_from_server();
    DNSData* dnsSessionData = get_dns_session_data(p, from_server, udp_session_data);

    if ( dnsSessionData and ( dnsSessionData->flags & DNS_FLAG_NOT_DNS ) )
    {
        dnsstats.aborted_sessions++;
        return ABORT;
    }

    if ( partial )
    {
        *fp = size + *data + 1;
        partial = false;
        return FLUSH;
    }

    if ( len == 1 )
    {
        size = *data << 8;
        partial = true;
        return SEARCH;
    }

    *fp = (*data << 8) + data[1] + 2;
    return FLUSH;
}


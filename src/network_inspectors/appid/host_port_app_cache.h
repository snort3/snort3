//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// host_port_app_cache.h author Sourcefire Inc.

#ifndef HOST_PORT_APP_CACHE_H
#define HOST_PORT_APP_CACHE_H

#include "application_ids.h"
#include "protocols/protocol_ids.h"

namespace snort
{
struct SfIp;
}

struct HostPortVal
{
    AppId appId;
    unsigned type;
};

class HostPortCache
{
public:
    static void initialize();
    static void terminate();
    static HostPortVal* find(const snort::SfIp*, uint16_t port, IpProtocol);
    static bool add(const snort::SfIp*, uint16_t port, IpProtocol, unsigned type, AppId);
    static void dump();
};

#endif


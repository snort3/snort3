//--------------------------------------------------------------------------
// Copyright (C) 2019-2020 Cisco and/or its affiliates. All rights reserved.
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
// oops_handler.cc author Michael Altizer <mialtize@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "oops_handler.h"

#include "protocols/packet.h"

static THREAD_LOCAL OopsHandler* local_oops_handler = nullptr;

void OopsHandler::handle_crash()
{
    if (local_oops_handler)
        local_oops_handler->eternalize();
}

OopsHandler::OopsHandler()
{
    assert(local_oops_handler == nullptr);
    local_oops_handler = this;
}

OopsHandler::~OopsHandler()
{
    local_oops_handler = nullptr;
}

void OopsHandler::eternalize()
{
    // Copy the crashed thread's data.  C++11 specs ensure the
    // thread that segfaulted will still be running.
    if (packet && packet->pkth)
    {
        pkth = *(packet->pkth);
        if (packet->pkt)
        {
            memcpy(data, packet->pkt, 0xFFFF & packet->pktlen);
            packet->pkt = data;
        }
    }
}

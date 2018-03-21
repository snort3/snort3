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

#ifndef UDP_SESSION_H
#define UDP_SESSION_H

#include <sys/time.h>

#include "flow/session.h"

class UdpSession : public Session
{
public:
    UdpSession(snort::Flow*);

    bool setup(snort::Packet*) override;
    void update_direction(char dir, const snort::SfIp*, uint16_t port) override;
    int process(snort::Packet*) override;
    void clear() override;

public:
    struct timeval ssn_time;
};

void udp_stats();
void udp_reset();

#endif


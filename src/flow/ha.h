//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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
// ha.h author Ed Borgoyn <eborgoyn@cisco.com>

#ifndef HA_H
#define HA_H

#include "flow.h"
#include "main/snort_config.h"
#include "main/snort_types.h"
#include "packet_io/sfdaq.h"
#include "side_channel/side_channel.h"

//-------------------------------------------------------------------------

class HighAvailability
{
public:
    HighAvailability();
    ~HighAvailability();

    void process(Flow*, const DAQ_PktHdr_t*);

private:
    void receive_handler(SCMessage*);
    SideChannel* sc;
};

class HighAvailabilityManager
{
public:
    static void thread_init();
    static void thread_term();
    static void process(Flow*, const DAQ_PktHdr_t*);
private:
    HighAvailabilityManager() = delete;
};
#endif


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
// stream_ha.h author Ed Borgoyn <eborgoyn@cisco.com>

#ifndef STREAM_HA_H
#define STREAM_HA_H

#include "flow/flow.h"
#include "flow/ha.h"
#include "main/snort_types.h"

//-------------------------------------------------------------------------

class StreamHAClient : public FlowHAClient
{
public:
    StreamHAClient() : FlowHAClient(true) { }
    bool consume(Flow*, HAMessage*);
    bool produce(Flow*, HAMessage*);
    size_t get_message_size()
    { return sizeof(LwState); }

private:
};

class ProtocolHA
{
public:
    ProtocolHA();
    virtual ~ProtocolHA() { }
    virtual void delete_session(Flow*) { }
    virtual void create_session(Flow*) { }
    virtual void deactivate_session(Flow*) { }
    virtual void process_deletion(Flow*);

private:
};

class StreamHAManager
{
public:
    static void tinit();
    static void tterm();
    static void process_deletion(Flow*);

    static THREAD_LOCAL StreamHAClient* ha_client;
};
#endif


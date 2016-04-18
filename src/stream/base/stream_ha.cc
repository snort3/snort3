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
// stream_ha.cc author Ed Borgoyn <eborgoyn@cisco.com>

#include "stream_ha.h"

#include "main/snort_debug.h"

typedef LwState SessionHAContent;

void StreamHAClient::consume(Flow*, HAMessage*)
{
    DebugMessage(DEBUG_HA,"StreamHAClient::consume()\n");
}

void StreamHAClient::produce(Flow* flow, HAMessage* msg)
{
    DebugMessage(DEBUG_HA,"StreamHAClient::produce()\n");
    // Check for buffer overflows
    if ( (int)(msg->cursor - msg->content()) < (int)(msg->content_length() -
        sizeof(SessionHAContent)) )
    {
        memcpy(msg->cursor,&(flow->ssn_state),sizeof(SessionHAContent));
        msg->cursor += sizeof(SessionHAContent);
    }
}

ProtocolHA::ProtocolHA()
{
    DebugMessage(DEBUG_HA,"ProtocolHA::ProtocolHA()\n");
}

void ProtocolHA::process_deletion(Flow* flow)
{
    HighAvailabilityManager::process_deletion(flow);
}

StreamHAClient* StreamHAManager::ha_client;

void StreamHAManager::tinit()
{
    ha_client = new StreamHAClient();
}

void StreamHAManager::process_deletion(Flow*)
{
}


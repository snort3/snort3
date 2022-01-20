//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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

// cip_session.h author RA/Cisco

/* Description: Functions for managing CIP state data across multiple packets and TCP connections.
   */

#ifndef CIP_SESSION_H
#define CIP_SESSION_H

#include <cstdint>

#include "main/snort_config.h"
#include "main/snort_types.h"

#include "cip_definitions.h"

// Default unconnected request timeout, milliseconds.
#define DEFAULT_UNCONNECTED_REQUEST_TIMEOUT (30000)

/// ENIP Session Management.
bool enip_session_add(EnipSession* enip_session, uint32_t session_handle);
bool enip_session_remove(EnipSession* enip_session, uint32_t session_handle);

// Returns true if session_handle matches the active session.
bool enip_session_handle_valid(const EnipSession* enip_session, uint32_t session_handle);

/// CIP Connection Management.
CipConnection* cip_find_connection_by_id(
    CipConnectionList* connection_list,
    CipPacketDirection direction,
    uint32_t connection_id,
    bool established);

bool cip_add_connection_to_active(CipConnectionList* connection_list,
    const CipForwardOpenResponse* forward_open_response);
bool cip_remove_connection(CipConnectionList* connection_list,
    const CipConnectionSignature* connection_signature,
    bool established);

bool cip_add_connection_to_pending(CipConnectionList* connection_list,
    const CipForwardOpenRequest* forward_open_request);

/// CIP Request/Response Matching.
bool cip_request_add(CipUnconnectedMessageList* unconnected_list,
    const EnipSessionData* enip_data,
    const CipRequest* cip_request,
    const struct timeval* timestamp);

// Find a request in the list, and remove it.
bool cip_request_remove(CipUnconnectedMessageList* unconnected_list,
    const EnipSessionData* enip_data,
    CipRequestType* request_type);

// Set timeout (milliseconds) to use for unconnected messages that don't have a built-in timeout.
void set_unconnected_timeout(uint32_t unconnected_timeout);

#endif  // CIP_SESSION_H


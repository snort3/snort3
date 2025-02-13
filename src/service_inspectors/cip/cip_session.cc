//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

// cip_session.cc author RA/Cisco

/* Description: Functions for managing CIP state data across multiple packets and TCP connections.
   Note: Performance of all lookup functions is O(n). */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "cip_session.h"

#include <sys/time.h>

#include <cmath>
#include <cstddef>
#include <cstring>

#include "time/timersub.h"     // For TIMERSUB

#include "cip_parsing.h"  // For CIP constants

static uint32_t f_unconnected_timeout_ms = DEFAULT_UNCONNECTED_REQUEST_TIMEOUT;

bool enip_session_add(EnipSession* enip_session, uint32_t session_handle)
{
    // Only 1 ENIP session per TCP connection is allowed.
    if (enip_session->active)
    {
        return false;
    }

    enip_session->session_handle = session_handle;
    enip_session->active = true;

    return true;
}

bool enip_session_remove(EnipSession* enip_session, uint32_t session_handle)
{
    if (!enip_session->active)
    {
        return false;
    }

    if (enip_session->session_handle != session_handle)
    {
        return false;
    }

    enip_session->active = false;

    return true;
}

bool enip_session_handle_valid(const EnipSession* enip_session, uint32_t session_handle)
{
    return (enip_session->active && enip_session->session_handle == session_handle);
}

/// CIP Request and Connection Management.
static void prune_cip_unconnected_list(CipUnconnectedMessageList* unconnected_list,
    const struct timeval* timestamp)
{
    struct timeval timestamp_diff;

    bool pruned = false;
    uint32_t oldest_slot = 0;

    // Prune any message that has exceeded the CIP timeout.
    for (uint32_t i = 0; i < unconnected_list->list_size; ++i)
    {
        if (unconnected_list->list[i].slot_active)
        {
            // cppcheck-suppress unreadVariable
            TIMERSUB(timestamp, &unconnected_list->list[i].timestamp, &timestamp_diff);

            // Round up to the nearest whole second.
            uint32_t timeout_sec
                = ceil(unconnected_list->list[i].timeout_ms / (double)MSEC_PER_SEC);

            // If the message timeout has been exceeded, remove the request from the list.
            if (timestamp_diff.tv_sec > timeout_sec)
            {
                unconnected_list->list[i].slot_active = false;
                unconnected_list->count--;
                pruned = true;
            }

            // Check if the current item's timestamp is older than the previous oldest.
            if (timercmp(&unconnected_list->list[i].timestamp,
                &unconnected_list->list[oldest_slot].timestamp,
                <) != 0)
            {
                oldest_slot = i;
            }
        }
    }

    // If no timeout was exceeded, prune the oldest one.
    if (!pruned)
    {
        unconnected_list->list[oldest_slot].slot_active = false;
        unconnected_list->count--;
        unconnected_list->request_pruned = true;
    }
}

static void prune_cip_connection_list(CipConnectionList* connection_list,
    const struct timeval* timestamp)
{
    struct timeval ot_timestamp_diff;
    struct timeval to_timestamp_diff;

    bool pruned = false;

    uint32_t stale_slot = 0;
    struct timeval stale_timestamp_diff;
    memset(&stale_timestamp_diff, 0, sizeof(stale_timestamp_diff));

    // Prune any connection that has exceeded the CIP timeout.
    for (uint32_t i = 0; i < connection_list->list_size; ++i)
    {
        if (connection_list->list[i].slot_active)
        {
            // cppcheck-suppress unreadVariable
            TIMERSUB(timestamp, &connection_list->list[i].ot_timestamp, &ot_timestamp_diff);
            // cppcheck-suppress unreadVariable
            TIMERSUB(timestamp, &connection_list->list[i].to_timestamp, &to_timestamp_diff);

            // If either OT or TO connection timeouts have been exceeded, remove the connection
            //  from the list.
            if (ot_timestamp_diff.tv_sec > connection_list->list[i].ot_connection_timeout_sec
                || to_timestamp_diff.tv_sec > connection_list->list[i].to_connection_timeout_sec)
            {
                connection_list->list[i].slot_active = false;
                connection_list->count--;
                pruned = true;
            }

            // Pick the most recent timestamp for this connection.
            struct timeval connection_timestamp;
            if (timercmp(&connection_list->list[i].ot_timestamp,
                &connection_list->list[i].to_timestamp,
                >) != 0)
            {
                connection_timestamp = connection_list->list[i].ot_timestamp;
            }
            else
            {
                connection_timestamp = connection_list->list[i].to_timestamp;
            }

            struct timeval timestamp_diff;
            TIMERSUB(timestamp, &connection_timestamp, &timestamp_diff);

            // Check if the current connection is more stale than the previously found one.
            if (timercmp(&timestamp_diff, &stale_timestamp_diff, >) != 0)
            {
                stale_slot = i;
                stale_timestamp_diff = timestamp_diff;
            }
        }
    }

    // If no timeout was exceeded, prune the least recently used one.
    if (!pruned)
    {
        connection_list->list[stale_slot].slot_active = false;
        connection_list->count--;
        connection_list->connection_pruned = true;
    }
}

static bool cip_connection_signature_match(const CipConnectionSignature* left,
    const CipConnectionSignature* right)
{
    if (left->connection_serial_number == right->connection_serial_number
        && left->originator_serial_number == right->originator_serial_number
        && left->vendor_id == right->vendor_id)
    {
        return true;
    }
    else
    {
        return false;
    }
}

static CipConnection* cip_find_connection_slot(CipConnectionList* connection_list,
    const struct timeval* timestamp)
{
    CipConnection* connection = nullptr;

    // Prune old connections if the list is at max capacity.
    if (connection_list->count == connection_list->list_size)
    {
        prune_cip_connection_list(connection_list, timestamp);
    }

    for (uint32_t i = 0; i < connection_list->list_size; ++i)
    {
        if (!connection_list->list[i].slot_active)
        {
            connection = &connection_list->list[i];
            break;
        }
    }

    return connection;
}

CipConnection* cip_find_connection_by_id(
    CipConnectionList* connection_list,
    CipPacketDirection direction,
    uint32_t connection_id,
    bool established)
{
    CipConnection* connection = nullptr;

    for (uint32_t i = 0; i < connection_list->list_size; ++i)
    {
        if (connection_list->list[i].slot_active
            && (connection_list->list[i].established == established))
        {
            if (direction == CIP_FROM_CLIENT
                && connection_list->list[i].connection_id_pair.ot_connection_id == connection_id)
            {
                connection = &connection_list->list[i];
                break;
            }

            if (direction == CIP_FROM_SERVER
                && connection_list->list[i].connection_id_pair.to_connection_id == connection_id)
            {
                connection = &connection_list->list[i];
                break;
            }
        }
    }

    return connection;
}

static const CipConnection* cip_find_connection_by_id_any(
    const CipConnectionList* connection_list,
    uint32_t ot_connection_id,
    uint32_t to_connection_id)
{
    const CipConnection* connection = nullptr;

    for (uint32_t i = 0; i < connection_list->list_size; ++i)
    {
        if (connection_list->list[i].slot_active && connection_list->list[i].established)
        {
            if (connection_list->list[i].connection_id_pair.ot_connection_id == ot_connection_id)
            {
                connection = &connection_list->list[i];
                break;
            }

            if (connection_list->list[i].connection_id_pair.to_connection_id == to_connection_id)
            {
                connection = &connection_list->list[i];
                break;
            }
        }
    }

    return connection;
}

static const CipConnection* cip_find_connection_any(const CipConnectionList* connection_list,
    const CipConnectionSignature* signature)
{
    const CipConnection* connection = nullptr;

    for (uint32_t i = 0; i < connection_list->list_size; ++i)
    {
        if (connection_list->list[i].slot_active
            && cip_connection_signature_match(&connection_list->list[i].signature, signature))
        {
            connection = &connection_list->list[i];
            break;
        }
    }

    return connection;
}

static CipConnection* cip_find_connection(CipConnectionList* connection_list,
    const CipConnectionSignature* signature,
    bool established)
{
    CipConnection* connection = nullptr;

    for (uint32_t i = 0; i < connection_list->list_size; ++i)
    {
        if (connection_list->list[i].slot_active
            && (connection_list->list[i].established == established)
            && cip_connection_signature_match(&connection_list->list[i].signature, signature))
        {
            connection = &connection_list->list[i];
            break;
        }
    }

    return connection;
}

bool cip_add_connection_to_active(CipConnectionList* connection_list,
    const CipForwardOpenResponse* forward_open_response)
{
    // Check that no existing connection has a matching connection ID for either direction.
    const CipConnection* existing_connection = cip_find_connection_by_id_any(connection_list,
        forward_open_response->connection_pair.ot_connection_id,
        forward_open_response->connection_pair.to_connection_id);
    if (existing_connection)
    {
        return false;
    }

    // Find the existing pending connection.
    CipConnection* connection = cip_find_connection(connection_list,
        &forward_open_response->connection_signature,
        false);
    if (!connection)
    {
        return false;
    }

    // Save the new Connection ID information, and mark the connection as
    //  fully established.
    connection->connection_id_pair = forward_open_response->connection_pair;
    connection->established = true;
    connection->to_timestamp = forward_open_response->timestamp;

    return true;
}

bool cip_remove_connection(CipConnectionList* connection_list,
    const CipConnectionSignature* connection_signature,
    bool established)
{
    CipConnection* connection = cip_find_connection(connection_list,
        connection_signature,
        established);
    if (!connection)
    {
        return false;
    }

    connection->slot_active = false;
    connection_list->count--;

    return true;
}

bool cip_add_connection_to_pending(CipConnectionList* connection_list,
    const CipForwardOpenRequest* forward_open_request)
{
    // Check that there are no pending or existing connections with this signature.
    const CipConnection* existing_connection = cip_find_connection_any(connection_list,
        &forward_open_request->connection_signature);
    if (existing_connection)
    {
        return false;
    }

    CipConnection* connection = cip_find_connection_slot(connection_list,
        &forward_open_request->timestamp);
    if (!connection)
    {
        return false;
    }

    connection->signature = forward_open_request->connection_signature;
    connection->class_id = forward_open_request->connection_path.class_id;
    connection->established = false;

    // Round up to the nearest whole second.
    connection->ot_connection_timeout_sec
        = ceil(forward_open_request->ot_connection_timeout_us / (double)USEC_PER_SEC);
    connection->to_connection_timeout_sec
        = ceil(forward_open_request->to_connection_timeout_us / (double)USEC_PER_SEC);

    connection->ot_timestamp = forward_open_request->timestamp;
    connection->to_timestamp = forward_open_request->timestamp;

    connection->slot_active = true;
    connection_list->count++;

    return true;
}

/// CIP Request/Response Matching.
static CipUnconnectedMessage* find_unconnected_request_slot(
    CipUnconnectedMessageList* unconnected_list,
    const struct timeval* timestamp)
{
    CipUnconnectedMessage* unconnected_message = nullptr;

    // Prune old messages if the list is at max capacity.
    if (unconnected_list->count == unconnected_list->list_size)
    {
        prune_cip_unconnected_list(unconnected_list, timestamp);
    }

    for (uint32_t i = 0; i < unconnected_list->list_size; ++i)
    {
        if (!unconnected_list->list[i].slot_active)
        {
            unconnected_message = &unconnected_list->list[i];
            break;
        }
    }

    return unconnected_message;
}

static CipUnconnectedMessage* find_unconnected_request(
    CipUnconnectedMessageList* unconnected_list,
    uint64_t sender_context)
{
    CipUnconnectedMessage* unconnected_message = nullptr;

    for (uint32_t i = 0; i < unconnected_list->list_size; ++i)
    {
        if (unconnected_list->list[i].slot_active
            && unconnected_list->list[i].sender_context == sender_context)
        {
            unconnected_message = &unconnected_list->list[i];
            break;
        }
    }

    return unconnected_message;
}

bool cip_request_add(CipUnconnectedMessageList* unconnected_list,
    const EnipSessionData* enip_data,
    const CipRequest* cip_request,
    const struct timeval* timestamp)
{
    bool valid = true;

    if (enip_data->enip_header.command == ENIP_COMMAND_SEND_RR_DATA)
    {
        CipUnconnectedMessage* slot = find_unconnected_request_slot(unconnected_list, timestamp);
        if (slot)
        {
            slot->sender_context = enip_data->enip_header.sender_context;
            slot->request_type = cip_request->request_type;

            if (cip_request->has_timeout)
            {
                slot->timeout_ms = cip_request->timeout_ms;
            }
            else
            {
                slot->timeout_ms = f_unconnected_timeout_ms;
            }

            slot->timestamp = *timestamp;
            slot->slot_active = true;
            unconnected_list->count++;

            valid = true;
        }
        else
        {
            valid = false;
        }
    }

    return valid;
}

bool cip_request_remove(CipUnconnectedMessageList* unconnected_list,
    const EnipSessionData* enip_data,
    CipRequestType* request_type)
{
    bool valid = true;

    if (enip_data->enip_header.command == ENIP_COMMAND_SEND_RR_DATA)
    {
        CipUnconnectedMessage* request = find_unconnected_request(unconnected_list,
            enip_data->enip_header.sender_context);
        if (request)
        {
            *request_type = request->request_type;

            // Remove the request from the list.
            request->slot_active = false;
            unconnected_list->count--;

            valid = true;
        }
        else
        {
            valid = false;
        }
    }

    return valid;
}


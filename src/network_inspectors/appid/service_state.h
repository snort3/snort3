//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

// service_state.h author Sourcefire Inc.

#ifndef SERVICE_STATE_H
#define SERVICE_STATE_H

#include "sfip/sfip_t.h"

struct RNAServiceElement;
struct ServiceMatch;
enum class IpProtocol : uint8_t;

// Service state stored in hosttracker for maintaining service matching states.
enum SERVICE_ID_STATE
{
    /**first search of service. The matching criteria is coded in ProtocolID funtion.
     */
    SERVICE_ID_NEW = 0,

    /**service is already detected and valid.
     */
    SERVICE_ID_VALID,

    /**match based on source or destination port in first packet in flow.
     */
    SERVICE_ID_PORT,

    /**match based on pattern in first response from server or client in
     * case of client_services.
     */
    SERVICE_ID_PATTERN,

    /**match based on round-robin through tcpServiceList or UdpServiceList. RNA walks
     * the list from first element to last. In a detector declares a flow incompatible
     * or the flow closes earlier than expected by detector, then the next detector is
     * tried. This can obviously delay detection under some scenarios.
     */
    SERVICE_ID_BRUTE_FORCE,
};

#define DETECTOR_TYPE_PASSIVE   0
#define DETECTOR_TYPE_DECODER   0
#define DETECTOR_TYPE_NETFLOW   1
#define DETECTOR_TYPE_PORT      2
#define DETECTOR_TYPE_DERIVED   3
#define DETECTOR_TYPE_CONFLICT  4
#define DETECTOR_TYPE_PATTERN   5

// Service state saved in hosttracker, for identifying a service across multiple flow instances.
struct AppIdServiceIDState
{
    const RNAServiceElement* svc;

    /**State of service identification.*/
    SERVICE_ID_STATE state;
    unsigned valid_count;
    unsigned detract_count;
    sfip_t last_detract;

    /**Number of consequetive flows that were declared incompatible by detectors. Incompatibility
     * means client packet did not match.
     */
    unsigned invalid_client_count;

    /**IP address of client in last flow that was declared incompatible. If client IP address is
     * different everytime, then consequetive incompatible status indicate that flow is not using
     * specific service.
     */
    sfip_t last_invalid_client;

    /** Count for number of unknown sessions saved
     */
    unsigned unknowns_logged;
    time_t reset_time;

    /**List of ServiceMatch nodes which are sorted in order of pattern match. The list is contructed
     * once on first packet from server and then used for subsequent flows. This saves repeat pattern
     * matching, but has the disadvantage of making one flow match dependent on first instance of the
     * same flow.
     */
    ServiceMatch* serviceList;
    ServiceMatch* currenService;

    /** Is this entry currently being used in an active session? */
    bool searching;
};

struct AppIdServiceStateKey4
{
    uint16_t port;
    IpProtocol proto;
    uint32_t ip;
    uint32_t level;
};

struct AppIdServiceStateKey6
{
    uint16_t port;
    IpProtocol proto;
    uint8_t ip[16];
    uint32_t level;
};

union AppIdServiceStateKey
{
    AppIdServiceStateKey4 key4;
    AppIdServiceStateKey6 key6;
};

int AppIdServiceStateInit(unsigned long memcap);
void AppIdServiceStateCleanup();
void AppIdRemoveServiceIDState(sfip_t*, IpProtocol proto, uint16_t port, uint32_t level);
AppIdServiceIDState* AppIdGetServiceIDState( const sfip_t*, IpProtocol proto, uint16_t port, uint32_t level);
AppIdServiceIDState* AppIdAddServiceIDState( const sfip_t*, IpProtocol proto, uint16_t port, uint32_t level);
void AppIdServiceStateDumpStats();

#endif

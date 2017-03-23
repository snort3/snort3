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

#include "sfip/sf_ip.h"
#include "service_plugins/service_discovery.h"
#include "protocols/protocol_ids.h"
#include "utils/util.h"

class ServiceDetector;

enum class IpProtocol : uint8_t;

// Service state stored in hosttracker for maintaining service matching states.
enum SERVICE_ID_STATE
{
    SERVICE_ID_NEW = 0,     // service search starting
    SERVICE_ID_VALID,       // service detected
    SERVICE_ID_PORT,        // matched based on src/dest port of first packet
    SERVICE_ID_PATTERN,     // match based on pattern in first response packet
    SERVICE_ID_BRUTE_FORCE, // match based on round-robin through tcp/udp service lists
                            // the lists are walked from first element to last. In a detector
                            // declares a flow incompatible or the flow closes earlier than
                            // expected by detector, then the next detector is tried. This can
                            //  obviously delay detection under some scenarios.
};

enum DetectorType
{
    DETECTOR_TYPE_PASSIVE =  0,
    DETECTOR_TYPE_DECODER =  0,
    DETECTOR_TYPE_NETFLOW,
    DETECTOR_TYPE_PORT,
    DETECTOR_TYPE_DERIVED,
    DETECTOR_TYPE_CONFLICT,
    DETECTOR_TYPE_PATTERN,
    DETECTOR_TYPE_NOT_SET
};

// Service state saved in hosttracker, for identifying a service across multiple flow instances.
class ServiceDiscoveryState
{
public:
    ServiceDiscoveryState()
    {
        last_detract.clear();
        last_invalid_client.clear();
        reset_time = 0;
    }

    ~ServiceDiscoveryState()
    {
        if ( brute_force_mgr )
            delete brute_force_mgr;
    }

    ServiceDetector* service = nullptr;
    AppIdDetectorList* brute_force_mgr = nullptr;

    /**State of service identification.*/
    SERVICE_ID_STATE state = SERVICE_ID_NEW;
    unsigned valid_count = 0;
    unsigned detract_count = 0;
    SfIp last_detract;

    /**Number of consequetive flows that were declared incompatible by detectors. Incompatibility
     * means client packet did not match.
     */
    unsigned invalid_client_count = 0;

    /**IP address of client in last flow that was declared incompatible. If client IP address is
     * different everytime, then consequetive incompatible status indicate that flow is not using
     * specific service.
     */
    SfIp last_invalid_client;

    /** Count for number of unknown sessions saved
     */
    unsigned unknowns_logged = 0;
    time_t reset_time;

    /** Is this entry currently being used in an active session? */
    bool searching = false;
};

class AppIdServiceState
{
public:
    static void initialize(unsigned long);
    static void clean();
    static ServiceDiscoveryState* add(const SfIp*, IpProtocol, uint16_t port, uint32_t level);
    static ServiceDiscoveryState* get(const SfIp*, IpProtocol, uint16_t port, uint32_t level);
    static void remove(const SfIp*, IpProtocol, uint16_t port, uint32_t level);
    static void dump_stats();
};

#endif


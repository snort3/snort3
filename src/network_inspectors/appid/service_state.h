//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

#include <mutex>

#include "sfip/sf_ip.h"
#include "service_plugins/service_discovery.h"
#include "protocols/protocol_ids.h"
#include "utils/util.h"

class ServiceDetector;

enum SERVICE_ID_STATE
{
    SEARCHING_PORT_PATTERN = 0,
    SEARCHING_BRUTE_FORCE,
    FAILED,
    VALID
};

class AppIdDetectorList
{
public:
    AppIdDetectorList(IpProtocol proto)
    {
        if (proto == IpProtocol::TCP)
            detectors = &ServiceDiscovery::get_instance().tcp_detectors;
        else
            detectors = &ServiceDiscovery::get_instance().udp_detectors;
        dit = detectors->begin();
    }

    ServiceDetector* next()
    {
        ServiceDetector* detector = nullptr;

        if ( dit != detectors->end())
            detector = (ServiceDetector*)(dit++)->second;
        return detector;
    }

    void reset()
    {
        dit = detectors->begin();
    }

private:
    AppIdDetectors* detectors;
    AppIdDetectorsIterator dit;
};

class ServiceDiscoveryState
{
public:
    ServiceDiscoveryState();
    ~ServiceDiscoveryState();
    void set_service_id_valid(ServiceDetector* sd);
    void set_service_id_failed(AppIdSession* asd, const SfIp* client_ip);

    SERVICE_ID_STATE state;
    ServiceDetector* service = nullptr;
    AppIdDetectorList* brute_force_mgr = nullptr;
    unsigned valid_count = 0;
    unsigned detract_count = 0;
    SfIp last_detract;

    // consecutive incompatible flows - incompatibile means client packet did not match.
    unsigned invalid_client_count = 0;

    /**IP address of client in last flow that was declared incompatible. If client IP address is
     * different everytime, then consecutive incompatible status indicate that flow is not using
     * specific service.
     */
    SfIp last_invalid_client;
    time_t reset_time;
};

class AppIdServiceState
{
public:
    static void initialize();
    static void clean();
    static ServiceDiscoveryState* add(const SfIp*, IpProtocol, uint16_t port, bool decrypted);
    static ServiceDiscoveryState* get(const SfIp*, IpProtocol, uint16_t port, bool decrypted);
    static void remove(const SfIp*, IpProtocol, uint16_t port, bool decrypted);
    static void check_reset(AppIdSession* asd, const SfIp* ip, uint16_t port );

    static void dump_stats();
};

#endif


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

// service_state.h author Sourcefire Inc.

#ifndef SERVICE_STATE_H
#define SERVICE_STATE_H

#include "protocols/protocol_ids.h"
#include "sfip/sf_ip.h"

#include "service_plugins/service_discovery.h"
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
            detectors = ServiceDiscovery::get_instance().get_tcp_detectors();
        else
            detectors = ServiceDiscovery::get_instance().get_udp_detectors();
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
    ServiceDetector* select_detector_by_brute_force(IpProtocol proto);
    void set_service_id_valid(ServiceDetector* sd);
    void set_service_id_failed(AppIdSession& asd, const snort::SfIp* client_ip,
        unsigned invalid_delta = 0);
    void update_service_incompatiable(const snort::SfIp* ip);

    SERVICE_ID_STATE get_state() const
    {
        return state;
    }

    void set_state(SERVICE_ID_STATE state)
    {
        this->state = state;
    }

    ServiceDetector* get_service() const
    {
        return service;
    }

    void set_service(ServiceDetector* service)
    {
        this->service = service;
    }

    time_t get_reset_time() const
    {
        return reset_time;
    }

    void set_reset_time(time_t resetTime)
    {
        reset_time = resetTime;
    }

private:
    SERVICE_ID_STATE state;
    ServiceDetector* service = nullptr;
    AppIdDetectorList* tcp_brute_force_mgr = nullptr;
    AppIdDetectorList* udp_brute_force_mgr = nullptr;
    unsigned valid_count = 0;
    unsigned detract_count = 0;
    snort::SfIp last_detract;

    // consecutive incompatible flows - incompatible means client packet did not match.
    unsigned invalid_client_count = 0;

    /**IP address of client in last flow that was declared incompatible. If client IP address is
     * different every time, then consecutive incompatible status indicate that flow is not using
     * specific service.
     */
    snort::SfIp last_invalid_client;
    time_t reset_time;
};

class AppIdServiceState
{
public:
    static void initialize();
    static void clean();
    static ServiceDiscoveryState* add(const snort::SfIp*, IpProtocol, uint16_t port, bool decrypted);
    static ServiceDiscoveryState* get(const snort::SfIp*, IpProtocol, uint16_t port, bool decrypted);
    static void remove(const snort::SfIp*, IpProtocol, uint16_t port, bool decrypted);
    static void check_reset(AppIdSession& asd, const snort::SfIp* ip, uint16_t port);

    static void dump_stats();
};

#endif


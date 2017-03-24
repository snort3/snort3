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

// service_discovery.h author Sourcefire Inc.

#ifndef SERVICE_DISCOVERY_H
#define SERVICE_DISCOVERY_H

#include "appid_discovery.h"

#include <map>
#include <vector>

#include "utils/sflsq.h"
#include "flow/flow.h"
#include "log/messages.h"

class AppIdConfig;
class AppIdSession;
class ServiceDetector;
class ServiceDiscoveryState;

#define MAX_CANDIDATE_SERVICES 10
#define RNA_SERVICE_MAX_PORT 65536

#define STATE_ID_INCONCLUSIVE_SERVICE_WEIGHT 3
#define STATE_ID_INVALID_CLIENT_THRESHOLD    9
#define STATE_ID_NEEDED_DUPE_DETRACT_COUNT   3
#define STATE_ID_MAX_VALID_COUNT 5

enum SERVICE_HOST_INFO_CODE
{
    SERVICE_HOST_INFO_NETBIOS_NAME = 1
};

void FailInProcessService(AppIdSession*, const AppIdConfig*);
int AddFTPServiceState(AppIdSession*);

class ServiceDiscovery : public AppIdDiscovery
{
public:
    ~ServiceDiscovery();
    static ServiceDiscovery& get_instance();

    void finalize_service_patterns();
    int add_service_port(AppIdDetector*, const ServiceDetectorPort&) override;

    AppIdDetectorsIterator get_detector_iterator(IpProtocol);
    ServiceDetector* get_next_tcp_detector(AppIdDetectorsIterator&);
    ServiceDetector* get_next_udp_detector(AppIdDetectorsIterator&);

    bool do_service_discovery(AppIdSession&, IpProtocol, int, AppId, AppId,  Packet*);
    int AppIdDiscoverService(Packet*, const int dir, AppIdSession*);
    int fail_service(AppIdSession*, const Packet*, int dir, ServiceDetector*);
    int incompatible_data(AppIdSession*, const Packet*, int dir, ServiceDetector*);

    std::map<uint16_t, std::vector<ServiceDetector*> > tcp_services;
    std::map<uint16_t, std::vector<ServiceDetector*> > udp_services;
    std::map<uint16_t, std::vector<ServiceDetector*> > udp_reversed_services;

private:
    ServiceDiscovery();
    void initialize() override;
    void get_next_service(const Packet*, const int dir, AppIdSession*, ServiceDiscoveryState*);
    void get_port_based_services(IpProtocol, uint16_t port, AppIdSession*);
    void match_services_by_pattern(AppIdSession*, const Packet*, IpProtocol);
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

//#define SERVICE_DEBUG 1
//#define SERVICE_DEBUG_PORT  80

#ifdef SERVICE_DEBUG
static const char* service_id_state_name[] =
{
    "NEW",
    "VALID",
    "PORT",
    "PATTERN",
    "BRUTE_FORCE"
};

#ifdef SERVICE_DEBUG_PORT
#define APPID_LOG_SERVICE(fmt) fprintf(SF_DEBUG_FILE, fmt)
#define APPID_LOG_FILTER_PORTS(dp, sp, fmt, ...) \
    if (dp == SERVICE_DEBUG_PORT || sp == SERVICE_DEBUG_PORT) \
        fprintf(SF_DEBUG_FILE, fmt, __VA_ARGS__)
#define APPID_LOG_FILTER_SERVICE_PORT(port, fmt, ...) \
    if (port == SERVICE_DEBUG_PORT) \
        fprintf(SF_DEBUG_FILE, fmt, __VA_ARGS__)
#define APPID_LOG_IP_FILTER_PORTS(dp, sp, ip, fmt, ...) \
    if (dp == SERVICE_DEBUG_PORT || sp == SERVICE_DEBUG_PORT) \
    { \
        char ipstr[INET6_ADDRSTRLEN]; \
        sfip_ntop(&ip, ipstr, sizeof(ipstr)); \
        fprintf(SF_DEBUG_FILE, fmt, __VA_ARGS__); \
    }
#else
#define APPID_LOG_SERVICE(fmt) fprintf(SF_DEBUG_FILE, fmt)
#define APPID_LOG_FILTER_PORTS(dp, sp, fmt, ...) fprintf(SF_DEBUG_FILE, fmt, __VA_ARGS__)
#define APPID_LOG_FILTER_SERVICE_PORT(port, fmt, ...) \
    UNUSED(port); \
    fprintf(SF_DEBUG_FILE, fmt, __VA_ARGS__)
#define APPID_LOG_IP_FILTER_PORTS(dp, sp, ip, fmt, ...) \
    { \
        char ipstr[INET6_ADDRSTRLEN]; \
        sfip_ntop(&ip, ipstr, sizeof(ipstr)); \
        fprintf(SF_DEBUG_FILE, fmt, __VA_ARGS__); \
    }
#endif
#else
#define APPID_LOG_SERVICE(fmt)
#define APPID_LOG_FILTER_PORTS(dp, sp, fmt, ...)
#define APPID_LOG_FILTER_SERVICE_PORT(port, fmt, ...) UNUSED(port);
#define APPID_LOG_IP_FILTER_PORTS(dp, sp, ip, fmt, ...) UNUSED(ip);
#endif

#endif


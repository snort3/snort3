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

// service_discovery.h author Sourcefire Inc.

#ifndef SERVICE_DISCOVERY_H
#define SERVICE_DISCOVERY_H

#include "appid_discovery.h"

#include <unordered_map>
#include <vector>

#include "flow/flow.h"
#include "log/messages.h"
#include "utils/sflsq.h"

#include "appid_types.h"

class AppIdConfig;
class AppIdSession;
class ServiceDetector;
class ServiceDiscoveryState;

namespace snort
{
struct Packet;
}

#define STATE_ID_INCONCLUSIVE_SERVICE_WEIGHT 3
#define STATE_ID_INVALID_CLIENT_THRESHOLD    9
#define STATE_ID_NEEDED_DUPE_DETRACT_COUNT   3
#define STATE_ID_MAX_VALID_COUNT 5

enum SERVICE_HOST_INFO_CODE
{
    SERVICE_HOST_INFO_NETBIOS_NAME = 1
};

/* Service state stored per flow, which acts based on global SERVICE_ID_STATE
 * at the beginning of the flow, then independently do service discovery, and
 * synchronize findings at the end of service discovery by the flow.
 */
enum SESSION_SERVICE_SEARCH_STATE
{
    START = 0,
    PORT,
    PATTERN,
    PENDING
};

class ServiceDiscovery : public AppIdDiscovery
{
public:
    static ServiceDiscovery& get_instance(AppIdInspector* ins = nullptr);
    static void release_instance();

    void finalize_service_patterns();
    int add_service_port(AppIdDetector*, const ServiceDetectorPort&) override;

    AppIdDetectorsIterator get_detector_iterator(IpProtocol);
    ServiceDetector* get_next_tcp_detector(AppIdDetectorsIterator&);
    ServiceDetector* get_next_udp_detector(AppIdDetectorsIterator&);

    bool do_service_discovery(AppIdSession&, snort::Packet*, AppidSessionDirection dir);
    int identify_service(AppIdSession&, snort::Packet*, AppidSessionDirection dir);
    int fail_service(AppIdSession&, const snort::Packet*, AppidSessionDirection dir, ServiceDetector*, ServiceDiscoveryState* sds = nullptr);
    int incompatible_data(AppIdSession&, const snort::Packet*, AppidSessionDirection dir, ServiceDetector*);
    static int add_ftp_service_state(AppIdSession&);
    void release_thread_resources();
private:
    ServiceDiscovery(AppIdInspector& ins);
    void initialize() override;
    void get_next_service(const snort::Packet*, const AppidSessionDirection dir, AppIdSession&);
    void get_port_based_services(IpProtocol, uint16_t port, AppIdSession&);
    void match_by_pattern(AppIdSession&, const snort::Packet*, IpProtocol);
    static ServiceDiscovery* discovery_manager;
    std::vector<AppIdDetector*> service_detector_list;
    std::unordered_map<uint16_t, std::vector<ServiceDetector*> > tcp_services;
    std::unordered_map<uint16_t, std::vector<ServiceDetector*> > udp_services;
    std::unordered_map<uint16_t, std::vector<ServiceDetector*> > udp_reversed_services;
};

#endif


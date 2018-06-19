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

// service_mdns.h author Sourcefire Inc.

#ifndef SERVICE_MDNS_H
#define SERVICE_MDNS_H

#include "service_detector.h"

namespace snort
{
class SearchTool;
}
class ServiceDiscovery;
struct MatchedPatterns;

class MdnsServiceDetector : public ServiceDetector
{
public:
    MdnsServiceDetector(ServiceDiscovery*);
    ~MdnsServiceDetector() override;

    int validate(AppIdDiscoveryArgs&) override;
    void release_thread_resources() override;

private:
    unsigned create_match_list(const char* data, uint16_t dataSize);
    void scan_matched_patterns(const char* dataPtr, uint16_t index, const char** resp_endptr,
        int* pattern_length);
    void destroy_match_list();
    void destory_matcher();
    int validate_reply(const uint8_t* data, uint16_t size);
    int analyze_user(AppIdSession&, const snort::Packet*, uint16_t size);
    int reference_pointer(const char* start_ptr, const char** resp_endptr, int* start_index,
        uint16_t data_size, uint8_t* user_name_len, unsigned size);

    snort::SearchTool* matcher = nullptr;
};
#endif


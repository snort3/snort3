//--------------------------------------------------------------------------
// Copyright (C) 2019-2025 Cisco and/or its affiliates. All rights reserved.
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
// shadowtraffic_aggregator.h author Ashutosh Gupta <ashugup3@cisco.com>

#ifndef SHADOWTRAFFIC_AGGREGATOR_H
#define SHADOWTRAFFIC_AGGREGATOR_H

#include "framework/data_bus.h"

// Shadow traffic types are defined as bitmaps as a single flow can qualify for multiple shadow traffic types.

#define ShadowTraffic_Type_Encrypted_DNS      0x00000001
#define ShadowTraffic_Type_ECH                0x00000002
#define ShadowTraffic_Type_Evasive_VPN        0x00000004
#define ShadowTraffic_Type_Multihop_Proxy     0x00000008
#define ShadowTraffic_Type_Domain_Fronting    0x00000010
#define ShadowTraffic_Type_Domain_Faking      0x00000020

namespace snort
{

struct ShadowTrafficEventIds
{
    enum : unsigned
    {
        SHADOWTRAFFIC_FLOW_DETECTED,
        num_ids
    };

    static const snort::PubKey shadowtraffic_pub_key;
};

const snort::PubKey shadowtraffic_pub_key { "shadowtraffic", ShadowTrafficEventIds::num_ids };

class SO_PUBLIC ShadowTrafficEvent : public snort::DataEvent {
    public:
        ShadowTrafficEvent( const uint32_t shadowtraffic_type, const std::string& server_name, 
            const std::string& process_name, const std::string& application_name) : 
                shadowtraffictype(shadowtraffic_type), server_name(server_name), 
                    process_name(process_name), application_name(application_name) {}

        uint32_t get_shadowtraffic_type() { return shadowtraffictype; }
        std::string& get_server_name () { return server_name; }
        std::string& get_process_name () { return process_name; } 
        std::string& get_application_name () { return application_name; }
        
    private:
        uint32_t      shadowtraffictype;
        std::string   server_name;
        std::string   process_name;
        std::string   application_name; 
};

}
#endif // SHADOWTRAFFIC_AGGREGATOR_H

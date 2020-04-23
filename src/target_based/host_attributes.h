//--------------------------------------------------------------------------
// Copyright (C) 2014-2020 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2006-2013 Sourcefire, Inc.
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

// host_attributes.h author davis mcpherson

#ifndef HOST_ATTRIBUTES_H
#define HOST_ATTRIBUTES_H

// Provides attribute table initialization, lookup, swap, and releasing.

#include <vector>

#include "sfip/sf_cidr.h"
#include "sfrt/sfrt.h"
#include "target_based/snort_protocols.h"

struct ApplicationEntry
{
    ApplicationEntry() = default;
    ApplicationEntry(uint16_t port, uint16_t protocol, SnortProtocolId spi)
        : port(port), ipproto(protocol), snort_protocol_id(spi)
    { }
    ~ApplicationEntry() = default;

    uint16_t port = 0;
    uint16_t ipproto = 0;
    SnortProtocolId snort_protocol_id = 0;
};

struct HostInfo
{
    uint8_t streamPolicy = 0;
    uint8_t fragPolicy = 0;
};

struct HostAttributeEntry
{
    HostAttributeEntry() = default;
    ~HostAttributeEntry();

    void add_service(ApplicationEntry*);
    void update_service(HostAttributeEntry*, uint16_t port, uint16_t protocol, SnortProtocolId);
    SnortProtocolId get_snort_protocol_id(int ipprotocol, uint16_t port) const;

    snort::SfCidr ipAddr;
    HostInfo hostInfo;
    std::vector<ApplicationEntry*> services;
};

#define DEFAULT_MAX_ATTRIBUTE_HOSTS 10000
#define DEFAULT_MAX_ATTRIBUTE_SERVICES_PER_HOST 100
#define DEFAULT_MAX_METADATA_SERVICES 9

namespace snort
{
struct SfIp;
struct SnortConfig;
}

struct HostAttributesTable
{
    HostAttributesTable(uint32_t max_hosts);
    ~HostAttributesTable();

    bool add_host(HostAttributeEntry*);
    HostAttributeEntry* get_host(snort::SfIp*);
    HostAttributeEntry* find_host(const snort::SfIp*);
    void add_service(HostAttributeEntry*, ApplicationEntry*);

    bool is_host_attribute_table_full()
    { return num_hosts >= max_hosts; }

    uint32_t get_num_hosts () const
    { return num_hosts; }

private:
    table_t* host_table;
    uint32_t max_hosts;
    uint32_t num_hosts = 0;

    bool sfat_grammar_error_printed = false;
    bool sfat_insufficient_space_logged = false;

    static void free_host_entry(void* host);
};

class HostAttributes
{
public:
    static void load_hosts_file(snort::SnortConfig*, const char* fname);
    static HostAttributesTable* activate();
    static HostAttributesTable* get_host_attributes_table();
    static void set_host_attributes_table(HostAttributesTable*);
    static bool add_host(HostAttributeEntry*, snort::SnortConfig*);
    static HostAttributeEntry* find_host(const snort::SfIp* ipAddr);
    static void update_service(snort::SfIp*, uint16_t port, uint16_t protocol, uint16_t id);
    static void cleanup();
};


#endif


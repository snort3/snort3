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

// host_attributes.cc  Author: davis mcpherson

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "host_attributes.h"

#include "log/messages.h"
#include "main/shell.h"
#include "main/snort_config.h"
#include "protocols/packet.h"
#include "sfrt/sfrt.h"
#include "utils/stats.h"
#include "utils/util.h"

using namespace snort;

static THREAD_LOCAL HostAttributesTable* curr_cfg = nullptr;
static HostAttributesTable* next_cfg = nullptr;

void HostAttributesTable::free_host_entry(void* host)
{ delete (HostAttributeEntry*)host; }

HostAttributesTable::HostAttributesTable(uint32_t max_hosts)
    : max_hosts(max_hosts)
{
    // Add 1 to max for table purposes
    // We use max_hosts to limit memcap, assume 16k per entry costs
    // FIXIT-M 16k per host is no longer true
    host_table = sfrt_new(DIR_8x16, IPv6, max_hosts + 1, (max_hosts >> 6) + 1);
}

HostAttributesTable::~HostAttributesTable()
{
    sfrt_cleanup(host_table, HostAttributesTable::free_host_entry);
    sfrt_free(host_table);
}

bool HostAttributesTable::add_host(HostAttributeEntry* host)
{
    SfCidr* ipAddr = &host->ipAddr;
    int ret = sfrt_insert(ipAddr, (unsigned char)ipAddr->get_bits(), host,
                          RT_FAVOR_SPECIFIC, host_table);

    if ( ret == RT_SUCCESS )
    {
        ++num_hosts;
        return true;
    }

    if ( ret == RT_POLICY_TABLE_EXCEEDED )
    {
        if ( !sfat_insufficient_space_logged )
        {
            ParseWarning(WARN_HOSTS, "Attribute table insertion failed: %d Insufficient "
                         "space in attribute table, only configured to store %u hosts\n",
                         ret, max_hosts);
            sfat_insufficient_space_logged = true;
        }

        proc_stats.attribute_table_overflow++;
    }
    else if ( !sfat_grammar_error_printed )
    {
        ParseWarning(WARN_HOSTS, "Attribute table insertion failed: %d '%s'\n",
                     ret, rt_error_messages[ret]);
        sfat_grammar_error_printed = true;
    }

    return false;
}

HostAttributeEntry* HostAttributesTable::get_host(SfIp* ipAddr)
{
    HostAttributeEntry* host = (HostAttributeEntry*)sfrt_lookup(ipAddr, host_table);
    if ( !host && !is_host_attribute_table_full() )
    {
        host = new HostAttributeEntry;
        host->ipAddr.set(*ipAddr);
        if ( !curr_cfg->add_host(host) )
        {
            delete host;
            host = nullptr;
        }
    }

    return host;
}

HostAttributeEntry* HostAttributesTable::find_host(const SfIp* ipAddr)
{ return (HostAttributeEntry*)sfrt_lookup(ipAddr, host_table); }

HostAttributeEntry::~HostAttributeEntry()
{
   for ( auto app : services )
       delete app;
}

void HostAttributeEntry::add_service(ApplicationEntry* app)
{ services.push_back(app); }

void HostAttributeEntry::update_service
    (HostAttributeEntry* host, uint16_t port, uint16_t protocol, SnortProtocolId snort_protocol_id)
{
    unsigned service_count = 0;

    for ( auto app : services)
    {
        if ( app->ipproto == protocol && (uint16_t)app->port == port )
        {
            app->snort_protocol_id = snort_protocol_id;
            return;
        }

        service_count++;
    }

    // application service not found, add it
    if ( service_count >= SnortConfig::get_conf()->get_max_services_per_host() )
        return;

    ApplicationEntry* app = new ApplicationEntry(port, protocol, snort_protocol_id);
    host->add_service(app);
}

SnortProtocolId HostAttributeEntry::get_snort_protocol_id(int ipprotocol, uint16_t port) const
{
    for ( auto app : services )
    {
        if ( (app->ipproto == ipprotocol) && (app->port == port) )
            return app->snort_protocol_id;
    }

    return 0;
}

void HostAttributes::load_hosts_file(SnortConfig* sc, const char* fname)
{
    delete next_cfg;
    next_cfg = new HostAttributesTable(sc->max_attribute_hosts);

    Shell sh(fname);

    if ( !sh.configure(sc, false, true) )
    {
        delete next_cfg;
        next_cfg = nullptr;
    }
}

HostAttributesTable* HostAttributes::activate()
{
    curr_cfg = next_cfg;
    next_cfg = nullptr;

    if ( curr_cfg )
        proc_stats.attribute_table_hosts = curr_cfg->get_num_hosts();
    else
        proc_stats.attribute_table_hosts = 0;

    return curr_cfg;
}

void HostAttributes::set_host_attributes_table(HostAttributesTable* p)
{ curr_cfg = p; }

HostAttributesTable* HostAttributes::get_host_attributes_table()
{ return curr_cfg; }

bool HostAttributes::add_host(HostAttributeEntry* host, snort::SnortConfig* sc)
{
    if ( !next_cfg )
        next_cfg = new HostAttributesTable(sc->max_attribute_hosts);

    return next_cfg->add_host(host);
}

HostAttributeEntry* HostAttributes::find_host(const SfIp* ipAddr)
{
    if ( !curr_cfg )
        return nullptr;

    return curr_cfg->find_host(ipAddr);
}

void HostAttributes::update_service(SfIp* ipAddr, uint16_t port, uint16_t protocol, SnortProtocolId snort_protocol_id)
{
    if ( curr_cfg )
    {
        HostAttributeEntry* host = curr_cfg->get_host(ipAddr);
        if ( host )
            host->update_service(host, port, protocol, snort_protocol_id);
    }
}

void HostAttributes::cleanup()
{ delete curr_cfg; }

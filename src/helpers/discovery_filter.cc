//--------------------------------------------------------------------------
// Copyright (C) 2019-2019 Cisco and/or its affiliates. All rights reserved.
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

// discovery_filter.cc author Masud Hasan <mashasan@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "discovery_filter.h"

#include <fstream>
#include <sstream>
#include <string>

#include "log/messages.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;
using namespace std;

#define DF_APP_CHECKED    0x01
#define DF_APP_MONITORED  0x02
#define DF_HOST_CHECKED   0x04
#define DF_HOST_MONITORED 0x08
#define DF_USER_CHECKED   0x10
#define DF_USER_MONITORED 0x20

DiscoveryFilter::DiscoveryFilter(const string& conf_path)
{
    if ( conf_path.empty() )
        return;

    ifstream in_stream(conf_path);
    if ( !in_stream )
        return;

    vartable = sfvt_alloc_table(); // create empty table when configuration is given
    uint32_t line_num = 0;

    while ( in_stream )
    {
        string line("");
        getline(in_stream, line);
        ++line_num;
        if ( line.empty() or line.front() == '#' )
            continue;

        istringstream line_stream(line);
        string config_type("");
        line_stream >> config_type;

        if ( config_type == "config" )
        {
            string config_key(""), config_value("");
            line_stream >> config_key >> config_value;

            if ( config_key.empty() or config_value.empty() )
            {
                WarningMessage("Discovery Filter: Empty configuration items at line %u from %s\n",
                    line_num, conf_path.c_str());
                continue;
            }

            if ( config_key.find("Analyze", 0, sizeof("Analyze")-1) != 0 )
                continue;

            int64_t zone = DF_ANY_ZONE;
            string config_zone("");
            line_stream >> config_zone;
            if ( !config_zone.empty() and config_zone != "-1" )
            {
                if (config_zone == "0")
                    zone = 0;
                else
                {
                    zone = strtol(config_zone.c_str(), nullptr, 0);
                    if ( zone < 1 or zone >= DF_ANY_ZONE )
                    {
                        WarningMessage("Discovery Filter: Invalid zone at line %u from %s;"
                            " supported range is -1 (any) to %d\n", line_num,
                            conf_path.c_str(), DF_ANY_ZONE-1);
                        continue;
                    }
                }
            }

            // host or user discovery will also enable application discovery
            if ( config_key == "AnalyzeApplication" )
            {
                add_ip(DF_APP, zone, config_value);
            }
            else if ( config_key == "AnalyzeHost" )
            {
                add_ip(DF_APP, zone, config_value);
                add_ip(DF_HOST, zone, config_value);
            }
            else if ( config_key == "AnalyzeUser" )
            {
                add_ip(DF_APP, zone, config_value);
                add_ip(DF_USER, zone, config_value);
            }
            else if ( config_key == "AnalyzeHostUser" or config_key == "Analyze" )
            {
                add_ip(DF_APP, zone, config_value);
                add_ip(DF_HOST, zone, config_value);
                add_ip(DF_USER, zone, config_value);
            }
        }
    }

    // Merge any-zone rules to zone-based rules
    for (int type = DF_APP; type < DF_MAX; ++type)
    {
        auto any_list = get_list((FilterType)type, DF_ANY_ZONE);
        if (!any_list)
            continue;
        for (auto& zone_entry : zone_list[type])
        {
            if (zone_entry.second != any_list and
                sfvar_add(zone_entry.second, any_list) != SFIP_SUCCESS)
                WarningMessage("Discovery Filter: Failed to add any network list "
                    "to zone network list for type %d", type);
        }
    }

    in_stream.close();
}

DiscoveryFilter::~DiscoveryFilter()
{
    sfvt_free_table(vartable);
}

bool DiscoveryFilter::is_app_monitored(const Packet* p, uint8_t* flag)
{
    if ( flag == nullptr )
        return is_monitored(p, DF_APP);
    return is_monitored(p, DF_APP, *flag, DF_APP_CHECKED, DF_APP_MONITORED);
}

bool DiscoveryFilter::is_host_monitored(const Packet* p, uint8_t* flag)
{
    if ( flag == nullptr )
        return is_monitored(p, DF_HOST);
    return is_monitored(p, DF_HOST, *flag, DF_HOST_CHECKED, DF_HOST_MONITORED);
}

bool DiscoveryFilter::is_user_monitored(const Packet* p, uint8_t* flag)
{
    if ( flag == nullptr )
        return is_monitored(p, DF_USER);
    return is_monitored(p, DF_USER, *flag, DF_USER_CHECKED, DF_USER_MONITORED);
}

bool DiscoveryFilter::is_monitored(const Packet* p, FilterType type, uint8_t& flag,
    uint8_t checked, uint8_t monitored)
{
    if ( flag & checked )
        return flag & monitored;

    flag |= checked;

    if ( is_monitored(p, type) )
    {
        flag |= monitored;
        return true;
    }

    flag &= ~monitored;
    return false;
}

bool DiscoveryFilter::is_monitored(const Packet* p, FilterType type)
{
    if ( !vartable )
        return true; // when not configured, 'any' ip/port/zone are monitored by default

    // Do port-based filtering first, which is independent of application/host/user type.
    // Keep an unordered map of <port, exclusion> where exclusion object holds pointers
    // to ip-list from vartable for each direction (src/dst) and protocol (tcp/udp).

    if (zone_list[type].empty())
        return false; // the configuration did not have this type of rule

    auto zone = p->pkth->ingress_group;
    if ( zone == DAQ_PKTHDR_UNKNOWN or zone < 0 )
        zone = DF_ANY_ZONE;
    auto varip = get_list(type, zone, true);
    if (!varip and zone != DF_ANY_ZONE)
        varip = get_list(type, DF_ANY_ZONE, true);

    return sfvar_ip_in(varip, p->ptrs.ip_api.get_src()); // source ip only
}

void DiscoveryFilter::add_ip(FilterType type, ZoneType zone, string& ip)
{
    auto varip = get_list(type, zone);
    if ( varip )
        sfvt_add_to_var(vartable, varip, ip.c_str());
    else
    {
        string named_ip = to_string((int)type);
        named_ip += "_";
        named_ip += to_string(zone);
        named_ip += " ";
        named_ip += ip;

        if ( sfvt_add_str(vartable, named_ip.c_str(), &varip) == SFIP_SUCCESS )
            zone_list[type].emplace(zone, varip);
    }
}

sfip_var_t* DiscoveryFilter::get_list(FilterType type, ZoneType zone, bool exclude_empty)
{
    auto& list = zone_list[type];
    auto entry = list.find(zone);

    // If head is empty and the boolean flag is true, treat every IP as excluded. The flag
    // is not used during parsing when we are still building, it is used during searching.
    if ( entry == list.end() or (exclude_empty and entry->second->head == nullptr) )
        return nullptr;
    return entry->second;
}

#ifdef UNIT_TEST
TEST_CASE("Discovery Filter", "[is_monitored]")
{
    string conf("test.txt");
    ofstream out_stream(conf.c_str());
    out_stream << "config Error\n"; // invalid
    out_stream << "config AnalyzeUser ::/0 0\n"; // any ipv6, zone 0
    out_stream << "config AnalyzeApplication 1.1.1.0/24 -1\n"; // targeted ipv4, any zone
    out_stream.close();

    Packet p;
    SfIp ip;
    ip.set("1.1.1.1"); // zone 0 by default
    p.ptrs.ip_api.set(ip, ip);
    DiscoveryFilter df(conf);

    // Without flag
    CHECK(df.is_app_monitored(&p, nullptr) == true);   // any zone rule for app is added to zone 0
    CHECK(df.is_host_monitored(&p, nullptr) == false); // no rule for host
    CHECK(df.is_user_monitored(&p, nullptr) == false); // no any zone rule for user

    // With flag
    uint8_t flag = 0;
    CHECK((flag & DF_APP_CHECKED) != DF_APP_CHECKED);
    CHECK((flag & DF_APP_MONITORED) != DF_APP_MONITORED);
    CHECK(df.is_app_monitored(&p, &flag) == true); // first attempt
    CHECK((flag & DF_APP_CHECKED) == DF_APP_CHECKED);
    CHECK((flag & DF_APP_MONITORED) == DF_APP_MONITORED);
    CHECK(df.is_app_monitored(&p, &flag) == true); // second attempt
    CHECK((flag & DF_APP_CHECKED) == DF_APP_CHECKED);
    CHECK((flag & DF_APP_MONITORED) == DF_APP_MONITORED);

    CHECK((flag & DF_USER_CHECKED) != DF_USER_CHECKED);
    CHECK((flag & DF_USER_MONITORED) != DF_USER_MONITORED);
    CHECK(df.is_user_monitored(&p, &flag) == false); // first attempt
    CHECK((flag & DF_USER_CHECKED) == DF_USER_CHECKED);
    CHECK((flag & DF_USER_MONITORED) != DF_USER_MONITORED);
    CHECK(df.is_user_monitored(&p, &flag) == false); // second attempt
    CHECK((flag & DF_USER_CHECKED) == DF_USER_CHECKED);
    CHECK((flag & DF_USER_MONITORED) != DF_USER_MONITORED);

    remove("test.txt");
}

TEST_CASE("Discovery Filter Empty Configuration", "[is_monitored_config]")
{
    string conf("test_empty_analyze.txt");
    ofstream out_stream(conf.c_str());
    out_stream << "Error\n"; // invalid
    out_stream << "config AnalyzeNothing ::/0 3\n"; // invalid
    out_stream.close();

    Packet p;
    SfIp ip;
    ip.set("1.1.1.1");
    p.ptrs.ip_api.set(ip, ip);
    DiscoveryFilter df(conf);

    CHECK(df.is_app_monitored(&p, nullptr) == false);
    CHECK(df.is_host_monitored(&p, nullptr) == false);
    CHECK(df.is_user_monitored(&p, nullptr) == false);

    remove("test_empty_analyze.txt");
}

TEST_CASE("Discovery Filter Zone", "[is_monitored_zone_vs_ip]")
{
    string conf("test_zone_ip.txt");
    ofstream out_stream(conf.c_str());
    out_stream << "config AnalyzeHost 1.1.1.1 -1\n";         // zone any
    out_stream << "config AnalyzeHost 1.1.1.2 0\n";          // zone 0
    out_stream << "config AnalyzeHost 1.1.1.3 2\n";          // zone 2
    out_stream << "config AnalyzeHost 1.1.1.4 -3\n";         // zone out of range
    out_stream << "config AnalyzeHost 1.1.1.5 2147483648\n"; // zone out of range
    out_stream << "config AnalyzeHost 1.1.1.6 kidding\n";    // zone invalid
    out_stream.close();

    Packet p;
    SfIp ip1, ip2, ip3, ip4, ip5, ip6, ip7;
    ip1.set("1.1.1.1");
    ip2.set("1.1.1.2");
    ip3.set("1.1.1.3");
    ip4.set("1.1.1.4");
    ip5.set("1.1.1.5");
    ip6.set("1.1.1.6");
    ip7.set("1.1.1.7");
    const DAQ_PktHdr_t* saved_hdr = p.pkth;
    DAQ_PktHdr_t z_undefined, z1, z2;
    z_undefined.ingress_group = DAQ_PKTHDR_UNKNOWN;
    z1.ingress_group = 1;
    z2.ingress_group = 2;
    DiscoveryFilter df(conf);

    p.ptrs.ip_api.set(ip1, ip7);  // ip from undefined zone matches zone any list
    p.pkth = &z_undefined;
    CHECK(df.is_app_monitored(&p, nullptr) == true); // analyze host enables application discovery
    CHECK(df.is_host_monitored(&p, nullptr) == true);
    CHECK(df.is_user_monitored(&p, nullptr) == false);

    p.pkth = &z2; // the ip is not in zone 2 list, but it is in zone any list
    CHECK(df.is_host_monitored(&p, nullptr) == true);

    p.ptrs.ip_api.set(ip3, ip7); // the ip matches zone 2 list
    CHECK(df.is_host_monitored(&p, nullptr) == true);

    p.pkth = &z1; // no zone 1 list and the ip is not in zone any list
    CHECK(df.is_host_monitored(&p, nullptr) == false);

    p.ptrs.ip_api.set(ip1, ip7); // no zone 1 list, but the ip is in zone any list
    CHECK(df.is_host_monitored(&p, nullptr) == true);

    p.pkth = saved_hdr;
    p.ptrs.ip_api.set(ip2, ip7);  // the ip matches zone 0 list
    CHECK(df.is_host_monitored(&p, nullptr) == true);

    // no match since the configuration for these ip addresses were invalid
    p.ptrs.ip_api.set(ip4, ip7);
    CHECK(df.is_host_monitored(&p, nullptr) == false);
    p.ptrs.ip_api.set(ip5, ip7);
    CHECK(df.is_host_monitored(&p, nullptr) == false);
    p.ptrs.ip_api.set(ip6, ip7);
    CHECK(df.is_host_monitored(&p, nullptr) == false);

    remove("test_zone_ip.txt");
}
#endif

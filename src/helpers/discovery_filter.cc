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

#define DF_APP        "app"
#define DF_HOST       "host"
#define DF_USER       "user"

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

    uint32_t line_num = 0;
    string line, config_type, config_key, config_value;

    while ( in_stream )
    {
        line = "";
        getline(in_stream, line);
        ++line_num;
        if ( line.empty() or line.front() == '#' )
            continue;

        istringstream line_stream(line);
        config_type = config_key = config_value = "";
        line_stream >> config_type >> config_key >> config_value;

        if ( config_type == "config" )
        {
            if ( config_key.empty() or config_value.empty() )
            {
                WarningMessage("Discovery Filter: Empty configuration items at line %u from %s\n",
                    line_num, conf_path.c_str());
                continue;
            }

            // host or user discovery will also enable application discovery
            if ( config_key == "AnalyzeApplication" )
            {
                add_ip(DF_APP, config_value);
            }
            else if ( config_key == "AnalyzeHost" )
            {
                add_ip(DF_APP, config_value);
                add_ip(DF_HOST, config_value);
            }
            else if ( config_key == "AnalyzeUser" )
            {
                add_ip(DF_APP, config_value);
                add_ip(DF_USER, config_value);
            }
            else if ( config_key == "AnalyzeHostUser" or config_key == "Analyze" )
            {
                add_ip(DF_APP, config_value);
                add_ip(DF_HOST, config_value);
                add_ip(DF_USER, config_value);
            }
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

bool DiscoveryFilter::is_monitored(const Packet* p, const char* type, uint8_t& flag,
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

bool DiscoveryFilter::is_monitored(const Packet* p, const char* type)
{
    if ( !vartable )
        return true; // when not configured, 'any' ip/port/zone are monitored by default

    // Do port-based filtering first, which is independent of application/host/user type.
    // Keep an unordered map of <port, exclusion> where exclusion object holds pointers
    // to ip-list from vartable for each direction (src/dst) and protocol (tcp/udp).

    // To do zone-based filtering, keep an unordered map of <zone, ip-list pointer> where
    // the pointer refers to a list from vartable. The list itself should be created
    // during parsing by appending zone id to the name of ip-list. Absence of the list
    // for a particular zone means lookup the 'any' (-1) zone list.

    if ( !varip or strcmp(varip->name, type) )
    {
        varip = sfvt_lookup_var(vartable, type);
        if ( !varip )
            return false;
    }

    return sfvar_ip_in(varip, p->ptrs.ip_api.get_src()); // check source ip only
}

void DiscoveryFilter::add_ip(const char* name, string ip)
{
    if ( !vartable )
        vartable = sfvt_alloc_table();
    else if ( !varip or strcmp(varip->name, name) )
        varip = sfvt_lookup_var(vartable, name);

    if ( varip )
        sfvt_add_to_var(vartable, varip, ip.c_str());
    else
    {
        ip = " " + ip;
        ip = name + ip;
        sfvt_add_str(vartable, ip.c_str(), &varip);
    }
}

#ifdef UNIT_TEST
TEST_CASE("Discovery Filter", "[is_monitored]")
{
    string conf("test.txt");
    ofstream out_stream(conf.c_str());
    out_stream << "config Error\n"; // invalid
    out_stream << "config AnalyzeUser ::/0 3\n"; // any ipv6, zone 3
    out_stream << "config AnalyzeApplication 0.0.0.0/0 -1\n"; // any ipv4, any zone
    out_stream.close();

    Packet p;
    SfIp ip;
    ip.set("1.1.1.1");
    p.ptrs.ip_api.set(ip, ip);
    DiscoveryFilter df(conf);

    // Without flag
    CHECK(df.is_app_monitored(&p, nullptr) == true);
    CHECK(df.is_host_monitored(&p, nullptr) == false);
    CHECK(df.is_user_monitored(&p, nullptr) == false);

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
#endif

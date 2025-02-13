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

// discovery_filter.cc author Masud Hasan <mashasan@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "discovery_filter.h"

#include <fstream>
#include <netdb.h>
#include <sstream>
#include <string>

#include "log/messages.h"
#include "protocols/protocol_ids.h"

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

            int64_t intf = DF_ANY_INTF;
            string config_intf("");
            line_stream >> config_intf;
            if ( !config_intf.empty() and config_intf != "-1" )
            {
                if (config_intf == "0")
                    intf = 0;
                else
                {
                    intf = strtoll(config_intf.c_str(), nullptr, 0);
                    if ( intf < 1 or intf >= DF_ANY_INTF )
                    {
                        WarningMessage("Discovery Filter: Invalid interface at line %u from %s;"
                            " supported range is -1 (any) to %d\n", line_num,
                            conf_path.c_str(), DF_ANY_INTF-1);
                        continue;
                    }
                }
            }

            // host or user discovery will also enable application discovery
            if ( config_key == "AnalyzeApplication" )
            {
                add_ip(DF_APP, intf, config_value);
            }
            else if ( config_key == "AnalyzeHost" )
            {
                add_ip(DF_APP, intf, config_value);
                add_ip(DF_HOST, intf, config_value);
            }
            else if ( config_key == "AnalyzeUser" )
            {
                add_ip(DF_APP, intf, config_value);
                add_ip(DF_USER, intf, config_value);
            }
            else if ( config_key == "AnalyzeHostUser" or config_key == "Analyze" )
            {
                add_ip(DF_APP, intf, config_value);
                add_ip(DF_HOST, intf, config_value);
                add_ip(DF_USER, intf, config_value);
            }
        }
        else if ( config_type == "portexclusion" )
        {
            string dir_str, proto_str, port_str, ip;
            line_stream >> dir_str >> proto_str >> port_str >> ip;

            uint16_t port = strtol(port_str.c_str(), nullptr, 10);
            if ( port == 0 )
            {
                WarningMessage("Discovery Filter: Invalid port at line %u from %s;",
                    line_num, conf_path.c_str());
                continue;
            }

            protoent* pt = getprotobyname(proto_str.c_str());
            if ( pt == nullptr )
            {
                WarningMessage("Discovery Filter: Invalid protocol at line %u from %s;",
                    line_num, conf_path.c_str());
                continue;
            }

            // Port exclusion is done from a session standpoint rather than
            // from a packet standpoint. An illustrative example is the
            // "Discovery Filter Port Exclusion" test.

            if ( dir_str == "dst" )
                add_ip(Direction::SERVER, (uint16_t) pt->p_proto, port, ip);
            else if ( dir_str == "src" )
                add_ip(Direction::CLIENT, (uint16_t) pt->p_proto, port, ip);
            else if ( dir_str == "both" )
            {
                add_ip(Direction::SERVER, (uint16_t) pt->p_proto, port, ip);
                add_ip(Direction::CLIENT, (uint16_t) pt->p_proto, port, ip);
            }
            else
            {
                WarningMessage("Discovery Filter: Invalid direction %s at line %u from %s;"
                   " supported values are src and dst\n", dir_str.c_str(),
                   line_num, conf_path.c_str());
                continue;
            }

        }

    }

    // Merge any-interface rules to interface-based rules
    for (int type = DF_APP; type < DF_MAX; ++type)
    {
        auto any_list = get_list((FilterType)type, DF_ANY_INTF);
        if (!any_list)
            continue;
        for (const auto& intf_entry : intf_ip_list[type])
        {
            if (intf_entry.second != any_list and
                sfvar_add(intf_entry.second, any_list) != SFIP_SUCCESS)
                WarningMessage("Discovery Filter: Failed to add any network list "
                    "to interface network list for type %d", type);
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

bool DiscoveryFilter::is_host_monitored(const Packet* p, uint8_t* flag, const SfIp* ip,
    FlowCheckDirection flowdir)
{
    if ( flag == nullptr )
        return is_monitored(p, DF_HOST, ip, flowdir);
    return is_monitored(p, DF_HOST, *flag, DF_HOST_CHECKED, DF_HOST_MONITORED, ip, flowdir);
}

bool DiscoveryFilter::is_user_monitored(const Packet* p, uint8_t* flag)
{
    if ( flag == nullptr )
        return is_monitored(p, DF_USER);
    return is_monitored(p, DF_USER, *flag, DF_USER_CHECKED, DF_USER_MONITORED);
}

bool DiscoveryFilter::is_monitored(const Packet* p, FilterType type, uint8_t& flag,
    uint8_t checked, uint8_t monitored, const SfIp* ip, FlowCheckDirection flowdir)
{
    if ( flag & checked )
        return flag & monitored;

    flag |= checked;

    if ( is_monitored(p, type, ip, flowdir) )
    {
        flag |= monitored;
        return true;
    }

    flag &= ~monitored;
    return false;
}

bool DiscoveryFilter::is_monitored(const Packet* p, FilterType type, const SfIp* ip,
    FlowCheckDirection flowdir)
{
    if ( !vartable )
        return true; // when not configured, 'any' ip/port/interface are monitored by default

    // port exclusion
    if ( is_port_excluded(p) )
        return false;

    // check interface
    if ( intf_ip_list[type].empty() )
        return false; // the configuration did not have this type of rule

    int32_t intf = p->pkth->ingress_index;
    const SfIp* host_ip;
    if ( flowdir == FlowCheckDirection::DF_SERVER )
    {
        if ( p->flow->server_intf != DAQ_PKTHDR_UNKNOWN )
            intf = p->flow->server_intf;
        host_ip = &p->flow->server_ip;
    }
    else if ( flowdir == FlowCheckDirection::DF_CLIENT )
    {
        if ( p->flow->client_intf != DAQ_PKTHDR_UNKNOWN )
            intf = p->flow->client_intf;
        host_ip = &p->flow->client_ip;
    }
    else
        host_ip = p->ptrs.ip_api.get_src();

    if ( intf == DAQ_PKTHDR_UNKNOWN or intf < 0 )
        intf = DF_ANY_INTF;
    if ( ip )
        host_ip = ip;

    auto varip = get_list(type, intf, true);
    if ( !varip and intf != DF_ANY_INTF )
        varip = get_list(type, DF_ANY_INTF, true);

    if ( !host_ip )
        return true; // Don't check for non-IP, non ARP

    return sfvar_ip_in(varip, host_ip);
}

bool DiscoveryFilter::is_port_excluded(const Packet* p)
{
    // Port exclusion: if the ip is in the port x protocol list, return true.
    uint32_t key;
    const SfIp* ip;
    uint16_t port;
    auto proto = p->ptrs.ip_api.proto();

    if ( port_ip_list[Direction::CLIENT].empty() and port_ip_list[Direction::SERVER].empty() )
        return false;

    if ( !(proto == IpProtocol::TCP or proto == IpProtocol::UDP) or
        p->ptrs.sp == 0 or p->ptrs.dp == 0 )
        return false;

    if ( p->is_from_client() )
    {
        port = p->ptrs.sp;
        ip = p->ptrs.ip_api.get_src();
        key = proto_port_key(to_utype(proto), port);
        if ( sfvar_ip_in(get_port_list(Direction::CLIENT, key), ip) )
            return true;

        port = p->ptrs.dp;
        ip = p->ptrs.ip_api.get_dst();
        key = proto_port_key(to_utype(proto), port);
        if ( sfvar_ip_in(get_port_list(Direction::SERVER, key), ip) )
            return true;
    }
    else if ( p->is_from_server() )
    {
        port = p->ptrs.dp;
        ip = p->ptrs.ip_api.get_dst();
        key = proto_port_key(to_utype(proto), port);
        if ( sfvar_ip_in(get_port_list(Direction::CLIENT, key), ip) )
            return true;

        port = p->ptrs.sp;
        ip = p->ptrs.ip_api.get_src();
        key = proto_port_key(to_utype(proto), port);
        if ( sfvar_ip_in(get_port_list(Direction::SERVER, key), ip) )
            return true;
    }

    return false;
}

void DiscoveryFilter::add_ip(FilterType type, IntfType intf, string& ip)
{
    auto varip = get_list(type, intf);
    if ( varip )
        sfvt_add_to_var(vartable, varip, ip.c_str());
    else
    {
        string named_ip = to_string((int)type);
        named_ip += "_";
        named_ip += to_string(intf);
        named_ip += " ";
        named_ip += ip;

        if ( sfvt_add_str(vartable, named_ip.c_str(), &varip) == SFIP_SUCCESS )
            intf_ip_list[type].emplace(intf, varip);
    }
}

sfip_var_t* DiscoveryFilter::get_list(FilterType type, IntfType intf, bool exclude_empty)
{
    auto& list = intf_ip_list[type];
    auto entry = list.find(intf);

    // If head is empty and the boolean flag is true, treat every IP as excluded. The flag
    // is not used during parsing when we are still building, it is used during searching.
    if ( entry == list.end() or (exclude_empty and entry->second->head == nullptr) )
        return nullptr;
    return entry->second;
}

void DiscoveryFilter::add_ip(Direction dir, uint16_t proto, uint16_t port, const string& ip)
{
    uint32_t key = proto_port_key(proto, port);

    // find it in the local cache first:
    auto varip = get_port_list(dir, key);
    if ( varip )
        sfvt_add_to_var(vartable, varip, ip.c_str());
    else
    {
        string named_ip = to_string(dir);
        named_ip += "_";
        named_ip += to_string(proto);
        named_ip += "_";
        named_ip += to_string(port);
        named_ip += " ";
        named_ip += ip;

        if ( sfvt_add_str(vartable, named_ip.c_str(), &varip) == SFIP_SUCCESS )
            port_ip_list[dir].emplace(key, varip);
    }
}

sfip_var_t* DiscoveryFilter::get_port_list(Direction dir, uint32_t key)
{
    auto& list = port_ip_list[dir];
    auto entry = list.find(key);
    return entry == list.end() ? nullptr : entry->second;
}

#ifdef UNIT_TEST

bool is_port_excluded_test(DiscoveryFilter& df, Packet* p)
{
    return df.is_port_excluded(p);
}

TEST_CASE("Discovery Filter", "[is_monitored]")
{
    string conf("test.txt");
    ofstream out_stream(conf.c_str());
    out_stream << "config Error\n"; // invalid
    out_stream << "config AnalyzeUser ::/0 0\n"; // any ipv6, interface 0
    out_stream << "config AnalyzeApplication 1.1.1.0/24 -1\n"; // targeted ipv4, any interface
    out_stream.close();

    Packet p;
    SfIp ip;
    ip.set("1.1.1.1"); // interface 0 by default
    p.ptrs.ip_api.set(ip, ip);
    DiscoveryFilter df(conf);

    // Without flag
    CHECK(true == df.is_app_monitored(&p, nullptr));   // any interface rule for app is added to interface 0
    CHECK(false == df.is_host_monitored(&p, nullptr)); // no rule for host
    CHECK(false == df.is_user_monitored(&p, nullptr)); // no any interface rule for user

    // With flag
    uint8_t flag = 0;
    CHECK((flag & DF_APP_CHECKED) != DF_APP_CHECKED);
    CHECK((flag & DF_APP_MONITORED) != DF_APP_MONITORED);
    CHECK(true == df.is_app_monitored(&p, &flag)); // first attempt
    CHECK((flag & DF_APP_CHECKED) == DF_APP_CHECKED);
    CHECK((flag & DF_APP_MONITORED) == DF_APP_MONITORED);
    CHECK(true == df.is_app_monitored(&p, &flag)); // second attempt
    CHECK((flag & DF_APP_CHECKED) == DF_APP_CHECKED);
    CHECK((flag & DF_APP_MONITORED) == DF_APP_MONITORED);

    CHECK((flag & DF_USER_CHECKED) != DF_USER_CHECKED);
    CHECK((flag & DF_USER_MONITORED) != DF_USER_MONITORED);
    CHECK(false == df.is_user_monitored(&p, &flag)); // first attempt
    CHECK((flag & DF_USER_CHECKED) == DF_USER_CHECKED);
    CHECK((flag & DF_USER_MONITORED) != DF_USER_MONITORED);
    CHECK(false == df.is_user_monitored(&p, &flag)); // second attempt
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

    CHECK(false == df.is_app_monitored(&p, nullptr));
    CHECK(false == df.is_host_monitored(&p, nullptr));
    CHECK(false == df.is_user_monitored(&p, nullptr));

    remove("test_empty_analyze.txt");
}

TEST_CASE("Discovery Filter Intf", "[is_monitored_intf_vs_ip]")
{
    string conf("test_intf_ip.txt");
    ofstream out_stream(conf.c_str());
    out_stream << "config AnalyzeHost 1.1.1.1 -1\n";         // interface any
    out_stream << "config AnalyzeHost 1.1.1.2 0\n";          // interface 0
    out_stream << "config AnalyzeHost 1.1.1.3 2\n";          // interface 2
    out_stream << "config AnalyzeHost 1.1.1.4 -3\n";         // interface out of range
    out_stream << "config AnalyzeHost 1.1.1.5 2147483648\n"; // interface out of range
    out_stream << "config AnalyzeHost 1.1.1.6 kidding\n";    // interface invalid
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
    z_undefined.ingress_index = DAQ_PKTHDR_UNKNOWN;
    z1.ingress_index = 1;
    z2.ingress_index = 2;
    DiscoveryFilter df(conf);

    p.ptrs.ip_api.set(ip1, ip7);  // ip from undefined interface matches interface any list
    p.pkth = &z_undefined;
    CHECK(true == df.is_app_monitored(&p, nullptr)); // analyze host enables application discovery
    CHECK(true == df.is_host_monitored(&p, nullptr));
    CHECK(false == df.is_user_monitored(&p, nullptr));

    p.pkth = &z2; // the ip is not in interface 2 list, but it is in interface any list
    CHECK(true == df.is_host_monitored(&p, nullptr));

    p.ptrs.ip_api.set(ip3, ip7); // the ip matches interface 2 list
    CHECK(true == df.is_host_monitored(&p, nullptr));

    p.pkth = &z1; // no interface 1 list and the ip is not in interface any list
    CHECK(false == df.is_host_monitored(&p, nullptr));

    p.ptrs.ip_api.set(ip1, ip7); // no interface 1 list, but the ip is in interface any list
    CHECK(true == df.is_host_monitored(&p, nullptr));

    p.pkth = saved_hdr;
    p.ptrs.ip_api.set(ip2, ip7);  // the ip matches interface 0 list
    CHECK(true == df.is_host_monitored(&p, nullptr));

    // no match since the configuration for these ip addresses were invalid
    p.ptrs.ip_api.set(ip4, ip7);
    CHECK(false == df.is_host_monitored(&p, nullptr));
    p.ptrs.ip_api.set(ip5, ip7);
    CHECK(false == df.is_host_monitored(&p, nullptr));
    p.ptrs.ip_api.set(ip6, ip7);
    CHECK(false == df.is_host_monitored(&p, nullptr));

    remove("test_intf_ip.txt");
}

TEST_CASE("Discovery Filter Port Exclusion", "[portexclusion]")
{
    uint16_t a_port = 1234;
    uint16_t b_port = 80;

    string a_ip_str = "10.0.0.1";
    SfIp aip;
    aip.set(a_ip_str.c_str());

    string b_ip_str = "10.0.0.2";
    SfIp bip;
    bip.set(b_ip_str.c_str());

    ip::IP4Hdr ab_hdr;                  // A -> B IPV4 header
    ip::IP4Hdr ba_hdr;                  // B -> A IPV4 header

    ab_hdr.ip_proto = IpProtocol::TCP;
    ab_hdr.ip_src = aip.get_ip4_value();
    ab_hdr.ip_dst = bip.get_ip4_value();

    ba_hdr.ip_proto = IpProtocol::TCP;
    ba_hdr.ip_src = bip.get_ip4_value();
    ba_hdr.ip_dst = aip.get_ip4_value();

    string conf("discovery_filter.conf");
    ofstream out(conf.c_str());

    // portexclusion dst tcp 80 10.0.0.2"
    //
    // Exclude traffic outgoing to or returning from 10.0.0.2:80, i.e. traffic
    // in which 10.0.0.2 is the responder (server).
    //
    // This will not exclude traffic initiated by 10.0.0.2 from port 80 though.

    out << "portexclusion dst tcp " << b_port << " " << b_ip_str << endl;
    out.close();

    DiscoveryFilter df(conf);

    Packet p;
    p.ptrs.type = PktType::TCP;

    // Positive test: A = initiator (client), B = responder (server)
    // exclude A <-> B:b_port traffic

    // A -> B:b_port
    p.ptrs.ip_api.set(&ab_hdr);
    p.ptrs.sp = a_port;
    p.ptrs.dp = b_port;
    p.packet_flags = 0x0;
    p.packet_flags |= PKT_FROM_CLIENT;
    CHECK(true == is_port_excluded_test(df, &p));

    // A:any <- B:b_port
    p.ptrs.ip_api.set(&ba_hdr);
    p.ptrs.sp = b_port;
    p.ptrs.dp = a_port;
    p.packet_flags = 0x0;
    p.packet_flags |= PKT_FROM_SERVER;
    CHECK(true == is_port_excluded_test(df, &p));


    // Negative test: B = initiator (client), A = responder (server)
    // do not exclude A <-> B:b_port

    // A <- B:b_port
    p.ptrs.ip_api.set(&ba_hdr);
    p.ptrs.sp = b_port;
    p.ptrs.dp = a_port;
    p.packet_flags = 0x0;
    p.packet_flags |= PKT_FROM_CLIENT;
    CHECK(false == is_port_excluded_test(df, &p));

    // A -> B:b_port
    p.ptrs.ip_api.set(&ab_hdr);
    p.ptrs.sp = a_port;
    p.ptrs.dp = b_port;
    p.packet_flags = 0x0;
    p.packet_flags |= PKT_FROM_SERVER;
    CHECK(false == is_port_excluded_test(df, &p));

    remove(conf.c_str());
}

TEST_CASE("Discovery Filter with Problem Config", "[df_problem_config]")
{
    // Checks a set of configs that previously caused
    // a heap-use-after-free when initializing nodes

    string conf("test_intf_ip.txt");
    ofstream out_stream(conf.c_str());
    out_stream << "config AnalyzeHost 10.0.0.0/24 -1\n";  // interface any
    out_stream << "config AnalyzeHost 10.0.0.0/21 4\n";   // interface 4
    out_stream << "config AnalyzeHost 192.8.8.0/24 -1\n"; // interface any
    out_stream.close();


    // Verifies the config loads with no issues - otherwise, ASAN
    // will report leaks when constructing df below
    DiscoveryFilter df(conf);

    remove("test_intf_ip.txt");
}

#endif

//--------------------------------------------------------------------------
// Copyright (C) 2020-2021 Cisco and/or its affiliates. All rights reserved.
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

// netflow.cc author Ron Dempster <rdempste@cisco.com>
//                   Shashikant Lad <shaslad@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "netflow_headers.h"
#include "netflow_module.h"

#include <fstream>
#include <mutex>
#include <sys/stat.h>
#include <unordered_map>
#include <vector>

#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "sfip/sf_ip.h"
#include "utils/util.h"

using namespace snort;

THREAD_LOCAL NetflowStats netflow_stats;
THREAD_LOCAL ProfileStats netflow_perf_stats;

// compare struct to use with ip sort
struct IpCompare
{
    bool operator()(const snort::SfIp& a, const snort::SfIp& b)
    { return a.less_than(b); }
};

// -----------------------------------------------------------------------------
// static variables
// -----------------------------------------------------------------------------

// Used to avoid creating multiple events for the same initiator IP.
// Cache can be thread local since Netflow packets coming from a Netflow
// device will go to the same thread.
typedef std::unordered_map<snort::SfIp, NetflowSessionRecord, NetflowHash> NetflowCache;
static THREAD_LOCAL NetflowCache* netflow_cache = nullptr;

// cache required to dump the output
static NetflowCache* dump_cache = nullptr;


// -----------------------------------------------------------------------------
// static functions
// -----------------------------------------------------------------------------
static bool filter_record(const NetflowRules* rules, const int zone,
    const SfIp* src, const SfIp* dst)
{
    const SfIp* addr[2] = {src, dst};

    for( auto const & address : addr )
    {
        for( auto const& rule : rules->exclude )
        {
            if ( rule.filter_match(address, zone) )
            {
                return false;
            }
        }
    }

    for( auto const & address : addr )
    {
        for( auto const& rule : rules->include )
        {
            if ( rule.filter_match(address, zone) )
            {
                // check i.create_host i.create_service
                // and publish events
                return true;
            }
        }
    }
    return false;
}

// FIXIT-M - keeping only few checks right now
static bool decode_netflow_v9(const unsigned char* data, uint16_t size)
{
    Netflow9Hdr header;
    const Netflow9Hdr *pheader;

    if( size < sizeof(Netflow9Hdr) )
        return false;

    pheader = (const Netflow9Hdr *)data;
    header.flow_count = ntohs(pheader->flow_count);

    // Invalid header flow count
    if( header.flow_count < NETFLOW_MIN_COUNT or header.flow_count > NETFLOW_MAX_COUNT)
        return false;

    return true;
}

static bool decode_netflow_v5(const unsigned char* data, uint16_t size,
    const Packet* p, const NetflowConfig* cfg)
{
    Netflow5Hdr header;
    const Netflow5Hdr *pheader;
    const Netflow5RecordHdr *precord;
    const Netflow5RecordHdr *end;

    end = (const Netflow5RecordHdr *)(data + size);

    pheader = (const Netflow5Hdr *)data;
    header.flow_count  = ntohs(pheader->flow_count);

    // invalid header flow count
    if( header.flow_count  < NETFLOW_MIN_COUNT or header.flow_count  > NETFLOW_MAX_COUNT )
        return false;

    const NetflowRules* p_rules = nullptr;
    auto d = cfg->device_rule_map.find(*p->ptrs.ip_api.get_src());
    if ( d != cfg->device_rule_map.end() )
        p_rules = &(d->second);
    
    if ( p_rules == nullptr )
        return false;
    const int zone = p->pkth->ingress_index;

    data += sizeof(Netflow5Hdr);
    precord = (const Netflow5RecordHdr *)data;

    // Invalid flow count
    if ( (precord + header.flow_count) > end )
        return false;

    header.sys_uptime = ntohl(pheader->sys_uptime) / 1000;
    header.unix_secs = ntohl(pheader->unix_secs);
    header.unix_secs -= header.sys_uptime;

    // update total records
    netflow_stats.records += header.flow_count;

    unsigned i;
    for ( i=0; i < header.flow_count; i++, precord++ )
    {

        uint32_t first_packet = header.unix_secs + (ntohl(precord->flow_first)/1000);
        uint32_t last_packet = header.unix_secs + (ntohl(precord->flow_last)/1000);

        // invalid flow time values
        if ( first_packet > MAX_TIME or last_packet > MAX_TIME or first_packet > last_packet )
            return false;

        NetflowSessionRecord record = {};

        // Invalid source IP address provided
        if ( record.initiator_ip.set(&precord->flow_src_addr, AF_INET) != SFIP_SUCCESS )
            return false;

        if ( record.responder_ip.set(&precord->flow_dst_addr, AF_INET) != SFIP_SUCCESS )
            return false;

        if ( record.next_hop_ip.set(&precord->next_hop_addr, AF_INET) != SFIP_SUCCESS )
            return false;

        if ( !filter_record(p_rules, zone, &record.initiator_ip, &record.responder_ip) )
            continue;

        record.initiator_port = ntohs(precord->src_port);
        record.responder_port = ntohs(precord->dst_port);
        record.proto = precord->flow_protocol;
        record.first_pkt_second = first_packet;
        record.last_pkt_second = last_packet;
        record.initiator_pkts = ntohl(precord->pkt_count);
        record.responder_pkts = 0;
        record.initiator_bytes = ntohl(precord->bytes_sent);
        record.responder_bytes = 0;
        record.tcp_flags = precord->tcp_flags;
        record.nf_src_tos = precord->tos;
        record.nf_dst_tos = precord->tos;
        record.nf_snmp_in = ntohs(precord->snmp_if_in);
        record.nf_snmp_out = ntohs(precord->snmp_if_out);
        record.nf_src_as = (uint32_t)ntohs(precord->src_as);
        record.nf_dst_as = (uint32_t)ntohs(precord->dst_as);
        record.nf_src_mask = precord->src_mask;
        record.nf_dst_mask = precord->dst_mask;

        // insert record
        auto result = netflow_cache->emplace(record.initiator_ip, record);

        // new unique record
        if ( result.second )
            ++netflow_stats.unique_flows;

    }
    return true;
}

static bool validate_netflow(const Packet* p, const NetflowConfig* cfg)
{
    uint16_t size = p->dsize;
    const unsigned char* data = p->data;
    uint16_t version;
    bool retval = false;

    // invalid packet size
    if( size < sizeof(Netflow5Hdr))
        return false;

    version = ntohs(*((const uint16_t *)data));

    if( version == 5 )
    {
        retval = decode_netflow_v5(data, size, p, cfg);
        if ( retval )
        {
            ++netflow_stats.packets;
            ++netflow_stats.version_5;
        }
    }
    else if (version == 9)
    {
        retval = decode_netflow_v9(data, size);
        if ( retval )
        {
            ++netflow_stats.packets;
            ++netflow_stats.version_9;
        }
    }

    return retval;
}

//-------------------------------------------------------------------------
// inspector stuff
//-------------------------------------------------------------------------

class NetflowInspector : public snort::Inspector
{
public:
    NetflowInspector(const NetflowConfig*);
    ~NetflowInspector() override;

    void tinit() override;
    void tterm() override;

    void eval(snort::Packet*) override;
    void show(const snort::SnortConfig*) const override;

private:
    const NetflowConfig *config;

    bool log_netflow_cache();
    void stringify(std::ofstream&);
};

static std::string to_string(const std::vector <snort::SfCidr>& networks)
{
    std::string nets;
    if ( networks.empty() )
    {
        nets = "any";
    }
    else
    {
        for( auto const& n : networks )
        {
            SfIpString s;
            n.ntop(s);
            nets += s;
            auto bits = n.get_bits();
            bits -= (n.get_family() == AF_INET and bits) ? 96 : 0;
            nets += "/" + std::to_string(bits);
            nets += " ";
        }
    }
    return nets;
}

static std::string to_string(const std::vector <int>& zones)
{
    std::string zs;
    if ( zones.empty() )
    {
        zs = "any";
    }
    else
    {
        for( auto const& z : zones )
        {
            if ( z == NETFLOW_ANY_ZONE )
            {
                zs = "any";
                break;
            }
            else
                zs += std::to_string(z) + " ";
        }
    }
    return zs;
}

static void show_device(const NetflowRule& d, bool is_exclude)
{
    ConfigLogger::log_flag("exclude", is_exclude, true);
    ConfigLogger::log_flag("create_host", d.create_host, true);
    ConfigLogger::log_flag("create_service", d.create_service, true);
    ConfigLogger::log_value("networks", to_string(d.networks).c_str(), true);
    ConfigLogger::log_value("zones", to_string(d.zones).c_str(), true);
}

void NetflowInspector::show(const SnortConfig*) const
{
    ConfigLogger::log_value("dump_file", config->dump_file);
    ConfigLogger::log_value("update_timeout", config->update_timeout);
    std::once_flag d_once;
    for ( auto const& d : config->device_rule_map )
    {
        std::call_once(d_once, []{ ConfigLogger::log_option("rules"); });
        SfIpString addr_str;
        d.first.ntop(addr_str);
        for( auto const& r : d.second.exclude )
        {
            ConfigLogger::log_value("device_ip", addr_str);
            show_device(r, true);
        }
        for( auto const& r : d.second.include )
        {
            ConfigLogger::log_value("device_ip", addr_str);
            show_device(r, false);
        }
    }
}

void NetflowInspector::stringify(std::ofstream& file_stream)
{
    std::vector<snort::SfIp> keys;
    keys.reserve(dump_cache->size());

    for (const auto& elem : *dump_cache)
        keys.push_back(elem.first);

    std::sort(keys.begin(),keys.end(), IpCompare());

    std::string str;
    SfIpString ip_str;
    uint32_t i = 0;

    auto& cache = *dump_cache;

    for (auto elem : keys)
    {
        str = "Netflow Record #";
        str += std::to_string(++i);
        str += "\n";

        str += "    Initiator IP (Port): ";
        str += elem.ntop(ip_str);
        str += " (" + std::to_string(cache[elem].initiator_port) + ")";

        str += " -> Responder IP (Port): ";
        str += cache[elem].responder_ip.ntop(ip_str);
        str += " (" + std::to_string(cache[elem].responder_port) + ")";
        str += "\n";

        str += "    Protocol: ";
        str += std::to_string(cache[elem].proto);

        str += " Packets: ";
        str += std::to_string(cache[elem].initiator_pkts);
        str += "\n";

        str += "    Source Mask: ";
        str += std::to_string(cache[elem].nf_src_mask);

        str += " Destination Mask: ";
        str += std::to_string(cache[elem].nf_dst_mask);
        str += "\n";

        str += "    Next Hop IP: ";
        str += cache[elem].next_hop_ip.ntop(ip_str);
        str += "\n";

        str += "------\n";
        file_stream << str << std::endl;

        str.clear();

    }
    return;
}

bool NetflowInspector::log_netflow_cache()
{
    const char* file_name = config->dump_file;

    // Prevent damaging any existing file, intentionally or not
    struct stat file_stat;
    if ( stat(file_name, &file_stat) == 0 )
    {
        LogMessage("File %s already exists!\n", file_name);
        return false;
    }

    // open file for writing.
    std::ofstream dump_file_stream(file_name);
    if ( !dump_file_stream )
    {
        LogMessage("Error opening %s for dumping netflow cache\n", file_name);
        return false;
    }

    // print netflow cache dump
    stringify(dump_file_stream);

    dump_file_stream.close();

    LogMessage("Dumped netflow cache to %s\n", file_name);

    return true;
}

NetflowInspector::NetflowInspector(const NetflowConfig* pc)
{
    config = pc;

    if ( config->dump_file )
    {
        // create dump cache
        if ( ! dump_cache )
            dump_cache = new NetflowCache;
    }
}

NetflowInspector::~NetflowInspector()
{
    // config and cache removal
    if ( config )
    {
        if ( config->dump_file )
        {
            // log the cache and delete it
            if ( dump_cache )
            {
                // making sure we only dump if cache is non-zero
                if ( dump_cache->size() != 0 )
                    log_netflow_cache();
                delete dump_cache;
                dump_cache = nullptr;
            }
            snort_free((void*)config->dump_file);
        }

        delete config;
        config = nullptr;
    }
}

void NetflowInspector::eval(Packet* p)
{
    // precondition - what we registered for
    assert((p->is_udp() and p->dsize and p->data));
    assert(netflow_cache);

    if ( ! validate_netflow(p, config) )
        ++netflow_stats.invalid_netflow_pkts;
}

void NetflowInspector::tinit()
{
    if ( !netflow_cache )
        netflow_cache = new NetflowCache;
}

void NetflowInspector::tterm()
{
    if ( config->dump_file and dump_cache )
    {
        static std::mutex stats_mutex;
        std::lock_guard<std::mutex> lock(stats_mutex);
        {
            // insert each cache
            dump_cache->insert(netflow_cache->begin(), netflow_cache->end());
        }
    }
    delete netflow_cache;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* netflow_mod_ctor()
{ return new NetflowModule; }

static void netflow_mod_dtor(Module* m)
{ delete m; }

static Inspector* netflow_ctor(Module* m)
{
    NetflowModule *mod = (NetflowModule*)m;
    return new NetflowInspector(mod->get_data());
}

static void netflow_dtor(Inspector* p)
{ delete p; }

static const InspectApi netflow_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        NETFLOW_NAME,
        NETFLOW_HELP,
        netflow_mod_ctor,
        netflow_mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__UDP,
    nullptr,    // buffers
    "netflow",  // service
    nullptr,
    nullptr,    //pterm
    nullptr,    // pre-config tinit
    nullptr,    // pre-config tterm
    netflow_ctor,
    netflow_dtor,
    nullptr,    // ssn
    nullptr     // reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* sin_netflow[] =
#endif
{
    &netflow_api.base,
    nullptr
};


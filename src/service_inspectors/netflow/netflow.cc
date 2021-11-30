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
#include "src/utils/endian.h"
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

// Netflow version 9 Template fields cache.
typedef std::unordered_map<std::pair<uint16_t, snort::SfIp>, std::vector<Netflow9TemplateField>, TemplateIpHash> TemplateFieldCache;
static THREAD_LOCAL TemplateFieldCache* template_cache = nullptr;

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

static bool version_9_record_update(const unsigned char* data, uint32_t unix_secs,
        std::vector<Netflow9TemplateField>::iterator field, NetflowSessionRecord &record)
{

    switch ( field->field_type )
    {
        case NETFLOW_PROTOCOL:

            // invalid protocol
            if( field->field_length != sizeof(record.proto) )
                return false;

            record.proto = (uint8_t)*data;
            break;

        case NETFLOW_TCP_FLAGS:

            // invalid tcp flags
            if( field->field_length != sizeof(record.tcp_flags ) )
                return false;

            record.tcp_flags = (uint8_t)*data;
            break;

        case NETFLOW_SRC_PORT:

            // invalid src port
            if( field->field_length != sizeof(record.initiator_port) )
                return false;

            record.initiator_port = ntohs(*(const uint16_t*) data);
            break;

        case NETFLOW_SRC_IP:

            // invalid source ip
            if( field->field_length != sizeof(uint32_t) )
                return false;

            // Invalid source IP address provided
            if ( record.initiator_ip.set((const uint32_t *)data, AF_INET) != SFIP_SUCCESS )
                return false;
            break;

        case NETFLOW_SRC_IPV6:

            // Invalid source IP address provided
            if ( record.initiator_ip.set((const uint32_t *)data, AF_INET6) != SFIP_SUCCESS )
                return false;
            break;

        case NETFLOW_DST_PORT:

            // invalid destination port
            if( field->field_length != sizeof(record.responder_port) )
                return false;

            record.responder_port = ntohs(*(const uint16_t*) data);
            break;

        case NETFLOW_DST_IP:

            // invalid length
            if( field->field_length != sizeof(uint32_t) )
                return false;

            // Invalid destination IP address
            if ( record.responder_ip.set((const uint32_t *)data, AF_INET) != SFIP_SUCCESS )
                return false;
            break;

        case NETFLOW_DST_IPV6:

            // Invalid destination IP address
            if ( record.responder_ip.set((const uint32_t *)data, AF_INET6) != SFIP_SUCCESS )
                return false;
            break;

        case NETFLOW_IPV4_NEXT_HOP:

            // invalid length
            if( field->field_length != sizeof(uint32_t) )
                return false;

            // Invalid next-hop IP address
            if ( record.next_hop_ip.set((const uint32_t *)data, AF_INET) != SFIP_SUCCESS )
                return false;
            break;

        case NETFLOW_LAST_PKT:

            if( field->field_length != sizeof(record.last_pkt_second) )
                return false;

            record.last_pkt_second = unix_secs + ntohl(*(const time_t*)data)/1000;

            // invalid flow time value
            if( record.last_pkt_second > MAX_TIME )
                return false;

            break;

        case NETFLOW_FIRST_PKT:

            if( field->field_length != sizeof(record.first_pkt_second) )
                return false;

            record.first_pkt_second = unix_secs + ntohl(*(const time_t*)data)/1000;

            // invalid flow time value
            if( record.first_pkt_second > MAX_TIME )
                return 0;

            break;

        case NETFLOW_IN_BYTES:

            if ( field->field_length == sizeof(uint64_t) )
                record.initiator_bytes = ntohll(*(const uint64_t*)data);
            else if ( field->field_length == sizeof(uint32_t) )
                record.initiator_bytes = (uint64_t)ntohl(*(const uint32_t*)data);
            else if ( field->field_length == sizeof(uint16_t) )
                record.initiator_bytes = (uint64_t)ntohs(*(const uint16_t*) data);
            else
                return false;

            break;

        case NETFLOW_IN_PKTS:

            if ( field->field_length == sizeof(uint64_t) )
                record.initiator_pkts = ntohll(*(const uint64_t*)data);
            else if ( field->field_length == sizeof(uint32_t) )
                record.initiator_pkts = (uint64_t)ntohl(*(const uint32_t*)data);
            else if ( field->field_length == sizeof(uint16_t) )
                record.initiator_pkts = (uint64_t)ntohs(*(const uint16_t*) data);
            else
                return false;

            break;

        case NETFLOW_SRC_TOS:

            if( field->field_length != sizeof(record.nf_src_tos) )
                return false;

            record.nf_src_tos = (uint8_t)*data;
            break;

        case NETFLOW_DST_TOS:

            if( field->field_length != sizeof(record.nf_dst_tos))
                return false;

            record.nf_dst_tos = (uint8_t)*data;
            break;

        case NETFLOW_SNMP_IN:

            if ( field->field_length == sizeof(uint32_t) )
                record.nf_snmp_in = ntohl(*(const uint32_t*)data);
            else if ( field->field_length == sizeof(uint16_t) )
                record.nf_snmp_in = (uint32_t)ntohs(*(const uint16_t*) data);
            else
                return false;

            break;

        case NETFLOW_SNMP_OUT:

            if ( field->field_length == sizeof(uint32_t) )
                record.nf_snmp_out = ntohl(*(const uint32_t*)data);
            else if ( field->field_length == sizeof(uint16_t) )
                record.nf_snmp_out = (uint32_t)ntohs(*(const uint16_t*) data);
            else
                return false;

            break;

        case NETFLOW_SRC_AS:

            if( field->field_length == sizeof(uint16_t) )
                record.nf_src_as = (uint32_t)ntohs(*(const uint16_t*) data);
            else if( field->field_length == sizeof(uint32_t) )
                record.nf_src_as = ntohl(*(const uint32_t*)data);
            else
                return false;
            break;

        case NETFLOW_DST_AS:

            if( field->field_length == sizeof(uint16_t) )
                record.nf_dst_as = (uint32_t)ntohs(*(const uint16_t*) data);
            else if( field->field_length == sizeof(uint32_t) )
                record.nf_dst_as = ntohl(*(const uint32_t*)data);
            else
                return false;
            break;

        case NETFLOW_SRC_MASK:
        case NETFLOW_SRC_MASK_IPV6:

            if( field->field_length != sizeof(record.nf_src_mask) )
                return false;

            record.nf_src_mask = (uint8_t)*data;
            break;

        case NETFLOW_DST_MASK:
        case NETFLOW_DST_MASK_IPV6:

            if( field->field_length != sizeof(record.nf_dst_mask) )
                return false;

            record.nf_dst_mask = (uint8_t)*data;
            break;

        default:
            break;
    }

    return true;

}

static bool decode_netflow_v9(const unsigned char* data, uint16_t size,
    const Packet* p, const NetflowRules* p_rules)
{
    Netflow9Hdr header;
    const Netflow9Hdr *pheader;
    const Netflow9FlowSet *flowset;
    const uint8_t *end;
    const uint8_t *flowset_end;
    uint16_t records;

    if( size < sizeof(Netflow9Hdr) )
        return false;

    end = data + size;

    pheader = (const Netflow9Hdr *)data;
    header.flow_count = ntohs(pheader->flow_count);

    // invalid header flow count
    if( header.flow_count < NETFLOW_MIN_COUNT or header.flow_count > NETFLOW_MAX_COUNT)
        return false;

    // stats
    netflow_stats.records += header.flow_count;
    records = header.flow_count;

    header.sys_uptime =  ntohl(pheader->sys_uptime) / 1000;
    header.unix_secs = ntohl(pheader->unix_secs);
    header.unix_secs -= header.sys_uptime;

    const int zone = p->pkth->ingress_index;
    const snort::SfIp device_ip = *p->ptrs.ip_api.get_src();

    data += sizeof(Netflow9Hdr);

    while ( data < end )
    {
        uint16_t length, f_id;

        // invalid data length
        if ( data + sizeof(*flowset) > end )
            return false;

        flowset = (const Netflow9FlowSet *)data;

        // length includes the flowset_id and length fields
        length = ntohs(flowset->field_length);

        // invalid Netflow length
        if( data + length > end )
            return false;

        flowset_end = data + length;
        data += sizeof(*flowset);

        // field id
        f_id = ntohs(flowset->field_id);

        auto ti_key = std::make_pair(f_id, device_ip);

        // It's a data flowset
        if ( f_id > 255 && template_cache->count(ti_key) > 0 )
        {
            std::vector<Netflow9TemplateField> tf;
            tf = template_cache->at(ti_key);

            while( data < flowset_end && records )
            {

                NetflowSessionRecord record = {};
                bool bad_field = false;

                for ( auto t_field = tf.begin(); t_field != tf.end(); ++t_field )
                {
                    // invalid field length
                    if ( data + t_field->field_length > flowset_end )
                        bad_field = true;

                    if ( !bad_field )
                    {
                        bool status = version_9_record_update(data, header.unix_secs, t_field, record);

                        if ( !status )
                            bad_field = true;
                    }

                    data += t_field->field_length;
                }

                if ( bad_field )
                {
                    ++netflow_stats.invalid_netflow_record;
                    records--;
                    continue;
                }

                // filter based on configuration
                if ( !filter_record(p_rules, zone, &record.initiator_ip, &record.responder_ip) )
                {
                    records--;
                    continue;
                }

                // create flow event here

                // check if record exists
                auto result = netflow_cache->find(record.initiator_ip);

                if ( result != netflow_cache->end() )
                {
                    // record exists and hence first remove the element
                    netflow_cache->erase(record.initiator_ip);
                    --netflow_stats.unique_flows;
                }

                // emplace doesn't replace element if exist, hence removing it first
                netflow_cache->emplace(record.initiator_ip, record);
                ++netflow_stats.unique_flows;

                records--;
            }
        }
        // template flowset
        else if ( f_id == 0 )
        {
            // Step through the templates in this flowset and store them
            while ( data < flowset_end && records )
            {
                const Netflow9Template* t_template;
                uint16_t field_count, t_id;
                const Netflow9TemplateField* field;
                std::vector<Netflow9TemplateField> tf;

                t_template = (const Netflow9Template *)data;
                field_count = ntohs(t_template->template_field_count);

                if ( data + sizeof(*t_template) > flowset_end )
                    return false;

                data += sizeof(*t_template);

                // template id
                t_id = ntohs(t_template->template_id);

                // Parse the data and add the template fields for this template id
                for ( int i = 0; i < field_count; i++ )
                {
                    // invalid flowset field
                    if ( data + sizeof(*field) > flowset_end )
                        return false;

                    field = (const Netflow9TemplateField *)data;
                    tf.emplace_back(ntohs(field->field_type), ntohs(field->field_length));
                    data += sizeof(*field);
                }

                if ( field_count > 0 )
                {
                    auto t_key = std::make_pair(t_id, device_ip);

                    // remove if there any entry exists for this template
                    auto is_erased = template_cache->erase(t_key);

                    // count only unique templates
                    if ( is_erased == 1 )
                        --netflow_stats.v9_templates;

                    // add template to cache
                    template_cache->emplace(t_key, tf);

                    // update the total templates count
                    ++netflow_stats.v9_templates;

                    // don't count template as record
                    netflow_stats.records--;
                }
                records--;
            }
        }

        // It's an option template flowset
        else if ( f_id == 1 )
        {
            ++netflow_stats.v9_options_template;

            // don't count option template as record
            netflow_stats.records--;
        }

        // its data and no templates are defined yet
        else
        {
            // Skip options, we don't use them currently
            data = flowset_end;
            ++netflow_stats.v9_missing_template;
        }

        if ( flowset_end != data )
        {
            // Invalid flowset Length
            if ( length != (length >> 2 ) << 2 )
                return false;

            // Data is not at flowset_end
            if ( flowset_end - data > 3 )
                return false;

            data = flowset_end;
        }
    }
    return true;
}

static bool decode_netflow_v5(const unsigned char* data, uint16_t size,
    const Packet* p, const NetflowRules* p_rules)
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

static bool validate_netflow(const Packet* p, const NetflowRules* p_rules)
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
        retval = decode_netflow_v5(data, size, p, p_rules);
        if ( retval )
        {
            ++netflow_stats.packets;
            ++netflow_stats.version_5;
        }
    }
    else if ( version == 9 )
    {
        retval = decode_netflow_v9(data, size, p, p_rules);
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
    bool log_header = true;
    for ( auto const& d : config->device_rule_map )
    {
        if (log_header)
        {
            ConfigLogger::log_option("rules");
            log_header = false;
        }
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
        NetflowSessionRecord& record = cache[elem];
        str = "Netflow Record #";
        str += std::to_string(++i);
        str += "\n";

        str += "    Initiator IP (Port): ";
        str += elem.ntop(ip_str);
        str += " (" + std::to_string(record.initiator_port) + ")";

        str += " -> Responder IP (Port): ";
        str += record.responder_ip.ntop(ip_str);
        str += " (" + std::to_string(record.responder_port) + ")";
        str += "\n";

        str += "    Protocol: ";
        str += std::to_string(record.proto);

        str += " Packets: ";
        str += std::to_string(record.initiator_pkts);
        str += "\n";

        str += "    Source Mask: ";
        str += std::to_string(record.nf_src_mask);

        str += " Destination Mask: ";
        str += std::to_string(record.nf_dst_mask);
        str += "\n";

        str += "    Next Hop IP: ";
        str += record.next_hop_ip.ntop(ip_str);
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

    auto d = config->device_rule_map.find(*p->ptrs.ip_api.get_src());

    if ( d != config->device_rule_map.end() )
    {
        const NetflowRules* p_rules = &(d->second);

        if ( ! validate_netflow(p, p_rules) )
            ++netflow_stats.invalid_netflow_record;
    }
}

void NetflowInspector::tinit()
{
    if ( !netflow_cache )
        netflow_cache = new NetflowCache;

    if ( !template_cache )
        template_cache = new TemplateFieldCache;

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
    delete template_cache;
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

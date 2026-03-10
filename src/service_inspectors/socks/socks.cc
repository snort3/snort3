//--------------------------------------------------------------------------
// Copyright (C) 2025-2026 Cisco and/or its affiliates. All rights reserved.
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

// socks.cc author Raza Shafiq <rshafiq@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <algorithm>
#include <cstring>

#include "detection/detection_engine.h"
#include "flow/flow.h"
#include "flow/session.h"
#include "framework/inspector.h"
#include "main/snort_config.h"
#include "log/messages.h"
#include "packet_io/active.h"
#include "profiler/profiler.h"
#include "protocols/packet_manager.h"
#include "log/unified2.h"
#include "main/analyzer.h"
#include "packet_io/packet_tracer.h"
#include "protocols/eth.h"
#include "protocols/ip.h"
#include "protocols/udp.h"
#include "protocols/packet.h"
#include "pub_sub/intrinsic_event_ids.h"
#include "sfip/sf_ip.h"
#include "socks.h"
#include "socks_event.h"
#include "socks_flow_data.h"
#include "socks_module.h"
#include "socks_splitter.h"
#include "stream/stream.h"
#include "utils/util.h"

using namespace snort;

THREAD_LOCAL ProfileStats socksPerfStats;
THREAD_LOCAL SocksStats socks_stats;

static void create_socks_event(SocksFlowData* fd, SocksEvent event)
{
    uint8_t bit = 1u << (static_cast<uint32_t>(event) - 1);
    if ( !(fd->events_suppressed & bit) )
    {
        DetectionEngine::queue_event(GID_SOCKS, static_cast<uint32_t>(event));
        fd->events_suppressed |= bit;
    }
}

static unsigned socks_pub_id = 0;
static SnortProtocolId socks_snort_protocol_id = UNKNOWN_PROTOCOL_ID;

SocksInspector::SocksInspector(const SocksModule* mod) : 
    config(mod),
    xtra_target_ip_id(Stream::reg_xtra_data_cb(get_xtra_target_ip))
{ }

bool SocksInspector::configure(SnortConfig* sc)
{
    if ( !socks_pub_id )
        socks_pub_id = DataBus::get_id(socks_pub_key);

    // Register protocol ID for dynamic UDP expectations (UDP ASSOCIATE)
    if ( socks_snort_protocol_id == UNKNOWN_PROTOCOL_ID )
        socks_snort_protocol_id = sc->proto_ref->add("socks");

    return true;
}

void SocksInspector::show(const SnortConfig*) const
{ }

void SocksInspector::eval(Packet* p)
{
    // cppcheck-suppress unreadVariable
    Profile profile(socksPerfStats);

    assert((p->is_udp() and p->dsize and p->data) or p->has_tcp_data() or p->has_paf_payload());
    assert(p->flow);

    Flow* flow = p->flow;
    SocksFlowData* flow_data = get_flow_data(flow);
    if ( !flow_data )
    {
        create_flow_data(flow);
        flow_data = get_flow_data(flow);
        assert(flow_data);  // Should never be null after create_flow_data
    }

    SetExtraData(p, xtra_target_ip_id);

    if ( flow_data->is_handoff_completed() )
        return;

    if ( !flow_data->initiator_detected() )
        detect_protocol_initiator(p, flow_data);

    if ( p->is_udp() )
    {
        // If SOCKS inspector is called for UDP, user explicitly bound this port
        // to SOCKS via binder config. Trust the binding and process as UDP ASSOCIATE.
        // Note: We don't auto-detect UDP via wizard patterns due to false positive risk.
        if ( flow_data->get_state() == SOCKS_STATE_INIT )
        {
            flow_data->set_state(SOCKS_STATE_ESTABLISHED);
            flow_data->set_command(SOCKS_CMD_UDP_ASSOCIATE);
            flow_data->set_socks_version(SOCKS5_VERSION);
            flow_data->set_initiator(SOCKS_INITIATOR_CLIENT);
        }

        if ( flow_data->get_state() == SOCKS_STATE_ESTABLISHED and
            flow_data->get_command() == SOCKS_CMD_UDP_ASSOCIATE )
        {
            process_udp_associate_data(p, flow_data);
        }
        return;
    }

    if ( flow_data->get_initiator() == SOCKS_INITIATOR_SERVER )
    {
        // Reverse flow (BIND reverse connection) - server initiated SOCKS
        if ( p->is_from_client() )
        {
            flow_data->set_direction(SOCKS_DIR_CLIENT_TO_SERVER);
            process_reverse_client_data(p, flow_data);
        }
        else
        {
            flow_data->set_direction(SOCKS_DIR_SERVER_TO_CLIENT);
            process_reverse_server_data(p, flow_data);
        }
    }
    else
    {
        if ( p->is_from_client() )
        {
            flow_data->set_direction(SOCKS_DIR_CLIENT_TO_SERVER);
            process_client_data(p, flow_data);
        }
        else
        {
            flow_data->set_direction(SOCKS_DIR_SERVER_TO_CLIENT);
            process_server_data(p, flow_data);
        }
    }
}

void SocksInspector::clear(Packet*) {}

StreamSplitter* SocksInspector::get_splitter(bool c2s)
{
    return new SocksSplitter(c2s);
}

//-------------------------------------------------------------------------
// SOCKS4/4a parsing functions
//-------------------------------------------------------------------------

bool SocksInspector::parse_socks4_request(const uint8_t* data, uint16_t len, SocksFlowData* flow_data)
{

    // SOCKS4 request: VER(1) CMD(1) PORT(2) IP(4) USERID(variable) NULL(1)
    if ( !has_minimum_length(len, SOCKS4_MIN_REQUEST_LEN) or !data )
        return false;

    const Socks4Request* req = reinterpret_cast<const Socks4Request*>(data);

    if ( !is_valid_socks4_version(req->version) )
    {
        create_socks_event(flow_data, SOCKS_EVENT_PROTOCOL_VIOLATION);
        return false;
    }

    flow_data->set_socks_version(SOCKS4_VERSION);

    if ( !is_valid_command(req->command) )
    {
        create_socks_event(flow_data, SOCKS_EVENT_UNKNOWN_COMMAND);
        return false;
    }

    flow_data->set_command(static_cast<SocksCommand>(req->command));

    if ( req->command == SOCKS_CMD_CONNECT )
        ++socks_stats.connect_requests;
    else if ( req->command == SOCKS_CMD_BIND )
        ++socks_stats.bind_requests;

    uint16_t port = ntohs(req->port);
    flow_data->set_target_port(port);

    uint32_t ip = ntohl(req->ip);

    // SOCKS4a extension: IP is 0.0.0.x (where x != 0) to indicate domain name follows userid
    // This allows SOCKS4 clients to send domain names instead of resolved IP addresses
    bool ip_indicates_socks4a = (ip & 0xFFFFFF00) == 0 and (ip & 0xFF) != 0;

    uint16_t offset = sizeof(Socks4Request);

    if ( offset >= len )
        return false;

    const uint8_t* userid_start = data + offset;
    const size_t max_search = std::min(static_cast<size_t>(len - offset), static_cast<size_t>(MAX_USERNAME_LEN + 1));
    const uint8_t* userid_end = static_cast<const uint8_t*>(memchr(userid_start, 0, max_search));

    if ( !userid_end )
    {
        create_socks_event(flow_data, SOCKS_EVENT_PROTOCOL_VIOLATION);
        return false;
    }

    size_t userid_len = userid_end - userid_start;
    if ( userid_len > MAX_USERNAME_LEN )
    {
        create_socks_event(flow_data, SOCKS_EVENT_PROTOCOL_VIOLATION);
        return false;
    }

    flow_data->set_userid(std::string(reinterpret_cast<const char*>(userid_start), userid_len));
    offset += userid_len + 1;  // +1 for null terminator

    // For SOCKS4a, we need room for domain name; for regular SOCKS4, we're done
    // But we need at least to have consumed all bytes up to and including the null terminator
    if ( offset > len )
        return false;

    if ( ip_indicates_socks4a )
    {
        std::string domain;
        if ( !parse_socks4a_domain(data, len, offset, domain) )
        {
            create_socks_event(flow_data, SOCKS_EVENT_PROTOCOL_VIOLATION);
            return false;
        }

        flow_data->set_socks4a(true);
        flow_data->set_target_address(std::move(domain));
        flow_data->set_address_type(SOCKS_ATYP_DOMAIN);
    }
    else
    {
        char ip_str[INET_ADDRSTRLEN];
        snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
                (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                (ip >> 8) & 0xFF, ip & 0xFF);

        flow_data->set_target_address(ip_str);
        flow_data->set_address_type(SOCKS_ATYP_IPV4);

        SfIp target_ip;
        // SfIp::set expects network-order bytes for AF_INET; use req->ip directly.
        target_ip.set(&req->ip, AF_INET);
        flow_data->set_target_ip(target_ip);
        
        // Enable XFF logging for this flow
        Packet* current_pkt = DetectionEngine::get_current_packet();
        if ( current_pkt && xtra_target_ip_id )
            Stream::set_extra_data(current_pkt->flow, current_pkt, xtra_target_ip_id);
    }

    set_next_state(flow_data, SOCKS_STATE_V4_CONNECT_RESPONSE);
    flow_data->increment_request_count();

    if ( !flow_data->is_session_counted() )
    {
        ++socks_stats.sessions;
        flow_data->set_session_counted(true);
    }

    return true;
}

bool SocksInspector::parse_socks4_response(const uint8_t* data, uint16_t len, SocksFlowData* flow_data)
{

    if ( !has_minimum_length(len, SOCKS4_RESPONSE_LEN) or !data )
        return false;

    const Socks4Response* resp = reinterpret_cast<const Socks4Response*>(data);

    // SOCKS4 response version is 0x00, not 0x04!
    if ( resp->version != 0x00 )
    {
        create_socks_event(flow_data, SOCKS_EVENT_PROTOCOL_VIOLATION);
        return false;
    }

    if ( resp->status == SOCKS4_REP_GRANTED )
    {
        // Connection granted
        // For BIND command, SOCKS4 sends TWO responses:
        // 1st response: Server is listening (goes to BIND_SECOND_RESPONSE state)
        // 2nd response: Connection established (goes to ESTABLISHED state)
        if ( flow_data->get_command() == SOCKS_CMD_BIND and 
             flow_data->get_state() == SOCKS_STATE_V4_CONNECT_RESPONSE )
        {
            set_next_state(flow_data, SOCKS_STATE_V4_BIND_SECOND_RESPONSE);
        }
        else
        {
            set_next_state(flow_data, SOCKS_STATE_ESTABLISHED);
            ++socks_stats.successful_connections;

            if ( flow_data->get_command() == SOCKS_CMD_CONNECT )
                flow_data->set_handoff_pending(true);

            Packet* p = DetectionEngine::get_current_packet();
            if ( p and p->flow )
            {
                SocksTunnelEvent event(flow_data, true);
                DataBus::publish(socks_pub_id, SocksEventIds::SOCKS_TUNNEL_ESTABLISHED, event, p->flow);

                if ( PacketTracer::is_active() )
                    PacketTracer::log("SOCKS: SOCKS4 tunnel established, cmd=%u, target=%s:%u\n",
                        flow_data->get_command(), flow_data->get_target_address().c_str(),
                        flow_data->get_target_port());
            }

            handle_protocol_handoff(flow_data);
        }

        flow_data->increment_response_count();

        uint32_t bind_addr = ntohl(resp->ip);
        uint16_t bind_port = ntohs(resp->port);

        char addr_str[INET_ADDRSTRLEN];
        struct in_addr addr;
        addr.s_addr = htonl(bind_addr);
        inet_ntop(AF_INET, &addr, addr_str, INET_ADDRSTRLEN);

        // Store in bind fields, NOT target fields (target was set from request)
        flow_data->set_bind_address(std::string(addr_str));
        flow_data->set_bind_port(bind_port);
        flow_data->set_bind_address_type(SOCKS_ATYP_IPV4);
        return true;
    }
    else
    {
        set_next_state(flow_data, SOCKS_STATE_ERROR);
        flow_data->set_last_error(static_cast<SocksReplyCode>(resp->status));
        ++socks_stats.failed_connections;

        Packet* p = DetectionEngine::get_current_packet();
        if ( p and p->flow )
        {
            SocksTunnelEvent event(flow_data, false);
            DataBus::publish(socks_pub_id, SocksEventIds::SOCKS_TUNNEL_FAILED, event, p->flow);

            if ( PacketTracer::is_active() )
                PacketTracer::log("SOCKS: SOCKS4 tunnel failed, status=0x%02x, target=%s:%u\n",
                    resp->status, flow_data->get_target_address().c_str(),
                    flow_data->get_target_port());
        }

        return false;
    }
}

bool SocksInspector::parse_socks4a_domain(const uint8_t* data, uint16_t len, uint16_t& offset, std::string& domain)
{
    domain.clear();

    const uint8_t* domain_start = data + offset;
    const size_t max_search = std::min(static_cast<size_t>(len - offset), static_cast<size_t>(RFC1035_MAX_DOMAIN_LEN + 1));
    const uint8_t* domain_end = static_cast<const uint8_t*>(memchr(domain_start, 0, max_search));

    if ( !domain_end )
        return false;

    size_t domain_len = domain_end - domain_start;

    if ( domain_len == 0 or domain_len > RFC1035_MAX_DOMAIN_LEN )
        return false;

    domain.assign(reinterpret_cast<const char*>(domain_start), domain_len);
    offset += domain_len;

    return true;
}

//-------------------------------------------------------------------------
// SOCKS5 parsing functions
//-------------------------------------------------------------------------

bool SocksInspector::parse_socks5_auth_negotiation(const uint8_t* data, uint16_t len, SocksFlowData* flow_data)
{

    if ( !has_minimum_length(len, SOCKS5_AUTH_NEG_MIN_LEN) or !data )
        return false;

    const Socks5AuthNegotiation* auth_neg = reinterpret_cast<const Socks5AuthNegotiation*>(data);

    if ( !is_valid_socks5_version(auth_neg->version) )
        return false;

    if ( auth_neg->num_methods == 0 or len < (SOCKS5_AUTH_RESPONSE_LEN + auth_neg->num_methods) )
    {
        create_socks_event(flow_data, SOCKS_EVENT_PROTOCOL_VIOLATION);
        return false;
    }

    flow_data->set_socks_version(SOCKS5_VERSION);
    flow_data->increment_request_count();
    set_next_state(flow_data, SOCKS_STATE_V5_AUTH_NEGOTIATION);

    ++socks_stats.auth_requests;


    if ( !flow_data->is_session_counted() )
    {
        ++socks_stats.sessions;
        flow_data->set_session_counted(true);
    }

    return true;
}

bool SocksInspector::parse_socks5_auth_response(const uint8_t* data, uint16_t len, SocksFlowData* flow_data)
{

    if ( !has_minimum_length(len, SOCKS5_AUTH_RESPONSE_LEN)  or !data )
        return false;

    const Socks5AuthResponse* auth_resp = reinterpret_cast<const Socks5AuthResponse*>(data);
    
    if ( !is_valid_socks5_version(auth_resp->version) )
        return false;

    flow_data->set_auth_method(static_cast<Socks5AuthMethod>(auth_resp->method));
    flow_data->increment_response_count();

    if ( !flow_data->is_session_counted() and flow_data->get_initiator() == SOCKS_INITIATOR_SERVER )
    {
        ++socks_stats.sessions;
        flow_data->set_session_counted(true);
    }

    if ( auth_resp->method == SOCKS5_AUTH_NO_ACCEPTABLE )
    {
        set_next_state(flow_data, SOCKS_STATE_ERROR);
        ++socks_stats.auth_failures;
        return false;
    }
    else if ( auth_resp->method == SOCKS5_AUTH_USERNAME_PASSWORD )
        set_next_state(flow_data, SOCKS_STATE_V5_USERNAME_PASSWORD_AUTH);
    else if ( auth_resp->method == SOCKS5_AUTH_NONE )
    {
        set_next_state(flow_data, SOCKS_STATE_V5_CONNECT_REQUEST);
        ++socks_stats.auth_successes;
    }
    else
    {
        // Unsupported auth method (e.g., GSSAPI 0x01, or private methods 0x80-0xFE)
        // We can't parse the auth exchange, but we can still parse the subsequent
        // CONNECT/BIND/UDP_ASSOCIATE request to extract tunnel metadata
        set_next_state(flow_data, SOCKS_STATE_V5_CONNECT_REQUEST);
        
        if ( PacketTracer::is_active() )
            PacketTracer::log("SOCKS: Unsupported auth method 0x%02x, skipping auth phase\n", 
                              auth_resp->method);
    }

    return true;
}

bool SocksInspector::validate_socks5_request_header(const Socks5ConnectRequest* conn_req, SocksFlowData* flow_data)
{
    if ( !conn_req or !is_valid_socks5_version(conn_req->version) )
        return false;

    if ( !is_valid_command(conn_req->command) )
    {
        create_socks_event(flow_data, SOCKS_EVENT_UNKNOWN_COMMAND);
        return false;
    }

    // RFC 1928: reserved byte should be 0x00, but warn instead of reject
    if ( conn_req->reserved != 0x00 )
        create_socks_event(flow_data, SOCKS_EVENT_PROTOCOL_VIOLATION);

    // Built-in rule: Unknown address type
    if ( !is_valid_address_type(conn_req->address_type) )
    {
        create_socks_event(flow_data, SOCKS5_EVENT_UNKNOWN_ADDRESS_TYPE);
        return false;
    }

    return true;
}

bool SocksInspector::parse_socks5_command_request(const uint8_t* data, uint16_t len, SocksFlowData* flow_data)
{

    if ( !has_minimum_length(len, SOCKS5_CONNECT_MIN_LEN) or !data )
        return false;

    const Socks5ConnectRequest* conn_req = reinterpret_cast<const Socks5ConnectRequest*>(data);

    if ( !validate_socks5_request_header(conn_req, flow_data) )
        return false;

    SocksCommand cmd = static_cast<SocksCommand>(conn_req->command);
    flow_data->set_command(cmd);
    flow_data->set_address_type(static_cast<SocksAddressType>(conn_req->address_type));

    if ( cmd == SOCKS_CMD_CONNECT )
        ++socks_stats.connect_requests;
    else if ( cmd == SOCKS_CMD_BIND )
        ++socks_stats.bind_requests;
    else if ( cmd == SOCKS_CMD_UDP_ASSOCIATE )
        ++socks_stats.udp_associate_requests;

    uint16_t offset = sizeof(Socks5ConnectRequest);
    SocksAddressType addr_type;
    std::string address;
    uint16_t port;

    if ( !parse_socks5_address(data, len, offset, addr_type, address, port) )
    {
        create_socks_event(flow_data, SOCKS_EVENT_PROTOCOL_VIOLATION);
        return false;
    }

    flow_data->set_target_address(address);
    flow_data->set_target_port(port);
    
    if ( addr_type == SOCKS_ATYP_IPV4 or addr_type == SOCKS_ATYP_IPV6 )
    {
        SfIp target_ip;
        if ( target_ip.set(address.c_str()) == SFIP_SUCCESS )
        {
            flow_data->set_target_ip(target_ip);
            
            // Enable XFF logging for this flow
            Packet* current_pkt = DetectionEngine::get_current_packet();
            if ( current_pkt && xtra_target_ip_id )
                Stream::set_extra_data(current_pkt->flow, current_pkt, xtra_target_ip_id);
        }
    }

    flow_data->increment_request_count();
    set_next_state(flow_data, SOCKS_STATE_V5_CONNECT_RESPONSE);
    return true;
}

bool SocksInspector::parse_socks5_address(const uint8_t* data, uint16_t len, uint16_t& offset,
                                          SocksAddressType& addr_type, std::string& address, uint16_t& port)
{
    if ( !data or len == 0 )
        return false;

    if ( offset == 0 or offset > len or offset - 1 >= len )
        return false;

    addr_type = static_cast<SocksAddressType>(data[offset - 1]); // Address type is at offset-1

    switch (addr_type)
    {
        case SOCKS_ATYP_IPV4:
        {
            if ( len - offset < IPV4_ADDR_LEN + PORT_LEN ) // 4 bytes IP + 2 bytes port (safe from overflow)
                return false;

            struct in_addr ipv4_addr;
            memcpy(&ipv4_addr, data + offset, IPV4_ADDR_LEN);
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ipv4_addr, ip_str, INET_ADDRSTRLEN);
            address = ip_str;

            uint16_t port_raw;
            memcpy(&port_raw, data + offset + IPV4_ADDR_LEN, sizeof(uint16_t));
            port = ntohs(port_raw);
            offset += IPV4_ADDR_LEN + PORT_LEN;
            break;
        }

        case SOCKS_ATYP_DOMAIN:
        {
            if ( offset >= len )
                return false;

            uint8_t domain_len = data[offset];

            if ( offset > UINT16_MAX - 1 )
                return false;

            offset++;

            if ( domain_len == 0 or domain_len > RFC1035_MAX_DOMAIN_LEN ) // RFC 1035 max domain length
                return false;

            if ( len - offset < domain_len + PORT_LEN ) // domain + 2 bytes port
                return false;
            
            address = std::string(reinterpret_cast<const char*>(data + offset), domain_len);

            if ( offset > UINT16_MAX - domain_len - PORT_LEN )
                return false;

            offset += domain_len;

            uint16_t port_raw;
            memcpy(&port_raw, data + offset, sizeof(uint16_t));
            port = ntohs(port_raw);
            offset += PORT_LEN;
            break;
        }

        case SOCKS_ATYP_IPV6:
        {
            if ( len - offset < IPV6_ADDR_LEN + PORT_LEN ) // 16 bytes IP + 2 bytes port (safe from overflow)
                return false;

            struct in6_addr ipv6_addr;
            memcpy(&ipv6_addr, data + offset, IPV6_ADDR_LEN);
            char ip_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &ipv6_addr, ip_str, INET6_ADDRSTRLEN);
            address = ip_str;

            uint16_t port_raw;
            memcpy(&port_raw, data + offset + IPV6_ADDR_LEN, sizeof(uint16_t));
            port = ntohs(port_raw);
            offset += IPV6_ADDR_LEN + PORT_LEN;
            break;
        }

        default:
            return false;
    }

    return true;
}

bool SocksInspector::is_valid_socks4_version(uint8_t version)
{ return version == SOCKS4_VERSION; }

bool SocksInspector::is_valid_socks5_version(uint8_t version)
{ return version == SOCKS5_VERSION; }

uint8_t SocksInspector::detect_socks_version(const uint8_t* data, uint16_t len)
{
    if (len < 1)
        return 0;

    uint8_t version = data[0];
    if (version == SOCKS4_VERSION or version == SOCKS5_VERSION)
        return version;

    return 0;
}

bool SocksInspector::is_valid_command(uint8_t command)
{ return command >= SOCKS_CMD_CONNECT and command <= SOCKS_CMD_UDP_ASSOCIATE; }

bool SocksInspector::is_valid_address_type(uint8_t addr_type)
{
    return addr_type == SOCKS_ATYP_IPV4 or
           addr_type == SOCKS_ATYP_DOMAIN or
           addr_type == SOCKS_ATYP_IPV6;
}

SocksFlowData* SocksInspector::get_flow_data(const Flow* flow)
{ return static_cast<SocksFlowData*>(flow->get_flow_data(SocksFlowData::get_inspector_id())); }

void SocksInspector::create_flow_data(Flow* flow)
{
    SocksFlowData* flow_data = new SocksFlowData();
    flow->set_flow_data(flow_data);
}

void SocksInspector::process_client_data(Packet* p, SocksFlowData* flow_data)
{
    const uint8_t* data = p->data;
    uint16_t len = p->dsize;

    switch ( flow_data->get_state() )
    {
        case SOCKS_STATE_INIT:
        {
            uint8_t version = detect_socks_version(data, len);
            
            if (version == SOCKS4_VERSION)
                parse_socks4_request(data, len, flow_data);
            else if (version == SOCKS5_VERSION)
                parse_socks5_auth_negotiation(data, len, flow_data);
            break;
        }

        case SOCKS_STATE_V5_USERNAME_PASSWORD_AUTH:
            parse_socks5_username_password_auth(data, len, flow_data);
            break;

        case SOCKS_STATE_V5_CONNECT_REQUEST:
            parse_socks5_command_request(data, len, flow_data);
            break;

        case SOCKS_STATE_ESTABLISHED:
            process_tunneled_data(p, flow_data);
            break;

        case SOCKS_STATE_ERROR:
            // State is already ERROR, skip redundant check in handle_error_state
            {
                if ( len == 0 or (data[0] != SOCKS4_VERSION and data[0] != SOCKS5_VERSION) )
                {
                    trigger_service_detection(p, flow_data);
                    flow_data->set_handoff_completed(true);
                }
            }
            break;

        default:
            break;
    }
}

void SocksInspector::process_server_data(Packet* p, SocksFlowData* flow_data)
{
    const uint8_t* data = p->data;
    uint16_t len = p->dsize;

    switch ( flow_data->get_state() )
    {
        case SOCKS_STATE_V4_CONNECT_RESPONSE:
            parse_socks4_response(data, len, flow_data);
            break;

        case SOCKS_STATE_V4_BIND_SECOND_RESPONSE:
            parse_socks4_response(data, len, flow_data);
            break;

        case SOCKS_STATE_V5_AUTH_NEGOTIATION:
            parse_socks5_auth_response(data, len, flow_data);
            break;

        case SOCKS_STATE_V5_USERNAME_PASSWORD_AUTH:
            parse_socks5_username_password_auth_resp(data, len, flow_data);
            break;

        case SOCKS_STATE_V5_CONNECT_RESPONSE:
            parse_socks5_command_response(data, len, flow_data);
            break;

        case SOCKS_STATE_ESTABLISHED:
            process_tunneled_data(p, flow_data);
            break;

        case SOCKS_STATE_ERROR:
            {
                if ( len == 0 or (data[0] != SOCKS4_VERSION and data[0] != SOCKS5_VERSION) )
                {
                    trigger_service_detection(p, flow_data);
                    flow_data->set_handoff_completed(true);
                }
            }
            break;
            
        default:
            break;
    }
}

bool SocksInspector::has_minimum_length(uint16_t data_len, uint16_t required_len)
{ return data_len >= required_len; }

void SocksInspector::set_next_state(SocksFlowData* flow_data, SocksState new_state)
{
    flow_data->set_state(new_state);
}

void SocksInspector::process_tunneled_data(Packet* p, SocksFlowData* flow_data)
{

    if ( flow_data->get_command() == SOCKS_CMD_CONNECT and flow_data->is_handoff_pending() )
    {
        trigger_service_detection(p, flow_data);
        return;
    }
}

void SocksInspector::process_udp_associate_data(Packet* p, SocksFlowData* flow_data)
{
    // Parse SOCKS5-UDP header (RFC 1928 Section 7)
    // +----+------+------+----------+----------+----------+
    // |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
    // +----+------+------+----------+----------+----------+
    // | 2  |  1   |  1   | Variable |    2     | Variable |
    // +----+------+------+----------+----------+----------+

    if ( p->dsize < SOCKS5_UDP_IPV4_HEADER )
        return;

    const uint8_t* data = p->data;

    // Parse header fields
    uint16_t rsv = (data[0] << 8) | data[1];
    uint8_t frag_byte = data[SOCKS5_UDP_RSV_LEN];
    uint8_t atyp = data[SOCKS5_UDP_RSV_LEN + SOCKS5_UDP_FRAG_LEN];

    if ( rsv != 0 )
    {
        create_socks_event(flow_data, SOCKS_EVENT_PROTOCOL_VIOLATION);
        return;
    }

    // RFC 1928 §7: Parse FRAG field
    // Low 7 bits (0x7F) = fragment position (0 = standalone, 1-127 = fragment position)
    uint8_t frag_pos = frag_byte & 0x7F;

    socks_stats.udp_packets++;

    // Validate ATYP field for minimum required length
    if ( atyp == SOCKS_ATYP_IPV6 )
    {
        if ( p->dsize < SOCKS5_UDP_IPV6_HEADER )  // RSV(2) + FRAG(1) + ATYP(1) + IPv6(16) + PORT(2)
            return;
    }
    else if ( atyp == SOCKS_ATYP_DOMAIN )
    {
        uint8_t domain_len = data[SOCKS5_UDP_HEADER_BASE];
        if ( p->dsize < SOCKS5_UDP_DOMAIN_HEADER_MIN + domain_len )  // RSV(2) + FRAG(1) + ATYP(1) + LEN(1) + DOMAIN + PORT(2)
            return;
    }
    else if ( atyp != SOCKS_ATYP_IPV4 )
        return;
    // IPv4 already validated by initial p->dsize < 10 check
    // RFC 1928 §7: Handle fragmentation
    // frag_pos=0: Standalone packet (no fragmentation)

    if ( frag_pos == 0 )
    {
        // Standalone packet (no fragmentation) - create pseudo packet for inner protocol inspection
        uint16_t header_len = SOCKS5_UDP_HEADER_BASE;  // RSV(2) + FRAG(1) + ATYP(1)

        if ( atyp == SOCKS_ATYP_IPV4 )
            header_len = SOCKS5_UDP_IPV4_HEADER;  // RSV(2) + FRAG(1) + ATYP(1) + IPv4(4) + PORT(2)
        else if ( atyp == SOCKS_ATYP_IPV6 )
            header_len = SOCKS5_UDP_IPV6_HEADER;  // RSV(2) + FRAG(1) + ATYP(1) + IPv6(16) + PORT(2)
        else if ( atyp == SOCKS_ATYP_DOMAIN )
        {
            uint8_t domain_len = data[SOCKS5_UDP_HEADER_BASE];
            header_len = SOCKS5_UDP_DOMAIN_HEADER_MIN + domain_len;  // RSV(2) + FRAG(1) + ATYP(1) + LEN(1) + DOMAIN + PORT(2)
        }

        if ( p->dsize <= header_len )
            return;
        const uint8_t* payload = data + header_len;
        uint16_t payload_len = p->dsize - header_len;

        SfIp dst_ip;
        uint16_t dst_port = 0;

        std::string target_address;
        
        if ( atyp == SOCKS_ATYP_IPV4 )
        {
            dst_ip.set(&data[SOCKS5_UDP_HEADER_BASE], AF_INET);
            dst_port = (data[SOCKS5_UDP_HEADER_BASE + IPV4_ADDR_LEN] << 8) | data[SOCKS5_UDP_HEADER_BASE + IPV4_ADDR_LEN + 1];
            
            char ip_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET, &data[SOCKS5_UDP_HEADER_BASE], ip_str, INET_ADDRSTRLEN);
            target_address = ip_str;
            
            if( PacketTracer::is_active() )
                PacketTracer::log("SOCKS5-UDP: Parsed IPv4 dst=%s:%u \n", dst_ip.ntop(ip_str), dst_port);
        }
        else if ( atyp == SOCKS_ATYP_IPV6 )
        {
            dst_ip.set(&data[SOCKS5_UDP_HEADER_BASE], AF_INET6);
            dst_port = (data[SOCKS5_UDP_HEADER_BASE + IPV6_ADDR_LEN] << 8) | data[SOCKS5_UDP_HEADER_BASE + IPV6_ADDR_LEN + 1];
            
            char ip_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &data[SOCKS5_UDP_HEADER_BASE], ip_str, INET6_ADDRSTRLEN);
            target_address = ip_str;
        }
        else if ( atyp == SOCKS_ATYP_DOMAIN )
        {
            uint8_t domain_len = data[SOCKS5_UDP_HEADER_BASE];
            target_address.assign(reinterpret_cast<const char*>(&data[SOCKS5_UDP_HEADER_BASE + 1]), domain_len);
            dst_port = (data[SOCKS5_UDP_HEADER_BASE + 1 + domain_len] << 8) | data[SOCKS5_UDP_HEADER_BASE + 1 + domain_len + 1];
        }
        
        // Populate flow data with UDP packet metadata for IPS options
        flow_data->set_address_type(static_cast<SocksAddressType>(atyp));
        flow_data->set_target_address(target_address);
        flow_data->set_target_port(dst_port);
        
        // ATYP=DOMAIN: metadata only, no pseudo-packet (can't build IP header without resolved IP)
        if ( atyp == SOCKS_ATYP_DOMAIN )
            return;

        // Determine packet direction for correct src/dst assignment in pseudo-packet
        // Client→Server: src=client_ip, dst=dst_ip (from SOCKS header)
        // Server→Client: src=dst_ip (from SOCKS header), dst=client_ip
        const bool from_client = p->is_from_client();

        // Build pseudo packet - check if parent has Ethernet header or is raw IP
        // Match the parent packet's link layer format by checking if packet has Ethernet layer
        const bool has_eth = (p->num_layers > 0 and
            (p->layers[0].prot_id == ProtocolId::ETHERNET_802_3 or
             p->layers[0].prot_id == ProtocolId::ETHERNET_802_11 or
             p->layers[0].prot_id == ProtocolId::ETHERNET_LLC));
        const uint32_t eth_len = has_eth ? sizeof(eth::EtherHdr) : 0;
        const uint32_t ip_len = dst_ip.is_ip4() ? sizeof(ip::IP4Hdr) : sizeof(ip::IP6Hdr);
        const uint32_t udp_len = sizeof(udp::UDPHdr);
        const uint32_t total_len = eth_len + ip_len + udp_len + payload_len;

        std::unique_ptr<uint8_t[]> pkt_data(new uint8_t[total_len]);
        memset(pkt_data.get(), 0, total_len);

        uint32_t offset = 0;

        if ( has_eth )
        {
            eth::EtherHdr* eth_hdr = reinterpret_cast<eth::EtherHdr*>(pkt_data.get());
            eth_hdr->ether_type = htons(dst_ip.is_ip4() ? 0x0800 : 0x86DD);
            offset = eth_len;
        }

        if ( dst_ip.is_ip4() )
        {
            ip::IP4Hdr* ip4_hdr = reinterpret_cast<ip::IP4Hdr*>(pkt_data.get() + offset);
            ip4_hdr->ip_verhl = 0x45;  // Version 4, header length 5 (20 bytes)
            ip4_hdr->ip_len = htons(ip_len + udp_len + payload_len);
            ip4_hdr->ip_ttl = 64;
            ip4_hdr->ip_proto = static_cast<IpProtocol>(IPPROTO_UDP);

            // Set src/dst based on direction
            if ( from_client )
            {
                // Client→Server: src=client, dst=target from SOCKS header
                if ( p->flow->client_ip.is_ip4() )
                    memcpy(&ip4_hdr->ip_src, p->flow->client_ip.get_ip4_ptr(), IPV4_ADDR_LEN);
                else
                    memset(&ip4_hdr->ip_src, 0, IPV4_ADDR_LEN);
                memcpy(&ip4_hdr->ip_dst, dst_ip.get_ip4_ptr(), IPV4_ADDR_LEN);
            }
            else
            {
                // Server→Client: src=target from SOCKS header, dst=client
                memcpy(&ip4_hdr->ip_src, dst_ip.get_ip4_ptr(), IPV4_ADDR_LEN);
                if ( p->flow->client_ip.is_ip4() )
                    memcpy(&ip4_hdr->ip_dst, p->flow->client_ip.get_ip4_ptr(), IPV4_ADDR_LEN);
                else
                    memset(&ip4_hdr->ip_dst, 0, IPV4_ADDR_LEN);
            }

            offset += ip_len;
        }
        else
        {
            ip::IP6Hdr* ip6_hdr = reinterpret_cast<ip::IP6Hdr*>(pkt_data.get() + offset);
            ip6_hdr->ip6_vtf = htonl(0x60000000);  // Version 6
            ip6_hdr->ip6_payload_len = htons(udp_len + payload_len);
            ip6_hdr->ip6_next = static_cast<IpProtocol>(IPPROTO_UDP);
            ip6_hdr->ip6_hoplim = 64;

            // Set src/dst based on direction
            if ( from_client )
            {
                // Client→Server: src=client, dst=target from SOCKS header
                if ( p->flow->client_ip.is_ip6() )
                    memcpy(&ip6_hdr->ip6_src, p->flow->client_ip.get_ip6_ptr(), IPV6_ADDR_LEN);
                else
                    memset(&ip6_hdr->ip6_src, 0, IPV6_ADDR_LEN);
                memcpy(&ip6_hdr->ip6_dst, dst_ip.get_ip6_ptr(), IPV6_ADDR_LEN);
            }
            else
            {
                // Server→Client: src=target from SOCKS header, dst=client
                memcpy(&ip6_hdr->ip6_src, dst_ip.get_ip6_ptr(), IPV6_ADDR_LEN);
                if ( p->flow->client_ip.is_ip6() )
                    memcpy(&ip6_hdr->ip6_dst, p->flow->client_ip.get_ip6_ptr(), IPV6_ADDR_LEN);
                else
                    memset(&ip6_hdr->ip6_dst, 0, IPV6_ADDR_LEN);
            }
            
            offset += ip_len;
        }

        udp::UDPHdr* udp_hdr = reinterpret_cast<udp::UDPHdr*>(pkt_data.get() + offset);
        // Set ports based on direction
        if ( from_client )
        {
            udp_hdr->uh_sport = htons(p->flow->client_port ? p->flow->client_port : 0);
            udp_hdr->uh_dport = htons(dst_port);
        }
        else
        {
            udp_hdr->uh_sport = htons(dst_port);
            udp_hdr->uh_dport = htons(p->flow->client_port ? p->flow->client_port : 0);
        }
        udp_hdr->uh_len = htons(udp_len + payload_len);
        udp_hdr->uh_chk = 0;

        offset += udp_len;

        memcpy(pkt_data.get() + offset, payload, payload_len);

        if( PacketTracer::is_active() )
            PacketTracer::log("SOCKS5-UDP: Rebuilt packet created, total_len=%u, ip_ver=%s, has_eth=%d, from_client=%d", 
                total_len, dst_ip.is_ip4() ? "4" : "6", has_eth, from_client);

        // Clear service/inspectors BEFORE creating pseudo packet so wizard can detect inner protocol
        const char* saved_service = p->flow->service;
        Inspector* saved_clouseau = p->flow->clouseau;
        Inspector* saved_gadget = p->flow->gadget;

        p->flow->service = nullptr;
        p->flow->clouseau = nullptr;
        p->flow->gadget = nullptr;

        Packet* pseudo_pkt = DetectionEngine::set_next_packet(p, p->flow);

        DAQ_PktHdr_t pkth;
        memset(&pkth, 0, sizeof(pkth));
        pkth.ts.tv_sec = p->pkth->ts.tv_sec;
        pkth.ts.tv_usec = p->pkth->ts.tv_usec;
        pkth.pktlen = total_len;

        DetectionEngine de;
        de.set_encode_packet(const_cast<Packet*>(p));

        Analyzer::get_local_analyzer()->process_rebuilt_packet(
            pseudo_pkt, &pkth, pkt_data.get(), total_len);

        de.set_encode_packet(nullptr);

        p->flow->service = saved_service;
        p->flow->clouseau = saved_clouseau;
        p->flow->gadget = saved_gadget;

    }
    else
    {
        // Fragmented packet (frag_pos 1-127)
        // RFC 1928 §7: Fragmentation is rarely used in practice
        // UDP reassembly not supported - generate alert and stop inspection on this flow
        create_socks_event(flow_data, SOCKS5_EVENT_UDP_FRAGMENTATION);
        ++socks_stats.udp_frags;
        return;
    }
}

bool SocksInspector::parse_socks5_username_password_auth(const uint8_t* data, uint16_t len, SocksFlowData* flow_data)
{
    if ( !has_minimum_length(len, SOCKS5_AUTH_NEG_MIN_LEN) or !data ) // version + username_len + minimum username
        return false;

    // Parse username/password authentication request (RFC 1929)
    if ( data[0] != 0x01 ) // Subnegotiation version must be 0x01
        return false;

    uint8_t username_len = data[1];
    if ( username_len == 0 )
    {
        create_socks_event(flow_data, SOCKS_EVENT_PROTOCOL_VIOLATION);
        return false;
    }

    if ( username_len > len - 3 )
        return false;

    uint8_t password_len = data[2 + username_len];
    if ( password_len > len - 3 - username_len )
        return false;
    flow_data->increment_request_count();
    set_next_state(flow_data, SOCKS_STATE_V5_USERNAME_PASSWORD_AUTH);
    return true;
}

bool SocksInspector::parse_socks5_username_password_auth_resp(const uint8_t* data, uint16_t len, SocksFlowData* flow_data)
{
    if ( !has_minimum_length(len, sizeof(Socks5UsernamePasswordAuthResp)) or !data )
        return false;

    const Socks5UsernamePasswordAuthResp* auth_resp = reinterpret_cast<const Socks5UsernamePasswordAuthResp*>(data);

    if ( auth_resp->version != 0x01 ) // Subnegotiation version must be 0x01
    {
        create_socks_event(flow_data, SOCKS_EVENT_PROTOCOL_VIOLATION);
        return false;
    }

    flow_data->increment_response_count();

    if ( auth_resp->status == 0x00 ) // Success
    {
        set_next_state(flow_data, SOCKS_STATE_V5_CONNECT_REQUEST);
        ++socks_stats.auth_successes;
    }
    else
    {
        set_next_state(flow_data, SOCKS_STATE_ERROR);
        ++socks_stats.auth_failures;
        return false;
    }

    return true;
}

bool SocksInspector::parse_socks5_command_response(const uint8_t* data, uint16_t len, SocksFlowData* flow_data)
{
    if ( !has_minimum_length(len, SOCKS5_CONNECT_MIN_LEN) or !data )
        return false;

    const Socks5ConnectResponse* conn_resp = reinterpret_cast<const Socks5ConnectResponse*>(data);

    if ( !is_valid_socks5_version(conn_resp->version) )
        return false;

    // RFC 1928 specifies reserved byte should be 0x00, but some implementations
    // may not strictly follow this. Log warning but don't reject.
    if ( conn_resp->reserved != 0x00 )
    {
        create_socks_event(flow_data, SOCKS_EVENT_PROTOCOL_VIOLATION);
        // Don't return false - continue processing
    }

    flow_data->set_last_error(static_cast<SocksReplyCode>(conn_resp->reply_code));
    flow_data->increment_response_count();

    uint16_t offset = 4; // Skip fixed header
    SocksAddressType addr_type = SOCKS_ATYP_IPV4;
    std::string bind_address;
    uint16_t bind_port = 0;


    if ( parse_socks5_address(data, len, offset, addr_type, bind_address, bind_port) )
    {
        // Store bind address from response (where proxy bound/connected)
        // This is separate from target (what client requested)
        flow_data->set_bind_address(bind_address);
        flow_data->set_bind_port(bind_port);
        flow_data->set_bind_address_type(addr_type);

        // Note: Do NOT set target_ip from bind_address - they are different concepts:
        // - target: where client wants to connect (from request)
        // - bind: where proxy bound/connected (from response)
    }
    else
        create_socks_event(flow_data, SOCKS_EVENT_PROTOCOL_VIOLATION);

    if ( conn_resp->reply_code == SOCKS5_REP_SUCCESS )
    {
        set_next_state(flow_data, SOCKS_STATE_ESTABLISHED);
        ++socks_stats.successful_connections;

        if ( flow_data->get_command() == SOCKS_CMD_CONNECT )
            flow_data->set_handoff_pending(true);
        Packet* p = DetectionEngine::get_current_packet();

        if ( flow_data->get_command() == SOCKS_CMD_UDP_ASSOCIATE and p and p->flow )
        {
            ++socks_stats.udp_associations_created;

            // Create dynamic UDP expectation for the bind address/port
            // This allows UDP traffic to the proxy's relay endpoint to be
            // automatically bound to the SOCKS inspector without wizard patterns
            if ( bind_port != 0 and (addr_type == SOCKS_ATYP_IPV4 or addr_type == SOCKS_ATYP_IPV6) )
            {
                SfIp bind_ip;
                if ( bind_ip.set(bind_address.c_str()) == SFIP_SUCCESS )
                {
                    // Client IP from the TCP control flow
                    const SfIp* client_ip = &p->flow->client_ip;

                    // Create SocksFlowData for the expected UDP flow
                    // Pre-configure it as UDP ASSOCIATE so UDP packets are processed correctly
                    SocksFlowData* udp_fd = new SocksFlowData;
                    udp_fd->set_state(SOCKS_STATE_ESTABLISHED);
                    udp_fd->set_command(SOCKS_CMD_UDP_ASSOCIATE);
                    udp_fd->set_socks_version(SOCKS5_VERSION);
                    udp_fd->set_initiator(SOCKS_INITIATOR_CLIENT);

                    // Create expectation: client -> bind_ip:bind_port (UDP)
                    // bidirectional=true so responses also match
                    int result = Stream::set_snort_protocol_id_expected(
                        p,                          // control packet (TCP)
                        PktType::UDP,               // expect UDP packets
                        IpProtocol::UDP,            // UDP protocol
                        client_ip,                  // source: SOCKS client
                        0,                          // any source port
                        &bind_ip,                   // dest: proxy's UDP relay
                        bind_port,                  // dest port from response
                        socks_snort_protocol_id,   // bind to SOCKS inspector
                        udp_fd,                     // attach pre-configured flow data
                        false,                      // don't swap direction
                        false,                      // single expectation
                        true);                      // bidirectional

                    if ( result >= 0 )
                        ++socks_stats.udp_expectations_created;
                    else
                        delete udp_fd;  // Clean up on failure

                    (void)result;  // Suppress unused variable warning
                }
            }

            if ( PacketTracer::is_active() )
                PacketTracer::log("SOCKS: SOCKS5 UDP ASSOCIATE established, BND.ADDR=%s BND.PORT=%u\n",
                    bind_address.c_str(), bind_port);
        }
        if ( p and p->flow )
        {
            SocksTunnelEvent event(flow_data, true);
            DataBus::publish(socks_pub_id, SocksEventIds::SOCKS_TUNNEL_ESTABLISHED, event, p->flow);
            
            if ( PacketTracer::is_active() )
                PacketTracer::log("SOCKS: SOCKS5 tunnel established, cmd=%u, target=%s:%u\n",
                    flow_data->get_command(), flow_data->get_target_address().c_str(),
                    flow_data->get_target_port());
        }

        handle_protocol_handoff(flow_data);
    }
    else
    {
        set_next_state(flow_data, SOCKS_STATE_ERROR);
        ++socks_stats.failed_connections;

        Packet* p = DetectionEngine::get_current_packet();
        if ( p and p->flow )
        {
            SocksTunnelEvent event(flow_data, false);
            DataBus::publish(socks_pub_id, SocksEventIds::SOCKS_TUNNEL_FAILED, event, p->flow);
            
            if ( PacketTracer::is_active() )
                PacketTracer::log("SOCKS: SOCKS5 tunnel failed, reply_code=0x%02x, target=%s:%u\n",
                    flow_data->get_last_error(), flow_data->get_target_address().c_str(),
                    flow_data->get_target_port());
        }
    }

    return true;
}

void SocksInspector::handle_protocol_handoff(SocksFlowData* flow_data)
{
    if ( flow_data->is_handoff_completed() )
        return;

    if ( flow_data->get_command() == SOCKS_CMD_CONNECT )
    {
        // Trigger handoff immediately - don't wait for tunneled data
        // This ensures the next packet goes directly to wizard
        Packet* current_pkt = DetectionEngine::get_current_packet();
        if ( current_pkt and current_pkt->flow )
        {
            bool is_reverse = (flow_data->get_initiator() == SOCKS_INITIATOR_SERVER);

            current_pkt->flow->set_proxied();
            current_pkt->flow->set_service(current_pkt, nullptr);
            current_pkt->flow->set_state(Flow::FlowState::INSPECT);

            DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::FLOW_SERVICE_CHANGE, current_pkt);

            flow_data->set_handoff_pending(false);
            flow_data->set_handoff_completed(true);

            // Get current PAF positions for wizard to continue scanning from.
            uint32_t to_server_paf = Stream::get_paf_position(current_pkt->flow, true);
            uint32_t to_client_paf = Stream::get_paf_position(current_pkt->flow, false);

            // Get wizard splitters for both directions.
            // For reverse SOCKS, we swap the splitter directions so the wizard sees
            // the tunneled protocol data correctly. In reverse SOCKS:
            // - The original TCP client sends HTTP requests (should be c2s for wizard)
            // - The original TCP server sends HTTP responses (should be s2c for wizard)
            // But without swap_roles(), the directions are inverted, so we install
            // the c2s splitter on the s2c tracker and vice versa.
            StreamSplitter* to_server_splitter = nullptr;
            StreamSplitter* to_client_splitter = nullptr;
            if ( current_pkt->flow->clouseau )
            {
                if ( is_reverse )
                {
                    // Swap splitter directions for reverse SOCKS
                    to_server_splitter = current_pkt->flow->clouseau->get_splitter(false);  // s2c splitter
                    to_client_splitter = current_pkt->flow->clouseau->get_splitter(true);   // c2s splitter
                }
                else
                {
                    to_server_splitter = current_pkt->flow->clouseau->get_splitter(true);
                    to_client_splitter = current_pkt->flow->clouseau->get_splitter(false);
                }
            }

            if ( to_server_splitter )
                Stream::set_splitter_with_rescan(current_pkt->flow, true, to_server_splitter, to_server_paf);

            if ( to_client_splitter )
                Stream::set_splitter_with_rescan(current_pkt->flow, false, to_client_splitter, to_client_paf);

            if ( PacketTracer::is_active() )
                PacketTracer::log("SOCKS: Protocol handoff completed, is_reverse=%d, to_server_paf=%u, to_client_paf=%u, dsize=%u. target = %s:%u\n",
                    is_reverse, to_server_paf, to_client_paf, current_pkt->dsize,
                    flow_data->get_target_address().c_str(), flow_data->get_target_port());
        }
    }
}


void SocksInspector::trigger_service_detection(Packet* p, SocksFlowData* flow_data)
{
    if ( !p or !p->flow or !flow_data )
        return;

    if ( PacketTracer::is_active() )
        PacketTracer::log("SOCKS: Triggering service detection for tunneled protocol, target=%s:%u\n", 
                            flow_data->get_target_address().c_str(), flow_data->get_target_port());
    p->flow->set_proxied();
    p->flow->set_service(p, nullptr);
    p->flow->set_state(Flow::FlowState::INSPECT);
    if ( p->flow->gadget )
        p->flow->clear_gadget();

    DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::FLOW_SERVICE_CHANGE, p);

    flow_data->set_handoff_pending(false);
    flow_data->set_handoff_completed(true);
}

bool SocksInspector::handle_error_state(Packet* p, SocksFlowData* flow_data)
{
    if ( flow_data->get_state() != SOCKS_STATE_ERROR )
        return false;

    const uint8_t* data = p->data;
    uint16_t len = p->dsize;

    if ( len == 0 or (data[0] != SOCKS4_VERSION and data[0] != SOCKS5_VERSION) )
    {
        trigger_service_detection(p, flow_data);
        flow_data->set_handoff_completed(true);
    }

    return true;
}

void SocksInspector::detect_protocol_initiator(const Packet* p, SocksFlowData* flow_data)
{
    const uint8_t* data = p->data;
    uint16_t len = p->dsize;

    if ( !data or len < 2 )
        return;

    bool from_client = p->is_from_client();

    // Note: SOCKS5 UDP detection is intentionally NOT implemented here.
    // The SOCKS5 UDP header pattern (00 00 00 XX) is too generic and would
    // cause false positives on DNS, QUIC, STUN, RTP, and other UDP protocols.
    // Risk of false drops/blocks on legitimate traffic is too high.
    // SOCKS5 UDP ASSOCIATE requires explicit port binding by the user.
    if ( p->is_udp() )
        return;

    if ( from_client )
    {
        if ( data[0] == SOCKS4_VERSION or data[0] == SOCKS5_VERSION )
        {
            flow_data->set_initiator(SOCKS_INITIATOR_CLIENT);
            return;
        }
    }

    if ( !from_client )
    {
        if ( data[0] == SOCKS5_VERSION )
        {
            flow_data->set_initiator(SOCKS_INITIATOR_SERVER);
            flow_data->set_socks_version(SOCKS5_VERSION);
            return;
        }

        // Note: Reverse SOCKS4 (server-initiated SOCKS4) is not supported.
        // SOCKS4 responses start with 0x00 which is ambiguous and the reverse
        // processing path only handles SOCKS5. Omitting detection here to avoid
        // setting initiator/version for a path that won't be processed.
    }
}

// Check if data looks like a SOCKS5 command request: ver=5, cmd=1-3, rsv=0, atyp=1/3/4
static bool is_socks5_command_request(const uint8_t* data, uint16_t len)
{
    return len >= 4 and data[0] == SOCKS5_VERSION and
           data[1] >= 0x01 and data[1] <= 0x03 and data[2] == 0x00 and
           (data[3] == 0x01 or data[3] == 0x03 or data[3] == 0x04);
}

// Check if data looks like a SOCKS5 auth negotiation: ver=5, nmethods > 0
static bool is_socks5_auth_negotiation(const uint8_t* data, uint16_t len)
{
    return len >= 3 and data[1] > 0;
}

void SocksInspector::process_reverse_server_data(Packet* p, SocksFlowData* flow_data)
{
    const uint8_t* data = p->data;
    uint16_t len = p->dsize;

    // In reverse SOCKS, server sends greeting, auth response, and CONNECT request
    // (opposite of normal flow where client sends these)

    switch ( flow_data->get_state() )
    {
        case SOCKS_STATE_V5_BIND_REVERSE_AUTH_NEGOTIATION:
            // Server can send either auth response OR connect request
            // In reverse SOCKS, server may send CONNECT request before client's auth response
            if ( len == 2 )
            {
                // RFC 1928: Auth method selection response (2 bytes)
                // parse_socks5_auth_response() sets forward flow states, override with reverse states
                if ( parse_socks5_auth_response(data, len, flow_data) )
                {
                    if ( flow_data->get_state() != SOCKS_STATE_ERROR )
                        set_next_state(flow_data, SOCKS_STATE_V5_BIND_REVERSE_AUTH_RESPONSE);
                }
            }
            else if ( is_socks5_command_request(data, len) )
            {
                // Server sends CONNECT request
                if ( parse_socks5_command_request(data, len, flow_data) )
                    set_next_state(flow_data, SOCKS_STATE_V5_BIND_REVERSE_CONNECT_REQUEST);
            }
            break;

        case SOCKS_STATE_V5_BIND_REVERSE_AUTH_RESPONSE:
            // Server can send CONNECT request or username/password auth
            if ( is_socks5_command_request(data, len) )
            {
                if ( parse_socks5_command_request(data, len, flow_data) )
                    set_next_state(flow_data, SOCKS_STATE_V5_BIND_REVERSE_CONNECT_REQUEST);
            }
            else if ( flow_data->get_auth_method() == SOCKS5_AUTH_USERNAME_PASSWORD )
            {
                parse_socks5_username_password_auth(data, len, flow_data);
            }
            break;

        case SOCKS_STATE_ESTABLISHED:
            process_tunneled_data(p, flow_data);
            break;

        case SOCKS_STATE_ERROR:
            if ( len == 0 or (data[0] != SOCKS4_VERSION and data[0] != SOCKS5_VERSION) )
            {
                trigger_service_detection(p, flow_data);
                flow_data->set_handoff_completed(true);
            }
            break;

        default:
            // Handle initial packets (auth negotiation, connect request)
            if ( len < 2 or data[0] != SOCKS5_VERSION )
                return;

            if ( is_socks5_command_request(data, len) )
            {
                if ( parse_socks5_command_request(data, len, flow_data) )
                    set_next_state(flow_data, SOCKS_STATE_V5_BIND_REVERSE_CONNECT_REQUEST);
            }
            else if ( is_socks5_auth_negotiation(data, len) )
            {
                if ( parse_socks5_auth_negotiation(data, len, flow_data) )
                    set_next_state(flow_data, SOCKS_STATE_V5_BIND_REVERSE_AUTH_NEGOTIATION);
            }
            break;
    }
}

// Check if data contains combined auth response + connect response
// Pattern: 05 XX 05 YY 00 ZZ ... (auth_resp followed by connect_resp)
static bool is_combined_auth_and_connect_response(const uint8_t* data, uint16_t len)
{
    return len >= 12 and data[2] == SOCKS5_VERSION and data[4] == 0x00;
}

// Check if data looks like a CONNECT response: ver=5, rep, rsv=0, atyp
static bool is_connect_response(const uint8_t* data, uint16_t len)
{
    return len >= 4 and data[0] == SOCKS5_VERSION and data[2] == 0x00;
}

void SocksInspector::process_reverse_client_data(Packet* p, SocksFlowData* flow_data)
{
    const uint8_t* data = p->data;
    uint16_t len = p->dsize;

    // Handle established tunnel or error states
    if ( flow_data->get_state() == SOCKS_STATE_ESTABLISHED )
    {
        process_tunneled_data(p, flow_data);
        return;
    }

    if ( handle_error_state(p, flow_data) )
        return;

    // Skip any non-SOCKS prefix data (splitter may not have flushed at marker
    // if initiator wasn't set yet when splitter ran)
    // Only resync in early handshake states to avoid misinterpreting tunneled data
    SocksState state = flow_data->get_state();
    if ( len >= 2 and data[0] != SOCKS5_VERSION and
         (state == SOCKS_STATE_INIT or
          state == SOCKS_STATE_V5_AUTH_NEGOTIATION or
          state == SOCKS_STATE_V5_BIND_REVERSE_AUTH_NEGOTIATION or
          state == SOCKS_STATE_V5_BIND_REVERSE_AUTH_RESPONSE or
          state == SOCKS_STATE_V5_BIND_REVERSE_CONNECT_REQUEST) )
    {
        for ( uint16_t i = 1; i + 1 < len; i++ )
        {
            if ( data[i] == SOCKS5_VERSION )
            {
                data += i;
                len -= i;
                break;
            }
        }
    }

    if ( len < 2 or data[0] != SOCKS5_VERSION )
        return;

    // In reverse SOCKS, client sends auth response and CONNECT response
    // TCP reassembly may combine multiple messages in one PDU

    // Case 1: Combined auth response + connect response
    if ( is_combined_auth_and_connect_response(data, len) )
    {
        if ( parse_socks5_auth_response(data, 2, flow_data) and
             flow_data->get_state() != SOCKS_STATE_ERROR )
        {
            set_next_state(flow_data, SOCKS_STATE_V5_BIND_REVERSE_AUTH_RESPONSE);
            data += 2;
            len -= 2;
        }
    }
    // Case 2: Standalone auth response (exactly 2 bytes)
    else if ( len == 2 )
    {
        if ( parse_socks5_auth_response(data, 2, flow_data) and
             flow_data->get_state() != SOCKS_STATE_ERROR )
        {
            set_next_state(flow_data, SOCKS_STATE_V5_BIND_REVERSE_AUTH_RESPONSE);
        }
        return;
    }

    // Case 3: CONNECT response
    if ( is_connect_response(data, len) )
    {
        if ( parse_socks5_command_response(data, len, flow_data) and
             flow_data->get_state() == SOCKS_STATE_ESTABLISHED and
             flow_data->get_command() == SOCKS_CMD_CONNECT )
        {
            flow_data->set_handoff_pending(true);
            handle_protocol_handoff(flow_data);
        }
        return;
    }

    // Case 4: Username/password auth (if that method was selected)
    if ( flow_data->get_state() == SOCKS_STATE_V5_BIND_REVERSE_AUTH_RESPONSE and
         flow_data->get_auth_method() == SOCKS5_AUTH_USERNAME_PASSWORD )
    {
        parse_socks5_username_password_auth(data, len, flow_data);
    }
}

// Helper function to cast IP pointer to mutable bytes for XFF API
// Note: XFF API requires non-const pointer but data is not actually modified
static inline uint8_t* ip_to_mutable_bytes(const void* ptr)
{
    // Cast away const for API compatibility - data is read-only in practice
    return static_cast<uint8_t*>(const_cast<void*>(ptr));
}

// cppcheck-suppress constParameterPointer ; API requirement
int SocksInspector::get_xtra_target_ip(Flow* flow, uint8_t** buf, uint32_t* len, uint32_t* type)
{
    if ( !flow )
        return 0;

    const auto* fd = static_cast<const SocksFlowData*>(flow->get_flow_data(SocksFlowData::get_inspector_id()));
    if ( !fd )
        return 0;

    const auto& target = fd->get_target_address_ref();
    const auto* target_ip_ptr = target.get_ip();
    if ( !target_ip_ptr )
        return 0;

    const auto& target_ip = *target_ip_ptr;

    if ( target_ip.is_ip4() )
    {
        *buf = ip_to_mutable_bytes(target_ip.get_ip4_ptr());
        *len = 4;
        *type = EVENT_INFO_XFF_IPV4;
    }
    else if ( target_ip.is_ip6() )
    {
        *buf = ip_to_mutable_bytes(target_ip.get_ip6_ptr());
        *len = 16;
        *type = EVENT_INFO_XFF_IPV6;
    }
    else
        return 0;

    return 1;
}

//-------------------------------------------------------------------------
// API
//-------------------------------------------------------------------------

static void socks_init()
{
    SocksFlowData::init();
}

static Module* mod_ctor() { return new SocksModule; }
static void mod_dtor(Module* m) { delete m; }
static Inspector* socks_ctor(Module* m) { return new SocksInspector(static_cast<SocksModule*>(m)); }
static void socks_dtor(Inspector* p) { delete p; }

const InspectApi socks_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        SOCKS_NAME,
        SOCKS_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__ANY_PDU,
    nullptr,
    "socks",
    socks_init,
    nullptr,
    nullptr,
    nullptr,
    socks_ctor,
    socks_dtor,
    nullptr,
    nullptr
};

extern const BaseApi* ips_socks_version;
extern const BaseApi* ips_socks_state;
extern const BaseApi* ips_socks_command;
extern const BaseApi* ips_socks_address_type;
extern const BaseApi* ips_socks_remote_address;
extern const BaseApi* ips_socks_remote_port;

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &socks_api.base,
    ips_socks_version,
    ips_socks_state,
    ips_socks_command,
    ips_socks_address_type,
    ips_socks_remote_address,
    ips_socks_remote_port,
    nullptr
};
#else
const BaseApi* sin_socks[] =
{
    &socks_api.base,
    ips_socks_version,
    ips_socks_state,
    ips_socks_command,
    ips_socks_address_type,
    ips_socks_remote_address,
    ips_socks_remote_port,
    nullptr
};
#endif

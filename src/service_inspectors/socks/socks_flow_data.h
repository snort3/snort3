//--------------------------------------------------------------------------
// Copyright (C) 2026 Cisco and/or its affiliates. All rights reserved.
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
// socks_flow_data.h - author Raza Shafiq <rshafiq@cisco.com>

#ifndef SOCKS_FLOW_DATA_H
#define SOCKS_FLOW_DATA_H

#include "flow/flow_data.h"
#include "sfip/sf_ip.h"
#include <memory>
#include <string>

#define SOCKS5_VERSION 0x05
#define SOCKS4_VERSION 0x04
#define SOCKS4_RESPONSE_VERSION 0x00  // SOCKS4 responses use 0x00, not 0x04

// Protocol constants
constexpr uint16_t SOCKS4_MIN_REQUEST_LEN = 9;      // VER(1) + CMD(1) + PORT(2) + IP(4) + NULL(1)
constexpr uint16_t SOCKS4_RESPONSE_LEN = 8;         // VER(1) + STATUS(1) + PORT(2) + IP(4)
constexpr uint16_t SOCKS5_AUTH_NEG_MIN_LEN = 3;     // VER(1) + NMETHODS(1) + METHODS(1+)
constexpr uint16_t SOCKS5_AUTH_RESPONSE_LEN = 2;    // VER(1) + METHOD(1)
constexpr uint16_t SOCKS5_CONNECT_MIN_LEN = 10;     // VER(1) + CMD(1) + RSV(1) + ATYP(1) + ADDR(4+) + PORT(2)
constexpr uint8_t RFC1035_MAX_DOMAIN_LEN = 253;     // RFC 1035 maximum domain name length
constexpr uint8_t MAX_USERNAME_LEN = 255;           // SOCKS5 username/password auth
constexpr uint8_t MAX_PASSWORD_LEN = 255;           // SOCKS5 username/password auth
constexpr uint8_t SOCKS5_USERPASS_VERSION = 0x01;   // RFC 1929 username/password subnegotiation

// Address and port sizes
constexpr uint8_t IPV4_ADDR_LEN = 4;
constexpr uint8_t IPV6_ADDR_LEN = 16;
constexpr uint8_t PORT_LEN = 2;
constexpr uint8_t DOMAIN_LEN_FIELD = 1;

// SOCKS5 UDP header component sizes (RFC 1928 Section 7)
constexpr uint8_t SOCKS5_UDP_RSV_LEN = 2;
constexpr uint8_t SOCKS5_UDP_FRAG_LEN = 1;
constexpr uint8_t SOCKS5_UDP_ATYP_LEN = 1;
constexpr uint8_t SOCKS5_UDP_HEADER_BASE = SOCKS5_UDP_RSV_LEN + SOCKS5_UDP_FRAG_LEN + SOCKS5_UDP_ATYP_LEN;  // 4 bytes
constexpr uint8_t SOCKS5_UDP_IPV4_HEADER = SOCKS5_UDP_HEADER_BASE + IPV4_ADDR_LEN + PORT_LEN;  // 10 bytes
constexpr uint8_t SOCKS5_UDP_IPV6_HEADER = SOCKS5_UDP_HEADER_BASE + IPV6_ADDR_LEN + PORT_LEN;  // 22 bytes
constexpr uint8_t SOCKS5_UDP_DOMAIN_HEADER_MIN = SOCKS5_UDP_HEADER_BASE + DOMAIN_LEN_FIELD + PORT_LEN;  // 7 bytes (+ domain)

enum Socks5AuthMethod : uint8_t
{
    SOCKS5_AUTH_NONE = 0x00,
    SOCKS5_AUTH_GSSAPI = 0x01,
    SOCKS5_AUTH_USERNAME_PASSWORD = 0x02,
    SOCKS5_AUTH_NO_ACCEPTABLE = 0xFF
};

// Generic SOCKS command codes (same for v4 and v5)
enum SocksCommand : uint8_t
{
    SOCKS_CMD_CONNECT = 0x01,
    SOCKS_CMD_BIND = 0x02,
    SOCKS_CMD_UDP_ASSOCIATE = 0x03  // SOCKS5 only
};

// SOCKS address types (SOCKS5 only, SOCKS4 always uses IPv4)
enum SocksAddressType : uint8_t
{
    SOCKS_ATYP_IPV4 = 0x01,
    SOCKS_ATYP_DOMAIN = 0x03,
    SOCKS_ATYP_IPV6 = 0x04
};

// Generic SOCKS reply codes (includes both SOCKS4 and SOCKS5 wire format values)
enum SocksReplyCode : uint8_t
{
    // SOCKS5 reply codes (RFC 1928)
    SOCKS5_REP_SUCCESS = 0x00,
    SOCKS5_REP_GENERAL_FAILURE = 0x01,
    SOCKS5_REP_NOT_ALLOWED = 0x02,
    SOCKS5_REP_NETWORK_UNREACHABLE = 0x03,
    SOCKS5_REP_HOST_UNREACHABLE = 0x04,
    SOCKS5_REP_CONNECTION_REFUSED = 0x05,
    SOCKS5_REP_TTL_EXPIRED = 0x06,
    SOCKS5_REP_COMMAND_NOT_SUPPORTED = 0x07,
    SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08,

    // SOCKS4 reply codes (RFC 1928)
    SOCKS4_REP_GRANTED = 0x5A,           // Request granted
    SOCKS4_REP_REJECTED = 0x5B,          // Request rejected or failed
    SOCKS4_REP_NO_IDENTD = 0x5C,         // Request failed (no identd)
    SOCKS4_REP_IDENTD_FAILED = 0x5D      // Request failed (identd mismatch)
};

// Generic SOCKS state machine (handles both v4 and v5)
enum SocksState : uint8_t
{
    SOCKS_STATE_INIT = 0,
    // SOCKS4/4a states
    SOCKS_STATE_V4_CONNECT_REQUEST,
    SOCKS_STATE_V4_CONNECT_RESPONSE,
    SOCKS_STATE_V4_BIND_SECOND_RESPONSE,
    // SOCKS5 states (forward flow - client initiates)
    SOCKS_STATE_V5_AUTH_NEGOTIATION,
    SOCKS_STATE_V5_AUTH_REQUEST,
    SOCKS_STATE_V5_AUTH_RESPONSE,
    SOCKS_STATE_V5_USERNAME_PASSWORD_AUTH,
    SOCKS_STATE_V5_CONNECT_REQUEST,
    SOCKS_STATE_V5_CONNECT_RESPONSE,
    // SOCKS5 BIND reverse states (server initiates)
    SOCKS_STATE_V5_BIND_REVERSE_AUTH_NEGOTIATION,
    SOCKS_STATE_V5_BIND_REVERSE_AUTH_RESPONSE,
    SOCKS_STATE_V5_BIND_REVERSE_CONNECT_REQUEST,
    SOCKS_STATE_V5_BIND_REVERSE_CONNECT_RESPONSE,
    // Common states
    SOCKS_STATE_ESTABLISHED,
    SOCKS_STATE_ERROR
};

enum SocksDirection : uint8_t
{
    SOCKS_DIR_CLIENT_TO_SERVER = 0,
    SOCKS_DIR_SERVER_TO_CLIENT = 1
};

enum SocksFlowInitiator : uint8_t
{
    SOCKS_INITIATOR_UNKNOWN = 0,
    SOCKS_INITIATOR_CLIENT,
    SOCKS_INITIATOR_SERVER
};

#pragma pack(push, 1)

struct Socks5AuthNegotiation
{
    uint8_t version;
    uint8_t num_methods;
    uint8_t methods[255];
};

struct Socks5AuthResponse
{
    uint8_t version;
    uint8_t method;
};

struct Socks5UsernamePasswordAuth
{
    uint8_t version;
    uint8_t username_len;
    // password_len (1 byte)
    // password (variable length)
};

struct Socks5UsernamePasswordAuthResp
{
    uint8_t version; // Subnegotiation version (0x01)
    uint8_t status;  // 0x00 = success, any other = failure
};

struct Socks5ConnectRequest
{
    uint8_t version;      // SOCKS version (0x05)
    uint8_t command;      // Command (CONNECT, BIND, UDP_ASSOCIATE)
    uint8_t reserved;     // Reserved byte (0x00)
    uint8_t address_type; // Address type (IPv4, Domain, IPv6)
    // address (variable length based on type)
    // port (2 bytes)
};

// SOCKS4 structures
struct Socks4Request
{
    uint8_t version;    // 0x04
    uint8_t command;    // 0x01=CONNECT, 0x02=BIND
    uint16_t port;      // Network byte order
    uint32_t ip;        // Network byte order (0.0.0.x for SOCKS4a domain)
    // userid (variable, NULL-terminated)
    // domain (variable, NULL-terminated) - SOCKS4a only if IP is 0.0.0.x
};

struct Socks4Response
{
    uint8_t version;    // 0x00 (not 0x04!)
    uint8_t status;     // 0x5A=granted, 0x5B-0x5D=rejected
    uint16_t port;      // Network byte order
    uint32_t ip;        // Network byte order
};

struct Socks5ConnectResponse
{
    uint8_t version;      // SOCKS version (0x05)
    uint8_t reply_code;   // Reply code
    uint8_t reserved;     // Reserved byte (0x00)
    uint8_t address_type; // Address type
    // address (variable length based on type)
    // port (2 bytes)
};

struct Socks5UdpHeader
{
    uint16_t reserved;    // Reserved (0x0000)
    uint8_t fragment;     // Fragment number (0x00 = no fragmentation)
    uint8_t address_type; // Address type
    // address (variable length based on type)
    // port (2 bytes)
    // data (variable length)
};

#pragma pack(pop)

//-------------------------------------------------------------------------
// Unified Address Structure - Type-safe variant pattern
// Handles IPv4, IPv6, and domain names efficiently
//-------------------------------------------------------------------------

struct SocksAddress
{
    SocksAddressType type;
    uint16_t port;

    // Storage: Use string for all types, convert to SfIp when needed
    // Rationale: Domains need string anyway, IP strings are small
    std::string address;  // Domain name OR IP string ("10.0.0.1", "2001:db8::1")

    mutable std::unique_ptr<snort::SfIp> cached_ip;

    SocksAddress() : type(SOCKS_ATYP_IPV4), port(0), cached_ip(nullptr)
    { }

    bool is_set() const { return !address.empty(); }

    const snort::SfIp* get_ip() const
    {
        if ( !cached_ip and !address.empty() )
        {
            auto temp_ip = std::make_unique<snort::SfIp>();
            if ( temp_ip->set(address.c_str()) == SFIP_SUCCESS and temp_ip->is_set() )
                cached_ip = std::move(temp_ip);
        }
        return cached_ip.get();
    }

    void set(const std::string& addr, SocksAddressType addr_type, uint16_t p)
    {
        address = addr;
        type = addr_type;
        port = p;
        cached_ip.reset();
    }

    void set(const snort::SfIp& ip, uint16_t p)
    {
        cached_ip = std::make_unique<snort::SfIp>(ip);
        port = p;

        snort::SfIpString ip_str;
        if ( ip.is_ip4() )
        {
            type = SOCKS_ATYP_IPV4;
            address = ip.ntop(ip_str);
        }
        else if ( ip.is_ip6() )
        {
            type = SOCKS_ATYP_IPV6;
            address = ip.ntop(ip_str);
        }
    }

    void clear()
    {
        address.clear();
        port = 0;
        type = SOCKS_ATYP_IPV4;
        cached_ip.reset();
    }
};

class SocksFlowData : public snort::FlowData
{
public:
    SocksFlowData();
    ~SocksFlowData() noexcept override;

    static void init();

    SocksState get_state() const { return state; }
    void set_state(SocksState new_state) { state = new_state; }

    SocksDirection get_direction() const { return direction; }
    void set_direction(SocksDirection dir) { direction = dir; }

    SocksFlowInitiator get_initiator() const { return initiator; }
    
    void set_initiator(SocksFlowInitiator init) 
    {
        if (!initiator_detected())
            initiator = init; 
    }

    bool initiator_detected() const { return initiator != SOCKS_INITIATOR_UNKNOWN; }

    Socks5AuthMethod get_auth_method() const { return auth_method; }
    void set_auth_method(Socks5AuthMethod method) { auth_method = method; }

    SocksCommand get_command() const { return command; }
    void set_command(SocksCommand cmd) { command = cmd; }

    // Target destination access (unified interface)
    const std::string& get_target_address() const { return target.address; }
    void set_target_address(const std::string& addr) { target.address = addr; }

    uint16_t get_target_port() const { return target.port; }
    void set_target_port(uint16_t port) { target.port = port; }

    SocksAddressType get_address_type() const { return target.type; }
    void set_address_type(SocksAddressType type) { target.type = type; }

    // Target IP access (binary form)
    const snort::SfIp* get_target_ip() const { return target.get_ip(); }
    void set_target_ip(const snort::SfIp& ip) { target.set(ip, target.port); }

    const SocksAddress& get_target_address_ref() const { return target; }

    // Complete target setter
    void set_target(const std::string& addr, SocksAddressType type, uint16_t port)
    { target.set(addr, type, port); }

    void increment_request_count() { request_count++; }
    uint32_t get_request_count() const { return request_count; }

    void increment_response_count() { response_count++; }
    uint32_t get_response_count() const { return response_count; }

    // Bind address access (unified interface - consistent with target)
    const std::string& get_bind_address() const { return bind.address; }
    void set_bind_address(const std::string& addr) { bind.address = addr; }

    uint16_t get_bind_port() const { return bind.port; }
    void set_bind_port(uint16_t port) { bind.port = port; }

    SocksAddressType get_bind_address_type() const { return bind.type; }
    void set_bind_address_type(SocksAddressType type) { bind.type = type; }

    // Bind IP access (binary form - now consistent with target)
    const snort::SfIp* get_bind_ip() const { return bind.get_ip(); }
    void set_bind_ip(const snort::SfIp& ip) { bind.set(ip, bind.port); }

    // Complete bind setter
    void set_bind(const std::string& addr, SocksAddressType type, uint16_t port)
    { bind.set(addr, type, port); }

    void set_last_error(SocksReplyCode error) { last_error = error; }
    SocksReplyCode get_last_error() const { return last_error; }

    bool is_handoff_pending() const { return handoff_pending; }
    void set_handoff_pending(bool pending) { handoff_pending = pending; }
    bool is_handoff_completed() const { return handoff_completed; }
    void set_handoff_completed(bool completed) { handoff_completed = completed; }
    bool is_session_counted() const { return session_counted; }
    void set_session_counted(bool counted) { session_counted = counted; }



    // SOCKS version tracking
    uint8_t get_socks_version() const { return socks_version; }
    void set_socks_version(uint8_t version) { socks_version = version; }

    bool is_socks4a() const { return is_socks4a_protocol; }
    void set_socks4a(bool socks4a) { is_socks4a_protocol = socks4a; }

    const std::string& get_userid() const { return userid; }
    void set_userid(const std::string& id) { userid = id; }

    static unsigned get_inspector_id() { return inspector_id; }

private:
    static unsigned inspector_id;

    SocksState state;
    SocksDirection direction;
    SocksFlowInitiator initiator;
    uint8_t socks_version;
    bool is_socks4a_protocol;


    Socks5AuthMethod auth_method;
    std::string userid;            // SOCKS4 userid OR SOCKS5 username


    SocksCommand command;          // CONNECT, BIND, or UDP_ASSOCIATE

    // Target destination (from CLIENT request)
    // - For CONNECT: where client wants to connect
    // - For BIND: expected incoming connection source
    // - For UDP_ASSOCIATE: UDP relay endpoint
    SocksAddress target;

    // Bind address (from SERVER response)
    // - For CONNECT: not used (server doesn't send bind info)
    // - For BIND: address where server is listening
    // - For UDP_ASSOCIATE: UDP relay address to use
    SocksAddress bind;

    //---------------------------------------------------------------------
    // Statistics & Flow Control
    //---------------------------------------------------------------------
    uint32_t request_count;        // Number of SOCKS requests
    uint32_t response_count;       // Number of SOCKS responses
    SocksReplyCode last_error;     // Last error code from server
    bool handoff_pending;          // Waiting to handoff to wizard
    bool handoff_completed;        // Handoff completed
    bool session_counted;          // Session already counted in stats

};

#endif

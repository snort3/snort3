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

// socks.h author Raza Shafiq <rshafiq@cisco.com>

#ifndef SOCKS_H
#define SOCKS_H

#include "framework/inspector.h"
#include "socks_flow_data.h"

class SocksModule;

class SocksInspector : public snort::Inspector
{
public:
    SocksInspector(const SocksModule*);
    bool configure(snort::SnortConfig*) override;
    void show(const snort::SnortConfig*) const override;
    void eval(snort::Packet*) override;
    void clear(snort::Packet*) override;
    snort::StreamSplitter* get_splitter(bool) override;
    static int get_xtra_target_ip(snort::Flow*, uint8_t**, uint32_t*, uint32_t*);

protected:
    const SocksModule* config;  // Kept for config reload support
    uint32_t xtra_target_ip_id;

    // SOCKS4/4a parsing methods
    bool parse_socks4_request(const uint8_t* data, uint16_t len, SocksFlowData* flow_data);
    bool parse_socks4_response(const uint8_t* data, uint16_t len, SocksFlowData* flow_data);
    bool parse_socks4a_domain(const uint8_t* data, uint16_t len, uint16_t& offset, std::string& domain);

    // SOCKS5 parsing methods
    bool parse_socks5_auth_negotiation(const uint8_t* data, uint16_t len, SocksFlowData* flow_data);
    bool parse_socks5_auth_response(const uint8_t* data, uint16_t len, SocksFlowData* flow_data);
    bool parse_socks5_username_password_auth(const uint8_t* data, uint16_t len, SocksFlowData* flow_data);
    bool parse_socks5_username_password_auth_resp(const uint8_t* data, uint16_t len, SocksFlowData* flow_data);
    bool parse_socks5_command_request(const uint8_t* data, uint16_t len, SocksFlowData* flow_data);
    bool parse_socks5_command_response(const uint8_t* data, uint16_t len, SocksFlowData* flow_data);

    // Generic address parsing (works for both versions)
    bool parse_socks5_address(const uint8_t* data, uint16_t len, uint16_t& offset, 
                             SocksAddressType& addr_type, std::string& address, uint16_t& port);

    // Flow data management
    SocksFlowData* get_flow_data(const snort::Flow* flow);
    void create_flow_data(snort::Flow* flow);

    // State machine processing
    void process_client_data(snort::Packet* p, SocksFlowData* flow_data);
    void process_server_data(snort::Packet* p, SocksFlowData* flow_data);
    void process_tunneled_data(snort::Packet* p, SocksFlowData* flow_data);
    
    // Reverse flow processing (BIND reverse connections)
    void detect_protocol_initiator(const snort::Packet* p, SocksFlowData* flow_data);
    void process_reverse_client_data(snort::Packet* p, SocksFlowData* flow_data);
    void process_reverse_server_data(snort::Packet* p, SocksFlowData* flow_data);

    // UDP support
    void process_udp_associate_data(snort::Packet* p, SocksFlowData* flow_data);

    // Protocol handoff
    void handle_protocol_handoff(SocksFlowData* flow_data);
    void trigger_service_detection(snort::Packet* p, SocksFlowData* flow_data);
    
    // ERROR state handling
    bool handle_error_state(snort::Packet* p, SocksFlowData* flow_data);

    // Generic validation methods (work for both v4 and v5)
    [[nodiscard]] bool is_valid_socks4_version(uint8_t version); // Checks for 0x04
    [[nodiscard]] bool is_valid_socks5_version(uint8_t version); // Checks for 0x05
    [[nodiscard]] bool is_valid_command(uint8_t command);
    [[nodiscard]] bool is_valid_address_type(uint8_t addr_type);

    // Version detection helper
    uint8_t detect_socks_version(const uint8_t* data, uint16_t len);

    // Utility methods
    [[nodiscard]] bool has_minimum_length(uint16_t data_len, uint16_t required_len);
    void set_next_state(SocksFlowData* flow_data, SocksState new_state);

    // Helper methods
    [[nodiscard]] bool validate_socks5_request_header(const Socks5ConnectRequest* conn_req);
};

#endif

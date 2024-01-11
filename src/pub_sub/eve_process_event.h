//--------------------------------------------------------------------------
// Copyright (C) 2021-2024 Cisco and/or its affiliates. All rights reserved.
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
// eve_process_event.h author Cliff Judge <cljudge@cisco.com>

#ifndef EVE_PROCESS_EVENT_H
#define EVE_PROCESS_EVENT_H

#include <string>
#include "pub_sub/external_event_ids.h"

class EveProcessEvent : public snort::DataEvent
{
public:
    EveProcessEvent(const snort::Packet& p, const char* process, uint8_t process_conf) :
        p(p), process_name(process), process_confidence(process_conf) { }

    EveProcessEvent(const snort::Packet& p, const char* server) : p(p), server_name(server) { }

    const snort::Packet* get_packet() const override { return &p; }

    const std::string& get_process_name() const
    {
        return process_name;
    }

    uint8_t get_process_confidence() const
    {
        return process_confidence;
    }

    const std::string& get_server_name() const
    {
        return server_name;
    }

    void set_server_name(const char* server)
    {
        if (server)
            server_name = server;
    }

    const std::string& get_user_agent() const
    {
        return user_agent;
    }

    void set_user_agent(const char* u_a)
    {
        if (u_a)
            user_agent = u_a;
    }

    const std::vector<std::string> get_alpn() const
    {
        return alpn;
    }

    void set_alpn(const std::vector<std::string>& alpn_vec)
    {
        if(alpn_vec.size())
            alpn = alpn_vec;
    }

    void set_quic(bool flag)
    {
        is_quic = flag;
    }

    bool is_flow_quic() const
    {
        return is_quic;
    }

    bool is_client_process_mapping() const
    {
        return client_process_mapping;
    }

    void set_client_process_mapping(bool flag)
    {
        client_process_mapping = flag;
    }

private:
    const snort::Packet &p;
    std::string process_name;
    uint8_t process_confidence = 0;
    std::string server_name;
    std::string user_agent;
    std::vector<std::string> alpn;
    bool is_quic = false;
    bool client_process_mapping = true;
};
#endif

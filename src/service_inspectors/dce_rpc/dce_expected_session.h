//--------------------------------------------------------------------------
// Copyright (C) 2020-2023 Cisco and/or its affiliates. All rights reserved.
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

//dce_expected_session.h author Eduard Burmai <eburmai@cisco.com>

#ifndef DCE_EXPECTED_SESSION_H
#define DCE_EXPECTED_SESSION_H

#include "framework/decode_data.h"
#include "target_based/snort_protocols.h"

namespace snort
{
struct Packet;
struct SfIp;
}

struct dce2TcpProtoConf;

// Expected Session Manager
class DceExpSsnManager
{
public:
    DceExpSsnManager(IpProtocol p, PktType t) :
        proto(p), type(t) {}

    virtual ~DceExpSsnManager() = default;

    void set_proto_id(SnortProtocolId id)
    { protocol_id = id; }

    SnortProtocolId get_proto_id() const
    { return protocol_id; }

    IpProtocol get_ip_proto() const
    { return proto; }

    PktType get_pkt_type() const
    { return type; }

    static void create_expected_session(const snort::SfIp*, uint16_t, const char*);

private:
    virtual int create_expected_session_impl(snort::Packet*,
        const snort::SfIp*, uint16_t, const snort::SfIp*, uint16_t,
        PktType, IpProtocol, SnortProtocolId) = 0;

private:
    SnortProtocolId protocol_id = UNKNOWN_PROTOCOL_ID;
    IpProtocol proto;
    PktType type;
};

class DceTcpExpSsnManager : public DceExpSsnManager
{
public:
    DceTcpExpSsnManager() = delete;
    DceTcpExpSsnManager(const dce2TcpProtoConf&);
    DceTcpExpSsnManager(const DceTcpExpSsnManager&) = delete;
    DceTcpExpSsnManager& operator=(const DceTcpExpSsnManager&) =delete;

private:
    int create_expected_session_impl(snort::Packet*,
        const snort::SfIp*, uint16_t, const snort::SfIp*, uint16_t,
        PktType, IpProtocol, SnortProtocolId) override;

private:
    const dce2TcpProtoConf& pc;
};

#endif // DCE_EXPECTED_SESSION_H

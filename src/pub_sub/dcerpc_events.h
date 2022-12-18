//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
//--------------------------------------------------------------------------

#ifndef DCERPC_EVENTS_H
#define DCERPC_EVENTS_H

#include "framework/data_bus.h"

struct DceTcpEventIds { enum : unsigned { EXP_SESSION, num_ids }; };

const snort::PubKey dce_tcp_pub_key { "dce_tcp", DceTcpEventIds::num_ids };

namespace snort
{
struct SfIp;
}

class DceExpectedSessionEvent : public snort::DataEvent
{
public:

    DceExpectedSessionEvent(snort::Packet* p,
        const snort::SfIp* src_ip, const uint16_t src_port,
        const snort::SfIp* dst_ip, const uint16_t dst_port,
        IpProtocol proto, SnortProtocolId protocol_id) :
            p(p), src_ip(src_ip), src_port(src_port),
            dst_ip(dst_ip), dst_port(dst_port),
            proto(proto), protocol_id(protocol_id) { }

    const snort::Packet* get_packet() const override
    { return p; }

    const snort::SfIp* get_src_ip() const
    { return src_ip; }

    const snort::SfIp* get_dst_ip() const
    { return dst_ip; }

    uint16_t get_src_port() const
    { return src_port; }

    uint16_t get_dst_port() const
    { return dst_port; }

    SnortProtocolId get_proto_id() const
    { return protocol_id; }

    IpProtocol get_ip_proto() const
    { return proto; }

private:
    const snort::Packet* p;

    const snort::SfIp* src_ip;
    uint16_t src_port;

    const snort::SfIp* dst_ip;
    uint16_t dst_port;

    IpProtocol proto;
    SnortProtocolId protocol_id;
};

#endif // DCERPC_EVENTS_H

//--------------------------------------------------------------------------
// Copyright (C) 2015-2024 Cisco and/or its affiliates. All rights reserved.
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

// ha_test.cc authors Ed Borgoyn <eborgoyn@cisco.com>, Michael Altizer <mialtize@cisco.com>
// unit test main

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "flow/ha.cc"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace snort;

#include "flow_stubs.h"

#define MSG_SIZE 100
#define TEST_KEY 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47

class StreamHAClient;

static const FlowKey s_test_key =
{
    /* .ip_l = */ { 1, 2, 3, 4 },
    /* .ip_h = */ { 5, 6, 7, 8 },
    /* .mplsLabel = */ 9,
    /* .addressSpaceId = */ 0,
#ifndef DISABLE_TENANT_ID
    /* .tenant_id = */ 0,
#endif
    /* .port_l = */ 10,
    /* .port_h = */ 11,
    /* .group_l = */ 0,
    /* .group_h = */ 0,
    /* .vlan_tag = */ 12,
    /* .padding = */ 0,
    /* .ip_protocol = */ 14,
    /* .pkt_type = */ PktType::TCP,
    /* .version = */ 14,
    /* .flags.group_used = */ 0,
    /* .flags.padding_bits = */ 0,
};

static struct __attribute__((__packed__)) TestDeleteMessage {
    HAMessageHeader mhdr;
    FlowKey key;
} s_delete_message =
{
    {
        HA_DELETE_EVENT,
        HA_MESSAGE_VERSION,
#ifndef DISABLE_TENANT_ID
        65,
#else
        61,
#endif
        KEY_TYPE_IP6
    },
    s_test_key
};

static struct __attribute__((__packed__)) TestUpdateMessage {
    HAMessageHeader mhdr;
    FlowKey key;
    HAClientHeader schdr;
    uint8_t scmsg[10];
} s_update_stream_message =
{
    {
        HA_UPDATE_EVENT,
        HA_MESSAGE_VERSION,
#ifndef DISABLE_TENANT_ID
        77,
#else
        73,
#endif
        KEY_TYPE_IP6
    },
    s_test_key,
    {
        0,
        10
    },
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }
};


class StreamHAClient : public FlowHAClient
{
public:
    StreamHAClient() : FlowHAClient(10, true) { }
    ~StreamHAClient() override = default;
    bool consume(Flow*&, const FlowKey*, HAMessage& msg, uint8_t size) override
    {
        mock().actualCall("consume");
        mock().setData("stream_consume_size", (int)size);

        for ( uint8_t i = 0; i < 10; i++ )
        {
            if (*msg.cursor != i)
                return false;
            msg.advance_cursor(sizeof(*msg.cursor));
        }

        return true;
    }
    bool produce(Flow&, HAMessage& msg) override
    {
        if (!msg.fits(10))
            return false;

        for ( uint8_t i = 0; i < 10; i++ )
        {
            *msg.cursor = i;
            msg.advance_cursor(sizeof(*msg.cursor));
        }
        return true;
    }
    bool is_update_required(Flow*) override
    {
        return (bool)mock().getData("stream_update_required").getIntValue();
    }
};

class OtherHAClient : public FlowHAClient
{
public:
    OtherHAClient() : FlowHAClient(5, false) { }
    ~OtherHAClient() override = default;
    bool consume(Flow*&, const FlowKey*, HAMessage& msg, uint8_t size) override
    {
        mock().actualCall("other_consume");
        mock().setData("other_consume_size", (int)size);

        for ( uint8_t i = 0; i < 5; i++ )
        {
            if (*msg.cursor != i)
                return false;
            msg.advance_cursor(sizeof(*msg.cursor));
        }

        return true;
    }
    bool produce(Flow&, HAMessage& msg) override
    {
        if (!msg.fits(5))
            return false;

        for ( uint8_t i = 0; i < 5; i++ )
        {
            *msg.cursor = i;
            msg.advance_cursor(sizeof(*msg.cursor));
        }
        return true;
    }
    bool is_update_required(Flow*) override
    {
        return (bool)mock().getData("other_update_required").getIntValue();
    }
};

//-------------------------------------------------------------------------
// stubs, spies, etc.
//-------------------------------------------------------------------------

THREAD_LOCAL HAStats ha_stats = { };

Flow* Stream::get_flow(const FlowKey* flowkey)
{
    mock().actualCall("get_flow");
    FlowKey* s_flowkey = (FlowKey*)mock().getData("flowkey").getObjectPointer();
    if (s_flowkey)
        memcpy(s_flowkey, flowkey, sizeof(*s_flowkey));
    return (Flow*)mock().getData("flow").getObjectPointer();
}

void Stream::delete_flow(const FlowKey* flowkey)
{
    mock().actualCall("delete_flow");
    FlowKey* s_flowkey = (FlowKey*)mock().getData("flowkey").getObjectPointer();
    if (s_flowkey)
        memcpy(s_flowkey, flowkey, sizeof(*s_flowkey));
}

namespace snort
{
Flow::~Flow() = default;
void Flow::set_client_initiate(Packet*) { }
void Flow::set_direction(Packet*) { }

void packet_gettimeofday(struct timeval* tv)
{
    *tv = *(struct timeval*)mock().getData("packet_tv").getObjectPointer();
}
}

int SFDAQInstance::ioctl(DAQ_IoctlCmd, void*, size_t) { return DAQ_SUCCESS; }

FlowStash::~FlowStash() = default;

SideChannel* SideChannelManager::get_side_channel(SCPort)
{
    return (SideChannel*)mock().getData("s_side_channel").getObjectPointer();
}

Connector::Direction SideChannel::get_direction()
{ return Connector::CONN_DUPLEX; }

void SideChannel::set_default_port(SCPort) { }

void SideChannel::register_receive_handler(const SCProcessMsgFunc& handler)
{
    SCProcessMsgFunc* s_handler = (SCProcessMsgFunc*)mock().getData("s_handler").getObjectPointer();
    if (s_handler)
        *s_handler = handler;
}

void SideChannel::unregister_receive_handler() { }

bool SideChannel::discard_message(SCMessage*)
{ return true; }

static SCMsgHdr s_sc_header = { 0, 1, 0, 0 };
bool SideChannel::process(int)
{
    SCMessage* msg = (SCMessage*)mock().getData("message_content").getObjectPointer();
    SCProcessMsgFunc* s_handler = (SCProcessMsgFunc*)mock().getData("s_handler").getObjectPointer();
    if (s_handler && nullptr != *s_handler && msg && msg->content && msg->content_length != 0)
    {
        SCMessage s_rec_sc_message = {};
        s_rec_sc_message.content = msg->content;
        s_rec_sc_message.content_length = msg->content_length;
        s_rec_sc_message.hdr = &s_sc_header;
        s_rec_sc_message.sc = (SideChannel*)mock().getData("s_side_channel").getObjectPointer();;
        (*s_handler)(&s_rec_sc_message);
        return true;
    }
    else
        return false;
}

bool SideChannel::transmit_message(SCMessage* msg)
{
    mock().actualCall("transmit_message");
    mock().setDataObject("message", "SCMessage", msg);
    return true;
}

SCMessage* SideChannel::alloc_transmit_message(uint32_t len)
{
    if ( len > MSG_SIZE )
        return nullptr;

    SCMessage* message = (SCMessage*)mock().getData("message_content").getObjectPointer();
    message->content_length = len;
    return message;
}

//-------------------------------------------------------------------------
// tests
//-------------------------------------------------------------------------

TEST_GROUP(high_availability_manager_test)
{
    void setup() override
    {
        mock().setDataObject("s_handler", "SCProcessMsgFunc", nullptr);
    }

    void teardown() override
    {
        HighAvailabilityManager::term();
        mock().clear();
    }
};

TEST(high_availability_manager_test, init_term)
{
    HighAvailabilityConfig hac = { };
    HighAvailabilityManager::configure(&hac);
    HighAvailabilityManager::thread_init();
    CHECK(HighAvailabilityManager::active()==false);
    HighAvailabilityManager::thread_term();
    CHECK(HighAvailabilityManager::active()==false);
}

TEST(high_availability_manager_test, inst_init_term)
{
    HighAvailabilityConfig hac;
    hac.enabled = true;
    hac.daq_channel = false;
    hac.ports = new PortBitSet;
    hac.ports->set(1);
    hac.min_session_lifetime = { 1, 0 };
    hac.min_sync_interval = { 0, 500000 };

    HighAvailabilityManager::configure(&hac);
    HighAvailabilityManager::thread_init();
    CHECK(HighAvailabilityManager::active()==true);
    HighAvailabilityManager::thread_term();
    CHECK(HighAvailabilityManager::active()==false);
}

TEST_GROUP(flow_ha_state_test)
{
    struct timeval s_packet_time;

    void setup() override
    {
        s_packet_time = {};
        mock().setDataObject("packet_tv", "struct timeval", &s_packet_time);
        mock().setDataObject("s_side_channel", "SideChannel", nullptr);
        mock().setDataObject("s_handler", "SCProcessMsgFunc", nullptr);
    }

    void teardown() override
    {
        mock().clear();
    }
};

TEST(flow_ha_state_test, timing_test)
{
    struct timeval min_age = { 10, 0 };  // 10 second min age

    FlowHAState::config_timers(min_age, min_age); // one-time config

    s_packet_time.tv_sec = 1;
    FlowHAState state;
    state.set_next_update();       // set the time for next update
    s_packet_time.tv_sec = 2;       // advance the clock to 2 seconds
    CHECK(state.sync_interval_elapsed() == false);

    s_packet_time.tv_sec = 1;
    FlowHAState state2;
    CHECK(state2.sync_interval_elapsed() == false);
    s_packet_time.tv_sec = 22;      // advance the clock to 22 seconds
    state2.set_next_update();       // set the time for next update
    CHECK(state2.sync_interval_elapsed() == true);

}

TEST(flow_ha_state_test, pending_test)
{
    FlowHAState state;

    state.clear_pending(ALL_CLIENTS);
    CHECK(state.check_pending(ALL_CLIENTS) == false);
    state.set_pending(1);
    CHECK(state.check_pending(1) == true);
    state.clear_pending(1);
    CHECK(state.check_pending(1) == false);
    state.set_pending(1);
    CHECK(state.check_pending(1) == true);
    state.reset();
    CHECK(state.check_pending(1) == false);
}

TEST(flow_ha_state_test, state_test)
{
    FlowHAState state;

    CHECK(state.check_any(FlowHAState::MODIFIED|FlowHAState::STANDBY|
        FlowHAState::DELETED|FlowHAState::CRITICAL|FlowHAState::MAJOR) == false);
    CHECK(state.check_any(FlowHAState::NEW) == true);
    CHECK(state.check_any(FlowHAState::NEW_SESSION) == true);
    state.add(FlowHAState::MODIFIED);
    CHECK(state.check_any(FlowHAState::MODIFIED) == true);
    state.set(FlowHAState::MODIFIED|FlowHAState::MAJOR);
    CHECK(state.check_any(FlowHAState::MODIFIED) == true);
    state.reset();
    CHECK(state.check_any(FlowHAState::MODIFIED|FlowHAState::NEW|
        FlowHAState::STANDBY|FlowHAState::DELETED|FlowHAState::NEW_SESSION|
        FlowHAState::CRITICAL|FlowHAState::MAJOR) == false);
}

TEST_GROUP(high_availability_test)
{
    Flow s_flow;
    Active active;
    StreamHAClient* s_ha_client;
    FlowHAClient* s_other_ha_client;
    uint8_t s_message[MSG_SIZE];
    SCMessage s_sc_message;
    Packet s_pkt;
    struct timeval s_packet_time;
    HighAvailabilityConfig hac;
    FlowHAState* ha_state;
    FlowKey flow_key;
    SCProcessMsgFunc handler;
    SideChannel side_channel;
    FlowKey s_flow_key;

    void setup() override
    {
        s_packet_time = {};
        mock().setDataObject("packet_tv", "struct timeval", &s_packet_time);
        mock().setData("stream_update_required", false);
        mock().setData("other_update_required", false);
        mock().setDataObject("s_handler", "SCProcessMsgFunc", &handler);
        mock().setDataObject("s_side_channel", "SideChannel", &side_channel);
        mock().setDataObject("flowkey", "FlowKey", &s_flow_key);
        ha_state = new FlowHAState;
        s_flow.ha_state = ha_state;
        flow_key = {};
        s_flow.key = &flow_key;
        mock().setDataObject("flow", "Flow", &s_flow);
        active = {};
        memset(s_message, 0, sizeof(s_message));
        s_sc_message = {};
        s_sc_message.content = s_message;
        mock().setDataObject("message_content", "SCMessage", &s_sc_message);
        s_pkt.active = &active;

        memset(&ha_stats, 0, sizeof(ha_stats));

        hac.enabled = true;
        hac.daq_channel = false;
        hac.ports = new PortBitSet;
        hac.ports->set(1);
        hac.min_session_lifetime = { 1, 0 };
        hac.min_sync_interval = { 0, 500000 };

        HighAvailabilityManager::configure(&hac);
        HighAvailabilityManager::thread_init();
        s_ha_client = new StreamHAClient;
        s_other_ha_client = new OtherHAClient;
    }

    void teardown() override
    {
        delete s_other_ha_client;
        delete s_ha_client;
        delete ha_state;
        HighAvailabilityManager::thread_term();
        HighAvailabilityManager::term();
        mock().clear();
    }
};

TEST(high_availability_test, receive_deletion)
{
    s_sc_message.content = (uint8_t*) &s_delete_message;
    s_sc_message.content_length = sizeof(s_delete_message);
    mock().expectNCalls(1, "delete_flow");
    HighAvailabilityManager::process_receive();
    mock().checkExpectations();
    MEMCMP_EQUAL_TEXT(&s_test_key, &s_flow_key, sizeof(s_test_key), "flow key should be s_test_key");
}

TEST(high_availability_test, receive_update_stream_only)
{
    s_sc_message.content = (uint8_t*) &s_update_stream_message;
    s_sc_message.content_length = sizeof(s_update_stream_message);
    mock().expectNCalls(1, "get_flow");
    mock().expectNCalls(1, "consume");
    HighAvailabilityManager::process_receive();
    mock().checkExpectations();
    CHECK(mock().getData("stream_consume_size").getIntValue() == 10);
    MEMCMP_EQUAL_TEXT(&s_test_key, &s_flow_key, sizeof(s_test_key), "flow key should be s_test_key");
}

TEST(high_availability_test, transmit_deletion)
{
    mock().expectNCalls(1, "transmit_message");
    HighAvailabilityManager::process_deletion(s_flow);
}

TEST(high_availability_test, transmit_update_no_update)
{
    mock().setData("stream_update_required", (int)false);
    mock().setData("other_update_required", (int)false);
    mock().expectNCalls(1, "transmit_message");
    HighAvailabilityManager::process_update(&s_flow, &s_pkt);
}

TEST(high_availability_test, transmit_update_stream_only)
{
    mock().setData("stream_update_required", (int)true);
    mock().setData("other_update_required", (int)false);
    mock().expectNCalls(1, "transmit_message");
    HighAvailabilityManager::process_update(&s_flow, &s_pkt);
}

TEST(high_availability_test, transmit_update_both_update)
{
    mock().setData("stream_update_required", (int)true);
    mock().setData("other_update_required", (int)true);
    CHECK(s_other_ha_client->handle == 1);
    s_flow.ha_state->set_pending(s_other_ha_client->handle);
    mock().expectNCalls(1, "transmit_message");
    HighAvailabilityManager::process_update(&s_flow, &s_pkt);
}

TEST(high_availability_test, read_flow_key_error_v4)
{
    HAMessageHeader hdr = { 0, 0, 0, KEY_TYPE_IP4 };
    HAMessage msg((uint8_t*) &s_test_key, KEY_SIZE_IP4 / 2);
    FlowKey key{};

    CHECK(read_flow_key(msg, &hdr, key) == 0);
    CHECK(ha_stats.truncated_msgs == 1);
}

TEST(high_availability_test, read_flow_key_error_v6)
{
    HAMessageHeader hdr = { 0, 0, 0, KEY_TYPE_IP6 };
    HAMessage msg((uint8_t*) &s_test_key, KEY_SIZE_IP6 / 2);
    FlowKey key{};

    CHECK(read_flow_key(msg, &hdr, key) == 0);
    CHECK(ha_stats.truncated_msgs == 1);
}

TEST(high_availability_test, read_flow_key_error_unknown)
{
    HAMessageHeader hdr = { 0, 0, 0, 0x42 };
    HAMessage msg((uint8_t*) &s_test_key, sizeof(s_test_key));
    FlowKey key{};

    CHECK(read_flow_key(msg, &hdr, key) == 0);
    CHECK(ha_stats.unknown_key_type == 1);
}

TEST(high_availability_test, consume_error_truncated_client_hdr)
{
    HAClientHeader chdr = { 0, 0 };
    HAMessage msg((uint8_t*) &chdr, sizeof(chdr) / 2);
    FlowKey key{};

    mock().expectNCalls(1, "get_flow");
    consume_ha_update_message(msg, key, &s_pkt);
    CHECK(ha_stats.update_msgs_consumed == 0);
    CHECK(ha_stats.truncated_msgs == 1);
}

TEST(high_availability_test, consume_error_invalid_client_idx)
{
    HAClientHeader chdr = { 0x42, 0 };
    HAMessage msg((uint8_t*) &chdr, sizeof(chdr));
    FlowKey key{};

    mock().expectNCalls(1, "get_flow");
    consume_ha_update_message(msg, key, &s_pkt);
    CHECK(ha_stats.update_msgs_consumed == 0);
    CHECK(ha_stats.unknown_client_idx == 1);
}

TEST(high_availability_test, consume_error_truncated_client_msg)
{
    struct __attribute__((__packed__))
    {
        HAClientHeader chdr = { 0, 0x42 };
        uint8_t cmsg[0x42 / 2] = { };
    } input;
    HAMessage msg((uint8_t*) &input, sizeof(input));
    FlowKey key{};

    mock().expectNCalls(1, "get_flow");
    consume_ha_update_message(msg, key, &s_pkt);
    CHECK(ha_stats.update_msgs_consumed == 0);
    CHECK(ha_stats.truncated_msgs == 1);
}

TEST(high_availability_test, consume_error_client_consume)
{
    struct __attribute__((__packed__))
    {
        HAClientHeader chdr = { 0, 10 };
        uint8_t cmsg[0x42 / 2] = { };
    } input;
    HAMessage msg((uint8_t*) &input, sizeof(input));
    FlowKey key{};

    mock().expectNCalls(1, "get_flow");
    mock().expectNCalls(1, "consume");
    consume_ha_update_message(msg, key, &s_pkt);
    CHECK(ha_stats.update_msgs_consumed == 0);
    CHECK(ha_stats.client_consume_errors == 1);
}

TEST(high_availability_test, consume_error_key_mismatch)
{
    HAMessageHeader hdr[10] = { 0, HA_MESSAGE_VERSION, 0x32, KEY_TYPE_IP4 };
    HAMessage msg((uint8_t*) &hdr, sizeof(hdr));

    FlowKey packet_key{};
    FlowKey* key = &packet_key;
    CHECK(consume_ha_message(msg, key, &s_pkt) == nullptr);
    CHECK(ha_stats.key_mismatch == 1);
}

TEST(high_availability_test, consume_error_truncated_msg_hdr)
{
    HAMessageHeader hdr = { };
    HAMessage msg((uint8_t*) &hdr, sizeof(hdr) / 2);

    FlowKey* key = nullptr;
    CHECK(consume_ha_message(msg, key, &s_pkt) == nullptr);
    CHECK(ha_stats.truncated_msgs == 1);
}

TEST(high_availability_test, consume_error_version_mismatch)
{
    HAMessageHeader hdr = { 0, HA_MESSAGE_VERSION + 1, 0, 0 };
    HAMessage msg((uint8_t*) &hdr, sizeof(hdr));

    FlowKey* key = nullptr;
    CHECK(consume_ha_message(msg, key, &s_pkt) == nullptr);
    CHECK(ha_stats.msg_version_mismatch == 1);
}

TEST(high_availability_test, consume_error_length_mismatch)
{
    HAMessageHeader hdr = { 0, HA_MESSAGE_VERSION, 0x42, 0 };
    HAMessage msg((uint8_t*) &hdr, sizeof(hdr));

    FlowKey* key = nullptr;
    CHECK(consume_ha_message(msg, key, &s_pkt) == nullptr);
    CHECK(ha_stats.msg_length_mismatch == 1);
}

TEST(high_availability_test, produce_error_client_hdr_overflow)
{
    uint8_t buffer[sizeof(HAClientHeader) / 2];
    HAMessage msg(buffer, sizeof(buffer));
    write_update_msg_client(s_ha_client, s_flow, msg);
    CHECK(msg.cursor == msg.buffer);
}

TEST(high_availability_test, produce_error_client_produce)
{
    uint8_t buffer[sizeof(HAClientHeader)];
    HAMessage msg(buffer, sizeof(buffer));
    write_update_msg_client(s_ha_client, s_flow, msg);
    CHECK(msg.cursor == msg.buffer);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}


//--------------------------------------------------------------------------
// Copyright (C) 2015-2026 Cisco and/or its affiliates. All rights reserved.
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
        1,  // stream client index (alphabetical: "other"=0, "stream"=1)
        10
    },
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }
};

// The session HA client wire name is internal to ha.cc; tests reference it
// by literal here so they exercise the same registration path real callers do.
static constexpr const char* HA_CLIENT_NAME_STREAM = "stream";


class StreamHAClient : public FlowHAClient
{
public:
    StreamHAClient() : FlowHAClient(10, HA_CLIENT_NAME_STREAM) { }
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
    OtherHAClient() : FlowHAClient(5, "other") { }
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
FlowDataStore::~FlowDataStore() = default;

void packet_gettimeofday(struct timeval* tv)
{
    *tv = *(struct timeval*)mock().getData("packet_tv").getObjectPointer();
}
}

int SFDAQInstance::ioctl(DAQ_IoctlCmd, void*, size_t) { return DAQ_SUCCESS; }

SideChannel::SideChannel(ScMsgFormat)
{ }

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

bool SideChannel::discard_message(SCMessage*) const
{ return true; }

bool SideChannel::process(int)
{
    SCMessage* msg = (SCMessage*)mock().getData("message_content").getObjectPointer();
    SCProcessMsgFunc* s_handler = (SCProcessMsgFunc*)mock().getData("s_handler").getObjectPointer();
    if (s_handler && nullptr != *s_handler && msg && msg->content && msg->content_length != 0)
    {
        SCMessage s_rec_sc_message((SideChannel*)mock().getData("s_side_channel").getObjectPointer(),
            msg->connector, ConnectorMsg());
        s_rec_sc_message.content = msg->content;
        s_rec_sc_message.content_length = msg->content_length;
        (*s_handler)(&s_rec_sc_message);
        return true;
    }
    else
        return false;
}

bool SideChannel::transmit_message(SCMessage* msg) const
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
    SCMessage s_sc_message = SCMessage(nullptr, nullptr, ConnectorMsg());
    Packet s_pkt;
    struct timeval s_packet_time;
    HighAvailabilityConfig hac;
    FlowHAState* ha_state;
    FlowKey flow_key;
    SCProcessMsgFunc handler;
    SideChannel side_channel = SideChannel(ScMsgFormat::BINARY);
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
        HighAvailabilityManager::register_ha_client(HA_CLIENT_NAME_STREAM, nullptr, /*is_session=*/true);
        HighAvailabilityManager::register_ha_client("other");
        HighAvailabilityManager::register_ha_client("temp");
        HighAvailabilityManager::finalize_ha_client_indices();
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
        HAClientHeader chdr = { 1, 10 };  // stream client (index 1)
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

//-------------------------------------------------------------------------
// test client used only in ha_reload_test group (index 2 — unused by stream/other)
//-------------------------------------------------------------------------

class TempHAClient : public FlowHAClient
{
public:
    TempHAClient() : FlowHAClient(5, "temp") { }
    ~TempHAClient() override = default;
    bool consume(Flow*&, const FlowKey*, HAMessage&, uint8_t) override { return true; }
    bool produce(Flow&, HAMessage&) override { return true; }
};

//-------------------------------------------------------------------------
// tests for thread_reinit and FlowHAClient lifecycle
//-------------------------------------------------------------------------

TEST_GROUP(ha_reload_test)
{
    struct timeval s_packet_time;

    void setup() override
    {
        s_packet_time = {};
        mock().setDataObject("packet_tv", "struct timeval", &s_packet_time);
        memset(&ha_stats, 0, sizeof(ha_stats));
    }

    void teardown() override
    {
        HighAvailabilityManager::thread_term();
        HighAvailabilityManager::term();
        mock().clear();
    }
};

// thread_reinit() must recreate the HA object and leave ha active when still configured
TEST(ha_reload_test, thread_reinit_preserves_ha_when_configured)
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
    CHECK(HighAvailabilityManager::active() == true);

    HighAvailabilityManager::thread_reinit();

    CHECK(HighAvailabilityManager::active() == true);
}

// thread_reinit() after configure(nullptr) must leave ha=null
TEST(ha_reload_test, thread_reinit_disables_ha_when_unconfigured)
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
    CHECK(HighAvailabilityManager::active() == true);

    HighAvailabilityManager::configure(nullptr);
    HighAvailabilityManager::thread_reinit();

    CHECK(HighAvailabilityManager::active() == false);
}

// thread_reinit() disabled→enabled: ha starts null, configure enabled, reinit → ha active
TEST(ha_reload_test, thread_reinit_enables_ha_from_disabled)
{
    // Start with no config (ha stays null after thread_init)
    HighAvailabilityConfig hac_off = { };
    HighAvailabilityManager::configure(&hac_off);
    HighAvailabilityManager::thread_init();
    CHECK(HighAvailabilityManager::active() == false);

    HighAvailabilityConfig hac_on;
    hac_on.enabled = true;
    hac_on.daq_channel = false;
    hac_on.ports = new PortBitSet;
    hac_on.ports->set(1);
    hac_on.min_session_lifetime = { 1, 0 };
    hac_on.min_sync_interval = { 0, 500000 };

    HighAvailabilityManager::configure(&hac_on);
    HighAvailabilityManager::thread_reinit();

    CHECK(HighAvailabilityManager::active() == true);
    CHECK(HighAvailabilityManager::configured() == true);
}

// thread_reinit() enabled→enabled: new ha object created, active stays true
TEST(ha_reload_test, thread_reinit_enabled_to_enabled)
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
    CHECK(HighAvailabilityManager::active() == true);

    // Reconfigure with different port
    HighAvailabilityConfig hac2;
    hac2.enabled = true;
    hac2.daq_channel = false;
    hac2.ports = new PortBitSet;
    hac2.ports->set(2);
    hac2.min_session_lifetime = { 2, 0 };
    hac2.min_sync_interval = { 0, 500000 };

    HighAvailabilityManager::configure(&hac2);
    HighAvailabilityManager::thread_reinit();

    CHECK(HighAvailabilityManager::active() == true);
    CHECK(ha != nullptr);
}

// thread_reinit() disabled→disabled: ha stays null, no crash
TEST(ha_reload_test, thread_reinit_disabled_to_disabled)
{
    HighAvailabilityConfig hac_off = { };
    HighAvailabilityManager::configure(&hac_off);
    HighAvailabilityManager::thread_init();
    CHECK(HighAvailabilityManager::active() == false);

    HighAvailabilityManager::configure(nullptr);
    HighAvailabilityManager::thread_reinit();

    CHECK(HighAvailabilityManager::active() == false);
    CHECK(HighAvailabilityManager::configured() == false);
}

// thread_reinit() called twice in a row must not crash and preserve active state
TEST(ha_reload_test, thread_reinit_idempotent)
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

    HighAvailabilityManager::thread_reinit();
    CHECK(HighAvailabilityManager::active() == true);

    HighAvailabilityManager::thread_reinit();
    CHECK(HighAvailabilityManager::active() == true);
}

// Bug 5: configure(nullptr) must clear use_daq_channel so configured() returns false
TEST(ha_reload_test, reset_config_clears_daq_channel)
{
    HighAvailabilityConfig hac;
    hac.enabled = true;
    hac.daq_channel = true;
    // no ports — relies solely on daq_channel for configured()
    HighAvailabilityManager::configure(&hac);
    CHECK(HighAvailabilityManager::configured() == true);

    HighAvailabilityManager::configure(nullptr);
    CHECK(HighAvailabilityManager::configured() == false);
}

// HAReloadTuner::tswap() delegates entirely to thread_reinit();
// the HAReloadTuner class itself is tested at the integration level.
// Here we verify thread_reinit() leaves ha active after a same-config cycle.
TEST(ha_reload_test, thread_reinit_same_as_tswap_effect)
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
    CHECK(HighAvailabilityManager::active() == true);

    // Simulate what HAReloadTuner::tswap() does
    HighAvailabilityManager::thread_reinit();
    CHECK(HighAvailabilityManager::active() == true);
}

// Session client destructor nulls its client_map slot and session_client pointer
TEST(ha_reload_test, session_client_dtor_nulls_slot)
{
    HighAvailabilityConfig hac;
    hac.enabled = true;
    hac.daq_channel = false;
    hac.ports = new PortBitSet;
    hac.ports->set(1);
    hac.min_session_lifetime = { 1, 0 };
    hac.min_sync_interval = { 0, 500000 };

    HighAvailabilityManager::configure(&hac);
    HighAvailabilityManager::register_ha_client(HA_CLIENT_NAME_STREAM, nullptr, /*is_session=*/true);
    HighAvailabilityManager::finalize_ha_client_indices();
    HighAvailabilityManager::thread_init();

    uint8_t idx = HighAvailabilityManager::get_ha_client_index(HA_CLIENT_NAME_STREAM);
    StreamHAClient* sc = new StreamHAClient();
    CHECK(ha->client_map[idx] == sc);
    CHECK(ha->session_client == sc);
    delete sc;
    CHECK(ha->client_map[idx] == nullptr);
    CHECK(ha->session_client == nullptr);
}

// Client registration survives a reinit cycle: clients re-register at same indices
TEST(ha_reload_test, clients_reregister_after_reinit)
{
    HighAvailabilityConfig hac;
    hac.enabled = true;
    hac.daq_channel = false;
    hac.ports = new PortBitSet;
    hac.ports->set(1);
    hac.min_session_lifetime = { 1, 0 };
    hac.min_sync_interval = { 0, 500000 };

    HighAvailabilityManager::configure(&hac);
    HighAvailabilityManager::register_ha_client(HA_CLIENT_NAME_STREAM, nullptr, /*is_session=*/true);
    HighAvailabilityManager::finalize_ha_client_indices();
    HighAvailabilityManager::thread_init();

    uint8_t idx = HighAvailabilityManager::get_ha_client_index(HA_CLIENT_NAME_STREAM);
    StreamHAClient* sc = new StreamHAClient();
    CHECK(sc->index == idx);
    CHECK(ha->client_map[idx] == sc);
    delete sc;

    // Simulate reinit: destroy and recreate ha via public API
    HighAvailabilityManager::thread_reinit();
    CHECK(HighAvailabilityManager::active() == true);
    CHECK(ha->client_map[idx] == nullptr);

    // Re-register — must land at same index (name map survives reinit)
    StreamHAClient* sc2 = new StreamHAClient();
    CHECK(sc2->index == idx);
    CHECK(ha->client_map[idx] == sc2);
    delete sc2;
}

//-------------------------------------------------------------------------
// tests for Bug 18: canonical indices and FlowHAClient destructor
//-------------------------------------------------------------------------

// Sorted name-based indices must be applied correctly at construction time
TEST(high_availability_test, canonical_client_indices)
{
    // Alphabetical: "other"=0, "stream"=1, "temp"=2
    CHECK(s_ha_client->index == 1);
    CHECK(s_other_ha_client->index == 0);
    CHECK(ha->client_map[1] == s_ha_client);
    CHECK(ha->client_map[0] == s_other_ha_client);
    CHECK(ha->session_client == s_ha_client);
}

// FlowHAClient destructor must null out its client_map slot
TEST(high_availability_test, client_dtor_nulls_map)
{
    TempHAClient* temp = new TempHAClient();
    CHECK(ha->client_map[2] == temp);
    delete temp;
    CHECK(ha->client_map[2] == nullptr);
}

// Produce loops must skip null slots in a sparse client_map (Bug 18)
TEST(high_availability_test, produce_skips_null_client_map_slots)
{
    // Slots 0 and 1 are registered (stream + other). Slot 2 is empty.
    // Registering a client at slot 3 creates a gap at slot 2.
    TempHAClient* temp = new TempHAClient();   // index 2
    delete temp;                                // leaves slot 2 null, handle_counter unchanged
    // Produce should not crash even though slot 2 is null
    mock().setData("stream_update_required", (int)true);
    mock().expectNCalls(1, "transmit_message");
    HighAvailabilityManager::process_update(&s_flow, &s_pkt);
    mock().checkExpectations();
}

//-------------------------------------------------------------------------
// Coverage tests: FlowHAClient construction, configure(), multi-client
// produce/consume, null/empty guards
//-------------------------------------------------------------------------

// FlowHAClient ctor takes early return when ha is null — no registration, no crash
TEST(ha_reload_test, flow_ha_client_no_ha)
{
    // ha is null — setup does not call configure()/thread_init()
    // OtherHAClient ctor calls FlowHAClient(5, "other") which early-returns when ha==null
    OtherHAClient* oc = new OtherHAClient();
    CHECK(oc->handle == 0);  // not registered (would be 1 if registered)
    CHECK(oc->index == 0);   // not registered (would be 1 if registered)
    delete oc;               // ~FlowHAClient sees ha==null, no-op
}

// Sorted-name finalize is order-independent: registering the same set of names
// in different orders must produce the identical name->index map. This locks
// in the cross-peer wire-format contract.
TEST(ha_reload_test, finalize_sorted_deterministic)
{
    HighAvailabilityConfig hac;
    hac.enabled = true;
    hac.daq_channel = false;
    hac.ports = new PortBitSet;
    hac.ports->set(1);
    hac.min_session_lifetime = { 1, 0 };
    hac.min_sync_interval = { 0, 500000 };

    // Order A: stream, alpha, beta
    HighAvailabilityManager::configure(&hac);
    HighAvailabilityManager::register_ha_client(HA_CLIENT_NAME_STREAM, nullptr, /*is_session=*/true);
    HighAvailabilityManager::register_ha_client("alpha");
    HighAvailabilityManager::register_ha_client("beta");
    HighAvailabilityManager::finalize_ha_client_indices();
    uint8_t a_alpha  = HighAvailabilityManager::get_ha_client_index("alpha");
    uint8_t a_beta   = HighAvailabilityManager::get_ha_client_index("beta");
    uint8_t a_stream = HighAvailabilityManager::get_ha_client_index(HA_CLIENT_NAME_STREAM);

    // Order B: beta, stream, alpha (registry is cleared by configure())
    HighAvailabilityConfig hac2;
    hac2.enabled = true;
    hac2.daq_channel = false;
    hac2.ports = new PortBitSet;
    hac2.ports->set(1);
    hac2.min_session_lifetime = { 1, 0 };
    hac2.min_sync_interval = { 0, 500000 };
    HighAvailabilityManager::configure(&hac2);
    HighAvailabilityManager::register_ha_client("beta");
    HighAvailabilityManager::register_ha_client(HA_CLIENT_NAME_STREAM, nullptr, /*is_session=*/true);
    HighAvailabilityManager::register_ha_client("alpha");
    HighAvailabilityManager::finalize_ha_client_indices();
    uint8_t b_alpha  = HighAvailabilityManager::get_ha_client_index("alpha");
    uint8_t b_beta   = HighAvailabilityManager::get_ha_client_index("beta");
    uint8_t b_stream = HighAvailabilityManager::get_ha_client_index(HA_CLIENT_NAME_STREAM);

    CHECK_EQUAL(a_alpha,  b_alpha);
    CHECK_EQUAL(a_beta,   b_beta);
    CHECK_EQUAL(a_stream, b_stream);

    // Sanity: alphabetical order: alpha=0, beta=1, stream=2
    CHECK_EQUAL(0, a_alpha);
    CHECK_EQUAL(1, a_beta);
    CHECK_EQUAL(2, a_stream);
}

// FlowHAClient ctor with an unregistered name must not crash and must not
// install the client into the client_map.
TEST(ha_reload_test, flow_ha_client_unregistered_name)
{
    HighAvailabilityConfig hac;
    hac.enabled = true;
    hac.daq_channel = false;
    hac.ports = new PortBitSet;
    hac.ports->set(1);
    hac.min_session_lifetime = { 1, 0 };
    hac.min_sync_interval = { 0, 500000 };

    HighAvailabilityManager::configure(&hac);
    HighAvailabilityManager::register_ha_client(HA_CLIENT_NAME_STREAM, nullptr, /*is_session=*/true);
    HighAvailabilityManager::finalize_ha_client_indices();
    HighAvailabilityManager::thread_init();

    // "other" was never registered — ctor should ErrorMessage and leave handle/index at 0.
    OtherHAClient* oc = new OtherHAClient();
    CHECK(oc->handle == 0);
    CHECK(oc->index == 0);
    // No slot in client_map should now point to oc.
    for (uint8_t i = 0; i < MAX_CLIENTS; i++)
        CHECK(ha->client_map[i] != oc);
    delete oc;
}

// Bug 11: configure() must delete old ports when reconfigured with null ports
TEST(ha_reload_test, configure_removes_ports)
{
    HighAvailabilityConfig hac;
    hac.enabled = true;
    hac.daq_channel = false;
    hac.ports = new PortBitSet;
    hac.ports->set(1);
    hac.min_session_lifetime = { 1, 0 };
    hac.min_sync_interval = { 0, 500000 };

    HighAvailabilityManager::configure(&hac);
    CHECK(HighAvailabilityManager::configured() == true);

    // Reconfigure with null ports, no daq_channel — old ports must be freed
    HighAvailabilityConfig hac2 = { };
    HighAvailabilityManager::configure(&hac2);
    CHECK(HighAvailabilityManager::configured() == false);
}

// process_update() produces when only a non-session client has pending
// (stream not required, NEW cleared)
TEST(high_availability_test, process_update_other_client_produce)
{
    mock().setData("stream_update_required", (int)false);
    // Clear NEW so the guard doesn't return early; set pending on other client
    s_flow.ha_state->set(FlowHAState::MODIFIED);
    s_flow.ha_state->set_pending(s_other_ha_client->handle);

    mock().expectNCalls(1, "transmit_message");
    HighAvailabilityManager::process_update(&s_flow, &s_pkt);
    mock().checkExpectations();
}

// Both session and non-session clients' consume() are called for a multi-client message
TEST(high_availability_test, receive_update_both_clients)
{
    struct __attribute__((__packed__)) {
        HAMessageHeader mhdr;
        FlowKey key;
        HAClientHeader schdr;
        uint8_t scmsg[10];
        HAClientHeader ochdr;
        uint8_t ocmsg[5];
    } msg_data = {
        { HA_UPDATE_EVENT, HA_MESSAGE_VERSION, 0, KEY_TYPE_IP6 },
        s_test_key,
        { 1, 10 },  // stream client (index 1)
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 },
        { 0, 5 },   // other client (index 0)
        { 0, 1, 2, 3, 4 }
    };
    msg_data.mhdr.total_length = sizeof(msg_data);

    s_sc_message.content = (uint8_t*)&msg_data;
    s_sc_message.content_length = sizeof(msg_data);

    mock().expectNCalls(1, "get_flow");
    mock().expectNCalls(1, "consume");
    mock().expectNCalls(1, "other_consume");
    HighAvailabilityManager::process_receive();
    mock().checkExpectations();
    CHECK(mock().getData("stream_consume_size").getIntValue() == 10);
    CHECK(mock().getData("other_consume_size").getIntValue() == 5);
}

// write_update_msg_client correctly produces header + content for a non-session client
TEST(high_availability_test, other_ha_client_is_update_required)
{
    uint8_t buffer[MSG_SIZE];
    HAMessage msg(buffer, sizeof(buffer));
    write_update_msg_client(s_other_ha_client, s_flow, msg);

    // Verify client header was written correctly
    HAClientHeader* hdr = reinterpret_cast<HAClientHeader*>(buffer);
    CHECK(hdr->client == 0);   // other client index (alphabetical: "other"=0)
    CHECK(hdr->length == 5);   // 5 bytes of content

    // Verify content: OtherHAClient::produce writes bytes 0-4
    uint8_t* content = buffer + sizeof(HAClientHeader);
    for (uint8_t i = 0; i < 5; i++)
        CHECK(content[i] == i);
}

// process_receive with a 0-length message — handler not invoked, no crash
TEST(high_availability_test, process_receive_empty_message)
{
    s_sc_message.content_length = 0;
    // SideChannel::process() stub returns false when content_length==0
    // No handler invoked, no consume, no crash
    HighAvailabilityManager::process_receive();
    CHECK(ha_stats.msgs_recv == 0);
}

// process_update with null flow takes early return — no crash, no transmit
TEST(high_availability_test, process_update_null_flow)
{
    mock().setData("stream_update_required", (int)true);
    HighAvailabilityManager::process_update(nullptr, &s_pkt);
    CHECK(ha_stats.daq_stores == 0);
}

// consume_ha_message with a truncated key discards the message safely
TEST(high_availability_test, consume_message_bad_key)
{
    struct __attribute__((__packed__)) {
        HAMessageHeader mhdr;
        uint8_t partial_key[2];
    } msg_data = {
        { HA_UPDATE_EVENT, HA_MESSAGE_VERSION, 0, KEY_TYPE_IP6 },
        { 0xAA, 0xBB }
    };
    msg_data.mhdr.total_length = sizeof(msg_data);

    HAMessage msg((uint8_t*)&msg_data, sizeof(msg_data));
    FlowKey* key = nullptr;
    CHECK(consume_ha_message(msg, key, nullptr) == nullptr);
    CHECK(ha_stats.truncated_msgs == 1);
}

//-------------------------------------------------------------------------
// Review-driven tests: registry edge cases and null ha_state guards
//-------------------------------------------------------------------------

// register_ha_client after finalize_ha_client_indices() must be rejected so
// the sorted index space cannot shift out from under packet threads.
TEST(ha_reload_test, register_after_finalize_rejected)
{
    HighAvailabilityConfig hac;
    hac.enabled = true;
    hac.daq_channel = false;
    hac.ports = new PortBitSet;
    hac.ports->set(1);
    hac.min_session_lifetime = { 1, 0 };
    hac.min_sync_interval = { 0, 500000 };

    HighAvailabilityManager::configure(&hac);
    HighAvailabilityManager::register_ha_client(HA_CLIENT_NAME_STREAM, nullptr, /*is_session=*/true);
    HighAvailabilityManager::register_ha_client("alpha");
    HighAvailabilityManager::finalize_ha_client_indices();

    const size_t before = ha_client_name_map.size();
    HighAvailabilityManager::register_ha_client("late");
    CHECK_EQUAL(before, ha_client_name_map.size());
    // "late" must not have been inserted
    CHECK(ha_client_name_map.find("late") == ha_client_name_map.end());
}

// finalize_ha_client_indices() with no session client registered must refuse
// to set ha_indices_finalized; later FlowHAClient ctors will then early-return
// instead of being installed at colliding indices.
TEST(ha_reload_test, finalize_without_session_client_rejected)
{
    HighAvailabilityConfig hac;
    hac.enabled = true;
    hac.daq_channel = false;
    hac.ports = new PortBitSet;
    hac.ports->set(1);
    hac.min_session_lifetime = { 1, 0 };
    hac.min_sync_interval = { 0, 500000 };

    HighAvailabilityManager::configure(&hac);
    // Intentionally omit HA_CLIENT_NAME_STREAM
    HighAvailabilityManager::register_ha_client("alpha");
    HighAvailabilityManager::register_ha_client("beta");
    HighAvailabilityManager::finalize_ha_client_indices();

    CHECK(ha_indices_finalized == false);
}

// finalize_ha_client_indices() with more than MAX_CLIENTS (16) total clients
// must reject (the FlowHAClientHandle pending mask is 16 bits wide).
TEST(ha_reload_test, finalize_too_many_non_session_clients_rejected)
{
    HighAvailabilityConfig hac;
    hac.enabled = true;
    hac.daq_channel = false;
    hac.ports = new PortBitSet;
    hac.ports->set(1);
    hac.min_session_lifetime = { 1, 0 };
    hac.min_sync_interval = { 0, 500000 };

    HighAvailabilityManager::configure(&hac);
    HighAvailabilityManager::register_ha_client(HA_CLIENT_NAME_STREAM, nullptr, /*is_session=*/true);
    // stream + 17 others = 18 total, over MAX_CLIENTS=16
    char name[8];
    for (int i = 0; i < 17; i++)
    {
        snprintf(name, sizeof(name), "c%02d", i);
        HighAvailabilityManager::register_ha_client(name);
    }
    HighAvailabilityManager::finalize_ha_client_indices();

    CHECK(ha_indices_finalized == false);
}

// process_update() must early-return when flow->ha_state is null (a flow
// created before HA was enabled by reload). No transmit, no crash.
TEST(ha_reload_test, process_update_null_ha_state)
{
    HighAvailabilityConfig hac;
    hac.enabled = true;
    hac.daq_channel = false;
    hac.ports = new PortBitSet;
    hac.ports->set(1);
    hac.min_session_lifetime = { 1, 0 };
    hac.min_sync_interval = { 0, 500000 };

    HighAvailabilityManager::configure(&hac);
    HighAvailabilityManager::register_ha_client(HA_CLIENT_NAME_STREAM, nullptr, /*is_session=*/true);
    HighAvailabilityManager::finalize_ha_client_indices();
    HighAvailabilityManager::thread_init();

    Flow flow;
    FlowKey key = {};
    flow.key = &key;
    flow.ha_state = nullptr;  // pre-existing-flow scenario
    Active active{};
    Packet pkt;
    pkt.active = &active;

    // No transmit_message expectation set; mock would fail if one were issued
    HighAvailabilityManager::process_update(&flow, &pkt);
    mock().checkExpectations();
}

// process_deletion() must early-return when flow.ha_state is null.
TEST(ha_reload_test, process_deletion_null_ha_state)
{
    HighAvailabilityConfig hac;
    hac.enabled = true;
    hac.daq_channel = false;
    hac.ports = new PortBitSet;
    hac.ports->set(1);
    hac.min_session_lifetime = { 1, 0 };
    hac.min_sync_interval = { 0, 500000 };

    HighAvailabilityManager::configure(&hac);
    HighAvailabilityManager::register_ha_client(HA_CLIENT_NAME_STREAM, nullptr, /*is_session=*/true);
    HighAvailabilityManager::finalize_ha_client_indices();
    HighAvailabilityManager::thread_init();

    Flow flow;
    FlowKey key = {};
    flow.key = &key;
    flow.ha_state = nullptr;

    HighAvailabilityManager::process_deletion(flow);
    mock().checkExpectations();
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}


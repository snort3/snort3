//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// ha_test.cc author Ed Borgoyn <eborgoyn@cisco.com>
// unit test main

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "flow/ha.h"

#include "flow/flow.h"
#include "flow/flow_key.h"
#include "main/snort_debug.h"
#include "stream/stream.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

#define MSG_SIZE 100
#define TEST_KEY 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47

class StreamHAClient;

static const uint8_t s_test_key[] =
{
TEST_KEY
};

static const uint8_t s_delete_message[] =
{
    0x01,
    0x03,
    0x00,
    0x00,
    0x01,
TEST_KEY
};

static const uint8_t s_update_stream_message[] =
{
    0x02,
    0x03,
    0x00,
    0x00,
    0x01,
TEST_KEY,
    0x00,
    10,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9
};


static struct timeval s_packet_time = { 0, 0 };
static uint8_t s_message[MSG_SIZE];
static SideChannel s_side_channel;
static SCMessage s_sc_message;
static SCMessage s_rec_sc_message;
static bool s_stream_consume_called = false;
static bool s_other_consume_called = false;
static bool s_get_session_called = false;
static bool s_delete_session_called = false;
static bool s_transmit_message_called = false;
static bool s_stream_update_required = false;
static bool s_other_update_required = false;
static uint8_t* s_message_content = nullptr;
static uint8_t s_message_length = 0;
static Flow s_flow;
static FlowKey s_flowkey;
static DAQ_PktHdr_t s_pkthdr;
static StreamHAClient* s_ha_client;
static FlowHAClient* s_other_ha_client;
static std::function<void (SCMessage*)> s_handler = nullptr;
static SCMsgHdr s_sc_header = { 0, 1, 0, 0, };

class StreamHAClient : public FlowHAClient
{
public:
    StreamHAClient() : FlowHAClient(10, true) { }
    ~StreamHAClient() override = default;
    bool consume(Flow*&, FlowKey*, HAMessage*) override
    {
        s_stream_consume_called = true;
        return true;
    }
    bool produce(Flow*, HAMessage* msg) override
    {
        for ( uint8_t i=0; i<10; i++ )
            *(msg->cursor)++ = i;
        return true;
    }
    uint8_t get_message_size() { return 10; }
    bool is_update_required(Flow*) override { return s_stream_update_required; }
    bool fit(HAMessage*,uint8_t) { return true; }
    bool place(HAMessage*,uint8_t*,uint8_t) { return true; }

private:
};

class OtherHAClient : public FlowHAClient
{
public:
    OtherHAClient() : FlowHAClient(5, false) { }
    ~OtherHAClient() override = default;
    bool consume(Flow*&, HAMessage*)
    {
        s_other_consume_called = true;
        return true;
    }
    bool produce(Flow*, HAMessage* msg) override
    {
        for ( uint8_t i=0; i<5; i++ )
            *(msg->cursor)++ = i;
        return true;
    }
    uint8_t get_message_size() { return 5; }
    bool is_update_required(Flow*) override { return s_other_update_required; }
    bool fit(HAMessage*,uint8_t) { return true; }
    bool place(HAMessage*,uint8_t*,uint8_t) { return true; }

private:
};

Flow*  Stream::get_flow(const FlowKey* flowkey)
{
    s_flowkey = *flowkey;
    s_get_session_called = true;
    return &s_flow;
}

void Stream::delete_flow(const FlowKey* flowkey)
{
    s_flowkey = *flowkey;
    s_delete_session_called = true;
}

namespace snort
{
void ErrorMessage(const char*,...) { }
void LogMessage(const char*,...) { }
}

void packet_gettimeofday(struct timeval* tv)
{ *tv = s_packet_time; }

Flow::Flow() { ha_state = new FlowHAState; key = new FlowKey; }

SideChannel* SideChannelManager::get_side_channel(SCPort)
{ return &s_side_channel; }

SideChannel::SideChannel() = default;

Connector::Direction SideChannel::get_direction()
{ return Connector::CONN_DUPLEX; }

void SideChannel::set_default_port(SCPort) { }

void SideChannel::register_receive_handler(const std::function<void (SCMessage*)>& handler)
{
    s_handler = handler;
}

void SideChannel::unregister_receive_handler() { }

bool SideChannel::discard_message(SCMessage*)
{ return true; }

bool SideChannel::process(int)
{
    if ( s_handler && s_message_content && (s_message_length != 0))
    {
        s_rec_sc_message.content = s_message_content;
        s_rec_sc_message.content_length = s_message_length;
        s_rec_sc_message.hdr = &s_sc_header;
        s_rec_sc_message.sc = &s_side_channel;
        s_handler(&s_rec_sc_message);
        return true;
    }
    else
        return false;
}

bool SideChannel::transmit_message(SCMessage* msg)
{
    s_transmit_message_called = true;
    s_message_content = msg->content;
    s_message_length = msg->content_length;
    return true; }

SCMessage* SideChannel::alloc_transmit_message(uint32_t len)
{
    if ( len > MSG_SIZE )
        return nullptr;

    s_sc_message.content = s_message;
    s_sc_message.content_length = len;
    return &s_sc_message;
}

TEST_GROUP(high_availability_manager_test)
{
    void setup() override
    {
        MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    }

    void teardown() override
    {
        MemoryLeakWarningPlugin::turnOnNewDeleteOverloads();
    }
};

TEST(high_availability_manager_test, init_term)
{
    HighAvailabilityManager::pre_config_init();
    HighAvailabilityManager::thread_init();
    CHECK(HighAvailabilityManager::active()==false);
    HighAvailabilityManager::thread_term();
    CHECK(HighAvailabilityManager::active()==false);
}

TEST(high_availability_manager_test, inst_init_term)
{
    HighAvailabilityManager::pre_config_init();
    PortBitSet port_set;
    port_set.set(1);
    struct timeval age = { 1, 0 };
    struct timeval interval = { 0, 500000 };
    HighAvailabilityManager::instantiate(&port_set, false, &age, &interval);
    HighAvailabilityManager::thread_init();
    s_ha_client = new StreamHAClient;
    CHECK(HighAvailabilityManager::active()==true);
    delete s_ha_client;
    HighAvailabilityManager::thread_term();
    CHECK(HighAvailabilityManager::active()==false);
}

TEST_GROUP(flow_ha_state_test)
{
    void setup() override { }
    void teardown() override { }
};

TEST(flow_ha_state_test, timing_test)
{
    struct timeval min_age = { 10, 0 };  // 10 second min age

    FlowHAState::config_timers(min_age, min_age); // one-time config

    s_packet_time.tv_sec = 1;
    FlowHAState* state = new FlowHAState;
    state->set_next_update();       // set the time for next update
    s_packet_time.tv_sec = 2;       // advance the clock to 2 seconds
    CHECK(state->sync_interval_elapsed() == false);
    delete state;

    s_packet_time.tv_sec = 1;
    state = new FlowHAState;
    CHECK(state->sync_interval_elapsed() == false);
    s_packet_time.tv_sec = 22;      // advance the clock to 22 seconds
    state->set_next_update();       // set the time for next update
    CHECK(state->sync_interval_elapsed() == true);
    delete state;

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
    void setup() override
    {
        MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
        HighAvailabilityManager::pre_config_init();
        PortBitSet port_set;
        port_set.set(1);
        struct timeval age = { 1, 0 };
        struct timeval interval = { 0, 500000 };
        HighAvailabilityManager::instantiate(&port_set, false, &age, &interval);
        HighAvailabilityManager::thread_init();
        s_ha_client = new StreamHAClient;
        s_other_ha_client = new OtherHAClient;
    }

    void teardown() override
    {
        delete s_other_ha_client;
        delete s_ha_client;
        HighAvailabilityManager::thread_term();
        MemoryLeakWarningPlugin::turnOnNewDeleteOverloads();
    }
};

TEST(high_availability_test, receive_deletion)
{
    s_delete_session_called = false;
    s_message_content = (uint8_t*)s_delete_message;
    s_message_length = sizeof(s_delete_message);
    HighAvailabilityManager::process_receive();
    CHECK(s_delete_session_called == true);
    CHECK(memcmp((const void*)&s_flowkey, (const void*)&s_test_key, sizeof(s_test_key)) == 0);
}

TEST(high_availability_test, receive_update_stream_only)
{
    s_stream_consume_called = false;
    s_message_content = (uint8_t*)s_update_stream_message;
    s_message_length = sizeof(s_update_stream_message);
    HighAvailabilityManager::process_receive();
    CHECK(s_stream_consume_called == true);
    CHECK(memcmp((const void*)&s_flowkey, (const void*)&s_test_key, sizeof(s_test_key)) == 0);
}

TEST(high_availability_test, transmit_deletion)
{
    s_transmit_message_called = false;
    HighAvailabilityManager::process_deletion(&s_flow);
    CHECK(s_transmit_message_called == true);
}

TEST(high_availability_test, transmit_update_no_update)
{
    s_transmit_message_called = false;
    s_stream_update_required = false;
    s_other_update_required = false;
    HighAvailabilityManager::process_update(&s_flow, &s_pkthdr);
    CHECK(s_transmit_message_called == false);
}

TEST(high_availability_test, transmit_update_stream_only)
{
    s_transmit_message_called = false;
    s_stream_update_required = true;
    s_other_update_required = false;
    HighAvailabilityManager::process_update(&s_flow, &s_pkthdr);
    CHECK(s_transmit_message_called == true);
}

TEST(high_availability_test, transmit_update_both_update)
{
    s_transmit_message_called = false;
    s_stream_update_required = true;
    s_other_update_required = true;
    CHECK(s_other_ha_client->handle == 1);
    s_flow.ha_state->set_pending(s_other_ha_client->handle);
    HighAvailabilityManager::process_update(&s_flow, &s_pkthdr);
    CHECK(s_transmit_message_called == true);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}


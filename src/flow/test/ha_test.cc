//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

#include "flow/ha.h"

#include "flow/flow.h"
#include "main/snort_debug.h"
#include "stream/stream_api.h"

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


static struct timeval s_time = { 0, 0 };
static uint8_t s_message[MSG_SIZE];
static SideChannel s_side_channel;
static SCMessage s_sc_message;
static SCMessage s_rec_sc_message;
static bool s_get_session_called = false;
static bool s_delete_session_called = false;
static bool s_transmit_message_called = false;
static uint8_t* s_message_content = nullptr;
static uint8_t s_message_length = 0;
static Flow s_flow;
static FlowKey s_flowkey;
static DAQ_PktHdr_t s_pkthdr;
static StreamHAClient* ha_client;
static std::function<void (SCMessage*)> s_handler = nullptr;
static SCMsgHdr s_sc_header = { 0, 1, 0, 0, };

class StreamHAClient : public FlowHAClient
{
public:
    StreamHAClient() : FlowHAClient(10, true) { }
    ~StreamHAClient() { }
    bool consume(Flow*, HAMessage*) { return true; }
    bool produce(Flow*, HAMessage* msg)
    {
        for ( uint8_t i=0; i<10; i++ )
            *(msg->cursor)++ = i;
        return true;
    }
    uint8_t get_message_size() { return 10; }

private:
};

Flow*  Stream::get_session(const FlowKey* flowkey)
{
    s_flowkey = *flowkey;
    s_get_session_called = true;
    return &s_flow;
}

void Stream::delete_session(const FlowKey* flowkey)
{
    s_flowkey = *flowkey;
    s_delete_session_called = true;
}

void ErrorMessage(const char*,...) { }
void LogMessage(const char*,...) { }

void Debug::print(const char*, int, uint64_t, const char*, ...) { }

void packet_gettimeofday(struct timeval* tv)
{ *tv = s_time; }

Flow::Flow() { ha_state = new FlowHAState; key = new FlowKey; }
Flow::~Flow() { }

SideChannel* SideChannelManager::get_side_channel(SCPort)
{ return &s_side_channel; }

SideChannel::~SideChannel() { }

SideChannel::SideChannel() { }

Connector::Direction SideChannel::get_direction()
{ return Connector::CONN_DUPLEX; }

void SideChannel::set_default_port(SCPort) { }

void SideChannel::register_receive_handler(std::function<void (SCMessage*)> handler)
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
    void setup()
    {
        MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    }

    void teardown()
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
    HighAvailabilityManager::instantiate(&port_set, false);
    HighAvailabilityManager::thread_init();
    ha_client = new StreamHAClient;
    CHECK(HighAvailabilityManager::active()==true);
    delete ha_client;
    HighAvailabilityManager::thread_term();
    CHECK(HighAvailabilityManager::active()==false);
}

TEST_GROUP(high_availability_test)
{
    void setup()
    {
        MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
        HighAvailabilityManager::pre_config_init();
        PortBitSet port_set;
        port_set.set(1);
        HighAvailabilityManager::instantiate(&port_set, false);
        HighAvailabilityManager::thread_init();
        ha_client = new StreamHAClient;
    }

    void teardown()
    {
        delete ha_client;
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

TEST(high_availability_test, transmit_deletion)
{
    s_transmit_message_called = false;
    HighAvailabilityManager::process_deletion(&s_flow);
    CHECK(s_transmit_message_called == true);
}

TEST(high_availability_test, transmit_update_stream_only)
{
    s_transmit_message_called = false;
    HighAvailabilityManager::process_update(&s_flow, &s_pkthdr);
    CHECK(s_transmit_message_called == true);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}


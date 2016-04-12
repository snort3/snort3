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

#include "../ha.cc"

#define MSG_SIZE 100

class StreamHAClient : public FlowHAClient
{
public:
    StreamHAClient() : FlowHAClient(true) { }
    ~StreamHAClient() { }
    void consume(Flow*, HAMessage*) { }
    void produce(Flow*, HAMessage* msg)
    { for ( uint8_t i=0; i<10; i++,*(msg->cursor)++=i); }
    size_t get_message_size() { return sizeof(10); }

private:
};

static struct timeval s_time = { 0, 0 };
static uint8_t message[MSG_SIZE];
static SideChannel s_side_channel;
static SCMessage s_sc_message;
static Flow s_flow;
static DAQ_PktHdr_t s_pkthdr;

void LogMessage(const char* format,...)
{ UNUSED(format); }

void Debug::print(const char* file, int line, uint64_t dbg, const char* fmt, ...)
{ UNUSED(file);  UNUSED(line); UNUSED(dbg); UNUSED(fmt); }

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

void SideChannel::register_receive_handler(std::function<void (SCMessage*)>) { }

void SideChannel::unregister_receive_handler() { }

bool SideChannel::discard_message(SCMessage*)
{ return true; }

bool SideChannel::process(int)
{ return false; }

bool SideChannel::transmit_message(SCMessage*)
{ return true; }

SCMessage* SideChannel::alloc_transmit_message(uint32_t len)
{
    if ( len > MSG_SIZE )
        return nullptr;

    s_sc_message.content = message;
    s_sc_message.content_length = len;
    return &s_sc_message;
}

TEST_GROUP(high_availability_manager_test)
{
    StreamHAClient* ha_client;
    void setup()
    {
        ha_client = new StreamHAClient;
    }

    void teardown()
    {
        delete ha_client;
    }
};

TEST(high_availability_manager_test, pre_config_init)
{
    HighAvailabilityManager::pre_config_init();
}

TEST(high_availability_manager_test, init_term)
{
    HighAvailabilityManager::pre_config_init();
    HighAvailabilityManager::thread_init();
    CHECK(ha == nullptr);
    CHECK(HighAvailabilityManager::active()==false);
    HighAvailabilityManager::thread_term();
    CHECK(ha == nullptr);
}

TEST(high_availability_manager_test, inst_init_term)
{
    HighAvailabilityManager::pre_config_init();
    PortBitSet port_set;
    port_set.set(1);
    HighAvailabilityManager::instantiate(&port_set, false);
    HighAvailabilityManager::thread_init();
    CHECK(ha != nullptr);
    CHECK(HighAvailabilityManager::active()==true);
    HighAvailabilityManager::thread_term();
    CHECK(ha == nullptr);
}

TEST(high_availability_manager_test, inst_init_deletion_term)
{
    HighAvailabilityManager::pre_config_init();
    PortBitSet port_set;
    port_set.set(1);
    HighAvailabilityManager::instantiate(&port_set, false);
    HighAvailabilityManager::thread_init();
    CHECK(ha != nullptr);
    HighAvailabilityManager::process_receive();
    HighAvailabilityManager::process_deletion(&s_flow);
    HighAvailabilityManager::thread_term();
    CHECK(ha == nullptr);
}

TEST(high_availability_manager_test, inst_init_update_term)
{
    HighAvailabilityManager::pre_config_init();
    PortBitSet port_set;
    port_set.set(1);
    HighAvailabilityManager::instantiate(&port_set, false);
    HighAvailabilityManager::thread_init();
    CHECK(ha != nullptr);
    HighAvailabilityManager::process_update(&s_flow, &s_pkthdr);
    HighAvailabilityManager::process_receive();
    HighAvailabilityManager::thread_term();
    CHECK(ha == nullptr);
}

TEST_GROUP(high_availability_test)
{
    void setup()
    {
        HighAvailabilityManager::pre_config_init();
        PortBitSet port_set;
        port_set.set(1);
        HighAvailabilityManager::instantiate(&port_set, false);
        HighAvailabilityManager::thread_init();
    }

    void teardown()
    {
        HighAvailabilityManager::thread_term();
    }
};

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}


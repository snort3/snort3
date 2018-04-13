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

// tcp_normalizer_test.cc author Davis McPherson <davmcphe@cisco.com>
// unit test main

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "stream/tcp/tcp_module.h"
#include "stream/tcp/tcp_normalizers.h"
#include "protocols/tcp_options.h"
#include "stream/tcp/tcp_defs.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace snort;

NormMode mockNormMode = NORM_MODE_ON;
bool norm_enabled = true;
THREAD_LOCAL TcpStats tcpStats;
THREAD_LOCAL SnortConfig* snort_conf = nullptr;

Flow::Flow( void ) {}

class FlowMock : public Flow
{
public:

};

TcpSession::TcpSession( Flow* ) : Session( flow ) { }
TcpSession::~TcpSession( void ) { }
bool TcpSession::setup(Packet*){ return true; }
void TcpSession::update_direction(char, SfIp const*, unsigned short){ }
int TcpSession::process(Packet*){ return 0; }
void TcpSession::restart(Packet*){ }
void TcpSession::precheck(Packet*){ }
void TcpSession::clear(){ }
void TcpSession::cleanup(Packet* = nullptr){ }
bool TcpSession::add_alert(Packet*, unsigned int, unsigned int){ return true; }
bool TcpSession::check_alerted(Packet*, unsigned int, unsigned int){ return true; }
int TcpSession::update_alert(Packet*, unsigned int, unsigned int, unsigned int, unsigned int){ return 0; }
void TcpSession::flush_client(Packet*){ }
void TcpSession::flush_server(Packet*){ }
void TcpSession::flush_talker(Packet*){ }
void TcpSession::flush_listener(Packet*){ }
void TcpSession::set_splitter(bool, StreamSplitter*){ }
StreamSplitter* TcpSession::get_splitter(bool){ return nullptr; }
void TcpSession::set_extra_data(Packet*, unsigned int){ }
bool TcpSession::is_sequenced(unsigned char){ return true; }
bool TcpSession::are_packets_missing(unsigned char){ return false; }
uint8_t TcpSession::get_reassembly_direction(){ return 0; }
uint8_t  TcpSession::missing_in_reassembled(unsigned char){ return 0; }

class TcpSessionMock : public TcpSession
{
public:
    TcpSessionMock( Flow* flow ) : TcpSession( flow ), client( true ), server( false ) { }
    ~TcpSessionMock( void ) { }

    TcpStreamTracker client;
    TcpStreamTracker server;
};

class Active
{
public:
    static void drop_packet(const Packet*, bool force = false);

};

void Active::drop_packet(const Packet* , bool ) { }

bool Normalize_IsEnabled(NormFlags )
{
    return norm_enabled;
}

NormMode Normalize_GetMode(NormFlags )
{
    if( norm_enabled )
        return mockNormMode;
    else
        return NORM_MODE_TEST;
}

TEST_GROUP(tcp_normalizers)
{
    //Flow* flow = nullptr;
    //TcpSession* session = nullptr;

    void setup()
    {
    }

    void teardown()
    {
    }
};

TEST(tcp_normalizers, os_policy)
{
    StreamPolicy os_policy;
    Flow* flow = new FlowMock;
    TcpSession* session = new TcpSessionMock( flow );
    TcpNormalizerState tns;

    for( os_policy = StreamPolicy::OS_FIRST; os_policy <= StreamPolicy::OS_PROXY; ++os_policy )
    {
        TcpNormalizer* normalizer = TcpNormalizerFactory::create(
            tns, os_policy, session, session->client, session->server);

        CHECK( normalizer.get_os_policy(tns) == os_policy );
    }

    delete flow;
    delete session;
}

TEST(tcp_normalizers, paws_fudge_config)
{
    StreamPolicy os_policy;
    Flow* flow = new FlowMock;
    TcpSession* session = new TcpSessionMock( flow );
    TcpNormalizerState tns;

    for( os_policy = StreamPolicy::OS_FIRST; os_policy <= StreamPolicy::OS_PROXY; ++os_policy )
    {
        TcpNormalizer* normalizer = TcpNormalizerFactory::create(
            tns, os_policy, session, session->client, session->server);

        switch ( os_policy )
        {
        case StreamPolicy::OS_LINUX:
            CHECK( normalizer.get_paws_ts_fudge(tns) == 1 );
            break;

        default:
            CHECK( normalizer.get_paws_ts_fudge(tns) == 0 );
            break;
        }
    }

    delete flow;
    delete session;
}

TEST(tcp_normalizers, paws_drop_zero_ts_config)
{
    StreamPolicy os_policy;
    Flow* flow = new FlowMock;
    TcpSession* session = new TcpSessionMock( flow );
    TcpNormalizerState tns;

    for( os_policy = StreamPolicy::OS_FIRST; os_policy <= StreamPolicy::OS_PROXY; ++os_policy )
    {
        TcpNormalizer* normalizer = TcpNormalizerFactory::create(
            tns, os_policy, session, session->client, session->server );

        switch ( os_policy )
        {
        case StreamPolicy::OS_OLD_LINUX:
        case StreamPolicy::OS_SOLARIS:
        case StreamPolicy::OS_WINDOWS:
        case StreamPolicy::OS_WINDOWS2K3:
        case StreamPolicy::OS_VISTA:
            CHECK( !normalizer.is_paws_drop_zero_ts(tns) );
            break;

        default:
            CHECK( normalizer.is_paws_drop_zero_ts(tns) );
            break;
        }
    }

    delete flow;
    delete session;
}

TEST(tcp_normalizers, norm_options_enabled)
{
    StreamPolicy os_policy;
    Flow* flow = new FlowMock;
    TcpSession* session = new TcpSessionMock( flow );

    norm_enabled = true;
    for( os_policy = StreamPolicy::OS_FIRST; os_policy <= StreamPolicy::OS_PROXY; ++os_policy )
    {
        TcpNormalizerState tns;
        TcpNormalizer* normalizer = TcpNormalizerFactory::create(
            tns, os_policy, session, session->client, session->server);

        CHECK( normalizer.get_opt_block(tns) == NORM_MODE_ON );
        CHECK( normalizer.get_strip_ecn(tns) == NORM_MODE_ON );
        CHECK( normalizer.get_tcp_block(tns) == NORM_MODE_ON );
        CHECK( normalizer.get_trim_syn(tns) == NORM_MODE_ON );
        CHECK( normalizer.get_trim_rst(tns) == NORM_MODE_ON );
        CHECK( normalizer.get_trim_mss(tns) == NORM_MODE_ON );
        CHECK( normalizer.get_trim_win(tns) == NORM_MODE_ON );
        CHECK( normalizer.is_tcp_ips_enabled(tns) );
    }

    norm_enabled = false;
    for( os_policy = StreamPolicy::OS_FIRST; os_policy <= StreamPolicy::OS_PROXY; ++os_policy )
    {
        TcpNormalizerState tns;
        TcpNormalizer* normalizer = TcpNormalizerFactory::create(
            tns, os_policy, session, session->client, session->server);

        CHECK( normalizer.get_opt_block(tns) == NORM_MODE_TEST );
        CHECK( normalizer.get_strip_ecn(tns) == NORM_MODE_TEST );
        CHECK( normalizer.get_tcp_block(tns) == NORM_MODE_TEST );
        CHECK( normalizer.get_trim_syn(tns) == NORM_MODE_TEST );
        CHECK( normalizer.get_trim_rst(tns) == NORM_MODE_TEST );
        CHECK( normalizer.get_trim_mss(tns) == NORM_MODE_TEST );
        CHECK( normalizer.get_trim_win(tns) == NORM_MODE_TEST );
        CHECK( !normalizer.is_tcp_ips_enabled(tns) );
    }

    delete flow;
    delete session;
}

int main(int argc, char** argv)
{
    //MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    return CommandLineTestRunner::RunAllTests(argc, argv);
}


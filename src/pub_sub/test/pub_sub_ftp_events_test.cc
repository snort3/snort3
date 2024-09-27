//--------------------------------------------------------------------------
// Copyright (C) 2024 Cisco and/or its affiliates. All rights reserved.
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

// ftp_events.h author Anna Norokh <anorokh@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>

#include "pub_sub/ftp_events.h"
#include "service_inspectors/ftp_telnet/ftpp_si.h"
#include "utils/util_net.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace snort;

namespace snort
{
void* snort_alloc(size_t sz)
{ return new uint8_t[sz]; }

char* snort_strdup(const char* str)
{
    assert(str);
    size_t n = strlen(str) + 1;
    char* p = (char*)snort_alloc(n);
    memcpy(p, str, n);
    return p;
}
}

static FTP_SESSION session;

TEST_GROUP(pub_sub_ftp_events_test)
{
    const char* raw_request = "RETR file.txt\r\n";
    const char* raw_response = "226 Transfer complete.\r\n";

    void setup() override
    {
        session.client.request.cmd_begin = raw_request;
        session.client.request.cmd_end = raw_request + 4;
        session.client.request.cmd_size = 4;
        session.client.request.param_begin = raw_request + 5;
        session.client.request.param_end = raw_request + 13;
        session.client.request.param_size = 8;

        session.server.response.rsp_begin = const_cast<char*>(raw_response);
        session.server.response.rsp_end = const_cast<char*>(raw_response) + 3;
        session.server.response.rsp_size = 3;
        session.server.response.msg_begin = const_cast<char*>(raw_response) + 4;
        session.server.response.msg_end = const_cast<char*>(raw_response) + 22;
        session.server.response.msg_size = 18;

        session.clientIP.set("10.10.10.1");
        session.serverIP.set("10.10.10.2");
        session.clientPort = 40000;
        session.serverPort = 20;
    }
};

TEST(pub_sub_ftp_events_test, ftp_request_event)
{
    FtpRequestEvent event(session);

    auto cmd = std::string(event.get_request().cmd_begin, event.get_request().cmd_size);
    auto param = std::string(event.get_request().param_begin, event.get_request().param_size);
    CHECK(cmd == "RETR");
    CHECK(event.get_request().cmd_size == 4);
    CHECK(param == "file.txt");
    CHECK(event.get_request().param_size == 8);

    InetBuf src;
    sfip_ntop(&event.get_client_ip(), src, sizeof(src));
    std::string client = src;
    CHECK(client == "10.10.10.1");
    CHECK(event.get_client_port() == 40000);
}

TEST(pub_sub_ftp_events_test, ftp_response_event)
{
    const FtpResponseEvent event(session);

    auto response = event.get_response();
    auto rsp = std::string(response.rsp_begin, response.rsp_size);
    auto msg = std::string(response.msg_begin, response.msg_size);
    CHECK(rsp == "226");
    CHECK(response.rsp_size == 3);
    CHECK(msg == "Transfer complete.");
    CHECK(response.msg_size == 18);

    InetBuf dst, src;
    sfip_ntop(&event.get_client_ip(), src, sizeof(src));
    sfip_ntop(&event.get_server_ip(), dst, sizeof(dst));
    std::string client = src;
    std::string server = dst;
    CHECK(client == "10.10.10.1");
    CHECK(event.get_client_port() == 40000);
    CHECK(server == "10.10.10.2");
    CHECK(event.get_server_port() == 20);

}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

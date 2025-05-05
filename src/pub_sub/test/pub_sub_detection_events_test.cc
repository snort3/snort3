//--------------------------------------------------------------------------
// Copyright (C) 2025 Cisco and/or its affiliates. All rights reserved.
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
// http_transaction_test.cc author Anna Norokh <anorokh@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detection/signature.h"
#include "pub_sub/detection_events.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

static SigInfo s_dummy;
Event::Event() : sig_info(s_dummy) { }
Event::Event(unsigned int, unsigned int, SigInfo const&, char const**, char const*) : sig_info(s_dummy) { }
bool Event::get_reference(unsigned int, const char*&, const char*&, const char*&) const
{
    return true;
}
const char* Event::get_msg() const
{
    return "\"mock message\"";
}

class MockIpsRuleEvent : public IpsRuleEvent
{
public:
    MockIpsRuleEvent() : IpsRuleEvent({}) {}
    void mock_references()
    {
        const char* url = new char[strlen("https://example.com") + 1];
        strcpy(const_cast<char*>(url), "https://example.com");
        references.push_back(url);
    }
};
class MockIpsQueuingEvent : public IpsQueuingEvent
{
public:
    MockIpsQueuingEvent() : IpsQueuingEvent(s_dummy) {}
};

TEST_GROUP(detection_events_test)
{
    MockIpsRuleEvent* mock_ips_rule_event = new MockIpsRuleEvent();

    void teardown() override
    {
        delete mock_ips_rule_event;
    }
};

TEST(detection_events_test, get_references_is_not_empty)
{
    mock_ips_rule_event->mock_references();

    auto vec = mock_ips_rule_event->get_references();

    CHECK_FALSE(vec.empty());
    CHECK(1 == vec.size());
    CHECK(strcmp("https://example.com", vec[0]) == 0);
}

TEST(detection_events_test, get_ips_rule_message_is_not_empty)
{
    // first call initialize the message
    auto stripped_msg1 = mock_ips_rule_event->get_stripped_msg();
    CHECK("mock message" == stripped_msg1);

    // check that we got cached message
    auto stripped_msg2 = mock_ips_rule_event->get_stripped_msg();
    CHECK("mock message" == stripped_msg2);
}

TEST(detection_events_test, get_ips_queued_message_is_not_empty)
{
    MockIpsQueuingEvent* ips_queuing_event = new MockIpsQueuingEvent();

    // first call initialize the message
    auto stripped_msg1 = ips_queuing_event->get_stripped_msg();
    CHECK("mock message" == stripped_msg1);

    // check that we got cached message
    auto stripped_msg2 = ips_queuing_event->get_stripped_msg();
    CHECK("mock message" == stripped_msg2);

    delete ips_queuing_event;
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

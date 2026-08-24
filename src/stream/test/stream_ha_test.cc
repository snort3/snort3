// stream_ha_test.cc author Utkarsh Upadhyay <utkupadh@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "stream/base/stream_ha.h"

#include "flow/flow_key.h"
#include "framework/data_bus.h"
#include "sfip/sf_ip.h"
#include "stream/stream.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

// Symbols referenced by stream_ha.cc but absent from shared test stubs.
namespace snort
{
FlowHAClient::FlowHAClient(uint8_t length, const char*, const char*) : max_length(length) { }
FlowHAClient::~FlowHAClient() = default;

FlowHAState::FlowHAState() = default;
// cppcheck-suppress functionStatic ; must match the real non-static FlowHAState::add declaration
void FlowHAState::add(uint8_t) { }
// cppcheck-suppress functionStatic ; must match the real non-static FlowHAState::clear declaration
void FlowHAState::clear(uint8_t) { }
// cppcheck-suppress functionStatic ; must match the real non-static FlowHAState::check_any declaration
bool FlowHAState::check_any(uint8_t) { return false; }
// cppcheck-suppress functionStatic ; must match the real non-static FlowHAState::sync_interval_elapsed declaration
bool FlowHAState::sync_interval_elapsed() { return false; }

void HighAvailabilityManager::process_deletion(Flow&) { }
bool HighAvailabilityManager::configured() { return false; }

void DataBus::publish(unsigned, unsigned, DataEvent&, Flow*) { }

// cppcheck-suppress functionStatic ; must match the real non-static SfIp::set declaration
SfIpRet SfIp::set(const void*) { return SFIP_SUCCESS; }

unsigned Stream::get_pub_id() { return 0; }
}

TEST_GROUP(stream_ha_consume)
{
};

// A valid (non-null) key must clear the null guard without hitting the debug
// assert; no ProtocolHA is registered in this test binary, so consume()
// legitimately returns false when it fails to create a flow, not the guard.
TEST(stream_ha_consume, valid_key_clears_guard)
{
    uint8_t buffer[sizeof(SessionHAContent)] = { };
    HAMessage msg(buffer, sizeof(buffer));
    uint8_t* const saved_cursor = msg.cursor;
    FlowKey key { };

    Flow* flow = nullptr;
    StreamHAClient client;

    CHECK_FALSE(client.consume(flow, &key, msg, sizeof(SessionHAContent)));
    POINTERS_EQUAL(nullptr, flow);
    POINTERS_EQUAL(saved_cursor, msg.cursor);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

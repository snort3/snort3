// stream_ha_test.cc author Utkarsh Upadhyay <utkupadh@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "stream/base/stream_ha.h"

#include <cstring>

#include "flow/flow_key.h"
#include "framework/data_bus.h"
#include "sfip/sf_ip.h"
#include "stream/stream.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

static unsigned test_call_sequence = 0;
static unsigned test_standby_added_at = 0;
static unsigned test_candidacy_called_at = 0;
static unsigned test_candidacy_calls = 0;
static uint32_t test_candidacy_prev_flags = 0;
static uint32_t test_candidacy_flags_on_entry = 0;

// Symbols referenced by stream_ha.cc but absent from shared test stubs.
namespace snort
{
FlowHAClient::FlowHAClient(uint8_t length, const char*, const char*) : max_length(length) { }
FlowHAClient::~FlowHAClient() = default;

Flow::Flow() = default;
Flow::~Flow() = default;
FlowDataStore::~FlowDataStore() = default;
// cppcheck-suppress functionStatic ; must match the real non-static FlowStash::reset declaration
void FlowStash::reset() { }

FlowHAState::FlowHAState() = default;
// cppcheck-suppress functionStatic ; must match the real non-static FlowHAState::add declaration
void FlowHAState::add(uint8_t added_state)
{
    if ( added_state == FlowHAState::STANDBY )
        test_standby_added_at = ++test_call_sequence;
}
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

void Flow::update_uni_candidacy(uint32_t prev_session_flags)
{
    ++test_candidacy_calls;
    test_candidacy_called_at = ++test_call_sequence;
    test_candidacy_prev_flags = prev_session_flags;
    test_candidacy_flags_on_entry = ssn_state.session_flags;
}
}

TEST_GROUP(stream_ha_consume)
{
    void setup() override
    {
        test_call_sequence = 0;
        test_standby_added_at = 0;
        test_candidacy_called_at = 0;
        test_candidacy_calls = 0;
        test_candidacy_prev_flags = 0;
        test_candidacy_flags_on_entry = 0;
    }
};

// consume() skips flow creation when it is handed an existing flow, so it reaches
// the reconcile.  No ProtocolHA is registered here, which makes
// protocol_deactivate_session() inert, but the STANDBY add next to it is observable.
static bool consume_imported_state(Flow& flow, uint32_t imported_session_flags)
{
    SessionHAContent hac { };
    hac.ssn_state.session_flags = imported_session_flags;
    hac.flow_state = Flow::FlowState::BLOCK;

    uint8_t buffer[sizeof(SessionHAContent)] = { };
    memcpy(buffer, &hac, sizeof(hac));

    HAMessage msg(buffer, sizeof(buffer));
    FlowKey key { };
    StreamHAClient client;

    Flow* flow_ptr = &flow;
    return client.consume(flow_ptr, &key, msg, sizeof(SessionHAContent));
}

TEST(stream_ha_consume, imported_block_is_reconciled)
{
    Flow flow;
    flow.ssn_state.session_flags = SSNFLAG_SEEN_CLIENT;

    CHECK_TRUE(consume_imported_state(flow, SSNFLAG_SEEN_CLIENT | SSNFLAG_DROP_CLIENT));

    UNSIGNED_LONGS_EQUAL(1, test_candidacy_calls);
    UNSIGNED_LONGS_EQUAL(SSNFLAG_SEEN_CLIENT, test_candidacy_prev_flags);
    CHECK((test_candidacy_flags_on_entry & SSNFLAG_DROP_CLIENT) != 0);
    CHECK(test_standby_added_at != 0);
    CHECK(test_candidacy_called_at > test_standby_added_at);

    delete flow.ha_state;
    flow.ha_state = nullptr;
}

TEST(stream_ha_consume, imported_unblock_is_reconciled)
{
    Flow flow;
    flow.ssn_state.session_flags = SSNFLAG_SEEN_CLIENT | SSNFLAG_DROP_CLIENT;

    CHECK_TRUE(consume_imported_state(flow, SSNFLAG_SEEN_CLIENT));

    UNSIGNED_LONGS_EQUAL(1, test_candidacy_calls);
    CHECK((test_candidacy_prev_flags & SSNFLAG_DROP_CLIENT) != 0);
    UNSIGNED_LONGS_EQUAL(SSNFLAG_SEEN_CLIENT, test_candidacy_flags_on_entry);
    CHECK(test_candidacy_called_at > test_standby_added_at);

    delete flow.ha_state;
    flow.ha_state = nullptr;
}

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

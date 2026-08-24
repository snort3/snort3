// appid_ha_test.cc author Utkarsh Upadhyay <utkupadh@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "network_inspectors/appid/appid_ha.h"

#include "flow/flow_key.h"
#include "main/analyzer.h"
#include "managers/inspector_manager.h"

#include "appid_debug.h"
#include "appid_session.h"
#include "tp_lib_handler.h"

using namespace snort;

#include "appid_mock_definitions.h"
#include "appid_mock_session.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

// Test controls for the SAFE_CURRENT_PACKET guard exercised by appid_ha.cc. The
// macro only calls DetectionEngine::get_current_packet() when both a local
// analyzer and a detection context exist; get_current_packet_calls lets a test
// prove it was skipped otherwise.
static Analyzer* test_local_analyzer = nullptr;
static IpsContext* test_detection_context = nullptr;
static Packet* test_current_packet = nullptr;
static unsigned get_current_packet_calls = 0;

// Symbols referenced by appid_ha.cc but absent from the shared mocks.
namespace snort
{
Packet::Packet(bool) { }
Packet::~Packet() = default;
IpsContext* DetectionEngine::get_context() { return test_detection_context; }
Packet* DetectionEngine::get_current_packet()
{
    ++get_current_packet_calls;
    return test_current_packet;
}

FlowHAClient::FlowHAClient(uint8_t length, const char*, const char*) : max_length(length) { }
FlowHAClient::~FlowHAClient() = default;

Inspector* InspectorManager::get_inspector(const char*, Module::Usage) { return nullptr; }

AppIdSessionApi::AppIdSessionApi(const AppIdSession*, const SfIp&) { }
// cppcheck-suppress functionStatic ; must match the real non-static AppIdSessionApi::get_tls_host declaration
const char* AppIdSessionApi::get_tls_host() const { return nullptr; }
}

// Global-scope AppID symbols referenced by appid_ha.cc but owned by
// translation units we do not link here.
Analyzer* Analyzer::get_local_analyzer() { return test_local_analyzer; }

void appid_log(const snort::Packet*, unsigned char, char const*, ...) { }

THREAD_LOCAL AppIdDebug* appidDebug = nullptr;
// cppcheck-suppress functionStatic ; must match the real non-static AppIdDebug::activate declaration
void AppIdDebug::activate(const snort::Flow*, const AppIdSession*, bool) { }

namespace snort
{
AppIdApi appid_api;
// cppcheck-suppress functionStatic ; must match the real non-static AppIdApi::get_appid_session declaration
AppIdSession* AppIdApi::get_appid_session(const Flow&) { return nullptr; }
}

TPLibHandler* TPLibHandler::self = nullptr;
THREAD_LOCAL bool ThirdPartyAppIdContext::tp_reload_in_progress = false;

// cppcheck-suppress functionStatic ; must match the real non-static AppIdSession::get_http_session declaration
AppIdHttpSession* AppIdSession::get_http_session(uint32_t) const { return nullptr; }
// cppcheck-suppress functionStatic ; must match the real non-static AppIdHttpSession::set_field declaration
void AppIdHttpSession::set_field(HttpFieldIds, const std::string* str, AppidChangeBits&) { delete str; }

void AppIdModule::reset_stats() { }
void ApplicationDescriptor::set_id(const snort::Packet&, AppIdSession&, AppidSessionDirection, AppId, AppidChangeBits&) { }

TEST_GROUP(appid_ha_null_guard)
{
};

// A valid key and flow must clear the null guard without hitting the debug
// assert; the mocked InspectorManager still returns nullptr here, so consume()
// legitimately returns false at the next (inspector) check, not the null guard.
TEST(appid_ha_null_guard, apps_valid_key_and_flow_clears_guard)
{
    uint8_t buf[64] = { };
    HAMessage msg(buf, sizeof(buf));
    FlowKey key { };
    FakeFlow real_flow;
    Flow* flow = &real_flow;
    AppIdHAAppsClient client;
    CHECK_FALSE(client.consume(flow, &key, msg, sizeof(AppIdSessionHAApps)));
}

TEST(appid_ha_null_guard, http_valid_key_and_flow_clears_guard)
{
    uint8_t buf[64] = { };
    HAMessage msg(buf, sizeof(buf));
    FlowKey key { };
    FakeFlow real_flow;
    Flow* flow = &real_flow;
    AppIdHAHttpClient client;
    CHECK_FALSE(client.consume(flow, &key, msg, sizeof(AppIdSessionHAHttp)));
}

TEST(appid_ha_null_guard, tls_valid_key_and_flow_clears_guard)
{
    uint8_t buf[64] = { };
    HAMessage msg(buf, sizeof(buf));
    FlowKey key { };
    FakeFlow real_flow;
    Flow* flow = &real_flow;
    AppIdHATlsHostClient client;
    CHECK_FALSE(client.consume(flow, &key, msg, sizeof(AppIdSessionHATlsHost)));
}

// Item #5: the consume-reachable SAFE_CURRENT_PACKET expression must not call
// DetectionEngine::get_current_packet() when there is no local analyzer or no
// active detection context (the HA side-channel/idle path).
TEST_GROUP(appid_ha_safe_current_packet)
{
    void setup() override
    {
        test_local_analyzer = nullptr;
        test_detection_context = nullptr;
        test_current_packet = nullptr;
        get_current_packet_calls = 0;
    }
};

TEST(appid_ha_safe_current_packet, no_analyzer_skips_get_current_packet)
{
    const Packet* p = SAFE_CURRENT_PACKET;
    CHECK(p == nullptr);
    CHECK_EQUAL(0u, get_current_packet_calls);
}

TEST(appid_ha_safe_current_packet, analyzer_without_context_skips_get_current_packet)
{
    char analyzer_storage;
    test_local_analyzer = reinterpret_cast<Analyzer*>(&analyzer_storage);
    test_detection_context = nullptr;
    const Packet* p = SAFE_CURRENT_PACKET;
    CHECK(p == nullptr);
    CHECK_EQUAL(0u, get_current_packet_calls);
}

TEST(appid_ha_safe_current_packet, analyzer_and_context_use_get_current_packet)
{
    char analyzer_storage;
    char context_storage;
    char packet_storage;
    test_local_analyzer = reinterpret_cast<Analyzer*>(&analyzer_storage);
    test_detection_context = reinterpret_cast<IpsContext*>(&context_storage);
    test_current_packet = reinterpret_cast<Packet*>(&packet_storage);
    const Packet* p = SAFE_CURRENT_PACKET;
    CHECK(p == test_current_packet);
    CHECK_EQUAL(1u, get_current_packet_calls);
}

int main(int argc, char** argv)
{
    mock_init_appid_pegs();
    int rc = CommandLineTestRunner::RunAllTests(argc, argv);
    mock_cleanup_appid_pegs();
    return rc;
}

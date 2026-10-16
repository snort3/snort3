//--------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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

// http_js_norm_attr_test.cc
// Unit tests for the script attribute match callback at the search buffer
// edge. The matcher reports an index one past the last matched byte, so a
// pattern ending on the final byte arrives as index == buffer length.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstdlib>
#include <iterator>

#include "service_inspectors/http_inspect/http_js_norm.cc"
#include "service_inspectors/http_inspect/http_test_manager.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;
using namespace HttpCommon;
using namespace HttpEnums;

THREAD_LOCAL const snort::Trace* js_trace = nullptr;
THREAD_LOCAL PegCount HttpModule::peg_counts[HttpEnums::PEG_COUNT_MAX] = { };

long HttpTestManager::print_amount {};
bool HttpTestManager::print_hex {};

namespace snort
{
SearchTool::SearchTool(bool, const char*) { }
SearchTool::~SearchTool() = default;
void SearchTool::add(const char*, unsigned, int, bool, bool) { }
void SearchTool::add(const uint8_t*, unsigned, int, bool, bool) { }
void SearchTool::prep() { }
int SearchTool::find(const char*, unsigned, MpseMatch, bool, void*) { return 0; }
int SearchTool::find(const char*, unsigned, MpseMatch, int&, bool, void*) { return 0; }
int SearchTool::find_all(const char*, unsigned, MpseMatch, bool, void*, const SnortConfig*)
{ return 0; }

JSNorm::JSNorm(JSNormConfig*, bool, uint32_t) : idn_ctx(nullptr) { }
JSNorm::~JSNorm() = default;
bool JSNorm::pre_proc() { return false; }
bool JSNorm::post_proc(int) { return false; }
void JSNorm::normalize(const void*, size_t, const void*&, size_t&) { }
void JSNorm::flush_data() { }
bool PDFJSNorm::pre_proc() { return false; }
bool PDFJSNorm::post_proc(int) { return false; }
Packet* DetectionEngine::get_current_packet() { return nullptr; }
int DetectionEngine::queue_event(unsigned, unsigned) { return 0; }
void trace_vprintf(const char*, TraceLevel, const char*, const Packet*, const char*, va_list) { }
uint8_t TraceApi::get_constraints_generation() { return 0; }
void TraceApi::filter(const Packet&) { }
[[noreturn]] void FatalError(const char*, ...) { exit(EXIT_FAILURE); }
const char* SnortStrnStr(const char*, int, const char*) { return nullptr; }
int JSNormalizeDecode(const char*, uint16_t, char*, uint16_t, const char**, int*, JSState*,
    uint8_t*) { return 0; }
}

// A boundary case ends the search buffer one byte before its literal's last
// character, so a read past the end would see that '=' or '>'.
TEST_GROUP(http_js_norm_attr) { };

TEST(http_js_norm_attr, src_last_in_buffer)
{
    static const uint8_t buf[] = "  src=";
    const uint8_t* const end = buf + std::size(buf) - 2;
    MatchContext ctx { buf, end, true, false, false };

    LONGS_EQUAL(0, match_attr((void*)AID_SRC, nullptr, 5, &ctx, nullptr));
    CHECK_FALSE(ctx.is_external);
    POINTERS_EQUAL(end, ctx.end);
}

TEST(http_js_norm_attr, src_trailing_spaces_to_buffer_end)
{
    static const uint8_t buf[] = "  src  =";
    const uint8_t* const end = buf + std::size(buf) - 2;
    MatchContext ctx { buf, end, true, false, false };

    LONGS_EQUAL(0, match_attr((void*)AID_SRC, nullptr, 5, &ctx, nullptr));
    CHECK_FALSE(ctx.is_external);
    POINTERS_EQUAL(end, ctx.end);
}

TEST(http_js_norm_attr, src_equals_still_detected)
{
    static const uint8_t buf[] = "  src  =";
    const uint8_t* const end = buf + std::size(buf) - 1;
    MatchContext ctx { buf, end, true, false, false };

    LONGS_EQUAL(0, match_attr((void*)AID_SRC, nullptr, 5, &ctx, nullptr));
    CHECK_TRUE(ctx.is_external);
    POINTERS_EQUAL(end, ctx.end);
}

TEST(http_js_norm_attr, slash_last_in_buffer)
{
    static const uint8_t buf[] = "  />";
    const uint8_t* const end = buf + std::size(buf) - 2;
    MatchContext ctx { buf, end, true, false, false };

    LONGS_EQUAL(0, match_attr((void*)AID_SLASH, nullptr, 3, &ctx, nullptr));
    CHECK_FALSE(ctx.is_shortened);
    POINTERS_EQUAL(end, ctx.end);
}

TEST(http_js_norm_attr, slash_shortened_tag_still_detected)
{
    static const uint8_t buf[] = "  />";
    const uint8_t* const end = buf + std::size(buf) - 1;
    MatchContext ctx { buf, end, true, false, false };

    LONGS_EQUAL(1, match_attr((void*)AID_SLASH, nullptr, 3, &ctx, nullptr));
    CHECK_TRUE(ctx.is_shortened);
    POINTERS_EQUAL(buf + 3, ctx.next);
    POINTERS_EQUAL(end, ctx.end);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

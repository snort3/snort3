//--------------------------------------------------------------------------
// Copyright (C) 2018-2026 Cisco and/or its affiliates. All rights reserved.
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
// http_context_data.h author Bhagya Tholpady <bbantwal@cisco.com>

#ifndef HTTP_CONTEXT_DATA_H
#define HTTP_CONTEXT_DATA_H

#include <array>
#include <cstdint>
#include <memory>

#include "detection/ips_context_data.h"

#include "http_cache_data.h"
#include "http_enum.h"

class HttpMsgSection;
struct HttpSplitterSnapshot;

enum class SplitterSlot : unsigned char { SLOT_300 = 0, SLOT_299 = 1, SLOT_298 = 2 };
static constexpr unsigned SPLITTER_SLOT_COUNT = 3;

struct HttpContextDataView
{
    HttpMsgSection* current_section = nullptr;
    std::array<const HttpSplitterSnapshot*, SPLITTER_SLOT_COUNT> splitter_snapshots {};
};

struct HttpSplitterSnapshot
{
    uint32_t request_size = 0;
    uint32_t request_line_length = 0;
    HttpEnums::RequestLineInvalidReasonCode reason_code_detail_300 =
        HttpEnums::RequestLineInvalidReasonCode::NONE;

    std::array<uint8_t, MAX_REQUEST_LINE_LOG_LEN> raw_request_line = {};
    uint16_t raw_request_line_len = 0;
    HttpEnums::VersionId version_id = HttpEnums::VERS__NOT_PRESENT;

    void set_raw_request_line(const uint8_t* data, uint16_t len);
};

struct HttpPendingSizeReport
{
    bool has_298 = false;
    uint32_t size_298 = 0;
    bool has_299 = false;
    uint32_t length_299 = 0;
};

class HttpContextData : public snort::IpsContextData
{
public:
    void clear() override;

    static void init()
    { ips_id = IpsContextData::get_ips_id(); }
    static HttpMsgSection* get_snapshot(const snort::Packet* p);
    static HttpMsgSection* get_snapshot(const snort::Flow* flow,
        snort::IpsContext* context = nullptr);
    static void save_snapshot(HttpMsgSection* section);
    static HttpMsgSection* clear_snapshot(snort::IpsContext* context);
    static void save_pending_section_buffer(const uint8_t*);
    static void claim_pending_section_buffer(snort::IpsContext*, const uint8_t*);
    static HttpContextDataView get_view(const snort::Packet* p);
    static HttpTmpBufferCache& get_tmp_buffers();
    static HttpTmpBufferCache* find_tmp_buffers(snort::IpsContext* context = nullptr);
    static void clear_tmp_buffers(snort::IpsContext* context = nullptr);

    // see dev_notes_splitter_buffers.txt
    static void latch_pending_size_298(uint32_t size, bool defer_to_next_context);
    static void latch_pending_length_299(uint32_t length, bool defer_to_next_context);
    static HttpPendingSizeReport claim_pending_size_report(snort::IpsContext* context = nullptr);

    enum class CaptureMode : unsigned char { FirstWriteWins, Refresh };

    template<typename F>
    static const HttpSplitterSnapshot& capture_splitter(SplitterSlot slot, CaptureMode mode,
        F&& populate)
    {
        HttpContextData* hcd = IpsContextData::get<HttpContextData>(HttpContextData::ips_id);
        auto& snap = hcd->splitter_snapshots[static_cast<unsigned>(slot)];
        const bool is_new = !snap;

        if ( is_new )
            snap = std::make_unique<HttpSplitterSnapshot>();

        if ( is_new or mode == CaptureMode::Refresh )
            populate(*snap);

        return *snap;
    }

    static unsigned ips_id;

private:
    // Owns direct HTTP/1 data pending transfer to an HttpMsgSection.
    const uint8_t* pending_section_buffer = nullptr;
    HttpMsgSection* current_section = nullptr;
    std::array<std::unique_ptr<HttpSplitterSnapshot>, SPLITTER_SLOT_COUNT> splitter_snapshots;
    HttpTmpBufferCache tmp_buffers;
    std::unique_ptr<HttpPendingSizeReport> pending_size_report;
};

#endif

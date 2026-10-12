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
// http_context_data.cc author Bhagya Tholpady <bbantwal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_context_data.h"

#include <algorithm>
#include <cstring>

#include "flow/stream_flow.h"

#include "http_msg_section.h"
#include "protocols/packet.h"

using namespace snort;

unsigned HttpContextData::ips_id = 0;

void HttpContextData::clear()
{
    tmp_buffers.clear();
    delete[] pending_section_buffer;
    pending_section_buffer = nullptr;
    current_section = nullptr;
    for (auto& snap : splitter_snapshots)
        snap.reset();
    pending_size_report.reset();
}

void HttpSplitterSnapshot::set_raw_request_line(const uint8_t* data, uint16_t len)
{
    raw_request_line_len = std::min<uint16_t>(len, MAX_REQUEST_LINE_LOG_LEN);
    memcpy(raw_request_line.data(), data, raw_request_line_len);
}

HttpMsgSection* HttpContextData::get_snapshot(const Packet* p)
{
    assert(p != nullptr);
    return get_view(p).current_section;
}

HttpMsgSection* HttpContextData::get_snapshot(const Flow* flow, IpsContext* context)
{
    assert(flow != nullptr);

    if (flow->stream_intf)
    {
        return static_cast<HttpMsgSection*>(flow->stream_intf->get_hi_msg_section(flow));
    }

    const HttpContextData* hcd = static_cast<HttpContextData*>(
        DetectionEngine::get_data(HttpContextData::ips_id, context));

    if ( !hcd )
        return nullptr;

    return hcd->current_section;
}

void HttpContextData::save_snapshot(HttpMsgSection* section)
{
    HttpContextData* hcd = IpsContextData::get<HttpContextData>(HttpContextData::ips_id);

    hcd->current_section = section;
}

HttpMsgSection* HttpContextData::clear_snapshot(IpsContext* context)
{
    HttpMsgSection* section = nullptr;
    HttpContextData* hcd = static_cast<HttpContextData*>(
        DetectionEngine::get_data(HttpContextData::ips_id, context));

    if ( hcd )
    {
        section = hcd->current_section;
        hcd->current_section = nullptr;
    }

    return section;
}

void HttpContextData::save_pending_section_buffer(const uint8_t* buffer)
{
    assert(buffer);

    DetectionEngine::wait_for_context();
    IpsContext* context = DetectionEngine::get_next_context();
    assert(context);

    auto* hcd = static_cast<HttpContextData*>(DetectionEngine::get_data(ips_id, context));
    if ( !hcd )
    {
        hcd = new HttpContextData;
        context->set_context_data(ips_id, hcd);
    }

    assert(!hcd->pending_section_buffer);
    hcd->pending_section_buffer = buffer;
}

void HttpContextData::claim_pending_section_buffer(IpsContext* context, const uint8_t* expected)
{
    assert(context);
    assert(expected);

    auto* const hcd = static_cast<HttpContextData*>(DetectionEngine::get_data(ips_id, context));
    assert(hcd);
    if ( hcd )
    {
        assert(hcd->pending_section_buffer == expected);
        if ( hcd->pending_section_buffer == expected )
            hcd->pending_section_buffer = nullptr;
    }
}

HttpContextDataView HttpContextData::get_view(const Packet* p)
{
    assert(p != nullptr);
    assert(p->flow != nullptr);

    HttpContextDataView view;
    if (p->flow->stream_intf)
    {
        view.current_section = static_cast<HttpMsgSection*>(
            p->flow->stream_intf->get_hi_msg_section(p->flow));
        if (view.current_section)
            return view;
    }

    const HttpContextData* hcd = static_cast<HttpContextData*>(
        DetectionEngine::get_data(HttpContextData::ips_id, p->context));

    if (hcd)
    {
        if (!p->flow->stream_intf)
            view.current_section = hcd->current_section;
        for (unsigned i = 0; i < SPLITTER_SLOT_COUNT; ++i)
            view.splitter_snapshots[i] = hcd->splitter_snapshots[i].get();
    }

    return view;
}

HttpTmpBufferCache& HttpContextData::get_tmp_buffers()
{
    HttpContextData* hcd = IpsContextData::get<HttpContextData>(HttpContextData::ips_id);
    return hcd->tmp_buffers;
}

HttpTmpBufferCache* HttpContextData::find_tmp_buffers(IpsContext* context)
{
    auto* const hcd = static_cast<HttpContextData*>(
        DetectionEngine::get_data(HttpContextData::ips_id, context));
    return hcd ? &hcd->tmp_buffers : nullptr;
}

void HttpContextData::clear_tmp_buffers(IpsContext* context)
{
    if (HttpTmpBufferCache* tmp = find_tmp_buffers(context))
        tmp->clear();
}

static HttpContextData* get_or_create_pending_report_owner(unsigned ips_id,
    bool defer_to_next_context)
{
    if ( !defer_to_next_context )
        return IpsContextData::get<HttpContextData>(ips_id);

    DetectionEngine::wait_for_context();
    IpsContext* context = DetectionEngine::get_next_context();
    assert(context);

    auto* hcd = static_cast<HttpContextData*>(DetectionEngine::get_data(ips_id, context));
    if ( !hcd )
    {
        hcd = new HttpContextData;
        context->set_context_data(ips_id, hcd);
    }
    return hcd;
}

void HttpContextData::latch_pending_size_298(uint32_t size, bool defer_to_next_context)
{
    HttpContextData* const hcd = get_or_create_pending_report_owner(ips_id, defer_to_next_context);

    if ( !hcd->pending_size_report )
        hcd->pending_size_report = std::make_unique<HttpPendingSizeReport>();

    if ( !hcd->pending_size_report->has_298 )
    {
        hcd->pending_size_report->has_298 = true;
        hcd->pending_size_report->size_298 = size;
    }
}

void HttpContextData::latch_pending_length_299(uint32_t length, bool defer_to_next_context)
{
    HttpContextData* const hcd = get_or_create_pending_report_owner(ips_id, defer_to_next_context);

    if ( !hcd->pending_size_report )
        hcd->pending_size_report = std::make_unique<HttpPendingSizeReport>();

    if ( !hcd->pending_size_report->has_299 )
    {
        hcd->pending_size_report->has_299 = true;
        hcd->pending_size_report->length_299 = length;
    }
}

HttpPendingSizeReport HttpContextData::claim_pending_size_report(IpsContext* context)
{
    auto* const hcd = static_cast<HttpContextData*>(DetectionEngine::get_data(ips_id, context));
    if ( !hcd or !hcd->pending_size_report )
        return {};

    HttpPendingSizeReport result = *hcd->pending_size_report;
    hcd->pending_size_report.reset();
    return result;
}

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

#include "http_msg_section.h"
#include "protocols/packet.h"
#include "service_inspectors/http2_inspect/http2_flow_data.h"

using namespace snort;

unsigned HttpContextData::ips_id = 0;

void HttpContextData::clear()
{
    delete[] pending_section_buffer;
    pending_section_buffer = nullptr;
    current_section = nullptr;
}

HttpMsgSection* HttpContextData::get_snapshot(const Packet* p)
{
    assert(p != nullptr);
    return get_snapshot(p->flow, p->context);
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

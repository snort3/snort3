//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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
// http_msg_start.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_msg_start.h"

#include "service_inspectors/http2_inspect/http2_flow_data.h"

#include "http_enum.h"

using namespace HttpEnums;

HttpMsgStart::HttpMsgStart(const uint8_t* buffer, const uint16_t buf_size, HttpFlowData* session_data_,
    HttpCommon::SourceId source_id_, bool buf_owner, snort::Flow* flow_,
    const HttpParaList* params_) : HttpMsgSection(buffer, buf_size, session_data_, source_id_,
    buf_owner, flow_, params_), own_msg_buffer(buf_owner)
{ }

HttpMsgStart::~HttpMsgStart()
{ }

void HttpMsgStart::analyze()
{
    start_line.set(msg_text);
    parse_start_line();
}

void HttpMsgStart::derive_version_id()
{
    if (version.start()[6] != '.')
    {
        version_id = VERS__PROBLEMATIC;
        add_infraction(INF_BAD_VERSION);
        create_event(EVENT_BAD_VERS);
    }
    else if ((version.start()[5] == '1') && (version.start()[7] == '1'))
    {
        if (session_data->for_httpx)
        {
            const Http2FlowData* const h2i_flow_data =
                (Http2FlowData*)flow->get_flow_data(Http2FlowData::inspector_id);

            version_id = (h2i_flow_data) ? VERS_2_0 : VERS_3_0;
        }
        else
            version_id = VERS_1_1;
    }
    else if ((version.start()[5] == '1') && (version.start()[7] == '0'))
    {
        version_id = VERS_1_0;
    }
    else if ((version.start()[5] < '0') || (version.start()[5] > '9') ||
        (version.start()[7] < '0') || (version.start()[7] > '9'))
    {
        version_id = VERS__PROBLEMATIC;
        add_infraction(INF_BAD_VERSION);
        create_event(EVENT_BAD_VERS);
    }
    else if ((version.start()[5] > '1'))
    {
        version_id = VERS__OTHER;
        add_infraction(INF_VERSION_HIGHER_THAN_1);
        create_event(EVENT_VERSION_HIGHER_THAN_1);
    }
    else if (version.start()[5] == '1')
    {
        version_id = VERS__OTHER;
        add_infraction(INF_INVALID_SUBVERSION);
        create_event(EVENT_INVALID_SUBVERSION);
    }
    else
    {
        version_id = VERS__OTHER;
        add_infraction(INF_VERSION_0);
        create_event(EVENT_VERSION_0);
    }
}


//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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
// http_msg_start.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP_MSG_START_H
#define HTTP_MSG_START_H

#include "http_common.h"
#include "http_enum.h"
#include "http_field.h"
#include "http_msg_section.h"

//-------------------------------------------------------------------------
// HttpMsgStart class
//-------------------------------------------------------------------------

class HttpMsgStart : public HttpMsgSection
{
public:
    void analyze() override;
    bool detection_required() const override { return false; }
    const Field& get_version() const { return version; }
    HttpEnums::VersionId get_version_id() const { return version_id; }
    // +2 to account for \r\n at the end of the section that was removed by the splitter
    uint32_t get_length() const override
    { auto len = HttpMsgSection::get_length(); return (len > 0) ? len + 2 : 0; }

    uint32_t get_start_line_length() const
    { return HttpMsgSection::get_length(); }
    HttpEnums::RequestLineInvalidReasonCode get_request_line_invalid_reason() const
    { return request_line_invalid_reason; }

protected:
    HttpMsgStart(const uint8_t* buffer, const uint16_t buf_size, HttpFlowData* session_data_,
        HttpCommon::SourceId source_id_, bool buf_owner, snort::Flow* flow_,
        const HttpParaList* params_);
    ~HttpMsgStart() override;
    virtual void parse_start_line() = 0;
    void derive_version_id();
    void create_event_request_line_not_valid(HttpEnums::RequestLineInvalidReasonCode reason);

    Field start_line;
    Field version;
    bool own_msg_buffer;
    HttpEnums::RequestLineInvalidReasonCode request_line_invalid_reason =
        HttpEnums::RequestLineInvalidReasonCode::NONE;
};

#endif


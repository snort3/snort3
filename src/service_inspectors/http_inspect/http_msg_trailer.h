//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// http_msg_trailer.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP_MSG_TRAILER_H
#define HTTP_MSG_TRAILER_H

#include "http_msg_head_shared.h"

//-------------------------------------------------------------------------
// HttpMsgTrailer class
//-------------------------------------------------------------------------

class HttpMsgTrailer : public HttpMsgHeadShared
{
public:
    HttpMsgTrailer(const uint8_t* buffer, const uint16_t buf_size, HttpFlowData* session_data_,
        HttpEnums::SourceId source_id_, bool buf_owner, snort::Flow* flow_,
        const HttpParaList* params_);
    HttpEnums::InspectSection get_inspection_section() const override
        { return HttpEnums::IS_TRAILER; }
    void gen_events() override;
    void update_flow() override;

#ifdef REG_TEST
    void print_section(FILE* output) override;
#endif
};

#endif


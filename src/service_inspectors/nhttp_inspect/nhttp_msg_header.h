//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
// nhttp_msg_header.h author Tom Peters <thopeter@cisco.com>

#ifndef NHTTP_MSG_HEADER_H
#define NHTTP_MSG_HEADER_H

#include "file_api/file_api.h"

#include "nhttp_enum.h"
#include "nhttp_msg_head_shared.h"

//-------------------------------------------------------------------------
// NHttpMsgHeader class
//-------------------------------------------------------------------------

class NHttpMsgHeader : public NHttpMsgHeadShared
{
public:
    NHttpMsgHeader(const uint8_t* buffer, const uint16_t buf_size, NHttpFlowData* session_data_,
        NHttpEnums::SourceId source_id_, bool buf_owner, Flow* flow_,
        const NHttpParaList* params_);
    NHttpEnums::InspectSection get_inspection_section() const override
        { return detection_section ? NHttpEnums::IS_DETECTION : NHttpEnums::IS_NONE; }
    void update_flow() override;
private:
    // Dummy configurations to support MIME processing
    MailLogConfig mime_conf;
    DecodeConfig decode_conf;

    void prepare_body();
    void setup_file_processing();
    void setup_decompression();

    bool detection_section = true;

#ifdef REG_TEST
    void print_section(FILE* output) override;
#endif
};

#endif


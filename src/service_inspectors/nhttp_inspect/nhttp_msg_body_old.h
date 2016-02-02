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
// nhttp_msg_body_old.h author Tom Peters <thopeter@cisco.com>

#ifndef NHTTP_MSG_BODY_OLD_H
#define NHTTP_MSG_BODY_OLD_H

#include "nhttp_msg_section.h"
#include "nhttp_msg_body.h"
#include "nhttp_field.h"

//-------------------------------------------------------------------------
// NHttpMsgBodyOld class
//-------------------------------------------------------------------------

class NHttpMsgBodyOld : public NHttpMsgBody
{
public:
    NHttpMsgBodyOld(const uint8_t* buffer, const uint16_t buf_size, NHttpFlowData* session_data_,
        NHttpEnums::SourceId source_id_, bool buf_owner, Flow* flow_, const NHttpParaList* params_)
        : NHttpMsgBody(buffer, buf_size, session_data_, source_id_, buf_owner, flow_, params_),
        data_length(session_data->data_length[source_id]) {}
    void update_flow() override;

#ifdef REG_TEST
    void print_section(FILE* output) override;
#endif

protected:
    int64_t data_length;
};

#endif


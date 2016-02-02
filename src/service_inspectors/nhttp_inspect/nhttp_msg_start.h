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
// nhttp_msg_start.h author Tom Peters <thopeter@cisco.com>

#ifndef NHTTP_MSG_START_H
#define NHTTP_MSG_START_H

#include "nhttp_msg_section.h"
#include "nhttp_field.h"

//-------------------------------------------------------------------------
// NHttpMsgStart class
//-------------------------------------------------------------------------

class NHttpMsgStart : public NHttpMsgSection
{
public:
    void analyze() override;
    const Field& get_version() const { return version; }

protected:
    NHttpMsgStart(const uint8_t* buffer, const uint16_t buf_size, NHttpFlowData* session_data_,
        NHttpEnums::SourceId source_id_, bool buf_owner, Flow* flow_, const NHttpParaList* params_)
        : NHttpMsgSection(buffer, buf_size, session_data_, source_id_, buf_owner, flow_, params_)
        { }
    virtual void parse_start_line() = 0;
    virtual void gen_events() = 0;
    void derive_version_id();

    Field start_line;
    Field version;
};

#endif


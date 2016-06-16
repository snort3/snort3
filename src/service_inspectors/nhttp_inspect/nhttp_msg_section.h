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
// nhttp_msg_section.h author Tom Peters <thopeter@cisco.com>

#ifndef NHTTP_MSG_SECTION_H
#define NHTTP_MSG_SECTION_H

#include "stream/stream_api.h"
#include "detection/detection_util.h"

#include "nhttp_field.h"
#include "nhttp_module.h"
#include "nhttp_flow_data.h"
#include "nhttp_transaction.h"
#include "nhttp_infractions.h"

//-------------------------------------------------------------------------
// NHttpMsgSection class
//-------------------------------------------------------------------------

class NHttpMsgSection
{
public:
    virtual ~NHttpMsgSection() { if (delete_msg_on_destruct) delete[] msg_text.start; }
    virtual NHttpEnums::InspectSection get_inspection_section() const
        { return NHttpEnums::IS_NONE; }
    NHttpEnums::SourceId get_source_id() { return source_id; }

    // Minimum necessary processing for every message
    virtual void analyze() = 0;

    // Manages the splitter and communication between message sections
    virtual void update_flow() = 0;

    const Field& get_classic_buffer(unsigned id, uint64_t sub_id, uint64_t form);

    // Provide buffer to be sent to detection
    virtual const Field& get_detect_buf() const { return msg_text; }

    NHttpEnums::MethodId get_method_id() const { return method_id; }

#ifdef REG_TEST
    // Test tool prints all derived message parts
    virtual void print_section(FILE* output) = 0;
#endif

protected:
    NHttpMsgSection(const uint8_t* buffer, const uint16_t buf_size, NHttpFlowData* session_data_,
        NHttpEnums::SourceId source_id_, bool buf_owner, Flow* flow_, const NHttpParaList*
        params_);

    const Field msg_text;

    NHttpFlowData* const session_data;
    const NHttpEnums::SourceId source_id;
    Flow* const flow;
    uint64_t msg_num;
    const NHttpParaList* const params;
    NHttpTransaction* const transaction;
    const bool tcp_close;

    NHttpInfractions infractions;
    NHttpEventGen events;
    NHttpEnums::VersionId version_id;
    NHttpEnums::MethodId method_id;
    int32_t status_code_num;

    // Convenience methods shared by multiple subclasses
    void update_depth() const;
    static const Field& classic_normalize(const Field& raw, Field& norm, bool& norm_alloc,
        const NHttpParaList::UriParam& uri_param);
#ifdef REG_TEST
    void print_section_title(FILE* output, const char* title) const;
    void print_section_wrapup(FILE* output) const;
    void print_peg_counts(FILE* output) const;
#endif

private:
    const bool delete_msg_on_destruct;
};

#endif


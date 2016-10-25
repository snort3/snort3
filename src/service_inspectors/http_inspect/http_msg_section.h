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
// http_msg_section.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP_MSG_SECTION_H
#define HTTP_MSG_SECTION_H

#include "detection/detection_util.h"

#include "http_field.h"
#include "http_module.h"
#include "http_flow_data.h"
#include "http_transaction.h"
#include "http_infractions.h"

//-------------------------------------------------------------------------
// HttpMsgSection class
//-------------------------------------------------------------------------

class HttpMsgSection
{
public:
    virtual ~HttpMsgSection() { if (delete_msg_on_destruct) delete[] msg_text.start; }
    virtual HttpEnums::InspectSection get_inspection_section() const
        { return HttpEnums::IS_NONE; }
    HttpEnums::SourceId get_source_id() { return source_id; }

    // Minimum necessary processing for every message
    virtual void analyze() = 0;

    // Manages the splitter and communication between message sections
    virtual void update_flow() = 0;

    const Field& get_classic_buffer(unsigned id, uint64_t sub_id, uint64_t form);

    // Provide buffer to be sent to detection
    virtual const Field& get_detect_buf() const { return msg_text; }

    HttpEnums::MethodId get_method_id() const { return method_id; }

    // Publish an inspection event for other modules to consume.
    virtual void publish() { }

#ifdef REG_TEST
    // Test tool prints all derived message parts
    virtual void print_section(FILE* output) = 0;
#endif

protected:
    HttpMsgSection(const uint8_t* buffer, const uint16_t buf_size, HttpFlowData* session_data_,
        HttpEnums::SourceId source_id_, bool buf_owner, Flow* flow_, const HttpParaList*
        params_);

    const Field msg_text;

    HttpFlowData* const session_data;
    const HttpEnums::SourceId source_id;
    Flow* const flow;
    uint64_t trans_num;
    const HttpParaList* const params;
    HttpTransaction* const transaction;
    const bool tcp_close;

    HttpInfractions infractions;
    HttpEventGen events;
    HttpEnums::VersionId version_id;
    HttpEnums::MethodId method_id;
    int32_t status_code_num;

    // Convenience methods shared by multiple subclasses
    void update_depth() const;
    static const Field& classic_normalize(const Field& raw, Field& norm, bool& norm_alloc,
        const HttpParaList::UriParam& uri_param);
#ifdef REG_TEST
    void print_section_title(FILE* output, const char* title) const;
    void print_section_wrapup(FILE* output) const;
    void print_peg_counts(FILE* output) const;
#endif

private:
    const bool delete_msg_on_destruct;
};

#endif


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
// http_msg_section.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP_MSG_SECTION_H
#define HTTP_MSG_SECTION_H

#include "detection/detection_util.h"

#include "http_field.h"
#include "http_module.h"
#include "http_flow_data.h"
#include "http_transaction.h"

//-------------------------------------------------------------------------
// HttpMsgSection class
//-------------------------------------------------------------------------

class HttpMsgSection
{
public:
    virtual ~HttpMsgSection() = default;
    virtual HttpEnums::InspectSection get_inspection_section() const
        { return HttpEnums::IS_NONE; }
    virtual bool detection_required() const;
    HttpEnums::SourceId get_source_id() const { return source_id; }
    HttpTransaction* get_transaction() const { return transaction; }
    const HttpParaList* get_params() const { return params; }

    // Minimum necessary processing for every message
    virtual void analyze() = 0;

    // analyze() generates many events in the course of its work. Many other events are generated
    // by JIT normalization but only if someone asks for the item in question. gen_events()
    // addresses a third category--things that do not come up during analysis but must be
    // inspected for every message even if no one else asks about them.
    virtual void gen_events() {}

    // Manages the splitter and communication between message sections
    virtual void update_flow() = 0;

    const Field& get_classic_buffer(unsigned id, uint64_t sub_id, uint64_t form);

    HttpEnums::MethodId get_method_id() const { return method_id; }

    int32_t get_status_code_num() const { return status_code_num; }

    // Publish an inspection event for other modules to consume.
    virtual void publish() { }

#ifdef REG_TEST
    // Test tool prints all derived message parts
    virtual void print_section(FILE* output) = 0;
#endif

protected:
    HttpMsgSection(const uint8_t* buffer, const uint16_t buf_size, HttpFlowData* session_data_,
        HttpEnums::SourceId source_id_, bool buf_owner, snort::Flow* flow_, const HttpParaList*
        params_);

    const Field msg_text;
    HttpFlowData* const session_data;
    snort::Flow* const flow;
    const HttpParaList* const params;
    HttpTransaction* const transaction;
    uint64_t trans_num;
    int32_t status_code_num;
    const HttpEnums::SourceId source_id;
    HttpEnums::VersionId version_id;
    HttpEnums::MethodId method_id;
    const bool tcp_close;

    // Convenience methods shared by multiple subclasses
    void add_infraction(int infraction);
    void create_event(int sid);
    void update_depth() const;
    static const Field& classic_normalize(const Field& raw, Field& norm,
        const HttpParaList::UriParam& uri_param);
#ifdef REG_TEST
    void print_section_title(FILE* output, const char* title) const;
    void print_section_wrapup(FILE* output) const;
    void print_peg_counts(FILE* output) const;
#endif
};

#endif


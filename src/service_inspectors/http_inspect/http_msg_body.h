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
// http_msg_body.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP_MSG_BODY_H
#define HTTP_MSG_BODY_H

#include "http_msg_section.h"
#include "http_field.h"

//-------------------------------------------------------------------------
// HttpMsgBody class
//-------------------------------------------------------------------------

class HttpMsgBody : public HttpMsgSection
{
public:
    void analyze() override;
    HttpEnums::InspectSection get_inspection_section() const override
        { return detection_section ? HttpEnums::IS_DETECTION : HttpEnums::IS_BODY; }
    bool detection_required() const override;
    const Field& get_classic_client_body();
    const Field& get_detect_data() { return detect_data; }
    static void fd_event_callback(void* context, int event);

protected:
    HttpMsgBody(const uint8_t* buffer, const uint16_t buf_size, HttpFlowData* session_data_,
        HttpEnums::SourceId source_id_, bool buf_owner, snort::Flow* flow_,
        const HttpParaList* params_);

    int64_t body_octets;

#ifdef REG_TEST
    void print_body_section(FILE* output);
#endif

private:
    void do_file_processing(Field& file_data);
    void do_utf_decoding(const Field& input, Field& output);
    void do_pdf_swf_decompression(const Field& input, Field& output);
    void do_js_normalization(const Field& input, Field& output);

    Field detect_data;
    Field classic_client_body;   // URI normalization applied
    Field decoded_body;
    Field decompressed_pdf_swf_body;
    Field js_norm_body;
    const bool detection_section;
};

#endif


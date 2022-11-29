//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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

#include "file_api/file_api.h"

#include <list>

#include "http_common.h"
#include "http_enum.h"
#include "http_field.h"
#include "http_msg_section.h"

//-------------------------------------------------------------------------
// HttpMsgBody class
//-------------------------------------------------------------------------

class HttpMsgBody : public HttpMsgSection
{
public:
    ~HttpMsgBody() override { delete mime_bufs; }
    void analyze() override;
    snort::PduSection get_inspection_section() const override
        { return snort::PS_BODY; }
    bool detection_required() const override { return (detect_data.length() > 0); }
    bool run_detection(snort::Packet* p) override;
    void clear() override;
    HttpMsgBody* get_body() override { return this; }
    const Field& get_classic_client_body();
    const Field& get_raw_body() { return raw_body; }
    const Field& get_decomp_vba_data();
    const Field& get_norm_js_data();
    const Field& get_detect_data() { return detect_data; }
    const Field& get_msg_text_new() const { return msg_text_new; }
    static void fd_event_callback(void* context, int event);
    bool is_first() { return first_body; }
    void publish() override;
    int32_t get_publish_length() const;

protected:
    HttpMsgBody(const uint8_t* buffer, const uint16_t buf_size, HttpFlowData* session_data_,
        HttpCommon::SourceId source_id_, bool buf_owner, snort::Flow* flow_,
        const HttpParaList* params_);

    int64_t body_octets;
    bool first_body;

#ifdef REG_TEST
    void print_body_section(FILE* output, const char* body_type_str);
#endif

private:
    void do_file_processing(const Field& file_data);
    void do_utf_decoding(const Field& input, Field& output);
    void do_file_decompression(const Field& input, Field& output);
    void do_legacy_js_normalization(const Field& input, Field& output);
    HttpJSNorm* acquire_js_ctx();
    HttpJSNorm* acquire_js_ctx_mime();
    void clear_js_ctx_mime();

    void clean_partial(uint32_t& partial_inspected_octets, uint32_t& partial_detect_length,
        uint8_t*& partial_detect_buffer,  uint32_t& partial_js_detect_length);
    void bookkeeping_regular_flush(uint32_t& partial_detect_length,
        uint8_t*& partial_detect_buffer, uint32_t& partial_js_detect_length,
        int32_t detect_length);
    void get_file_info( FileDirection dir, const uint8_t*& filename_buffer,
        uint32_t& filename_length, const uint8_t*& uri_buffer, uint32_t& uri_length);
    void get_ole_data();

    Field msg_text_new;
    Field decoded_body;
    Field raw_body;              // request_depth or response_depth applied
    Field decompressed_file_body;
    Field cumulative_data;
    Field js_norm_body;
    Field detect_data;
    Field norm_js_data;
    Field classic_client_body;   // URI normalization applied

    // MIME buffers
    Field decompressed_vba_data;
    Field ole_data;
    std::list<MimeBufs>* mime_bufs = nullptr;
    bool last_attachment_complete = true;

    int32_t publish_length = HttpCommon::STAT_NOT_PRESENT;
};

#endif


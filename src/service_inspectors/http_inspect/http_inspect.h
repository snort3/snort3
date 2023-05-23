//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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
// http_inspect.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP_INSPECT_H
#define HTTP_INSPECT_H

//-------------------------------------------------------------------------
// HttpInspect class
//-------------------------------------------------------------------------

#include "framework/cursor.h"
#include "framework/pdu_section.h"
#include "helpers/literal_search.h"
#include "log/messages.h"

#include "http_buffer_info.h"
#include "http_common.h"
#include "http_enum.h"
#include "http_field.h"
#include "http_inspect_base.h"
#include "http_module.h"
#include "http_stream_splitter.h"

class HttpApi;
class HttpParam;

class HttpInspect : public HttpInspectBase
{
public:
    HttpInspect(const HttpParaList* params_);
    ~HttpInspect() override;

    bool get_buf(snort::InspectionBuffer::Type ibt, snort::Packet* p,
        snort::InspectionBuffer& b) override;
    bool get_buf(unsigned id, snort::Packet* p, snort::InspectionBuffer& b) override;
    const Field& http_get_buf(snort::Packet* p, const HttpBufferInfo& buffer_info) const;
    const Field& http_get_param_buf(Cursor& c, snort::Packet* p,
        const HttpParam& param) const;
    int32_t http_get_num_headers(snort::Packet* p, const HttpBufferInfo& buffer_info) const;
    int32_t http_get_max_header_line(snort::Packet* p, const HttpBufferInfo& buffer_info) const;
    int32_t http_get_num_cookies(snort::Packet* p, const HttpBufferInfo& buffer_info) const;
    HttpEnums::VersionId http_get_version_id(snort::Packet* p,
        const HttpBufferInfo& buffer_info) const;
    HttpCommon::SectionType get_type_expected(snort::Flow* flow, HttpCommon::SourceId source_id) const override;
    void finish_hx_body(snort::Flow* flow, HttpCommon::SourceId source_id, HttpCommon::HXBodyState state,
        bool clear_partial_buffer) const override;
    void set_hx_body_state(snort::Flow* flow, HttpCommon::SourceId source_id, HttpCommon::HXBodyState state) const override;
    bool get_fp_buf(snort::InspectionBuffer::Type ibt, snort::Packet* p,
        snort::InspectionBuffer& b) override;
    bool configure(snort::SnortConfig*) override;
    void show(const snort::SnortConfig*) const override;
    void eval(snort::Packet* p) override;
    void eval(snort::Packet* p, HttpCommon::SourceId source_id, const uint8_t* data, uint16_t dsize) override;
    void clear(snort::Packet* p) override;

    HttpStreamSplitter* get_splitter(bool is_client_to_server) override
    { return &splitter[is_client_to_server ? HttpCommon::SRC_CLIENT : HttpCommon::SRC_SERVER]; }

    bool can_carve_files() const override
    { return true; }

    bool can_start_tls() const override
    { return true; }

    static snort::PduSection get_latest_is(const snort::Packet* p);
    static HttpCommon::SourceId get_latest_src(const snort::Packet* p);
    void disable_detection(snort::Packet* p);

    // Callbacks that provide "extra data"
    static int get_xtra_trueip(snort::Flow*, uint8_t**, uint32_t*, uint32_t*);
    static int get_xtra_uri(snort::Flow*, uint8_t**, uint32_t*, uint32_t*);
    static int get_xtra_host(snort::Flow*, uint8_t** buf, uint32_t* len, uint32_t* type);
    static int get_xtra_jsnorm(snort::Flow*, uint8_t**, uint32_t*, uint32_t*);

    unsigned get_pub_id()
    { return pub_id; }

    const uint8_t* adjust_log_packet(snort::Packet* p, uint16_t& length) override;

private:
    friend HttpApi;
    friend HttpStreamSplitter;

    HttpStreamSplitter splitter[2] = { { true, this }, { false, this } };

    void process(const uint8_t* data, const uint16_t dsize, snort::Flow* const flow,
        HttpCommon::SourceId source_id_, bool buf_owner, snort::Packet* p) const;
    static HttpFlowData* http_get_flow_data(const snort::Flow* flow);
    static void http_set_flow_data(snort::Flow* flow, HttpFlowData* flow_data);

    const HttpParaList* const params;
    snort::LiteralSearch::Handle* s_handle = nullptr;
    ScriptFinder* script_finder = nullptr;

    // Registrations for "extra data"
    const uint32_t xtra_trueip_id;
    const uint32_t xtra_uri_id;
    const uint32_t xtra_host_id;
    const uint32_t xtra_jsnorm_id;

    unsigned pub_id; // for inspection events
};

#endif


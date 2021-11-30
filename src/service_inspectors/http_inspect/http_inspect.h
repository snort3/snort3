//--------------------------------------------------------------------------
// Copyright (C) 2014-2021 Cisco and/or its affiliates. All rights reserved.
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
#include "helpers/literal_search.h"
#include "log/messages.h"

#include "http_buffer_info.h"
#include "http_common.h"
#include "http_enum.h"
#include "http_field.h"
#include "http_module.h"
#include "http_msg_section.h"
#include "http_stream_splitter.h"

class HttpApi;

class HttpInspect : public snort::Inspector
{
public:
    HttpInspect(const HttpParaList* params_);
    ~HttpInspect() override { delete params; delete script_finder; }

    bool get_buf(snort::InspectionBuffer::Type ibt, snort::Packet* p,
        snort::InspectionBuffer& b) override;
    bool get_buf(unsigned id, snort::Packet* p, snort::InspectionBuffer& b) override;
    const Field& http_get_buf(Cursor& c, snort::Packet* p,
        const HttpBufferInfo& buffer_info) const;
    int32_t http_get_num_headers(snort::Packet* p, const HttpBufferInfo& buffer_info) const;
    bool get_fp_buf(snort::InspectionBuffer::Type ibt, snort::Packet* p,
        snort::InspectionBuffer& b) override;
    bool configure(snort::SnortConfig*) override;
    void show(const snort::SnortConfig*) const override;
    void eval(snort::Packet* p) override;
    void clear(snort::Packet* p) override;

    HttpStreamSplitter* get_splitter(bool is_client_to_server) override
    { return new HttpStreamSplitter(is_client_to_server, this); }

    bool can_carve_files() const override
    { return true; }

    bool can_start_tls() const override
    { return true; }

    static HttpEnums::InspectSection get_latest_is(const snort::Packet* p);
    static HttpCommon::SourceId get_latest_src(const snort::Packet* p);
    void disable_detection(snort::Packet* p);

    // Callbacks that provide "extra data"
    static int get_xtra_trueip(snort::Flow*, uint8_t**, uint32_t*, uint32_t*);
    static int get_xtra_uri(snort::Flow*, uint8_t**, uint32_t*, uint32_t*);
    static int get_xtra_host(snort::Flow*, uint8_t** buf, uint32_t* len, uint32_t* type);
    static int get_xtra_jsnorm(snort::Flow*, uint8_t**, uint32_t*, uint32_t*);

private:
    friend HttpApi;
    friend HttpStreamSplitter;

    bool process(const uint8_t* data, const uint16_t dsize, snort::Flow* const flow,
        HttpCommon::SourceId source_id_, bool buf_owner) const;
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
};

#endif


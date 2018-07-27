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
// http_inspect.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP_INSPECT_H
#define HTTP_INSPECT_H

//-------------------------------------------------------------------------
// HttpInspect class
//-------------------------------------------------------------------------

#include "http_enum.h"
#include "http_field.h"
#include "http_module.h"
#include "http_msg_section.h"
#include "http_stream_splitter.h"
#include "log/messages.h"

class HttpApi;

class HttpInspect : public snort::Inspector
{
public:
    HttpInspect(const HttpParaList* params_);
    ~HttpInspect() override { delete params; }

    bool get_buf(snort::InspectionBuffer::Type ibt, snort::Packet* p,
        snort::InspectionBuffer& b) override;
    bool get_buf(unsigned id, snort::Packet* p, snort::InspectionBuffer& b) override;
    bool http_get_buf(unsigned id, uint64_t sub_id, uint64_t form, snort::Packet* p,
        snort::InspectionBuffer& b);
    bool get_fp_buf(snort::InspectionBuffer::Type ibt, snort::Packet* p, snort::InspectionBuffer& b) override;
    bool configure(snort::SnortConfig*) override;
    void show(snort::SnortConfig*) override { snort::LogMessage("HttpInspect\n"); }
    void eval(snort::Packet* p) override;
    void clear(snort::Packet* p) override;
    HttpStreamSplitter* get_splitter(bool is_client_to_server) override
    {
        return new HttpStreamSplitter(is_client_to_server, this);
    }
    static HttpEnums::InspectSection get_latest_is(const snort::Packet* p);

    // Callbacks that provide "extra data"
    static int get_xtra_trueip(snort::Flow*, uint8_t**, uint32_t*, uint32_t*);
    static int get_xtra_uri(snort::Flow*, uint8_t**, uint32_t*, uint32_t*);
    static int get_xtra_host(snort::Flow*, uint8_t** buf, uint32_t* len, uint32_t* type);
    static int get_xtra_jsnorm(snort::Flow*, uint8_t**, uint32_t*, uint32_t*);

private:
    friend HttpApi;
    friend HttpStreamSplitter;

    bool process(const uint8_t* data, const uint16_t dsize, snort::Flow* const flow,
        HttpEnums::SourceId source_id_, bool buf_owner) const;
    static HttpEnums::SourceId get_latest_src(const snort::Packet* p);

    const HttpParaList* const params;

    // Registrations for "extra data"
    static uint32_t xtra_trueip_id;
    static uint32_t xtra_uri_id;
    static uint32_t xtra_host_id;
    static uint32_t xtra_jsnorm_id;
};

#endif


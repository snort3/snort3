//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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
// http_msg_request.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP_MSG_REQUEST_H
#define HTTP_MSG_REQUEST_H

#include "http_common.h"
#include "http_enum.h"
#include "http_msg_start.h"
#include "http_query_parser.h"
#include "http_str_to_code.h"
#include "http_uri.h"
#include "http_uri_norm.h"

//-------------------------------------------------------------------------
// HttpMsgRequest class
//-------------------------------------------------------------------------

class HttpMsgRequest : public HttpMsgStart
{
public:
    HttpMsgRequest(const uint8_t* buffer, const uint16_t buf_size, HttpFlowData* session_data_,
        HttpCommon::SourceId source_id_, bool buf_owner, snort::Flow* flow_,
        const HttpParaList* params_);
    ~HttpMsgRequest() override;
    bool detection_required() const override
        { return version_id == HttpEnums::VERS_0_9; }
    snort::PduSection get_inspection_section() const override
        { return snort::PS_HEADER; }
    void gen_events() override;
    void update_flow() override;
    void publish(unsigned pub_id) override;

    const Field& get_method() { return method; }
    const Field& get_uri();
    const Field& get_uri_norm_classic();
    std::string get_aux_ip();
    HttpUri* get_http_uri() { return uri; }
    ParameterMap& get_query_params();
    ParameterMap& get_body_params();

    static bool is_webdav(HttpEnums::MethodId method)
    {
        if(method > HttpEnums::MethodId::METH__WEBDAV_LOW and
           method < HttpEnums::MethodId::METH__WEBDAV_HIGH)
        {
            return true;
        }

        return false;
    }

#ifdef REG_TEST
    void print_section(FILE* output) override;
#endif

private:
    static const StrCode method_list[];

    void parse_start_line() override;
    bool http_name_nocase_ok(const uint8_t* start);
    bool handle_zero_nine();

    Field method;
    HttpUri* uri = nullptr;

    ParameterMap* query_params = nullptr;
    ParameterMap* body_params = nullptr;
};

#endif


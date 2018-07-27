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
// http_msg_head_shared.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP_MSG_HEAD_SHARED_H
#define HTTP_MSG_HEAD_SHARED_H

#include <bitset>

#include "http_str_to_code.h"
#include "http_header_normalizer.h"
#include "http_msg_section.h"
#include "http_field.h"

//-------------------------------------------------------------------------
// HttpMsgHeadShared class
//-------------------------------------------------------------------------

class HttpMsgHeadShared : public HttpMsgSection
{
public:
    void analyze() override;

    const Field& get_classic_raw_header();
    const Field& get_classic_raw_cookie();
    const Field& get_classic_norm_header();
    const Field& get_classic_norm_cookie();
    const Field& get_header_value_raw(HttpEnums::HeaderId header_id) const;
    const Field& get_header_value_norm(HttpEnums::HeaderId header_id);
    int get_header_count(HttpEnums::HeaderId header_id) const;

    // Tables of header field names and header value names
    static const StrCode header_list[];
    static const StrCode content_code_list[];
    static const StrCode charset_code_list[];
    static const StrCode charset_code_opt_list[];

protected:
    HttpMsgHeadShared(const uint8_t* buffer, const uint16_t buf_size,
        HttpFlowData* session_data_, HttpEnums::SourceId source_id_, bool buf_owner, snort::Flow* flow_,
        const HttpParaList* params_)
        : HttpMsgSection(buffer, buf_size, session_data_, source_id_, buf_owner, flow_, params_)
        { }
    ~HttpMsgHeadShared() override;
    // Get the next item in a comma-separated header value and convert it to an enum value
    static int32_t get_next_code(const Field& field, int32_t& offset, const StrCode table[]);
    // Do a case insensitive search for "boundary=" in a Field
    static bool boundary_present(const Field& field);

#ifdef REG_TEST
    void print_headers(FILE* output);
#endif

private:
    static const int MAX = HttpEnums::HEAD__MAX_VALUE;

    // Header normalization strategies. There should be one defined for every different way we can
    // process a header field value.
    static const HeaderNormalizer NORMALIZER_BASIC;
    static const HeaderNormalizer NORMALIZER_NO_REPEAT;
    static const HeaderNormalizer NORMALIZER_CASE_INSENSITIVE;
    static const HeaderNormalizer NORMALIZER_NUMBER;
    static const HeaderNormalizer NORMALIZER_TOKEN_LIST;
    static const HeaderNormalizer NORMALIZER_METHOD_LIST;
    static const HeaderNormalizer NORMALIZER_DATE;
    static const HeaderNormalizer NORMALIZER_URI;
    static const HeaderNormalizer NORMALIZER_CONTENT_LENGTH;
    static const HeaderNormalizer NORMALIZER_CHARSET;

    // Master table of known header fields and their normalization strategies.
    static const HeaderNormalizer* const header_norms[];

    // All of these are indexed by the relative position of the header field in the message
    static const int MAX_HEADERS = 200;  // I'm an arbitrary number. FIXIT-L
    static const int MAX_HEADER_LENGTH = 4096; // Based on max cookie size of some browsers

    void parse_header_block();
    int32_t find_next_header(const uint8_t* buffer, int32_t length, int32_t& num_seps);
    void parse_header_lines();
    void create_norm_head_list();
    void derive_header_name_id(int index);

    Field classic_raw_header;    // raw headers with cookies spliced out
    Field classic_norm_header;   // URI normalization applied
    Field classic_norm_cookie;   // URI normalization applied to concatenated cookie values
    Field* header_line = nullptr;
    Field* header_name = nullptr;
    HttpEnums::HeaderId* header_name_id = nullptr;
    Field* header_value = nullptr;

    struct NormalizedHeader
    {
        NormalizedHeader(HttpEnums::HeaderId id_) : id(id_) {}

        Field norm;
        NormalizedHeader* next;
        int32_t count;
        const HttpEnums::HeaderId id;
    };
    NormalizedHeader* get_header_node(HttpEnums::HeaderId k) const;
    NormalizedHeader* norm_heads = nullptr;

    int32_t num_headers = HttpEnums::STAT_NOT_COMPUTE;
    std::bitset<MAX> headers_present = 0;
};

#endif


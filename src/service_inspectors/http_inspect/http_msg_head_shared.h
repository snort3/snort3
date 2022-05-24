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
// http_msg_head_shared.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP_MSG_HEAD_SHARED_H
#define HTTP_MSG_HEAD_SHARED_H

#include <bitset>

#include "http_common.h"
#include "http_enum.h"
#include "http_field.h"
#include "http_msg_section.h"
#include "http_normalized_header.h"
#include "http_str_to_code.h"

//-------------------------------------------------------------------------
// HttpMsgHeadShared class
//-------------------------------------------------------------------------

class HttpMsgHeadShared : public HttpMsgSection
{
public:
    void analyze() override;

    const Field& get_classic_raw_cookie();
    const Field& get_classic_norm_header();
    const Field& get_classic_norm_cookie();
    const Field& get_header_value_raw(HttpEnums::HeaderId header_id) const;
    const Field& get_all_header_values_raw(HttpEnums::HeaderId header_id);
    const Field& get_header_value_norm(HttpEnums::HeaderId header_id);
    int get_header_count(HttpEnums::HeaderId header_id) const;

    // Tables of header field names and header value names
    static const StrCode header_list[];
    static const StrCode content_code_list[];
    static const StrCode content_type_list[];
    static const StrCode charset_code_list[];
    static const StrCode charset_code_opt_list[];
    static const StrCode transfer_encoding_list[];
    static const StrCode upgrade_list[];

    // The file_cache_index is used along with the source ip and destination ip to cache file
    // verdicts.
    uint64_t get_file_cache_index();
    const Field& get_content_disposition_filename();
    int32_t get_num_headers() const { return num_headers; }
    int32_t get_content_type();

    static const int MAX_HEADERS = 200;  // I'm an arbitrary number. FIXIT-RC
protected:
    HttpMsgHeadShared(const uint8_t* buffer, const uint16_t buf_size,
        HttpFlowData* session_data_, HttpCommon::SourceId source_id_, bool buf_owner, snort::Flow* flow_,
        const HttpParaList* params_);
    ~HttpMsgHeadShared() override;
    // Get the next item in a comma-separated header value and convert it to an enum value
    static int32_t get_next_code(const Field& field, int32_t& offset, const StrCode table[]);
    // Do a case insensitive search for "boundary=" in a Field
    static bool boundary_present(const Field& field);

#ifdef REG_TEST
    void print_headers(FILE* output);
#endif

private:
    static const int MAX = HttpEnums::HEAD__MAX_VALUE + HttpEnums::MAX_CUSTOM_HEADERS;

    // All of these are indexed by the relative position of the header field in the message
    static const int MAX_HEADER_LENGTH = 4096; // Based on max cookie size of some browsers

    void parse_header_block();
    int32_t find_next_header(const uint8_t* buffer, int32_t length, int32_t& num_seps);
    void parse_header_lines();
    void create_norm_head_list();
    void derive_header_name_id(int index);
    const Field& get_classic_raw_header();

    Field classic_raw_header;    // raw headers with cookies spliced out
    Field classic_norm_header;   // URI normalization applied
    Field classic_norm_cookie;   // URI normalization applied to concatenated cookie values
    Field* header_line = nullptr;
    Field* header_name = nullptr;
    HttpEnums::HeaderId* header_name_id = nullptr;
    Field* header_value = nullptr;

    NormalizedHeader* get_header_node(HttpEnums::HeaderId k) const;
    NormalizedHeader* norm_heads = nullptr;

    int32_t num_headers = HttpCommon::STAT_NOT_COMPUTE;
    std::bitset<MAX> headers_present = 0;

    void extract_filename_from_content_disposition();
    Field content_disposition_filename;
    uint64_t file_cache_index = 0;
    bool file_cache_index_computed = false;

    bool own_msg_buffer;
    int32_t content_type = HttpCommon::STAT_NOT_COMPUTE;
};

#endif


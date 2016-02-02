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
// nhttp_msg_head_shared.h author Tom Peters <thopeter@cisco.com>

#ifndef NHTTP_MSG_HEAD_SHARED_H
#define NHTTP_MSG_HEAD_SHARED_H

#include <bitset>

#include "nhttp_str_to_code.h"
#include "nhttp_head_norm.h"
#include "nhttp_msg_section.h"
#include "nhttp_field.h"

//-------------------------------------------------------------------------
// NHttpMsgHeadShared class
//-------------------------------------------------------------------------

class NHttpMsgHeadShared : public NHttpMsgSection
{
public:
    void analyze() override;

    int32_t get_num_headers() const { return num_headers; }
    const Field& get_classic_raw_header();
    const Field& get_classic_raw_cookie();
    const Field& get_classic_norm_header();
    const Field& get_classic_norm_cookie();
    const Field& get_header_line(int k) const { return header_line[k]; }
    const Field& get_header_name(int k) const { return header_name[k]; }
    const Field& get_header_value(int k) const { return header_value[k]; }
    NHttpEnums::HeaderId get_header_name_id(int k)  const { return header_name_id[k]; }
    const Field& get_header_value_norm(NHttpEnums::HeaderId header_id);
    int get_header_count(NHttpEnums::HeaderId header_id) const;

    // Tables of header field names and header value names
    static const StrCode header_list[];
    static const StrCode trans_code_list[];
    static const StrCode content_code_list[];

protected:
    NHttpMsgHeadShared(const uint8_t* buffer, const uint16_t buf_size,
        NHttpFlowData* session_data_, NHttpEnums::SourceId source_id_, bool buf_owner, Flow* flow_,
        const NHttpParaList* params_)
        : NHttpMsgSection(buffer, buf_size, session_data_, source_id_, buf_owner, flow_, params_)
        { }
    ~NHttpMsgHeadShared();

#ifdef REG_TEST
    void print_headers(FILE* output);
#endif

private:
    static const int MAX = NHttpEnums::HEAD__MAX_VALUE;

    // Header normalization strategies. There should be one defined for every different way we can
    // process a header field value.
    static const HeaderNormalizer NORMALIZER_BASIC;
    static const HeaderNormalizer NORMALIZER_NUMBER;
    static const HeaderNormalizer NORMALIZER_TOKEN_LIST;
    static const HeaderNormalizer NORMALIZER_CAT;
    static const HeaderNormalizer NORMALIZER_COOKIE;

    // Master table of known header fields and their normalization strategies.
    static const HeaderNormalizer* const header_norms[];

    // All of these are indexed by the relative position of the header field in the message
    static const int MAX_HEADERS = 200;  // I'm an arbitrary number. FIXIT-L
    static const int MAX_HEADER_LENGTH = 4096; // Based on max cookie size of some browsers

    void parse_header_block();
    uint32_t find_header_end(const uint8_t* buffer, int32_t length, int& num_seps);
    void parse_header_lines();
    void create_norm_head_list();
    void derive_header_name_id(int index);

    std::bitset<MAX> headers_present = 0;
    int32_t num_headers = NHttpEnums::STAT_NOT_COMPUTE;
    Field* header_line = nullptr;
    Field* header_name = nullptr;
    NHttpEnums::HeaderId* header_name_id = nullptr;
    Field* header_value = nullptr;

    Field classic_raw_header;    // raw headers with cookies spliced out
    bool classic_raw_header_alloc = false;
    Field classic_norm_header;   // URI normalization applied
    bool classic_norm_header_alloc = false;
    Field classic_norm_cookie;   // URI normalization applied to concatenated cookie values
    bool classic_norm_cookie_alloc = false;

    struct NormalizedHeader
    {
        NHttpEnums::HeaderId id;
        int count;
        Field norm;
        NormalizedHeader* next;
    };

    NormalizedHeader* norm_heads = nullptr;
    NormalizedHeader* get_header_node(NHttpEnums::HeaderId k) const;
};

#endif


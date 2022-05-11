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
// http_module.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP_MODULE_H
#define HTTP_MODULE_H

#include <bitset>
#include <string>
#include <unordered_set>

#include "framework/module.h"
#include "helpers/literal_search.h"
#include "mime/file_mime_config.h"
#include "profiler/profiler.h"

#include "http_enum.h"
#include "http_str_to_code.h"

#define HTTP_NAME "http_inspect"
#define HTTP_HELP "HTTP inspector"

namespace snort
{
class Trace;
struct SnortConfig;
}

extern THREAD_LOCAL const snort::Trace* http_trace;

struct HttpParaList
{
public:
    ~HttpParaList();
    int64_t request_depth = -1;
    int64_t response_depth = -1;

    bool unzip = true;
    bool normalize_utf = true;
    int64_t maximum_host_length = -1;
    int64_t maximum_chunk_length = 0xFFFFFFFF;
    bool decompress_pdf = false;
    bool decompress_swf = false;
    bool decompress_zip = false;
    bool decompress_vba = false;
    snort::DecodeConfig* mime_decode_conf;
    bool script_detection = false;
    snort::LiteralSearch::Handle* script_detection_handle = nullptr;
    bool publish_request_body = true;

    struct JsNormParam
    {
    public:
        ~JsNormParam();
        bool normalize_javascript = false;
        int64_t js_norm_bytes_depth = -1;
        int32_t js_identifier_depth = 0;
        uint8_t max_template_nesting = 32;
        uint32_t max_bracket_depth = 256;
        uint32_t max_scope_depth = 256;
        std::unordered_set<std::string> ignored_ids;
        std::unordered_set<std::string> ignored_props;
        int max_javascript_whitespaces = 200;
        class HttpJsNorm* js_norm = nullptr;
    };
    JsNormParam js_norm_param;

    struct UriParam
    {
    public:
        UriParam();
        ~UriParam() { delete[] unicode_map; }

        bool percent_u = false;
        bool utf8 = true;
        bool utf8_bare_byte = false;
        int oversize_dir_length = 300;
        bool iis_unicode = false;
        std::string iis_unicode_map_file;
        int iis_unicode_code_page = 1252;
        uint8_t* unicode_map = nullptr;
        bool iis_double_decode = true;
        bool backslash_to_slash = true;
        bool plus_to_space = true;
        bool simplify_path = true;
        std::bitset<256> bad_characters;
        std::bitset<256> unreserved_char;
        HttpEnums::CharAction uri_char[256];

        static const std::bitset<256> default_unreserved_char;
    };
    UriParam uri_param;

    // This will store list of custom xff headers. These are stored in the
    // order of the header preference. The default header preference only
    // consists of known XFF Headers in the below order
    // 1. X-Forwarded-For
    // 2. True-Client-IP
    // Rest of the custom XFF Headers would be added to this list and will be
    // positioned based on the preference of the headers.
    // As of now, plan is to support a maximum of 8 xff type headers.
    StrCode xff_headers[HttpEnums::MAX_XFF_HEADERS + 1] = {};
    // The below header_list contains the list of known static header along with
    // any custom headers mapped with the their respective Header IDs.
    StrCode header_list[HttpEnums::HEAD__MAX_VALUE + HttpEnums::MAX_CUSTOM_HEADERS + 1] = {};

#ifdef REG_TEST
    int64_t print_amount = 1200;

    bool test_input = false;
    bool test_output = false;
    bool print_hex = false;
    bool show_pegs = true;
    bool show_scan = false;
#endif
};

class ScriptFinder
{
public:
    ScriptFinder(snort::LiteralSearch::Handle* h) : handle(h), 
        finder(snort::LiteralSearch::instantiate(h, (const uint8_t*)"</SCRIPT>", 9, true, true))
    {}

    ~ScriptFinder() { delete finder; }

    int search(const uint8_t* buf, unsigned len) const
    { return finder->search(handle, buf, len); }

private:
    snort::LiteralSearch::Handle* const handle;
    const snort::LiteralSearch* const finder;
};

class HttpModule : public snort::Module
{
public:
    HttpModule();
    ~HttpModule() override;
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    unsigned get_gid() const override { return HttpEnums::HTTP_GID; }
    const snort::RuleMap* get_rules() const override { return http_events; }

    const HttpParaList* get_once_params()
    {
        HttpParaList* ret_val = params;
        params = nullptr;
        return ret_val;
    }

    const PegInfo* get_pegs() const override { return peg_names; }
    PegCount* get_counts() const override { return peg_counts; }
    static void increment_peg_counts(HttpEnums::PEG_COUNT counter)
        { peg_counts[counter]++; }
    static void increment_peg_counts(HttpEnums::PEG_COUNT counter, uint64_t value)
        { peg_counts[counter] += value; }
    static void decrement_peg_counts(HttpEnums::PEG_COUNT counter)
        { peg_counts[counter]--; }
    static PegCount get_peg_counts(HttpEnums::PEG_COUNT counter)
        { return peg_counts[counter]; }

    snort::ProfileStats* get_profile() const override;

    static snort::ProfileStats& get_profile_stats()
    { return http_profile; }

    Usage get_usage() const override
    { return INSPECT; }

    bool is_bindable() const override
    { return true; }

    void set_trace(const snort::Trace*) const override;
    const snort::TraceOption* get_trace_options() const override;

#ifdef REG_TEST
    static const PegInfo* get_peg_names() { return peg_names; }
    static const PegCount* get_peg_counts() { return peg_counts; }
    static void reset_peg_counts()
    {
        for (unsigned k=0; k < HttpEnums::PEG_COUNT_MAX; peg_counts[k++] = 0);
    }
#endif

private:
    static const snort::Parameter http_params[];
    static const snort::RuleMap http_events[];
    HttpParaList* params = nullptr;
    static const PegInfo peg_names[];
    static THREAD_LOCAL snort::ProfileStats http_profile;
    static THREAD_LOCAL PegCount peg_counts[];
    snort::LiteralSearch::Handle* const script_detection_handle;
};

#endif


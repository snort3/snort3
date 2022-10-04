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
// http_module.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_module.h"

#include "log/messages.h"
#include "trace/trace.h"

#include "http_enum.h"
#include "http_js_norm.h"
#include "http_uri_norm.h"
#include "http_msg_head_shared.h"

using namespace snort;
using namespace HttpEnums;

HttpModule::HttpModule() : Module(HTTP_NAME, HTTP_HELP, http_params),
    script_detection_handle(LiteralSearch::setup())
{
}

HttpModule::~HttpModule()
{
    delete params;
    LiteralSearch::cleanup(script_detection_handle);
}

static const Parameter js_norm_ident_ignore_param[] =
{
    { "ident_name", Parameter::PT_STRING, nullptr, nullptr, "name of the identifier to ignore" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter js_norm_prop_ignore_param[] =
{
    { "prop_name", Parameter::PT_STRING, nullptr, nullptr, "name of the object property to ignore" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

const Parameter HttpModule::http_params[] =
{
    { "request_depth", Parameter::PT_INT, "-1:max53", "-1",
      "maximum request message body bytes to examine (-1 no limit)" },

    { "response_depth", Parameter::PT_INT, "-1:max53", "-1",
      "maximum response message body bytes to examine (-1 no limit)" },

    { "unzip", Parameter::PT_BOOL, nullptr, "true",
      "decompress gzip and deflate message bodies" },

    { "maximum_host_length", Parameter::PT_INT, "-1:max53", "-1",
      "maximum allowed length for Host header value (-1 no limit)" },

    { "maximum_chunk_length", Parameter::PT_INT, "0:4294967295", "4294967295",
      "maximum allowed length for a message body chunk" },

    { "maximum_header_length", Parameter::PT_INT, "0:65535", "4096",
      "alert when the length of a header exceeds this value" },

    { "maximum_headers", Parameter::PT_INT, "0:65535", "200",
      "alert when the number of headers in a message exceeds this value" },

    { "normalize_utf", Parameter::PT_BOOL, nullptr, "true",
      "normalize charset utf encodings in response bodies" },

    { "decompress_pdf", Parameter::PT_BOOL, nullptr, "false",
      "decompress pdf files in response bodies" },

    { "decompress_swf", Parameter::PT_BOOL, nullptr, "false",
      "decompress swf files in response bodies" },

    { "decompress_zip", Parameter::PT_BOOL, nullptr, "false",
      "decompress zip files in response bodies" },

    { "decompress_vba", Parameter::PT_BOOL, nullptr, "false",
      "decompress MS Office Visual Basic for Applications macro files in response bodies" },

    { "script_detection", Parameter::PT_BOOL, nullptr, "false",
      "inspect JavaScript immediately upon script end" },

    { "normalize_javascript", Parameter::PT_BOOL, nullptr, "false",
      "use legacy normalizer to normalize JavaScript in response bodies" },

    { "js_norm_bytes_depth", Parameter::PT_INT, "-1:max53", "-1",
      "number of input JavaScript bytes to normalize (-1 unlimited)" },

    // range of accepted identifier names is (var_0000:var_ffff), so the max is 2^16
    { "js_norm_identifier_depth", Parameter::PT_INT, "0:65536", "65536",
      "max number of unique JavaScript identifiers to normalize" },

    { "js_norm_max_tmpl_nest", Parameter::PT_INT, "0:255", "32",
      "maximum depth of template literal nesting that enhanced javascript normalizer "
      "will process" },

    { "js_norm_max_bracket_depth", Parameter::PT_INT, "1:65535", "256",
      "maximum depth of bracket nesting that enhanced JavaScript normalizer will process" },

    { "js_norm_max_scope_depth", Parameter::PT_INT, "1:65535", "256",
      "maximum depth of scope nesting that enhanced JavaScript normalizer will process" },

    { "js_norm_ident_ignore", Parameter::PT_LIST, js_norm_ident_ignore_param, nullptr,
      "list of JavaScript ignored identifiers which will not be normalized" },

    { "js_norm_prop_ignore", Parameter::PT_LIST, js_norm_prop_ignore_param, nullptr,
      "list of JavaScript ignored object properties which will not be normalized" },

    { "max_javascript_whitespaces", Parameter::PT_INT, "1:65535", "200",
      "maximum consecutive whitespaces allowed within the JavaScript obfuscated data" },

    { "bad_characters", Parameter::PT_BIT_LIST, "255", nullptr,
      "alert when any of specified bytes are present in URI after percent decoding" },

    { "ignore_unreserved", Parameter::PT_STRING, "(optional)", nullptr,
      "do not alert when the specified unreserved characters are percent-encoded in a URI."
      "Unreserved characters are 0-9, a-z, A-Z, period, underscore, tilde, and minus." },

    { "percent_u", Parameter::PT_BOOL, nullptr, "false",
      "normalize %uNNNN and %UNNNN encodings" },

    { "utf8", Parameter::PT_BOOL, nullptr, "true",
      "normalize 2-byte and 3-byte UTF-8 characters to a single byte" },

    { "utf8_bare_byte", Parameter::PT_BOOL, nullptr, "false",
      "when doing UTF-8 character normalization include bytes that were not percent encoded" },

    { "iis_unicode", Parameter::PT_BOOL, nullptr, "false",
      "use IIS unicode code point mapping to normalize characters" },

    { "iis_unicode_map_file", Parameter::PT_STRING, "(optional)", nullptr,
      "file containing code points for IIS unicode." },

    { "iis_unicode_code_page", Parameter::PT_INT, "0:65535", "1252",
      "code page to use from the IIS unicode map file" },

    { "iis_double_decode", Parameter::PT_BOOL, nullptr, "true",
      "perform double decoding of percent encodings to normalize characters" },

    { "oversize_dir_length", Parameter::PT_INT, "1:65535", "300",
      "maximum length for URL directory" },

    { "backslash_to_slash", Parameter::PT_BOOL, nullptr, "true",
      "replace \\ with / when normalizing URIs" },

    { "plus_to_space", Parameter::PT_BOOL, nullptr, "true",
      "replace + with <sp> when normalizing URIs" },

    { "simplify_path", Parameter::PT_BOOL, nullptr, "true",
      "reduce URI directory path to simplest form" },

    { "xff_headers", Parameter::PT_STRING, nullptr, "x-forwarded-for true-client-ip",
      "specifies the xff type headers to parse and consider in the same order "
      "of preference as defined" },

    { "request_body_app_detection", Parameter::PT_BOOL, nullptr, "true",
      "make HTTP/2 request message bodies available for application detection "
          "(detection requires AppId)" },

    { "allowed_methods", Parameter::PT_STRING, nullptr, nullptr,
      "list of allowed methods" },

    { "disallowed_methods", Parameter::PT_STRING, nullptr, nullptr,
      "list of disallowed methods" },

#ifdef REG_TEST
    { "test_input", Parameter::PT_BOOL, nullptr, "false",
      "read HTTP messages from text file" },

    { "test_output", Parameter::PT_BOOL, nullptr, "false",
      "print out HTTP section data" },

    { "print_amount", Parameter::PT_INT, "1:max53", "1200",
      "number of characters to print from a Field" },

    { "print_hex", Parameter::PT_BOOL, nullptr, "false",
      "nonprinting characters printed in [HH] format instead of using an asterisk" },

    { "show_pegs", Parameter::PT_BOOL, nullptr, "true",
      "display peg counts with test output" },

    { "show_scan", Parameter::PT_BOOL, nullptr, "false",
      "display scanned segments" },
#endif

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

THREAD_LOCAL ProfileStats HttpModule::http_profile;

ProfileStats* HttpModule::get_profile() const
{ return &http_profile; }

THREAD_LOCAL PegCount HttpModule::peg_counts[PEG_COUNT_MAX] = { };

THREAD_LOCAL const Trace* http_trace = nullptr;

static const TraceOption http_trace_options[] =
{
    { "js_proc",  TRACE_JS_PROC,  "enable JavaScript processing logging" },
    { "js_dump",  TRACE_JS_DUMP,  "enable JavaScript data logging" },
    { nullptr, 0, nullptr }
};

void HttpModule::set_trace(const Trace* trace) const
{
    http_trace = trace;
}

const TraceOption* HttpModule::get_trace_options() const
{
    return http_trace_options;
}

bool HttpModule::begin(const char* fqn, int, SnortConfig*)
{
    if (strcmp(fqn, "http_inspect"))
        return true;

    delete params;
    params = new HttpParaList;
    return true;
}

static void store_tokens(Value& val, std::set<std::string>& methods)
{
    val.set_first_token();
    std::string tok;
    while (val.get_next_csv_token(tok))
        methods.insert(tok);
}

bool HttpModule::set(const char*, Value& val, SnortConfig*)
{
    if (val.is("request_depth"))
    {
        params->request_depth = val.get_int64();
    }
    else if (val.is("response_depth"))
    {
        params->response_depth = val.get_int64();
    }
    else if (val.is("unzip"))
    {
        params->unzip = val.get_bool();
    }
    else if (val.is("normalize_utf"))
    {
        params->normalize_utf = val.get_bool();
    }
    else if (val.is("maximum_host_length"))
    {
        params->maximum_host_length = val.get_int64();
    }
    else if (val.is("maximum_chunk_length"))
    {
        params->maximum_chunk_length = val.get_int64();
    }
    else if (val.is("maximum_header_length"))
    {
        params->maximum_header_length = val.get_uint16();
    }
    else if (val.is("maximum_headers"))
    {
        params->maximum_headers = val.get_uint16();
    }
    else if (val.is("decompress_pdf"))
    {
        params->decompress_pdf = val.get_bool();
    }
    else if (val.is("decompress_swf"))
    {
        params->decompress_swf = val.get_bool();
    }
    else if (val.is("decompress_zip"))
    {
        params->decompress_zip = val.get_bool();
    }
    else if (val.is("decompress_vba"))
    {
        params->decompress_vba = val.get_bool();
    }
    else if (val.is("script_detection"))
    {
        params->script_detection = val.get_bool();
    }
    else if (val.is("normalize_javascript"))
    {
        params->js_norm_param.normalize_javascript = val.get_bool();
    }
    else if (val.is("js_norm_identifier_depth"))
    {
        params->js_norm_param.js_identifier_depth = val.get_int32();
    }
    else if (val.is("js_norm_bytes_depth"))
    {
        params->js_norm_param.js_norm_bytes_depth = val.get_int64();
    }
    else if (val.is("js_norm_max_tmpl_nest"))
    {
        params->js_norm_param.max_template_nesting = val.get_uint8();
    }
    else if (val.is("js_norm_max_bracket_depth"))
    {
        params->js_norm_param.max_bracket_depth = val.get_uint32();
    }
    else if (val.is("js_norm_max_scope_depth"))
    {
        params->js_norm_param.max_scope_depth = val.get_uint32();
    }
    else if (val.is("ident_name"))
    {
        params->js_norm_param.ignored_ids.insert(val.get_string());
    }
    else if (val.is("prop_name"))
    {
        params->js_norm_param.ignored_props.insert(val.get_string());
    }
    else if (val.is("max_javascript_whitespaces"))
    {
        params->js_norm_param.max_javascript_whitespaces = val.get_uint16();
    }
    else if (val.is("bad_characters"))
    {
        val.get_bits(params->uri_param.bad_characters);
    }
    else if (val.is("ignore_unreserved"))
    {
        const char* ignore = val.get_string();
        while (*ignore != '\0')
        {
            params->uri_param.unreserved_char[*(ignore++)] = false;
        }
    }
    else if (val.is("percent_u"))
    {
        params->uri_param.percent_u = val.get_bool();
    }
    else if (val.is("utf8"))
    {
        params->uri_param.utf8 = val.get_bool();
    }
    else if (val.is("utf8_bare_byte"))
    {
        params->uri_param.utf8_bare_byte = val.get_bool();
    }
    else if (val.is("iis_unicode"))
    {
        params->uri_param.iis_unicode = val.get_bool();
    }
    else if (val.is("iis_unicode_map_file"))
    {
        params->uri_param.iis_unicode_map_file = val.get_string();
    }
    else if (val.is("iis_unicode_code_page"))
    {
        params->uri_param.iis_unicode_code_page = val.get_uint16();
    }
    else if (val.is("iis_double_decode"))
    {
        params->uri_param.iis_double_decode = val.get_bool();
    }
    else if (val.is("oversize_dir_length"))
    {
        params->uri_param.oversize_dir_length = val.get_uint16();
    }
    else if (val.is("backslash_to_slash"))
    {
        params->uri_param.backslash_to_slash = val.get_bool();
        params->uri_param.uri_char[(uint8_t)'\\'] = val.get_bool() ? CHAR_SUBSTIT : CHAR_NORMAL;
    }
    else if (val.is("plus_to_space"))
    {
        params->uri_param.plus_to_space = val.get_bool();
        params->uri_param.uri_char[(uint8_t)'+'] = val.get_bool() ? CHAR_SUBSTIT : CHAR_NORMAL;
    }
    else if (val.is("simplify_path"))
    {
        params->uri_param.simplify_path = val.get_bool();
        params->uri_param.uri_char[(uint8_t)'/'] = val.get_bool() ? CHAR_PATH : CHAR_NORMAL;
        params->uri_param.uri_char[(uint8_t)'.'] = val.get_bool() ? CHAR_PATH : CHAR_NORMAL;
    }
    else if (val.is("xff_headers"))
    {
        std::string header;
        int custom_id_idx = 1;
        int hdr_idx;
        StrCode end_header = {0, nullptr};

        // Delete the default params if any
        for (int idx = 0; params->xff_headers[idx].code; idx++)
        {
            params->xff_headers[idx].code = 0;
            delete[] params->xff_headers[idx].name;
        }

        // The configured text should be converted to lower case as the header
        // text comparison is lower case sensitive
        val.lower();

        // Tokenize the entered config. Every space separated value is a custom xff header and is
        // preferred in the order in which it is configured
        val.set_first_token();
        for (hdr_idx = 0; val.get_next_token(header) && (hdr_idx < MAX_XFF_HEADERS); hdr_idx++)
        {
            int hdr_id;
            hdr_id = str_to_code(header.c_str(), HttpMsgHeadShared::header_list);
            hdr_id = (hdr_id != HttpCommon::STAT_OTHER) ? hdr_id : (HEAD__MAX_VALUE + custom_id_idx++);

            // Copy the custom header params to the params list. The custom
            // headers from this list would be appended to the instance specific
            // header_list
            params->xff_headers[hdr_idx].code = hdr_id;
            params->xff_headers[hdr_idx].name = new char[header.length() + 1];
            strcpy(const_cast<char*>(params->xff_headers[hdr_idx].name), header.c_str());
        }
        params->xff_headers[hdr_idx] = end_header;
    }
    else if (val.is("request_body_app_detection"))
    {
        params->publish_request_body = val.get_bool();
    }
    else if (val.is("allowed_methods"))
        store_tokens(val, params->allowed_methods);
    else if (val.is("disallowed_methods"))
        store_tokens(val, params->disallowed_methods);

#ifdef REG_TEST
    else if (val.is("test_input"))
    {
        params->test_input = val.get_bool();
    }
    else if (val.is("test_output"))
    {
        params->test_output = val.get_bool();
    }
    else if (val.is("print_amount"))
    {
        params->print_amount = val.get_int64();
    }
    else if (val.is("print_hex"))
    {
        params->print_hex = val.get_bool();
    }
    else if (val.is("show_pegs"))
    {
        params->show_pegs = val.get_bool();
    }
    else if (val.is("show_scan"))
    {
        params->show_scan = val.get_bool();
    }
#endif
    return true;
}

static void prepare_http_header_list(HttpParaList* params)
{
    int32_t hdr_idx;
    StrCode end_header = {0, nullptr};

    // Copy the global header_list
    for (hdr_idx = 0; HttpMsgHeadShared::header_list[hdr_idx].code ; hdr_idx++)
    {
        params->header_list[hdr_idx] = HttpMsgHeadShared::header_list[hdr_idx];
    }

    // Copy the custom xff headers to the header list except the known headers
    for (int32_t idx = 0; params->xff_headers[idx].code; idx++)
    {
        int32_t code = str_to_code(params->xff_headers[idx].name, HttpMsgHeadShared::header_list);
        if (code == HttpCommon::STAT_OTHER)
        {
            params->header_list[hdr_idx++] = params->xff_headers[idx];
        }
    }

    // A dummy header object to mark the end of the list
    params->header_list[hdr_idx] = end_header;
}

bool HttpModule::end(const char* fqn, int, SnortConfig*)
{
    if (strcmp(fqn, "http_inspect"))
        return true;

    if (!params->allowed_methods.empty() && !params->disallowed_methods.empty())
        ParseError("allowed methods can't be used in conjunction with disallowed methods");

    if (!params->uri_param.utf8 && params->uri_param.utf8_bare_byte)
    {
        ParseWarning(WARN_CONF, "Meaningless to do bare byte when not doing UTF-8");
        params->uri_param.utf8_bare_byte = false;
    }

    if (params->uri_param.iis_unicode)
    {
        params->uri_param.unicode_map = new uint8_t[65536];
        if (params->uri_param.iis_unicode_map_file.length() == 0)
            UriNormalizer::load_default_unicode_map(params->uri_param.unicode_map);
        else
            UriNormalizer::load_unicode_map(params->uri_param.unicode_map,
                params->uri_param.iis_unicode_map_file.c_str(),
                params->uri_param.iis_unicode_code_page);
    }

    params->js_norm_param.js_norm = new HttpJsNorm(params->uri_param, params->js_norm_param);

    params->script_detection_handle = script_detection_handle;

    prepare_http_header_list(params);

    params->mime_decode_conf = new DecodeConfig();
    params->mime_decode_conf->set_decompress_pdf(params->decompress_pdf);
    params->mime_decode_conf->set_decompress_swf(params->decompress_swf);
    params->mime_decode_conf->set_decompress_zip(params->decompress_zip);
    params->mime_decode_conf->set_decompress_vba(params->decompress_vba);

    return true;
}

HttpParaList::~HttpParaList()
{
    for (int idx = 0; xff_headers[idx].code; idx++)
    {
        delete[] xff_headers[idx].name;
    }
}

HttpParaList::JsNormParam::~JsNormParam()
{
    delete js_norm;
}

// Characters that should not be percent-encoded
// 0-9, a-z, A-Z, tilde, period, underscore, and minus
// Initializer string for std::bitset is in reverse order. The first character is element 255
// and the last is element 0.
// __STRDUMP_DISABLE__
const std::bitset<256> HttpParaList::UriParam::UriParam::default_unreserved_char
    { std::string(
        "00000000" "00000000" "00000000" "00000000"
        "00000000" "00000000" "00000000" "00000000"
        "00000000" "00000000" "00000000" "00000000"
        "00000000" "00000000" "00000000" "00000000"
        "01000111" "11111111" "11111111" "11111110"
        "10000111" "11111111" "11111111" "11111110"
        "00000011" "11111111" "01100000" "00000000"
        "00000000" "00000000" "00000000" "00000000") };
// __STRDUMP_ENABLE__

// Some values in these tables may be changed by configuration parameters.
HttpParaList::UriParam::UriParam() :

  unreserved_char { default_unreserved_char },

  uri_char {
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,

    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_PERCENT,   CHAR_NORMAL,    CHAR_NORMAL,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_SUBSTIT,   CHAR_NORMAL,    CHAR_NORMAL,    CHAR_PATH,      CHAR_PATH,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,

    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,

    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,
    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,    CHAR_NORMAL,

    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,

    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,

    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,

    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,
    CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT,  CHAR_EIGHTBIT
  }
{}


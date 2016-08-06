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

// hi_module.cc author Russ Combs <rucombs@cisco.com>

#include "hi_module.h"

#include <string>

#include "decompress/file_decomp.h"
#include "utils/util.h"

#include "hi_ui_config.h"
#include "hi_events.h"
#include "hi_cmd_lookup.h"
#include "hi_ui_iis_unicode_map.h"

//-------------------------------------------------------------------------
// http_inspect module
//-------------------------------------------------------------------------

// these are shared
static const Parameter hi_umap_params[] =
{
    { "code_page", Parameter::PT_INT, "0:", "1252",
      "select code page in map file" },

    { "map_file", Parameter::PT_STRING, nullptr, nullptr,
      "unicode map file" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter hi_decode_params[] =
{
    { "b64_decode_depth", Parameter::PT_INT, "-1:65535", "0",
      "single packet decode depth" },

    { "bitenc_decode_depth", Parameter::PT_INT, "-1:65535", "0",
      "single packet decode depth" },

    { "max_mime_mem", Parameter::PT_INT, "3276:", "838860",
      "single packet decode depth" },

    { "qp_decode_depth", Parameter::PT_INT, "-1:65535", "0",
      "single packet decode depth" },

    { "uu_decode_depth", Parameter::PT_INT, "-1:65535", "0",
      "single packet decode depth" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter hi_global_params[] =
{
    { "compress_depth", Parameter::PT_INT, "1:65535", "65535",
      "maximum amount of packet payload to decompress" },

    { "decode", Parameter::PT_TABLE, hi_decode_params, nullptr,
      "decode parameters" },

    { "decompress_depth", Parameter::PT_INT, "1:65535", "65535",
      "maximum amount of decompressed data to process" },

    // FIXIT-L does this work with bindings?
    { "detect_anomalous_servers", Parameter::PT_BOOL, nullptr, "false",
      "inspect non-configured ports for HTTP - bad idea" },

    { "max_gzip_mem", Parameter::PT_INT, "3276:", "838860",
      "total memory used for decompression across all active sessions" },

    { "memcap", Parameter::PT_INT, "2304:", "150994944",
      "limit of memory used for logging extra data" },

    //{ "mime", Parameter::PT_TABLE, hi_mime_params, nullptr,
    //  "help" },

    { "proxy_alert", Parameter::PT_BOOL, nullptr, "false",
      "alert on proxy usage for servers without allow_proxy_use" },

    { "unicode_map", Parameter::PT_TABLE, hi_umap_params, nullptr,
      "default unicode map configuration" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap hi_global_rules[] =
{
    { HI_CLIENT_ASCII, HI_CLIENT_ASCII_STR },
    { HI_CLIENT_DOUBLE_DECODE, HI_CLIENT_DOUBLE_DECODE_STR },
    { HI_CLIENT_U_ENCODE, HI_CLIENT_U_ENCODE_STR },
    { HI_CLIENT_BARE_BYTE, HI_CLIENT_BARE_BYTE_STR },
    { HI_CLIENT_BASE36, HI_CLIENT_BASE36_STR },
    { HI_CLIENT_UTF_8,  HI_CLIENT_UTF_8_STR },
    { HI_CLIENT_IIS_UNICODE, HI_CLIENT_IIS_UNICODE_STR },
    { HI_CLIENT_MULTI_SLASH, HI_CLIENT_MULTI_SLASH_STR },
    { HI_CLIENT_IIS_BACKSLASH,  HI_CLIENT_IIS_BACKSLASH_STR },
    { HI_CLIENT_SELF_DIR_TRAV, HI_CLIENT_SELF_DIR_TRAV_STR },
    { HI_CLIENT_DIR_TRAV, HI_CLIENT_DIR_TRAV_STR },
    { HI_CLIENT_APACHE_WS, HI_CLIENT_APACHE_WS_STR },
    { HI_CLIENT_IIS_DELIMITER, HI_CLIENT_IIS_DELIMITER_STR },
    { HI_CLIENT_NON_RFC_CHAR, HI_CLIENT_NON_RFC_CHAR_STR },
    { HI_CLIENT_OVERSIZE_DIR, HI_CLIENT_OVERSIZE_DIR_STR },
    { HI_CLIENT_LARGE_CHUNK, HI_CLIENT_LARGE_CHUNK_STR },
    { HI_CLIENT_PROXY_USE, HI_CLIENT_PROXY_USE_STR },
    { HI_CLIENT_WEBROOT_DIR, HI_CLIENT_WEBROOT_DIR_STR },
    { HI_CLIENT_LONG_HDR, HI_CLIENT_LONG_HDR_STR },
    { HI_CLIENT_MAX_HEADERS, HI_CLIENT_MAX_HEADERS_STR },
    { HI_CLIENT_MULTIPLE_CONTLEN, HI_CLIENT_MULTIPLE_CONTLEN_STR },
    { HI_CLIENT_CHUNK_SIZE_MISMATCH, HI_CLIENT_CHUNK_SIZE_MISMATCH_STR },
    { HI_CLIENT_INVALID_TRUEIP, HI_CLIENT_INVALID_TRUEIP_STR },
    { HI_CLIENT_MULTIPLE_HOST_HDRS, HI_CLIENT_MULTIPLE_HOST_HDRS_STR },
    { HI_CLIENT_LONG_HOSTNAME, HI_CLIENT_LONG_HOSTNAME_STR },
    { HI_CLIENT_EXCEEDS_SPACES, HI_CLIENT_EXCEEDS_SPACES_STR },
    { HI_CLIENT_CONSECUTIVE_SMALL_CHUNKS, HI_CLIENT_CONSECUTIVE_SMALL_CHUNKS_STR },
    { HI_CLIENT_UNBOUNDED_POST, HI_CLIENT_UNBOUNDED_POST_STR },
    { HI_CLIENT_MULTIPLE_TRUEIP_IN_SESSION, HI_CLIENT_MULTIPLE_TRUEIP_IN_SESSION_STR },
    { HI_CLIENT_BOTH_TRUEIP_XFF_HDRS, HI_CLIENT_BOTH_TRUEIP_XFF_HDRS_STR },
    { HI_CLIENT_UNKNOWN_METHOD, HI_CLIENT_UNKNOWN_METHOD_STR },
    { HI_CLIENT_SIMPLE_REQUEST, HI_CLIENT_SIMPLE_REQUEST_STR },
    { HI_CLIENT_UNESCAPED_SPACE_URI, HI_CLIENT_UNESCAPED_SPACE_URI_STR },
    { HI_CLIENT_PIPELINE_MAX, HI_CLIENT_PIPELINE_MAX_STR },
    { 0, nullptr }
};

#define hi_global_help \
    "http inspector global configuration and client rules for use with http_server"

HttpInspectModule::HttpInspectModule() :
    Module(GLOBAL_KEYWORD, hi_global_help, hi_global_params)
{
    config = nullptr;
}

HttpInspectModule::~HttpInspectModule()
{
    if ( config )
        delete config;
}

const RuleMap* HttpInspectModule::get_rules() const
{ return hi_global_rules; }

ProfileStats* HttpInspectModule::get_profile() const
{ return &hiPerfStats; }

const PegInfo* HttpInspectModule::get_pegs() const
{ return peg_names; }

PegCount* HttpInspectModule::get_counts() const
{ return (PegCount*)&hi_stats; }

HTTPINSPECT_GLOBAL_CONF* HttpInspectModule::get_data()
{
    HTTPINSPECT_GLOBAL_CONF* tmp = config;
    config = nullptr;
    return tmp;
}

bool HttpInspectModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("b64_decode_depth") )
        config->decode_conf->set_b64_depth(v.get_long());

    else if ( v.is("bitenc_decode_depth") )
        config->decode_conf->set_bitenc_depth(v.get_long());

    else if ( v.is("code_page") )
        config->iis_unicode_codepage = v.get_long();

    else if ( v.is("compress_depth") )
        config->compr_depth = v.get_long();

    else if ( v.is("decompress_depth") )
        config->decompr_depth = v.get_long();

    else if ( v.is("detect_anomalous_servers") )
        config->anomalous_servers = v.get_bool();

    else if ( v.is("map_file") )
        config->iis_unicode_map_filename = snort_strdup(v.get_string());

    else if ( v.is("max_gzip_mem") )
        config->max_gzip_mem = v.get_long();

    else if ( v.is("max_mime_mem") )
        config->decode_conf->set_max_mime_mem(v.get_long());

    else if ( v.is("memcap") )
        config->memcap = v.get_long();

    else if ( v.is("proxy_alert") )
        config->proxy_alert = v.get_bool();

    else if ( v.is("qp_decode_depth") )
        config->decode_conf->set_qp_depth(v.get_long());

    else if ( v.is("uu_decode_depth") )
        config->decode_conf->set_uu_depth(v.get_long());

    else
        return false;

    return true;
}

bool HttpInspectModule::begin(const char*, int, SnortConfig*)
{
    if ( !config )
        config = new HTTPINSPECT_GLOBAL_CONF;

    return true;
}

bool HttpInspectModule::end(const char* fqn, int, SnortConfig*)
{
    if ( strcmp(fqn, GLOBAL_KEYWORD) )
        return true;

    if ( config->iis_unicode_map_filename )
    {
        hi_ui_parse_iis_unicode_map(
            &config->iis_unicode_map,
            config->iis_unicode_map_filename,
            config->iis_unicode_codepage);
    }
    else
    {
        get_default_unicode_map(
            config->iis_unicode_map,
            config->iis_unicode_codepage);
    }
    return true;
}

//-------------------------------------------------------------------------
// http_server module
//-------------------------------------------------------------------------

#define profiles "default | apache | iis | iis_40 | iis_50"

#define default_methods \
    "GET POST PUT SEARCH MKCOL COPY MOVE LOCK UNLOCK NOTIFY POLL BCOPY " \
    "BDELETE BMOVE LINK UNLINK OPTIONS HEAD DELETE TRACE TRACK CONNECT " \
    "SOURCE SUBSCRIBE UNSUBSCRIBE PROPFIND PROPPATCH BPROPFIND BPROPPATCH " \
    "RPC_CONNECT PROXY_SUCCESS BITS_POST CCM_POST SMS_POST RPC_IN_DATA " \
    "RPC_OUT_DATA RPC_ECHO_DATA"

// You must make a parallel change in Http_Server_Module::Begin().
#define default_non_rfc_chars "0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07"

static const Parameter hi_profile_server_params[] =
{
    { "apache_whitespace", Parameter::PT_BOOL, nullptr, "false",
      "don't alert if tab is used in lieu of space characters" },

    { "ascii", Parameter::PT_BOOL, nullptr, "false",
      "enable decoding ASCII like %2f to /" },

    { "bare_byte", Parameter::PT_BOOL, nullptr, "false",
      "decode non-standard, non-ASCII character encodings" },

    { "chunk_length", Parameter::PT_INT, "1:", "500000",
      "alert on chunk lengths greater than specified" },

    { "client_flow_depth", Parameter::PT_INT, "-1:1460", "0",
      "raw request payload to inspect" },

    { "directory", Parameter::PT_BOOL, nullptr, "false",
      "normalize . and .. sequences out of URI" },

    { "double_decode", Parameter::PT_BOOL, nullptr, "false",
      "iis specific extra decoding" },

    { "iis_backslash", Parameter::PT_BOOL, nullptr, "false",
      "normalize directory slashes" },

    { "iis_delimiter", Parameter::PT_BOOL, nullptr, "false",
      "allow use of non-standard delimiter" },

    { "iis_unicode", Parameter::PT_BOOL, nullptr, "false",
      "enable unicode code point mapping using unicode_map settings" },

    { "iis_unicode_map", Parameter::PT_TABLE, hi_umap_params, nullptr,
      "server unicode map configuration" },

    { "max_header_length", Parameter::PT_INT, "0:65535", "750",
      "maximum allowed client request header field" },

    { "max_headers", Parameter::PT_INT, "0:1024", "100",
      "maximum allowed client request headers" },

    { "max_spaces", Parameter::PT_INT, "0:65535", "200",
      "maximum allowed whitespaces when folding" },

    { "multi_slash", Parameter::PT_BOOL, nullptr, "false",
      "normalize out consecutive slashes in URI" },

    { "non_strict", Parameter::PT_BOOL, nullptr, "true",
      "allows HTTP 0.9 processing" },

    { "max_javascript_whitespaces", Parameter::PT_INT, "0:", "200",
      "maximum number of consecutive whitespaces" },

    { "normalize_utf", Parameter::PT_BOOL, nullptr, "true",
      "normalize response bodies with UTF content-types" },

    { "normalize_javascript", Parameter::PT_BOOL, nullptr, "true",
      "normalize javascript between <script> tags" },

    { "post_depth", Parameter::PT_INT, "-1:65535", "65495",
      "amount of POST data to inspect" },

    { "profile_type", Parameter::PT_ENUM, profiles, "default",
      "set defaults appropriate for selected server" },

    { "server_flow_depth", Parameter::PT_INT, "-1:65535", "0",
      "response payload to inspect; includes headers with extended_response_inspection" },

    { "u_encode", Parameter::PT_BOOL, nullptr, "true",
      "decode %uXXXX character sequences" },

    { "utf_8", Parameter::PT_BOOL, nullptr, "false",
      "decode UTF-8 unicode sequences in URI" },

    { "webroot", Parameter::PT_BOOL, nullptr, "false",
      "alert on directory traversals past the top level (web server root)" },

    { "whitespace_chars", Parameter::PT_BIT_LIST, "255", nullptr,
      "allowed white space characters" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter hi_server_params[] =
{
    { "allow_proxy_use", Parameter::PT_BOOL, nullptr, "false",
      "don't alert on proxy use for this server" },

    { "decompress_pdf", Parameter::PT_BOOL, nullptr, "false",
      "enable decompression of the compressed portions of PDF files" },

    { "decompress_swf", Parameter::PT_BOOL, nullptr, "false",
      "enable decompression of SWF (Adobe Flash content)" },

    { "enable_cookies", Parameter::PT_BOOL, nullptr, "true",
      "extract cookies" },

    { "enable_xff", Parameter::PT_BOOL, nullptr, "false",
      "log True-Client-IP and X-Forwarded-For headers with unified2 alerts as extra data" },

    { "extended_ascii_uri", Parameter::PT_BOOL, nullptr, "false",
      "allow extended ASCII codes in the request URI" },

    { "extended_response_inspection", Parameter::PT_BOOL, nullptr, "true",
      "extract response headers" },

    { "http_methods", Parameter::PT_STRING, nullptr, default_methods,
      "request methods allowed in addition to GET and POST" },

    { "inspect_gzip", Parameter::PT_BOOL, nullptr, "true",
      "enable gzip decompression of compressed bodies" },

    { "inspect_uri_only", Parameter::PT_BOOL, nullptr, "false",
      "disable all detection except for uricontent" },

    { "log_hostname", Parameter::PT_BOOL, nullptr, "false",
      "enable logging of Hostname with unified2 alerts as extra data" },

    { "log_uri", Parameter::PT_BOOL, nullptr, "false",
      "enable logging of URI with unified2 alerts as extra data" },

    { "no_pipeline_req", Parameter::PT_BOOL, nullptr, "false",
      "don't inspect pipelined requests after first (still does general detection)" },

    { "non_rfc_chars", Parameter::PT_BIT_LIST, "255", default_non_rfc_chars,
      "alert on given non-RFC chars being present in the URI" },

    { "normalize_cookies", Parameter::PT_BOOL, nullptr, "false",
      "normalize cookies similar to URI" },

    { "normalize_headers", Parameter::PT_BOOL, nullptr, "false",
      "normalize headers other than cookie similar to URI" },

    { "oversize_dir_length", Parameter::PT_INT, "0:", "500",
      "alert if a URL has a directory longer than this limit" },

    { "profile", Parameter::PT_TABLE, hi_profile_server_params, nullptr,
      "set defaults appropriate for selected server" },

    { "small_chunk_count", Parameter::PT_INT, "0:255", "5",
      "alert if more than this limit of consecutive chunks are below small_chunk_length" },

    { "small_chunk_length", Parameter::PT_INT, "0:255", "10",
      "alert if more than small_chunk_count consecutive chunks below this limit" },

    { "tab_uri_delimiter", Parameter::PT_BOOL, nullptr, "false",
      "whether a tab not preceded by a space is considered a delimiter or part of URI" },

    { "unlimited_decompress", Parameter::PT_BOOL, nullptr, "true",
      "decompress across multiple packets" },

    // FIXIT-M need to implement xff header customization like:
    // {
    //     { name = 'x-forwarded-highest-priority', priority = 1 },
    //     { name = 'x-forwarded-second-highest-priority', priority = 2 },
    //     { name = 'x-forwarded-lowest-priority-custom', priority = 3 }
    // }
    { "xff_headers", Parameter::PT_BOOL, nullptr, "false",
      "not implemented" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap hi_server_rules[] =
{
    { HI_ANOM_SERVER, HI_ANOM_SERVER_STR },
    { HI_SERVER_INVALID_STATCODE, HI_SERVER_INVALID_STATCODE_STR },
    { HI_SERVER_NO_CONTLEN, HI_SERVER_NO_CONTLEN_STR },
    { HI_SERVER_UTF_NORM_FAIL, HI_SERVER_UTF_NORM_FAIL_STR },
    { HI_SERVER_UTF7, HI_SERVER_UTF7_STR },
    { HI_SERVER_DECOMPR_FAILED, HI_SERVER_DECOMPR_FAILED_STR },
    { HI_SERVER_CONSECUTIVE_SMALL_CHUNKS, HI_SERVER_CONSECUTIVE_SMALL_CHUNKS_STR },
    { HI_CLISRV_MSG_SIZE_EXCEPTION, HI_CLISRV_MSG_SIZE_EXCEPTION_STR },
    { HI_SERVER_JS_OBFUSCATION_EXCD, HI_SERVER_JS_OBFUSCATION_EXCD_STR },
    { HI_SERVER_JS_EXCESS_WS, HI_SERVER_JS_EXCESS_WS_STR },
    { HI_SERVER_MIXED_ENCODINGS, HI_SERVER_MIXED_ENCODINGS_STR },
    { HI_SERVER_SWF_ZLIB_FAILURE, HI_SERVER_SWF_ZLIB_FAILURE_STR },
    { HI_SERVER_SWF_LZMA_FAILURE, HI_SERVER_SWF_LZMA_FAILURE_STR },
    { HI_SERVER_PDF_DEFL_FAILURE, HI_SERVER_PDF_DEFL_FAILURE_STR },
    { HI_SERVER_PDF_UNSUP_COMP_TYPE, HI_SERVER_PDF_UNSUP_COMP_TYPE_STR },
    { HI_SERVER_PDF_CASC_COMP, HI_SERVER_PDF_CASC_COMP_STR },
    { HI_SERVER_PDF_PARSE_FAILURE, HI_SERVER_PDF_PARSE_FAILURE_STR },
    { 0, nullptr }
};

#define hi_server_help  \
    "http inspection and server rules; also configure http_inspect"

HttpServerModule::HttpServerModule() :
    Module(SERVER_KEYWORD, hi_server_help, hi_server_params)
{
    server = nullptr;
}

HttpServerModule::~HttpServerModule()
{
    if ( server )
        delete server;
}

const RuleMap* HttpServerModule::get_rules() const
{ return hi_server_rules; }

HTTPINSPECT_CONF* HttpServerModule::get_data()
{
    HTTPINSPECT_CONF* tmp = server;
    server = nullptr;
    return tmp;
}

bool HttpServerModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("allow_proxy_use") )
        server->allow_proxy = v.get_bool();

    else if ( v.is("apache_whitespace") )
        server->apache_whitespace.on = v.get_bool();

    else if ( v.is("ascii") )
        server->ascii.on = v.get_bool();

    else if ( v.is("bare_byte") )
        server->bare_byte.on = v.get_bool();

    else if ( v.is("chunk_length") )
        server->chunk_length = v.get_long();

    else if ( v.is("client_flow_depth") )
        server->client_flow_depth = v.get_long();

    else if ( v.is("code_page") )
        server->iis_unicode_codepage = v.get_long();

    else if ( v.is("decompress_pdf") )
        v.update_mask(server->file_decomp_modes, (FILE_PDF_DEFL_BIT | FILE_REVERT_BIT));

    else if ( v.is("decompress_swf") )
        v.update_mask(server->file_decomp_modes,
            (FILE_SWF_ZLIB_BIT | FILE_SWF_LZMA_BIT | FILE_REVERT_BIT));

    else if ( v.is("directory") )
        server->directory.on = v.get_bool();

    else if ( v.is("double_decode") )
        server->double_decoding.on = v.get_bool();

    else if ( v.is("enable_cookies") )
        server->enable_cookie = v.get_bool();

    else if ( v.is("extended_ascii_uri") )
        server->extended_ascii_uri = v.get_bool();

    else if ( v.is("extended_response_inspection") )
        server->inspect_response = v.get_bool();

    else if ( v.is("enable_xff") )
        server->enable_xff = v.get_bool();

    else if ( v.is("http_methods") )
        methods = v.get_string();

    else if ( v.is("iis_backslash") )
        server->iis_backslash.on = v.get_bool();

    else if ( v.is("iis_delimiter") )
        server->iis_delimiter.on = v.get_bool();

    else if ( v.is("iis_unicode") )
        server->iis_unicode.on = v.get_bool();

    else if ( v.is("inspect_gzip") )
        server->extract_gzip = v.get_bool();

    else if ( v.is("inspect_uri_only") )
        server->uri_only = v.get_bool();

    else if ( v.is("log_hostname") )
        server->log_hostname = v.get_bool();

    else if ( v.is("log_uri") )
        server->log_uri = v.get_bool();

    else if ( v.is("map_file") )
        server->iis_unicode_map_filename = snort_strdup(v.get_string());

    else if ( v.is("max_header_length") )
        server->max_hdr_len = v.get_long();

    else if ( v.is("max_headers") )
        server->max_headers = v.get_long();

    else if ( v.is("max_javascript_whitespaces") )
        server->max_js_ws = v.get_long();

    else if ( v.is("max_spaces") )
        server->max_spaces = v.get_long();

    else if ( v.is("multi_slash") )
        server->multiple_slash.on = v.get_bool();

    else if ( v.is("no_pipeline_req") )
        server->no_pipeline = v.get_bool();

    else if ( v.is("non_rfc_chars") )
        v.get_bits(server->non_rfc_chars);

    else if ( v.is("non_strict") )
        server->non_strict = v.get_bool();

    else if ( v.is("normalize_cookies") )
        server->normalize_cookies = v.get_bool();

    else if ( v.is("normalize_headers") )
        server->normalize_headers = v.get_bool();

    else if ( v.is("normalize_javascript") )
        server->normalize_javascript = v.get_bool();

    else if ( v.is("normalize_utf") )
        server->normalize_utf = v.get_bool();

    else if ( v.is("oversize_dir_length") )
        server->long_dir = v.get_long();

    else if ( v.is("post_depth") )
        server->post_depth = v.get_long();

    else if ( v.is("profile_type") )
        server->profile = (PROFILES)v.get_long();

    else if ( v.is("server_flow_depth") )
        server->server_flow_depth = v.get_long();

    else if ( v.is("small_chunk_count") )
        server->small_chunk_length.num = v.get_long();

    else if ( v.is("small_chunk_length") )
        server->small_chunk_length.size = v.get_long();

    else if ( v.is("tab_uri_delimiter") )
        server->tab_uri_delimiter = v.get_bool();

    else if ( v.is("u_encode") )
        server->u_encoding.on = v.get_bool();

    else if ( v.is("unlimited_decompress") )
        server->unlimited_decompress = v.get_bool();

    else if ( v.is("utf_8") )
        server->utf_8.on = v.get_bool();

    else if ( v.is("webroot") )
        server->webroot.on = v.get_bool();

    else if ( v.is("whitespace_chars") )
        v.get_bits(server->whitespace);

    else if ( v.is("xff_headers") )
        ;

    else
        return false;

    return true;
}

bool HttpServerModule::begin(const char*, int, SnortConfig*)
{
    if ( !server )
    {
        server = new HTTPINSPECT_CONF;
        server->inspect_response = true;
        methods = default_methods;

        // This sets the default non-RFC characters to 0x00 through 0x07
        // You must make a parallel change to the default_non_rfc_chars macro in this file
        for (int i = 0; i <= 7; i++)
        {
            server->non_rfc_chars.set(i);
        }
    }
    return true;
}

bool HttpServerModule::end(const char* fqn, int, SnortConfig*)
{
    if ( strcmp(fqn, SERVER_KEYWORD) )
        return true;

    if ( server->iis_unicode_map_filename )
    {
        hi_ui_parse_iis_unicode_map(
            &server->iis_unicode_map,
            server->iis_unicode_map_filename,
            server->iis_unicode_codepage);
    }
    else
    {
        get_default_unicode_map(
            server->iis_unicode_map,
            server->iis_unicode_codepage);
    }

    {
        Value v(methods.c_str());
        std::string tok;
        v.set_first_token();

        while ( v.get_next_token(tok) )
        {
            char* s = snort_strdup(tok.c_str());
            http_cmd_lookup_add(server->cmd_lookup, s, strlen(s), (HTTP_CMD_CONF*)s);
        }
    }
    return true;
}


/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2002-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
// config.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>
#include <iomanip>

#include "conversion_state.h"
#include "converter.h"
#include "snort2lua_util.h"

namespace {

class HttpInspectServer : public ConversionState
{
public:
    HttpInspectServer(Converter* cv)  : ConversionState(cv) {};
    virtual ~HttpInspectServer() {};
    virtual bool convert(std::stringstream& data_stream);

private:
    missing_arge_error(std::string arg);
};

} // namespace

bool HttpInspectServer::missing_arg_error(std::string arg)
{
    converter->add_comment_to_table("snort.conf missing argument for " + arg);
    return false;
}


#if 0

#* ports { [port] [port] . . . } *
#* iis_unicode_map [file (located in config dir)] [codemap (integer)] *
#* extended_response_inspection *
#* enable_cookie *
#* inspect_gzip *
#* unlimited_decompress *
#* decompress_swf { deflate lzma } *
#* decompress_pdf { deflate } *
#* normalize_javascript *
#* max_javascript_whitespaces [positive integer] *
#* enable_xff *
#* server_flow_depth [integer] *
#* flow_depth [integer] *  (to be deprecated)
#* client_flow_depth [integer] *
#* post_depth [integer] *
#* ascii [yes/no] *
#* extended_ascii_uri *
#* utf_8 [yes/no] *
#* u_encode [yes/no] *
#* bare_byte [yes/no] *
#* iis_unicode [yes/no] *
#* double_decode [yes/no] *
#* non_rfc_char { [byte] [0x00] . . . } *
#* multi_slash [yes/no] *
#* iis_backslash [yes/no] *
#* directory [yes/no] *
#* apache_whitespace [yes/no] *
#* iis_delimiter [yes/no] *
#* chunk_length [non-zero positive integer] *
#* small_chunk_length { <chunk size> <consecutive chunks> } *
#* no_pipeline_req *
#* non_strict *
#* allow_proxy_use *
#* no_alerts *
#* oversize_dir_length [non-zero positive integer] *
#* inspect_uri_only *
#* max_header_length [positive integer] *
#* max_spaces [positive integer] *
#* webroot *
#* tab_uri_delimiter *
#* normalize_headers *
#* normalize_cookies *
#* normalize_utf *
#* max_headers [positive integer] *
#*http_methods { <CMD1> <CMD2> } *
#* log_uri *
#* log_hostname *
#-- Profile Breakout --
#* http_client_body *
#* http_cookie *
#* http_raw_cookie *
#* http_header *
#* http_raw_header *
#* http_method *
#* http_uri *
#* http_raw_uri *
#* http_stat_code *
#* http_stat_msg *
#* http_encode *


    { "allow_proxy_use", Parameter::PT_BOOL, nullptr, "false",
      "don't alert on proxy use for this server" },

    { "apache_whitespace", Parameter::PT_BOOL, nullptr, "true",
      "don't alert if tab is used in lieu of space characters" },

    { "ascii", Parameter::PT_BOOL, nullptr, "true",
      "enable decoding ASCII like %2f to /" },

    { "bare_byte", Parameter::PT_BOOL, nullptr, "false",
      "decode non-standard, non-ASCII character encodings" },

    { "chunk_length", Parameter::PT_INT, "1:", "500000",
      "alert on chunk lengths greater than specified" },

    { "client_flow_depth", Parameter::PT_INT, "-1:1460", "300",
      "raw request payload to inspect" },

    { "directory", Parameter::PT_BOOL, nullptr, "true",
      "normalize . and .. sequences out of URI" },

    { "double_decode", Parameter::PT_BOOL, nullptr, "false",
      "iis specific extra decoding" },

    { "enable_cookies", Parameter::PT_BOOL, nullptr, "false",
      "extract cookies" },

    { "enable_xff", Parameter::PT_BOOL, nullptr, "false",
      "log True-Client-IP and X-Forwarded-For headers with unified2 alerts as extra data" },

    { "extended_ascii_uri", Parameter::PT_BOOL, nullptr, "false",
      "help" },

    { "extended_response_inspection", Parameter::PT_BOOL, nullptr, "false",
      "extract resonse headers" },

    { "http_methods", Parameter::PT_STRING, nullptr, nullptr,
      "request methods allowed in addition to GET and POST" },

    { "iis_backslash", Parameter::PT_BOOL, nullptr, "false",
      "normalize directory slashes" },

    { "iis_delimiter", Parameter::PT_BOOL, nullptr, "true",
      "allow use of non-standard delimiter" },

    { "iis_unicode", Parameter::PT_BOOL, nullptr, "false",
      "enable unicode code point mapping using unicode_map settings" },

    { "iis_unicode_map", Parameter::PT_TABLE, hi_umap_params, nullptr,
      "help" },

    { "inspect_gzip", Parameter::PT_BOOL, nullptr, "false",
      "enable gzip decompression of compressed bodies" },

    { "inspect_uri_only", Parameter::PT_BOOL, nullptr, "false",
      "disable all detection except for uricontent" },

    { "log_hostname", Parameter::PT_BOOL, nullptr, "false",
      "enable logging of Hostname with unified2 alerts as extra data" },

    { "log_uri", Parameter::PT_BOOL, nullptr, "false",
      "enable logging of URI with unified2 alerts as extra data" },

    { "max_header_length", Parameter::PT_INT, "0:65535", "0",
      "maximum allowed client request header field" },

    { "max_headers", Parameter::PT_INT, "0:1024", "0",
      "maximum allowd client request headers" },

    { "max_spaces", Parameter::PT_INT, "0:65535", "200",
      "help" },

    { "multi_slash", Parameter::PT_BOOL, nullptr, "true",
      "normalize out consecutive slashes in URI" },

    { "no_pipeline_req", Parameter::PT_BOOL, nullptr, "false",
      "don't inspect pipelined requests after first (still does general detection)" },

    { "non_rfc_chars", Parameter::PT_BIT_LIST, "255", "false",
      "alert on given non-RFC chars being present in the URI" },

    { "non_strict", Parameter::PT_BOOL, nullptr, "true",
      "allows HTTP 0.9 processing" },

    { "normalize_cookies", Parameter::PT_BOOL, nullptr, "false",
      "help" },

    { "normalize_headers", Parameter::PT_BOOL, nullptr, "false",
      "help" },

    { "normalize_javascript", Parameter::PT_BOOL, nullptr, "false",
      "normalize javascript between <script> tags" },

    { "max_javascript_whitespaces", Parameter::PT_INT, "0:", "200",
      "maximum number of consecutive whitespaces" },

    { "normalize_utf", Parameter::PT_BOOL, nullptr, "false",
      "help" },

    { "oversize_dir_length", Parameter::PT_INT, "0:", "0",
      "alert if a URL has a directory longer than this limit" },

    { "post_depth", Parameter::PT_INT, "-1:65535", "-1",
      "amount of POST data to inspect" },

    { "profile", Parameter::PT_ENUM, profiles, "none",
      "set defaults appropriate for selected server" },

    { "server_flow_depth", Parameter::PT_INT, "-1:65535", "300",
      "response payload to inspect; includes headers with extended_response_inspection" },

    { "small_chunk_count", Parameter::PT_INT, "0:255", "0",
      "alert if more than this limit of consecutive chunks are below small_chunk_length" },

    { "small_chunk_length", Parameter::PT_INT, "0:255", "0",
      "alert if more than small_chunk_count consecutive chunks below this limit" },

    { "tab_uri_delimiter", Parameter::PT_BOOL, nullptr, "false",
      "help" },

    { "u_encode", Parameter::PT_BOOL, nullptr, "false",
      "decode %uXXXX character sequences" },

    { "unicode_map", Parameter::PT_TABLE, hi_umap_params, nullptr,
      "help" },

    { "unlimited_decompress", Parameter::PT_INT, nullptr, "false",
      "decompress across multiple packets" },

    { "utf_8", Parameter::PT_BOOL, nullptr, "true",
      "decode UTF-8 unicode sequences in URI" },

    { "webroot", Parameter::PT_BOOL, nullptr, "true",
      "alert on directory traversals past the top level (web server root)" },

    { "whitespace_chars", Parameter::PT_BIT_LIST, "255", "false",
      "help" },
#endif

bool HttpInspectServer::convert(std::stringstream& data_stream)
{
    std::string keyword;

    if(data_stream >> keyword)
    {
        const ConvertMap* map = util::find_map(output_api, keyword);
        if (map)
        {
            converter->set_state(map->ctor(converter));
            return true;
        }
    }

    return false;    

    data_stream.setstate(std::basic_ios<char>::eofbit);
    return true;    
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter* cv)
{
    return new HttpInspectServer(cv);
}

static const ConvertMap preprocessor_httpinsepct_server = 
{
    "http_inspect_server",
    ctor,
};

const ConvertMap* httpinspect_server_map = &preprocessor_httpinsepct_server;


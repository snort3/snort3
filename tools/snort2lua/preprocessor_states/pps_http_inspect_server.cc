//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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
// pps_nhttp_inspect_server.cc author Bhagya Tholpady <bbantwal@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/s2l_util.h"
#include "helpers/util_binder.h"

namespace preprocessors
{
namespace
{
class HttpInspectServer : public ConversionState
{
public:
    HttpInspectServer(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;

private:
    static int binding_id;

};
} // namespace

int HttpInspectServer::binding_id = 0;

bool HttpInspectServer::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;
    bool ports_set = false;
    bool simplify = false;
    bool slash_dir_set = false;
    auto& bind = cv.make_binder();

    bind.set_when_proto("tcp");
    bind.set_use_type("http_inspect");

    if (!(data_stream >> keyword) || keyword != "server")
    {
        return false;
    }

    if (!(data_stream >> keyword))
        return false;

    if (keyword == "default")
    {
        table_api.open_table("http_inspect");
        table_api.add_diff_option_comment("http_inspect_server", "http_inspect");
    }
    else
    {
        std::string table_name = "http_inspect_" + std::to_string(binding_id);
        bind.set_use_name(table_name);
        table_api.open_table(table_name);
        binding_id++;

        if (keyword == "{")
        {
            std::string tmp;

            while (data_stream >> tmp && tmp != "}")
                bind.add_when_net(tmp);

            if (!data_stream.good())
                return false;
        }
        else
        {
            bind.add_when_net(keyword);
        }
    }

    // parse the file configuration
    while (data_stream >> keyword)
    {
        bool tmpval = true;

        if (keyword == "extended_response_inspection")
            table_api.add_deleted_comment("extended_response_inspection");

        else if (keyword == "allow_proxy_use")
            table_api.add_deleted_comment("allow_proxy_use");

        else if (keyword == "inspect_gzip")
        {
            table_api.add_diff_option_comment("inspect_gzip", "unzip");
            tmpval = table_api.add_option("unzip", true);
        }

        else if (keyword == "unlimited_decompress")
            table_api.add_deleted_comment("unlimited_decompress");

        else if (keyword == "normalize_javascript")
            table_api.add_option("normalize_javascript", true);

        else if (keyword == "enable_xff")
            table_api.add_deleted_comment("enable_xff");

        else if (keyword == "extended_ascii_uri")
            table_api.add_deleted_comment("extended_ascii_uri");

        else if (keyword == "non_strict")
            table_api.add_deleted_comment("non_strict");

        else if (keyword == "inspect_uri_only")
            table_api.add_deleted_comment("inspect_uri_only");

        else if (keyword == "tab_uri_delimiter")
            table_api.add_deleted_comment("tab_uri_delimiter");

        else if (keyword == "normalize_headers")
            table_api.add_deleted_comment("normalize_headers");

        else if (keyword == "normalize_utf")
            tmpval = table_api.add_option("normalize_utf", true);

        else if (keyword == "log_uri")
            table_api.add_deleted_comment("log_uri");

        else if (keyword == "normalize_cookies")
            table_api.add_deleted_comment("normalize_cookies");

        else if (keyword == "log_hostname")
            table_api.add_deleted_comment("log_hostname");

        else if (keyword == "no_pipeline_req")
            table_api.add_deleted_comment("no_pipeline_req");

        else if (keyword == "ascii")
            parse_deleted_option("ascii", data_stream);

        else if (keyword == "utf_8")
        {
            table_api.add_diff_option_comment("utf_8", "utf8");
            tmpval = parse_yn_bool_option("utf8", data_stream, false);
        }

        else if (keyword == "u_encode")
        {
            table_api.add_diff_option_comment("u_encode", "percent_u");
            tmpval = parse_yn_bool_option("percent_u", data_stream, false);
        }

        else if (keyword == "bare_byte")
        {
            table_api.add_diff_option_comment("bare_byte", "utf8_bare_byte");
            tmpval = parse_yn_bool_option("utf8_bare_byte", data_stream, false);
        }

        else if (keyword == "iis_unicode")
        {
            tmpval = parse_yn_bool_option("iis_unicode", data_stream, false);
        }

        else if (keyword == "double_decode")
        {
            table_api.add_diff_option_comment("double_decode", "iis_double_decode");
            tmpval = parse_yn_bool_option("iis_double_decode", data_stream, false);
        }

        else if (keyword == "multi_slash" || keyword == "directory")
        {
            std::string val;
            slash_dir_set = true;

            if (!(data_stream >> val))
                tmpval = simplify = false;
            else if (val == "yes")
                simplify = true;
            else if (val == "no")
                simplify = false;
            else
            {
                table_api.add_comment("Unable to convert_option: " + keyword + ' ' + val);
                tmpval = false;
            }

            table_api.add_diff_option_comment(keyword, "simplify_path");
        }

        else if (keyword == "iis_backslash")
        {
            table_api.add_diff_option_comment("iis_backslash", "backslash_to_slash");
            tmpval = parse_yn_bool_option("backslash_to_slash", data_stream, false);
        }

        else if (keyword == "apache_whitespace")
            parse_deleted_option("apache_whitespace", data_stream);

        else if (keyword == "iis_delimiter")
            parse_deleted_option("iis_delimiter", data_stream);

        else if (keyword == "webroot")
            parse_deleted_option("webroot", data_stream);

        else if (keyword == "max_javascript_whitespaces")
            tmpval = parse_int_option("max_javascript_whitespaces", data_stream, false);

        else if (keyword == "server_flow_depth" || keyword == "flow_depth")
        {
            table_api.add_diff_option_comment(keyword, "response_depth");
            tmpval = parse_int_option_reverse_m10("response_depth", data_stream);
        }
        else if (keyword == "client_flow_depth")
        {
            table_api.add_diff_option_comment("client_flow_depth", "request_depth");
            tmpval = parse_int_option_reverse_m10("request_depth", data_stream);
        }
        else if (keyword == "chunk_length")
            parse_deleted_option("chunk_length", data_stream);

        else if (keyword == "oversize_dir_length")
            tmpval = parse_int_option("oversize_dir_length", data_stream, false);

        else if (keyword == "max_header_length")
            parse_deleted_option("max_header_length", data_stream);

        else if (keyword == "max_spaces")
            parse_deleted_option("max_spaces", data_stream);

        else if (keyword == "max_headers")
            parse_deleted_option("max_headers", data_stream);

        else if (keyword == "no_alerts")
            table_api.add_deleted_comment("no_alerts");

        else if (keyword == "decompress_swf")
        {
            tmpval = parse_bracketed_unsupported_list("decompress_swf", data_stream);
            table_api.add_option("decompress_swf", true);
        }

        else if (keyword == "decompress_pdf")
        {
            tmpval = parse_bracketed_unsupported_list("decompress_pdf", data_stream);
            table_api.add_option("decompress_pdf", true);
        }

        else if (keyword == "http_methods")
            tmpval = parse_bracketed_unsupported_list("http_methods", data_stream);

        else if (keyword == "whitespace_chars")
            tmpval = parse_bracketed_unsupported_list("whitespace_chars", data_stream);

        else if (keyword == "base36")
            parse_deleted_option("base36", data_stream);

        else if (keyword == "post_depth")
            parse_deleted_option("post_depth", data_stream);

        else if (keyword == "non_rfc_char")
        {
            table_api.add_diff_option_comment("non_rfc_char", "bad_characters");
            parse_bracketed_byte_list("bad_characters", data_stream);
        }
        else if (keyword == "enable_cookie")
            table_api.add_deleted_comment("enable_cookie");

        else if (keyword == "ports")
        {
            table_api.add_diff_option_comment("ports", "bindings");

            if ((data_stream >> keyword) && keyword == "{")
            {
                while (data_stream >> keyword && keyword != "}")
                {
                    ports_set = true;
                    bind.add_when_port(keyword);
                }
            }
            else
            {
                data_api.failed_conversion(data_stream, "ports <bracketed_port_list>");
                retval = false;
            }
        }
        else if (keyword == "small_chunk_length")
        {
            std::string bracket;
            int length;
            int consec_chunks;

            if (!(data_stream >> bracket) || bracket != "{" ||
                !(data_stream >> length) ||
                !(data_stream >> consec_chunks) ||
                !(data_stream >> bracket) || bracket != "}")
            {
                tmpval = false;
            }
            else
            {
                table_api.add_deleted_comment("small_chunk_length");
            }
        }
        else if (keyword == "iis_unicode_map")
        {
            std::string map_file;
            int code_page;
            data_stream >> map_file;
            data_stream >> code_page;
            table_api.add_deleted_comment("iis_unicode_map not allowed in sever");
        }
        else if (keyword == "profile")
            parse_deleted_option("profile", data_stream);
        else if ( keyword == "xff_headers" )
            parse_bracketed_unsupported_list("xff_headers", data_stream);
        else
        {
            tmpval = false;
        }

        if (!tmpval)
        {
            data_api.failed_conversion(data_stream, keyword);
            retval = false;
        }
    }

    if ( slash_dir_set )
    {
        if ( !table_api.add_option("simplify_path", simplify) )
        {
            data_api.failed_conversion(data_stream, keyword);
            retval = false;
        }
    }

    if (!ports_set)
        bind.add_when_port("80");

    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    return new HttpInspectServer(c);
}

static const ConvertMap preprocessor_nhttpinpect_server =
{
    "http_inspect_server",
    ctor,
};

const ConvertMap* nhttpinspect_server_map = &preprocessor_nhttpinpect_server;
}

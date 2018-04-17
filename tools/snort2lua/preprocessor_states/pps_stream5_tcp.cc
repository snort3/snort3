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
// pps_stream_tcp.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>
#include <string>

#include "conversion_state.h"
#include "helpers/s2l_util.h"
#include "helpers/util_binder.h"

namespace preprocessors
{
namespace
{
class StreamTcp : public ConversionState
{
public:
    StreamTcp(Converter&);
    bool convert(std::istringstream& data_stream) override;

private:
    Binder* bind_client;
    Binder* bind_server;
    Binder* bind_any;
    Binder* bind_default;
    bool binding_chosen;
    bool ports_set;
    bool protos_set;
    std::vector<std::string> client_protocols;
    std::vector<std::string> server_protocols;
    std::vector<std::string> any_protocols;

    bool parse_small_segments(std::istringstream& data_stream);
    bool parse_ports(std::istringstream& data_stream);
    bool parse_protocol(std::istringstream& data_stream);
    void add_to_bindings(binder_func, std::string param);
};
} // namespace

StreamTcp::StreamTcp(Converter& c) : ConversionState(c)
{
    bind_client = nullptr;
    bind_server = nullptr;
    bind_any = nullptr;
    bind_default = nullptr;
    binding_chosen = false;
    ports_set = false;
    protos_set = false;
}

void StreamTcp::add_to_bindings(binder_func func, std::string param)
{
    (bind_client->*func)(param);
    (bind_server->*func)(param);
    (bind_any->*func)(param);
}

bool StreamTcp::parse_small_segments(std::istringstream& stream)
{
    int consec_segs;
    std::string bytes;
    int min_bytes;
    std::string ignore_ports;

    if (!(stream >> consec_segs) ||
        !(stream >> bytes) ||
        bytes != "bytes" ||
        !(stream >> min_bytes))
        return false;

    table_api.open_table("small_segments");
    table_api.add_option("count", consec_segs);
    table_api.add_option("maximum_size", min_bytes);
    table_api.close_table();

    if ((stream >> ignore_ports) && ignore_ports == "ignore_ports")
    {
        uint16_t port;

        while (stream >> port)
            ignore_ports += " " + std::to_string(port);
        table_api.add_deleted_comment(ignore_ports);
    }

    if (!stream.eof())
        return false;

    return true;
}

bool StreamTcp::parse_ports(std::istringstream& arg_stream)
{
    std::string port;
    std::string dir;
    Binder* bind;

    if (!(arg_stream >> dir))
        return false;

    if ( dir == "client")
    {
        table_api.add_diff_option_comment("client ports",
            "binder.when.ports; binder.when.role = client");
        bind = bind_client;
    }
    else if ( dir == "server")
    {
        table_api.add_diff_option_comment("server ports",
            "binder.when.ports; binder.when.role = server");
        bind = bind_server;
    }
    else if ( dir == "both")
    {
        table_api.add_diff_option_comment("both ports",
            "binder.when.ports; binder.when.role = any");
        bind = bind_any;
    }
    else
    {
        return false;
    }

    // Ensure we only print the chosen bindings
    if (!binding_chosen)
    {
        binding_chosen = true;
        bind_client->print_binding(false);
        bind_client->set_when_role("client");
    }
    bind->print_binding(true);
    bind_default = bind;

    // do nothing if no ports provided
    if (arg_stream >> port )
    {
        ports_set = true;

        // don't set the ports variable for "all"
        if (port == "all")
            void(0);

        // for none, don't print the binding
        else if (port == "none")
            bind->print_binding(false);

        else
        {
            do
            {
                bind->add_when_port(port);
            }
            while (arg_stream >> port);
        }
    }

    return true;
}

bool StreamTcp::parse_protocol(std::istringstream& arg_stream)
{
    std::string dir;
    std::string protocol;
    std::vector<std::string>* protocols;
    Binder* bind;

    // this may seem idiotic, but Snort does not actually require
    // any keywords for the 'protocol' keyword.  So, this is
    // still technically correct.
    if (!(arg_stream >> dir))
        return true;

    if (dir == "client")
    {
        table_api.add_diff_option_comment("client protocol",
            "binder.when.proto; binder.when.role = client");
        bind = bind_client;
        protocols = &client_protocols;
    }
    else if (dir == "server")
    {
        table_api.add_diff_option_comment("server protocol",
            "binder.when.proto; binder.when.role = server");
        bind = bind_server;
        protocols = &server_protocols;
    }
    else if (dir == "both")
    {
        table_api.add_diff_option_comment("both protocol",
            "binder.when.proto; binder.when.role = any");
        bind = bind_any;
        protocols = &any_protocols;
    }
    else
        return false;

    // Ensure we only print the chosen bindings
    if (!binding_chosen)
    {
        binding_chosen = true;
        bind_client->print_binding(false);
        bind_client->set_when_role("client");
    }
    bind->print_binding(true);
    bind_default = bind;

    // do nothing if no ports provided
    if (arg_stream >> protocol )
    {
        protos_set = true;

        // for all, don't set the protos variable
        if (protocol == "all")
            void(0);

        // for none, don't print the binding
        else if (protocol == "none")
            bind->print_binding(false);

        else
        {
            do
            {
                // yes, I agree this may appear odd that I am
                // adding the value to a vector rather than creating a
                // new binder.  The reason is each binder may still
                // change while parsing stream_tcp.  Since I don't want
                // to create and save a new Binder for each protocol,
                // lets save the different protocols and create new
                // Binders at the very end of the convert() functions.
                protocols->push_back(protocol);
            }
            while (arg_stream >> protocol);
        }
    }

    return true;
}

bool StreamTcp::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;

    auto& client = cv.make_binder();
    auto& server = cv.make_binder();
    auto& any = cv.make_binder();

    // by default, only print one binding
    client.print_binding(true);
    server.print_binding(false);
    any.print_binding(false);
    binding_chosen = false;

    // Only set client if specified in ports or protocol.
    // For now, client is the general binding for stream_tcp.
//    client.set_when_role("client");
    server.set_when_role("server");
    any.set_when_role("any");

    // create pointers so other member functions can access binders
    bind_client = &client;
    bind_server = &server;
    bind_any = &any;
    bind_default = bind_client;

    add_to_bindings(&Binder::set_when_proto, "tcp");
    add_to_bindings(&Binder::set_use_type, "stream_tcp");

    table_api.open_table("stream_tcp");

    while (util::get_string(data_stream, keyword, ","))
    {
        bool tmpval = true;
        std::istringstream arg_stream(keyword);

        // should be guaranteed to happen.  Checking for error just cause
        if (!(arg_stream >> keyword))
            tmpval = false;

        if (keyword == "overlap_limit")
            tmpval = parse_int_option("overlap_limit", arg_stream, false);

        else if (keyword == "max_window")
            tmpval = parse_int_option("max_window", arg_stream, false);

        else if (keyword == "small_segments")
            tmpval = parse_small_segments(arg_stream);

        else if (keyword == "ignore_any_rules")
            table_api.add_deleted_comment("ignore_any_rules");

        else if (keyword == "ports")
            tmpval = parse_ports(arg_stream);

        else if (keyword == "detect_anomalies")
            table_api.add_deleted_comment("detect_anomalies");

        else if (keyword == "dont_store_large_packets")
            table_api.add_deleted_comment("dont_store_large_packets");

        else if (keyword == "check_session_hijacking")
            table_api.add_deleted_comment("check_session_hijacking");

        else if (keyword == "log_asymmetric_traffic")
            table_api.add_deleted_comment("log_asymmetric_traffic");

        else if (keyword == "flush_factor")
            tmpval = parse_int_option("flush_factor", arg_stream, false);

        else if (keyword == "protocol")
            tmpval = parse_protocol(arg_stream);

        else if (keyword == "require_3whs")
        {
            int val;

            if ( arg_stream >> val )
                table_api.add_option("require_3whs", val);
            else
                table_api.add_option("require_3whs", 0);
        }
        else if (keyword == "bind_to")
        {
            table_api.add_diff_option_comment("bind_to", "bindings");

            std::string addr;
            if (arg_stream >> addr)
            {
                std::string tmp;
                while (arg_stream >> tmp)
                    addr += " " + tmp;

                add_to_bindings(&Binder::add_when_net, addr);
            }
            else
            {
                tmpval = false;
            }
        }
        else if (keyword == "dont_reassemble_async")
        {
            table_api.add_diff_option_comment("dont_reassemble_async", "reassemble_async");
            tmpval = table_api.add_option("reassemble_async", false);
        }
        else if (keyword == "use_static_footprint_sizes")
        {
            table_api.add_diff_option_comment("use_static_footprint_sizes",
                "stream.footprint = 192");
            table_api.open_top_level_table("stream");
            table_api.add_option("footprint", 192);
            table_api.close_table();
        }
        else if (keyword == "timeout")
        {
            table_api.add_diff_option_comment("timeout", "session_timeout");
            tmpval = parse_int_option("session_timeout", arg_stream, false);
        }
        else if (keyword == "max_queued_segs")
        {
            table_api.add_diff_option_comment("max_queued_segs", "queue_limit.max_segments");
            table_api.open_table("queue_limit");
            tmpval = parse_int_option("max_segments", arg_stream, false);
            table_api.close_table();
        }
        else if (keyword == "max_queued_bytes")
        {
            table_api.add_diff_option_comment("max_queued_bytes", "queue_limit.max_bytes");
            table_api.open_table("queue_limit");
            tmpval = parse_int_option("max_bytes", arg_stream, false);
            table_api.close_table();
        }
        else if (keyword == "policy")
        {
            std::string policy;

            if (!(arg_stream >> policy))
                data_api.failed_conversion(data_stream,  "stream5_tcp: policy <missing_arg>");

            else if (policy == "bsd")
                table_api.add_option("policy", "bsd");

            else if (policy == "first")
                table_api.add_option("policy", "first");

            else if (policy == "irix")
                table_api.add_option("policy", "irix");

            else if (policy == "last")
                table_api.add_option("policy", "last");

            else if (policy == "linux")
                table_api.add_option("policy", "linux");

            else if (policy == "macos")
                table_api.add_option("policy", "macos");

            else if (policy == "old-linux")
                table_api.add_option("policy", "old_linux");

            else if (policy == "solaris")
                table_api.add_option("policy", "solaris");

            else if (policy == "windows")
                table_api.add_option("policy", "windows");

            else if (policy == "vista")
                table_api.add_option("policy", "vista");

            else if (policy == "unknown")
                table_api.add_deleted_comment("policy unknown");

            else if (policy == "noack")
                table_api.add_deleted_comment("policy noack");

            else if (policy == "hpux")
            {
                table_api.add_diff_option_comment("policy hpux", "stream_tcp.policy = hpux11");
                table_api.add_option("policy", "hpux11");
            }
            else if (policy == "hpux10")
                table_api.add_option("policy", "hpux10");

            else if (policy == "win2003")
            {
                table_api.add_diff_option_comment("policy win2003",
                    "stream_tcp.policy = win_2003");
                table_api.add_option("policy", "win_2003");
            }
            else if (policy == "win2k3")
            {
                table_api.add_diff_option_comment("policy win2k3",
                    "stream_tcp.policy = win_2003");
                table_api.add_option("policy", "win_2003");
            }
            else if (policy == "hpux11")
            {
                table_api.add_option("policy", "hpux11");
            }
            else if (policy == "grannysmith")
            {
                table_api.add_diff_option_comment("policy grannysmith",
                    "stream_tcp.policy = macos");
                table_api.add_option("policy", "macos");
            }
            else
            {
                data_api.failed_conversion(data_stream, "stream5_tcp: policy " + policy);
            }
        }
        else
        {
            tmpval = false;
        }

        if (!tmpval)
        {
            data_api.failed_conversion(data_stream, arg_stream.str());
            retval = false;
        }
    }

    if (!ports_set)
    {
        const std::vector<std::string> default_ports = { "21", "23", "25", "42",
                                                         "53", "80", "110", "111", "135", "136",
                                                         "137", "139", "143", "445",
                                                         "513", "514", "1433", "1521", "2401",
                                                         "3306" };

        for (const std::string& s : default_ports)
            bind_default->add_when_port(s);
    }

    //  Add the port bindings separately from the protocol bindings since 
    //  in 2.9.x they are OR'd not AND'd. Clear the ports so they're not 
    //  included with the protocol bindings.
    cv.make_binder(client);
    client.clear_ports();

    cv.make_binder(server);
    server.clear_ports();

    cv.make_binder(any);
    any.clear_ports();

    if (!protos_set)
    {
        const std::vector<std::string> default_protos =
        { "ftp", "telnet", "smtp", "nameserver", "dns", "http",
          "pop3", "sunrpc", "dcerpc", "netbios-ssn", "imap",
          "login", "shell", "mssql", "oracle", "cvs", "mysql" };

        for (const std::string& s : default_protos)
        {
            auto& b = cv.make_binder(*bind_default);
            b.set_when_service(s);
        }
    }

    if (!client_protocols.empty())
    {
        for (const std::string& s : client_protocols)
        {
            auto& b = cv.make_binder(client);
            b.set_when_service(s);
        }
    }

    if (!server_protocols.empty())
    {
        for (const std::string& s : server_protocols)
        {
            auto& b = cv.make_binder(server);
            b.set_when_service(s);
        }
    }

    if (!any_protocols.empty())
    {
        for (const std::string& s : any_protocols)
        {
            auto& b = cv.make_binder(any);
            b.set_when_service(s);
        }
    }

    //  All bindings have already been added.
    client.print_binding(false);
    server.print_binding(false);
    any.print_binding(false);

    table_api.close_table(); // "tcp_stream"
    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    return new StreamTcp(c);
}

static const ConvertMap preprocessor_stream_tcp =
{
    "stream5_tcp",
    ctor,
};

const ConvertMap* stream_tcp_map = &preprocessor_stream_tcp;
} // namespace preprocessors


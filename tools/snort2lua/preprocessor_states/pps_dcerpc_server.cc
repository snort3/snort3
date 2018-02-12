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
// pps_dcerpc_server.cc author Maya Dagon <mdagon@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pps_dcerpc_server.h"

#include <algorithm>
#include <cstring>

namespace preprocessors
{
namespace dce
{
#define MIN_PORT 0
#define MAX_PORT 65535

enum DceDetectListState
{
    DCE_DETECT_LIST_STATE__START,
    DCE_DETECT_LIST_STATE__TYPE,
    DCE_DETECT_LIST_STATE__PORTS_START,
    DCE_DETECT_LIST_STATE__PORTS_END,
    DCE_DETECT_LIST_STATE__END,
};

std::string transport[5] = { "smb", "tcp", "udp", "http_proxy", "http_server" };

std::map <std::string, std::vector<uint16_t> > default_ports
{
    { "smb", { 139, 445 }
    },
    { "tcp", { 135 }
    },
    { "udp", { 135 }
    },
    { "http_proxy", { 80 }
    },
    { "http_server", { 593 }
    }
};

/////////////////////////
// Utility functions
////////////////////////

bool add_option_to_table(TableApi& table_api, const std::string& table_name,
    const std::string& option, const std::string& val)
{
    table_api.open_table(table_name);
    bool tmpval = table_api.add_option(option, val);
    table_api.close_table();

    return tmpval;
}

bool add_option_to_table(TableApi& table_api, const std::string& table_name,
    const std::string& option, const int val)
{
    table_api.open_table(table_name);
    bool tmpval = table_api.add_option(option, val);
    table_api.close_table();

    return tmpval;
}

bool add_option_to_table(TableApi& table_api, const std::string& table_name,
    const std::string& option, const bool val)
{
    table_api.open_table(table_name);
    bool tmpval = table_api.add_option(option, val);
    table_api.close_table();

    return tmpval;
}

bool add_deleted_comment_to_table(TableApi& table_api, const std::string& table_name,
    const std::string& option)
{
    table_api.open_table(table_name);
    bool tmpval = table_api.add_deleted_comment(option);
    table_api.close_table();

    return tmpval;
}

/////////////////////////////
/////   DcerpcServer
/////////////////////////////

int DcerpcServer::binding_id = 0;

DcerpcServer::DcerpcServer(Converter& c) : ConversionState(c)
{
    for (const auto& type: transport)
    {
        detect_ports_set[type] = false;
    }
}

bool DcerpcServer::get_bracket_list(std::istringstream& data_stream, std::string& list)
{
    std::string tail;
    do
    {
        if (!(data_stream >> tail))
        {
            return false;
        }
        list = list + tail;
    }
    while (tail.find(']') == std::string::npos);

    return true;
}

// Read from data_stream either a single value x or list : [x,y,z ... ]
// Put in str either a single value 'x', or space separated list 'x y z'
bool DcerpcServer::convert_val_or_list(std::istringstream& data_stream, std::string& str)
{
    if (!(data_stream >> str))
    {
        return false;
    }

    if ((str.find('[') != std::string::npos) &&  (str.find(']') == std::string::npos))
    {
        if (!get_bracket_list(data_stream, str))
        {
            return false;
        }
    }

    if (str.back() == ',')
        str.pop_back();

    if (str.back() == ']')
        str.pop_back();

    if (str.front() == '[')
        str.erase(0,1);

    // remove additional whitespaces
    str.erase(remove_if(str.begin(), str.end(), isspace), str.end());

    // remove ""
    str.erase(std::remove(str.begin(), str.end(), '"'), str.end());

    // convert ',' separators to spaces
    replace(str.begin(), str.end(), ',', ' ');

    return true;
}

bool DcerpcServer::parse_smb_file_inspection(std::istringstream& data_stream)
{
    bool tmpval = true;
    std::string file_inspect;

    if (!(data_stream >> file_inspect))
    {
        return false;
    }

    if (file_inspect.find('[') == std::string::npos) //single arg
    {
        if (file_inspect.back() == ',')
        {
            file_inspect.pop_back();
        }
        tmpval = table_api.add_option("smb_file_inspection", file_inspect);
    }
    else
    {
        if (file_inspect.find(']') == std::string::npos)
        {
            if (!get_bracket_list(data_stream, file_inspect))
            {
                return false;
            }
        }

        size_t pos = file_inspect.find(',');
        if ((pos == std::string::npos) || (pos <= 1))
        {
            return false;
        }

        std::string arg = file_inspect.substr(1, pos-1);
        // remove additional whitespaces
        arg.erase(remove_if(arg.begin(), arg.end(), isspace), arg.end());
        tmpval = table_api.add_option("smb_file_inspection", arg);

        pos = file_inspect.find("file-depth");
        if (pos == std::string::npos)
        {
            return false;
        }

        arg = file_inspect.substr(pos + strlen("file-depth"));
        tmpval = table_api.add_option("smb_file_depth", std::stoi(arg)) && tmpval;
    }

    return tmpval;
}

void DcerpcServer::add_default_ports(const std::string& type,  std::map<std::string,Binder*> bind)
{
    for (auto port : default_ports[type])
    {
        bind[type]->add_when_port(std::to_string(port));
    }
}

// add single port / range
bool DcerpcServer::parse_and_add_ports(const std::string& ports, const std::string& type, std::map<std::string,
    Binder*> bind, bool bind_port_to_tcp)
{
    if (ports.empty())
    {
        return true;
    }

    std::vector<std::string> port_list;

    util::split(ports, ',', port_list);
    for (const std::string& port : port_list)
    {
        size_t pos = port.find(':');
        if (pos == std::string::npos)
        {
            bind[type]->add_when_port(port);
            if ( bind_port_to_tcp )
                bind["tcp"]->add_when_port(port);
        }
        else
        {
            uint16_t min_port = MIN_PORT;
            uint16_t max_port = MAX_PORT;

            if (pos != 0)
            {
                min_port = std::stoi(port.substr(0, pos));
            }

            if (pos != (port.length()-1))
            {
                max_port = std::stoi(port.substr(pos+1));
            }

            if (max_port < min_port)
            {
                return false;
            }

            for (uint32_t i = min_port; i<= max_port; i++)
            {
                bind[type]->add_when_port(std::to_string(i));
                if ( bind_port_to_tcp )
                    bind["tcp"]->add_when_port(std::to_string(i));
            }
        }
    }

    detect_ports_set[type] = true;

    return true;
}

bool DcerpcServer::parse_detect(std::istringstream& data_stream,
    std::map<std::string,Binder*> bind, bool is_detect)
{
    std::string type;
    bool one_type = false;
    DceDetectListState state = DCE_DETECT_LIST_STATE__START;

    while (state != DCE_DETECT_LIST_STATE__END)
    {
        switch (state)
        {
        case DCE_DETECT_LIST_STATE__START:
        {
            char c = data_stream.peek();
            if (isspace(c))
            {
                data_stream.get(c);
            }
            else if (c == '[')
            {
                data_stream.get(c);
                state = DCE_DETECT_LIST_STATE__TYPE;
            }
            else
            {
                one_type = true;
                state = DCE_DETECT_LIST_STATE__TYPE;
            }
        }
        break;

        case DCE_DETECT_LIST_STATE__TYPE:
        {
            if (!(data_stream >> type))
            {
                return false;
            }

            // clear whitespaces
            type.erase(remove_if(type.begin(), type.end(), isspace), type.end());

            bool use_default_ports = false;

            if (type.back() == ',')
            {
                use_default_ports = true;
                type.pop_back();
                if (one_type)
                {
                    state = DCE_DETECT_LIST_STATE__END;
                }
            }

            if (type == "none")
            {
                for (const auto& transport_type: transport)
                {
                    if (is_detect)
                    {
                        detect_ports_set[transport_type] = true;
                        bind[transport_type]->print_binding(false);
                    }
                }
            }

            if (type.back() == ']')
            {
                return true;
            }

            if (!use_default_ports)
            {
                state = DCE_DETECT_LIST_STATE__PORTS_START;
            }
        }
        break;

        case DCE_DETECT_LIST_STATE__PORTS_START:
        {
            std::string ports;
            bool bind_port_to_tcp = false;

            if (!(data_stream >> ports))
            {
                if (one_type)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }

            if ((ports.find('[') != std::string::npos) &&  (ports.find(']') == std::string::npos))
            {
                std::string tail;

                if (!getline(data_stream, tail,']'))
                {
                    return false;
                }
                ports += tail;
            }

            if (ports.back() == ',')
            {
                ports.pop_back();
                if (!one_type)
                {
                    state = DCE_DETECT_LIST_STATE__TYPE;
                }
            }

            size_t pos = ports.find("]]");
            if ((pos != std::string::npos) ||
                ((ports.find('[') == std::string::npos) &&  (ports.find(']') !=
                std::string::npos)))
            {
                // found outer list separator
                if (one_type)
                {
                    return false;
                }
                else
                {
                    state = DCE_DETECT_LIST_STATE__END;
                }
            }

            if (state == DCE_DETECT_LIST_STATE__PORTS_START) // didn't fall under previous
            {                                                 // conditions
                state = DCE_DETECT_LIST_STATE__PORTS_END;
            }

            if (type == "rpc-over-http-server")
            {
                type = "http_server";
                bind_port_to_tcp = true;
            }
            else if (type == "rpc-over-http-proxy")
            {
                type = "http_proxy";
                bind_port_to_tcp = true;
            }

            // if ports are for unsupported types - stop here
            if (bind.find(type) == bind.end())
            {
                continue;
            }
            // if this is autodetect- stop here
            if (!is_detect)
            {
                add_deleted_comment_to_table(table_api, table_name[type], "autodetect");
                continue;
            }

            // remove '[',']'
            ports.erase(std::remove(ports.begin(), ports.end(), '['), ports.end());
            ports.erase(std::remove(ports.begin(), ports.end(), ']'), ports.end());
            // remove extra spaces
            ports.erase(remove_if(ports.begin(), ports.end(), isspace), ports.end());

            if (!parse_and_add_ports(ports, type, bind, bind_port_to_tcp))
            {
                return false;
            }
        }
        break;

        case DCE_DETECT_LIST_STATE__PORTS_END:
        {
            if (one_type)
            {
                return true;
            }
            else // wait for list terminator or item separator
            {
                char c;

                if (!data_stream.get(c))
                    return false;

                if (c == ']')
                {
                    state = DCE_DETECT_LIST_STATE__END;
                }
                else if (c == ',')
                {
                    state = DCE_DETECT_LIST_STATE__TYPE;
                }
                else if (!isspace(c))
                {
                    return false;
                }
            }
        }
        break;

        default:
            return false;
        }
    }
    return true;
}

bool DcerpcServer::init_net_created_table()
{
    bool tmpval = true;
    std::string val;

    table_api.open_table("dce_smb");
    if (table_api.option_exists("disable_defrag"))
    {
        table_api.close_table();
        for (const auto& type : transport)
        {
            if ( (type == "http_proxy") || (type == "http_server") )
                continue;
            tmpval = add_option_to_table(table_api, table_name[type], "disable_defrag", true) &&
                tmpval;
        }
        table_api.open_table("dce_smb");
    }
    if (table_api.option_exists("max_frag_len"))
    {
        if (!table_api.get_option_value("max_frag_len", val))
        {
            return false;
        }

        table_api.close_table();
        for (const auto& type : transport)
        {
            if ( (type == "http_proxy") || (type == "http_server") )
                continue;
            tmpval = add_option_to_table(table_api,table_name[type], "max_frag_len", std::stoi(
                val)) && tmpval;
        }
        table_api.open_table("dce_smb");
    }
    if (table_api.option_exists("reassemble_threshold"))
    {
        if (!table_api.get_option_value("reassemble_threshold", val))
        {
            return false;
        }

        table_api.close_table();
        for (const auto& type : transport)
        {
            if ( (type == "http_proxy") || (type == "http_server") ||
                (type == "udp") )
                continue;
            tmpval = add_option_to_table(table_api,table_name[type], "reassemble_threshold",
                std::stoi(val)) && tmpval;
        }
        table_api.open_table("dce_smb");
    }
    if (table_api.option_exists("smb_fingerprint_policy"))
    {
        if (!table_api.get_option_value("smb_fingerprint_policy", val))
        {
            return false;
        }
        table_api.close_table();
        tmpval = add_option_to_table(table_api,table_name["smb"], "smb_fingerprint_policy", val) &&
            tmpval;
        table_api.open_table("dce_smb");
    }
    if (table_api.option_exists("smb_legacy_mode"))
    {
        table_api.close_table();
        tmpval = add_option_to_table(table_api,table_name["smb"], "smb_legacy_mode", true) &&
            tmpval;
        table_api.open_table("dce_smb");
    }
    table_api.close_table();

    return tmpval;
}

bool DcerpcServer::init_new_tables(bool is_default)
{
    for (const auto& type : transport)
    {
        if (!is_default)
            table_name[type] = "dce_" + type + std::to_string(binding_id);
        else
            table_name[type] = "dce_" + type;

        // open an empty table - if no args are read binder still
        // reference it
        table_api.open_table(table_name[type]);
        table_api.close_table();
    }

    if (!is_default)
    {
        // copy global config options from default table
        if (!init_net_created_table())
        {
            return false;
        }

        binding_id++;
    }
    return true;
}

bool DcerpcServer::parse_nets(std::istringstream& data_stream, std::map<std::string,
    Binder*> bind)
{
    std::string nets;
    if (!convert_val_or_list(data_stream, nets))
    {
        return false;
    }

    for (const auto& type : transport)
    {
        bind[type]->set_use_name(table_name[type]);
        bind[type]->add_when_net(nets);
    }

    return true;
}

bool DcerpcServer::add_option_to_transports(const std::string& option, const std::string& value, bool co_only)
{
    bool retval = true;

    for (const auto& type: transport)
    {
        if ( (type == "http_proxy") || (type == "http_server") )
            continue;
        if (co_only && (type == "udp"))
            continue;
        table_api.open_table(table_name[type]);
        retval = table_api.add_option(option, value) && retval;
        table_api.close_table();
    }

    return retval;
}

bool DcerpcServer::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;

    auto& bind_tcp = cv.make_binder();
    auto& bind_smb = cv.make_binder();
    auto& bind_udp = cv.make_binder();
    auto& bind_http_proxy = cv.make_binder();
    auto& bind_http_server = cv.make_binder();

    std::map<std::string, Binder*> bind;

    bind["smb"] = &bind_smb;
    bind["tcp"] = &bind_tcp;
    bind["udp"] = &bind_udp;
    bind["http_proxy"] = &bind_http_proxy;
    bind["http_server"] = &bind_http_server;

    // FIXIT-N add when there is a way to make this play with http_inspect bindings
    // port 80 should not be added by default. If explicitly configured and conflicting
    // with other bindings, punt to wizard
    bind["http_proxy"]->print_binding(false);

    for (const auto& type : transport)
    {
        bind[type]->set_when_proto("tcp");
        bind[type]->set_use_type("dce_" + type);
    }
    bind["udp"]->set_when_proto("udp");
    bind["tcp"]->set_when_service("dce_tcp");

    if (!(data_stream >> keyword))
        return false;

    if (keyword.back() == ',')
        keyword.pop_back();

    if (keyword == "default")
    {
        if (!init_new_tables(true))
        {
            return false;
        }
    }
    else
    {
        if (keyword != "net")
        {
            return false;
        }

        if (!init_new_tables(false))
        {
            return false;
        }

        if (!parse_nets(data_stream, bind))
        {
            return false;
        }
    }

    while (data_stream >> keyword)
    {
        bool tmpval = true;

        if (keyword.back() == ',')
            keyword.pop_back();

        if (keyword.empty())
            continue;

        if (keyword == "policy")
        {
            std::string policy;

            if (!(data_stream >> policy))
                return false;

            if (policy.back() == ',')
                policy.pop_back();

            tmpval = add_option_to_transports("policy", policy, true);
        }
        else if (keyword == "detect")
        {
            tmpval = parse_detect(data_stream, bind, true);
        }
        else if (keyword == "autodetect")
        {
            tmpval = parse_detect(data_stream, bind, false);
        }
        else if (keyword == "no_autodetect_http_proxy_ports")
        {
            add_deleted_comment_to_table(table_api, table_name["http_proxy"], "no_autodetect_http_proxy_ports");
        }
        else if (keyword == "smb_invalid_shares")
        {
            std::string invalid_shares;

            if (!convert_val_or_list(data_stream, invalid_shares))
                return false;

            table_api.open_table(table_name["smb"]);
            tmpval = table_api.add_option("smb_invalid_shares", invalid_shares);
            table_api.close_table();
        }
        else if (keyword == "smb_max_chain")
        {
            table_api.open_table(table_name["smb"]);
            tmpval = parse_int_option("smb_max_chain", data_stream, false);
            table_api.close_table();
        }
        else if (keyword == "smb_file_inspection")
        {
            table_api.open_table(table_name["smb"]);
            tmpval = parse_smb_file_inspection(data_stream);
            table_api.close_table();
        }
        else if (keyword == "smb2_max_compound")
        {
            table_api.open_table(table_name["smb"]);
            tmpval = parse_int_option("smb_max_compound", data_stream, false);
            table_api.close_table();
        }
        else if (keyword == "valid_smb_versions")
        {
            std::string versions;

            if (!convert_val_or_list(data_stream, versions))
                return false;

            table_api.open_table(table_name["smb"]);
            tmpval = table_api.add_option("valid_smb_versions", versions);
            table_api.close_table();
        }
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

    for (const auto& type : transport)
    {
        if (!detect_ports_set[type])
        {
            add_default_ports(type, bind);
        }
    }

    return retval;
}
} // namespace dce

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    return new dce::DcerpcServer(c);
}

static const ConvertMap preprocessor_dcerpc_server =
{
    "dcerpc2_server",
    ctor,
};

const ConvertMap* dcerpc_server_map = &preprocessor_dcerpc_server;
} // namespace preprocessors


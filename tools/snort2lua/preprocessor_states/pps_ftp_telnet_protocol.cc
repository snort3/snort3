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
// pps_ftp_telnet_protocol.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <map>
#include <set>
#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/s2l_util.h"
#include "helpers/util_binder.h"

namespace preprocessors
{
/****************************************
 *******  FtpServer Protocol  ***********
 ****************************************/

namespace
{

class FtpServer : public ConversionState
{
public:
    FtpServer(Converter& c) : ConversionState(c)
    {
        commands = ftp_default_command_specs;
    }
    bool convert(std::istringstream& data_stream) override;

private:
    struct Command
    {
        std::string name;
        std::string format;
        int length;
    };

    static const int command_default_len = -1;
    static int ftpserver_binding_id;
    std::vector<Command> commands;

    bool parse_alt_max_cmd(std::istringstream& data_stream);
    bool parse_cmd_validity_cmd(std::istringstream& data_stream);
    std::vector<Command>::iterator get_command(const std::string& cmd_name,
        std::vector<FtpServer::Command>::iterator it);
    bool add_cmd_to_set(std::set<std::string>& cmd_set, std::istringstream& stream);

    std::vector<Command> ftp_default_command_specs =
    {
        { "ABOR", "", 0 },
        { "CCC", "", 0 },
        { "CDUP", "", 0 },
        { "ESTA", "", 0 },
        { "FEAT", "", 0 },
        { "LPSV", "", 0 },
        { "NOOP", "", 0 },
        { "PASV", "", 0 },
        { "PWD", "", 0 },
        { "QUIT", "", 0 },
        { "REIN", "", 0 },
        { "SYST", "", 0 },
        { "XCUP", "", 0 },
        { "XPWD", "", 0 },

        { "APPE", "", 200 },
        { "CMD", "", 200 },
        { "HELP", "", 200 },
        { "NLST", "", 200 },
        { "RETR", "", 200 },
        { "RNFR", "", 200 },
        { "STOR", "", 200 },
        { "STOU", "", 200 },
        { "XMKD", "", 200 },

        { "CWD", "", 256 },
        { "RNTO", "", 256 },
        { "SIZE", "", 512 },

        { "ALLO", "< int [ char R int ] >", 200 },
        { "PORT", "< host_port >", 400 },
        { "LPRT", "< long_host_port >", 400 },
        { "EPRT", "< extd_host_port >", 400 },

        { "EPSV", "< [ { char 12 | char A char L char L } ] >", command_default_len },
        { "MACB", "< string >", command_default_len },
        { "MDTM", "< [ date nnnnnnnnnnnnnn[.n[n[n]]] ] string >", command_default_len },
        { "MODE", "< char ASBCZ >", command_default_len },
        { "PROT", "< char CSEP >", command_default_len },
        { "STRU", "< char FRPO [ string ] >", command_default_len },
        { "TYPE", "< { char AE [ char NTC ] | char I | char L [ number ] } >",
            command_default_len }
    };

};
}  // namespace

int FtpServer::ftpserver_binding_id = 1;

std::vector<FtpServer::Command>::iterator FtpServer::get_command(
    const std::string& cmd_name,
    std::vector<FtpServer::Command>::iterator it)
{
    for (; it != commands.end(); ++it)
        if (cmd_name == (*it).name)
            return it;

    return commands.end();
}

bool FtpServer::parse_alt_max_cmd(std::istringstream& stream)
{
    int len;
    std::string elem;
    bool updated = false;

    if (!(stream >> len))
        return false;

    if (!(stream >> elem) || elem != "{")
        return false;

    while (stream >> elem && elem != "}")
    {
        auto it = get_command(elem, commands.begin()); // it == iterator

        if (it == commands.end())
        {
            Command c;
            c.name = std::string(elem);
            c.length = len;
            commands.push_back(c);
            updated = true;
        }
        else
        {
            // change the length for every command
            do
            {
                if ((*it).length < len)
                {
                    (*it).length = len;
                    updated = true;
                }

                it = get_command(elem, ++it);
            }
            while (it != commands.end());
        }
    }

    if (elem == "}")
    {
        if(updated)
        {
            table_api.open_table("cmd_validity");
            table_api.add_diff_option_comment("alt_max_param_len", "cmd_validity");
            table_api.close_table();
        }
        return updated;
    }
    return false;
}

bool FtpServer::parse_cmd_validity_cmd(std::istringstream& data_stream)
{
    std::string command;
    std::string elem;
    bool updated = false;

    if (!(data_stream >> command) ||
        !(data_stream >> elem) ||
        (elem != "<"))
        return false;

    std::string format = "<";
    while ((data_stream >> elem) && (elem != ">"))
        format += " " + elem;

    // last element must be a '>'
    if (elem != ">")
        return false;

    format += " >";
    auto it = get_command(command, commands.begin());

    if (it == commands.end())
    {
        Command c;
        c.name = std::string(command);
        c.format = std::string(format);
        c.length = command_default_len;
        commands.push_back(c);
        updated = true;
    }
    // command exists, but format unspecified (length likely specified)
    else if (it->format.empty())
    {
        it->format = std::string(format);
        updated = true;
    }
    // command && format exists, but format is different. create new command
    else if (format != it->format)
    {
        Command c;
        c.name = std::string(command);
        c.format = std::string(format);
        c.length = it->length;
        commands.push_back(c);
        updated = true;
    }
    else
    {
        // the two format names and options are identical.
        // do nothing
    }

    return updated;
}

// Add command to existing set of commands if it's not already there.
bool FtpServer::add_cmd_to_set(std::set<std::string>& cmd_set, std::istringstream& stream)
{
    std::string cmd;
    bool updated = false;

    if (!(stream >> cmd) || (cmd != "{"))
        return false;

    while (stream >> cmd && cmd != "}")
    {
        auto result = cmd_set.insert(cmd);
        if(result.second)
            updated = true; // cmd wasn't already in the set.
    }

    return updated;
}


std::set<std::string> ftp_default_cmds =
{
    "ABOR", "ACCT", "ADAT", "ALLO", "APPE", "AUTH", "CCC", "CDUP", "CEL",
    "CLNT", "CMD", "CONF", "CWD", "DELE", "ENC", "EPRT", "EPSV", "ESTA",
    "ESTP", "FEAT", "HELP", "LANG", "LIST", "LPRT", "LPSV", "MACB", "MAIL",
    "MDTM", "MIC", "MKD", "MLSD", "MLST", "MODE", "NLST", "NOOP", "OPTS",
    "PASS", "PASV", "PBSZ", "PORT", "PROT", "PWD", "QUIT", "REIN", "REST",
    "RETR", "RMD", "RNFR", "RNTO", "SDUP", "SITE", "SIZE", "SMNT", "STAT",
    "STOR", "STOU", "STRU", "SYST", "TEST", "TYPE", "USER", "XCUP", "XCRC",
    "XCWD", "XMAS", "XMD5", "XMKD", "XPWD", "XRCP", "XRMD", "XRSQ", "XSEM",
    "XSEN", "XSHA1", "XSHA256"
};

std::set<std::string> ftp_default_data_chan_cmds =
{
    "PORT", "PASV", "LPRT", "LPSV", "EPRT", "EPSV"
};

std::set<std::string> ftp_default_data_xfer_cmds =
{
    "RETR", "STOR", "STOU", "APPE", "LIST", "NLST"
};

std::set<std::string> ftp_default_file_put_cmds = { "STOR", "STOU" };

std::set<std::string> ftp_default_file_get_cmds = { "RETR" };

std::set<std::string> ftp_default_login_cmds = { "USER", "PASS" };

std::set<std::string> ftp_default_encr_cmds = { "AUTH" };

std::set<std::string> ftp_format_commands =
{
    "ACCT", "ADAT", "ALLO", "APPE", "AUTH", "CEL", "CLNT", "CMD", "CONF",
    "CWD", "DELE", "ENC", "EPRT", "EPSV", "ESTP", "HELP", "LANG", "LIST",
    "LPRT", "MACB", "MAIL", "MDTM", "MIC", "MKD", "MLSD", "MLST", "MODE",
    "NLST", "OPTS", "PASS", "PBSZ", "PORT", "PROT", "REST", "RETR", "RMD",
    "RNFR", "RNTO", "SDUP", "SITE", "SIZE", "SMNT", "STAT", "STOR", "STRU",
    "TEST", "TYPE", "USER", "XCRC", "XCWD", "XMAS", "XMD5", "XMKD", "XRCP",
    "XRMD", "XRSQ", "XSEM", "XSEN", "XSHA1", "XSHA256"
};


struct FtpDefaultCmd
{
    std::string default_name;
    std::set<std::string> cmd_set;
};

// Use these defaults for the entries that the original config didn't provide.
static std::map<std::string, FtpDefaultCmd> ftp_defaults =
{
    // NOTE: cmd_validity is handled separately.
    {"chk_str_fmt", {"ftp_format_commands", ftp_format_commands}},
    {"data_chan_cmds", {"ftp_default_data_chan_cmds", ftp_default_data_chan_cmds}},
    {"data_xfer_cmds", {"ftp_default_data_xfer_cmds", ftp_default_data_xfer_cmds}},
    {"encr_cmds", {"ftp_default_encr_cmds", ftp_default_encr_cmds}},
    {"file_put_cmds", {"ftp_default_file_put_cmds", ftp_default_file_put_cmds}},
    {"file_get_cmds", {"ftp_default_file_get_cmds", ftp_default_file_get_cmds}},
    {"ftp_cmds", {"ftp_default_cmds", ftp_default_cmds}},
    {"login_cmds", {"ftp_default_login_cmds", ftp_default_login_cmds}},
};

bool FtpServer::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;
    bool ports_set = false;

    // Set up ftp_data whenever we have ftp_server configured.
    if(!cv.added_ftp_data())
    {
        auto& ftp_data_bind = cv.make_binder();
        ftp_data_bind.set_use_type("ftp_data");
        ftp_data_bind.set_when_service("ftp-data");

        table_api.open_table("ftp_data");
        table_api.close_table();

        cv.set_added_ftp_data();
    }

    auto& bind = cv.make_binder();
    bind.set_use_type("ftp_server");
    bind.set_when_proto("tcp");

    if (data_stream >> keyword)
    {
        if (keyword == "default")
        {
            table_api.open_table("ftp_server");
        }
        else
        {
            std::string table_name = "ftp_server_target_" + std::to_string(ftpserver_binding_id);
            bind.set_use_name(table_name);
            table_api.open_table(table_name);
            ftpserver_binding_id++;

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
    }
    else
    {
        return false;
    }

    std::set<std::string> configured_keywords;
    std::map<std::string, FtpDefaultCmd> updated_defaults = ftp_defaults;

    while (data_stream >> keyword)
    {
        bool tmpval = true;

        if (keyword == "print_cmds")
            tmpval = table_api.add_option("print_cmds", true);

        else if (keyword == "def_max_param_len")
            tmpval = parse_int_option("def_max_param_len", data_stream, false);

        else if (keyword == "telnet_cmds")
            tmpval = parse_yn_bool_option("telnet_cmds", data_stream, false);

        else if (keyword == "ignore_telnet_erase_cmds")
            tmpval = parse_yn_bool_option("ignore_telnet_erase_cmds", data_stream, false);

        else if (keyword == "ignore_data_chan")
            tmpval = parse_yn_bool_option("ignore_data_chan", data_stream, false);

        else if (keyword == "ftp_cmds")
        {
            if(add_cmd_to_set(updated_defaults["ftp_cmds"].cmd_set, data_stream))
                configured_keywords.insert(keyword);
        }

        else if (keyword == "encr_cmds")
        {
            if(add_cmd_to_set(updated_defaults["encr_cmds"].cmd_set, data_stream))
                configured_keywords.insert(keyword);
        }

        else if (keyword == "login_cmds")
        {
            if(add_cmd_to_set(updated_defaults["login_cmds"].cmd_set, data_stream))
                configured_keywords.insert(keyword);
        }

        // FIXIT-M Snort2lua needs to handle dir_cmds.

        else if (keyword == "chk_str_fmt")
        {
            if(add_cmd_to_set(updated_defaults["chk_str_fmt"].cmd_set, data_stream))
                configured_keywords.insert(keyword);
        }

        else if (keyword == "alt_max_param_len")
        {
            // alt_max_param_len is converted to cmd_validity.
            if(parse_alt_max_cmd(data_stream))
                configured_keywords.insert("cmd_validity");
        }

        else if (keyword == "cmd_validity")
        {
            if(parse_cmd_validity_cmd(data_stream))
                configured_keywords.insert(keyword);
        }

        else if (keyword == "data_chan_cmds")
        {
            if(add_cmd_to_set(updated_defaults["data_chan_cmds"].cmd_set, data_stream))
                configured_keywords.insert(keyword);
        }

        else if (keyword == "data_rest_cmds")
            tmpval = parse_curly_bracket_list("data_rest_cmds", data_stream);

        else if (keyword == "data_xfer_cmds")
        {
            if(add_cmd_to_set(updated_defaults["data_xfer_cmds"].cmd_set, data_stream))
                configured_keywords.insert(keyword);
        }

        else if (keyword == "file_put_cmds")
        {
            if(add_cmd_to_set(updated_defaults["file_put_cmds"].cmd_set, data_stream))
                configured_keywords.insert(keyword);
        }

        else if (keyword == "file_get_cmds")
        {
            if(add_cmd_to_set(updated_defaults["file_get_cmds"].cmd_set, data_stream))
                configured_keywords.insert(keyword);
        }

        else if (keyword == "data_chan")
        {
            table_api.add_diff_option_comment("data_chan", "ignore_data_chan");
            tmpval = table_api.add_option("ignore_data_chan", true);
        }
        else if (keyword == "ports")
        {
            table_api.add_diff_option_comment("ports", "bindings");
            table_api.add_comment("check bindings table for port information");

            if ((data_stream >> keyword) && keyword == "{")
            {
                while (data_stream >> keyword && keyword != "}")
                {
                    bind.add_when_port(keyword);
                    ports_set = true;
                }
            }
            else
            {
                tmpval = false;
            }
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

    for(auto const& default_entry : updated_defaults)
    {
        if(configured_keywords.find(default_entry.first) == configured_keywords.end())
        {
            //  Use the defaults since no additional commands were added.
            if(!table_api.add_option(default_entry.first, "$" + default_entry.second.default_name))
                retval = false;
        }
        else
        {
            //  Use the defaults plus the added commands.
            for(auto const& cmd_entry : default_entry.second.cmd_set)
            {
                retval = table_api.add_list(default_entry.first, cmd_entry) && retval;
            }
        }
    }

    if(configured_keywords.find("cmd_validity") == configured_keywords.end())
    {
        //  Use the defaults since no changes were made to the format specs.
        if(!table_api.add_option("cmd_validity", "$ftp_command_specs"))
            retval = false;
    }
    else
    {
        table_api.open_table("cmd_validity");

        for (auto c : commands)
        {
            table_api.open_table();
            bool tmpval1 = table_api.add_option("command", c.name);
            bool tmpval2 = true;
            bool tmpval3 = true;

            if (!c.format.empty())
            {
                std::istringstream tmp_stream (c.format);
                std::string tmp_string;

                // If there is a variable present, need to handle correctly.
                // Therefore, add as list since that already handles variables
                while (tmp_stream >> tmp_string)
                    if (!table_api.add_list("format", tmp_string))
                        tmpval2 = false;
            }

            if (c.length != command_default_len)
                tmpval3 = table_api.add_option("length", c.length);

            table_api.close_table();

            if (!tmpval1 || !tmpval2 || !tmpval3)
                retval = false;
        }

        table_api.close_table();
    }

    if (!ports_set)
        bind.add_when_port("21");

    return retval;
}

/****************************************
 *******  FtpClient Protocol  ***********
 ****************************************/

namespace
{
class FtpClient : public ConversionState
{
public:
    FtpClient(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;

private:
    static int ftpclient_binding_id;
};
} // namespace

int FtpClient::ftpclient_binding_id = 1;

bool FtpClient::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;
    auto& bind = cv.make_binder();
    bind.set_use_type("ftp_client");
    bind.set_when_proto("tcp");

    if (data_stream >> keyword)
    {
        if (keyword == "default")
        {
            bind.set_when_service("ftp");
            table_api.open_table("ftp_client");
        }
        else
        {
            std::string table_name = "ftp_client_target_" +
                std::to_string(ftpclient_binding_id);
            bind.set_use_name(table_name);
            table_api.open_table(table_name);
            ftpclient_binding_id++;

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
    }
    else
    {
        return false;
    }

    while (data_stream >> keyword)
    {
        bool tmpval = true;

        if (keyword == "telnet_cmds")
            tmpval = parse_yn_bool_option("telnet_cmds", data_stream, false);

        else if (keyword == "ignore_telnet_erase_cmds")
            tmpval = parse_yn_bool_option("ignore_telnet_erase_cmds", data_stream, false);

        else if (keyword == "max_resp_len")
            tmpval = parse_int_option("max_resp_len", data_stream, false);

        else if (keyword == "bounce")
            tmpval = parse_yn_bool_option("bounce", data_stream, false);

        // add bounce_to as a commented list
        else if (keyword == "bounce_to")
        {
            // get rid of the "{"
            if (!(data_stream >> keyword) && keyword != "{")
            {
                data_api.failed_conversion(data_stream, "bounce_to");
                retval = false;
            }
            else
            {
                table_api.open_table("bounce_to");

                while (data_stream >> keyword && keyword != "}")
                {
                    std::istringstream bounce_stream(keyword);
                    std::string data;
                    bool tmpval1 = true, tmpval2 = true, tmpval3 = true;
                    table_api.open_table();

                    if (util::get_string(bounce_stream, data, ","))
                        tmpval1 = table_api.add_option("address", data);

                    if (util::get_string(bounce_stream, data, ","))
                        tmpval2 = table_api.add_option("port", std::stoi(data));

                    if (util::get_string(bounce_stream, data, ","))
                        tmpval3 = table_api.add_option("last_port", std::stoi(data));

                    // shouldn't be a fourth argument
                    if (!tmpval1 || !tmpval2 || !tmpval3 ||
                        util::get_string(bounce_stream, data, ","))
                    {
                        data_api.failed_conversion(data_stream, "bounce_to");
                        retval = false;
                    }

                    table_api.close_table(); // anonymous
                }
                table_api.close_table(); // "bounce_to"
            }
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

    return retval;
}

/****************************************
 *********  Telnet Protocol  ************
 ****************************************/

namespace
{
class Telnet : public ConversionState
{
public:
    Telnet(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool Telnet::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool ports_set = false;
    bool retval = true;
    auto& bind = cv.make_binder();

    bind.set_when_proto("tcp");
    bind.set_use_type("telnet");
    table_api.open_table("telnet");

    while (data_stream >> keyword)
    {
        bool tmpval = true;

        if (keyword == "normalize")
            tmpval = table_api.add_option("normalize", true);

        else if (keyword == "detect_anomalies")
            table_api.add_deleted_comment("detect_anomalies");

        else if (keyword == "ayt_attack_thresh")
        {
            int i_val;

            if (data_stream >> i_val)
                tmpval = table_api.add_option("ayt_attack_thresh", i_val);
            else
                tmpval = false;
        }
        else if (keyword == "ports")
        {
            table_api.add_diff_option_comment("ports", "bindings");
            table_api.add_comment("check bindings table for port information");

            // adding ports to the binding.
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
                data_api.failed_conversion(data_stream, "ports - invalid port list");
                retval = false;
            }
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

    // adding the default port.
    if (!ports_set)
        bind.add_when_port("23");

    return retval;
}

/****************************************
 *******  FtpTelnetProtocol  ************
 ****************************************/

namespace
{
class FtpTelnetProtocol : public ConversionState
{
public:
    FtpTelnetProtocol(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool FtpTelnetProtocol::convert(std::istringstream& data_stream)
{
    std::string protocol;

    if (data_stream >> protocol)
    {
        if (protocol == "telnet")
        {
            cv.set_state(new Telnet(cv));
        }
        else if (protocol == "ftp")
        {
            if (data_stream >> protocol)
            {
                if (protocol == "client")
                    cv.set_state(new FtpClient(cv));

                else if (protocol == "server")
                    cv.set_state(new FtpServer(cv));

                else
                    return false;
            }
        }
        else
            return false;

        return true;
    }

    return false;
}

/*******  PUBLIC API ************/

static ConversionState* ctor(Converter& c)
{
    return new FtpTelnetProtocol(c);
}

static const ConvertMap ftptelnet_protocol_preprocessor =
{
    "ftp_telnet_protocol",
    ctor,
};

const ConvertMap* ftptelnet_protocol_map = &ftptelnet_protocol_preprocessor;
} // namespace preprocessors


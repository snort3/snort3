//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

// ftp_module.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ftp_module.h"
#include "ftpp_return_codes.h"
#include "ftp_cmd_lookup.h"
#include "ftp_parse.h"
#include "log/messages.h"
#include "utils/util.h"
#include "ft_main.h"
#include "ftpp_si.h"

using namespace snort;
using namespace std;

#define ftp_client_help \
    "FTP client configuration module for use with ftp_server"

#define ftp_server_help \
    "main FTP module; ftp_client should also be configured"

//-------------------------------------------------------------------------
// client stuff
//-------------------------------------------------------------------------

static const Parameter client_bounce_params[] =
{
    { "address", Parameter::PT_ADDR, nullptr, "1.0.0.0/32",
      "allowed IP address in CIDR format" },

    // FIXIT-L port and last_port should be replaced with a port list
    { "port", Parameter::PT_PORT, nullptr, "20",
      "allowed port" },

    { "last_port", Parameter::PT_PORT, nullptr, nullptr,
      "optional allowed range from port to last_port inclusive" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter ftp_client_params[] =
{
    { "bounce", Parameter::PT_BOOL, nullptr, "false",
      "check for bounces" },

    { "bounce_to", Parameter::PT_LIST, client_bounce_params, nullptr,
      "allow bounces to CIDRs / ports" },

    { "ignore_telnet_erase_cmds", Parameter::PT_BOOL, nullptr, "false",
      "ignore erase character and erase line commands when normalizing" },

    { "max_resp_len", Parameter::PT_INT, "0:max32", "4294967295",
      "maximum FTP response accepted by client" },

    { "telnet_cmds", Parameter::PT_BOOL, nullptr, "false",
      "detect Telnet escape sequences on FTP control channel" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

FtpClientModule::FtpClientModule() :
    Module(FTP_CLIENT_NAME, ftp_client_help, ftp_client_params)
{ }

FtpClientModule::~FtpClientModule()
{
    if ( conf )
        delete conf;

    for ( auto p : bounce_to )
        delete p;
}

bool FtpClientModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("address") )
    {
        unsigned n;
        const uint8_t* b = v.get_buffer(n);
        address.assign((const char*)b, n);
    }
    else if ( v.is("bounce") )
        conf->bounce = v.get_bool();

    else if ( v.is("ignore_telnet_erase_cmds") )
        conf->ignore_telnet_erase_cmds = v.get_bool();

    else if ( v.is("last_port") )
        last_port = v.get_uint16();

    else if ( v.is("max_resp_len") )
        conf->max_resp_len = v.get_uint32();

    else if ( v.is("port") )
        port = v.get_uint16();

    else if ( v.is("telnet_cmds") )
        conf->telnet_cmds = v.get_bool();

    return true;
}

BounceTo::BounceTo(const string& a, Port l, Port h) : address(a), low(l), high(h)
{ }

const BounceTo* FtpClientModule::get_bounce(unsigned idx)
{
    if ( idx < bounce_to.size() )
        return bounce_to[idx];
    else
        return nullptr;
}

FTP_CLIENT_PROTO_CONF* FtpClientModule::get_data()
{
    FTP_CLIENT_PROTO_CONF* tmp = conf;
    conf = nullptr;
    return tmp;
}

bool FtpClientModule::begin(const char* fqn, int idx, SnortConfig*)
{
    if ( !conf )
        conf = new FTP_CLIENT_PROTO_CONF;

    if ( !strcmp(fqn, "ftp_client.bounce_to") )
    {
        if ( idx )
        {
            address.clear();
            port = last_port = 0;
        }
        else
        {
            for ( auto p : bounce_to )
                delete p;

            bounce_to.clear();
        }
    }
    return true;
}

bool FtpClientModule::end(const char* fqn, int idx, SnortConfig*)
{
    if ( strcmp(fqn, "ftp_client.bounce_to") )
        return true;

    if ( idx )
    {
        if ( address.empty() || (last_port && (port > last_port)) )
        {
            ParseError("bad ftp_client.bounce_to [%d]", idx);
            return false;
        }
        bounce_to.emplace_back(new BounceTo(address, port, last_port));
    }
    return true;
}

//-------------------------------------------------------------------------
// server stuff
//-------------------------------------------------------------------------

FtpCmd::FtpCmd(const std::string& key, uint32_t flg, int num) : name(key), flags(flg), number(num)
{ }

FtpCmd::FtpCmd(const std::string& key, const std::string& fmt, int num)
    : name(key), format(fmt), flags(CMD_VALID), number(0)
{
    if ( num >= 0 )
    {
        number = num;
        flags |= CMD_LEN;
    }
}

//-------------------------------------------------------------------------

#define FTP_TELNET_CMD_STR                       \
    "TELNET cmd on FTP command channel"
#define FTP_INVALID_CMD_STR                      \
    "invalid FTP command"
#define FTP_PARAMETER_LENGTH_OVERFLOW_STR        \
    "FTP command parameters were too long"
#define FTP_MALFORMED_PARAMETER_STR              \
    "FTP command parameters were malformed"
#define FTP_PARAMETER_STR_FORMAT_STR             \
    "FTP command parameters contained potential string format"
#define FTP_RESPONSE_LENGTH_OVERFLOW_STR         \
    "FTP response message was too long"
#define FTP_ENCRYPTED_STR                        \
    "FTP traffic encrypted"
#define FTP_BOUNCE_STR                           \
    "FTP bounce attempt"
#define FTP_EVASIVE_TELNET_CMD_STR               \
    "evasive (incomplete) TELNET cmd on FTP command channel"

//-------------------------------------------------------------------------

static const Parameter ftp_server_validity_params[] =
{
    { "command", Parameter::PT_STRING, nullptr, nullptr,
      "command string" },

    { "format", Parameter::PT_STRING, nullptr, nullptr,
      "format specification" },

    { "length", Parameter::PT_INT, "0:max32", "0",
      "specify non-default maximum for command" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter ftp_directory_params[] =
{
    { "dir_cmd", Parameter::PT_STRING, nullptr, nullptr,
      "directory command" },

    { "rsp_code", Parameter::PT_INT, "200:max32", "200",
      "expected successful response code for command" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter ftp_server_params[] =
{
    { "chk_str_fmt", Parameter::PT_STRING, nullptr, nullptr,
      "check the formatting of the given commands" },

    { "data_chan_cmds", Parameter::PT_STRING, nullptr, nullptr,
      "check the formatting of the given commands" },

    { "data_rest_cmds", Parameter::PT_STRING, nullptr, nullptr,
      "check the formatting of the given commands" },

    { "data_xfer_cmds", Parameter::PT_STRING, nullptr, nullptr,
      "check the formatting of the given commands" },

    { "directory_cmds", Parameter::PT_LIST, ftp_directory_params, nullptr,
      "specify command-response pairs" },

    { "file_put_cmds", Parameter::PT_STRING, nullptr, nullptr,
      "check the formatting of the given commands" },

    { "file_get_cmds", Parameter::PT_STRING, nullptr, nullptr,
      "check the formatting of the given commands" },

    { "encr_cmds", Parameter::PT_STRING, nullptr, nullptr,
      "check the formatting of the given commands" },

    { "login_cmds", Parameter::PT_STRING, nullptr, nullptr,
      "check the formatting of the given commands" },

    { "check_encrypted", Parameter::PT_BOOL, nullptr, "false",
      "check for end of encryption" },

    { "cmd_validity", Parameter::PT_LIST, ftp_server_validity_params, nullptr,
      "specify command formats" },

    { "def_max_param_len", Parameter::PT_INT, "1:max32", "100",
      "default maximum length of commands handled by server; 0 is unlimited" },

    { "encrypted_traffic", Parameter::PT_BOOL, nullptr, "false",
      "check for encrypted Telnet and FTP" },

    { "ftp_cmds", Parameter::PT_STRING, nullptr, nullptr,
      "specify additional commands supported by server beyond RFC 959" },

    { "ignore_data_chan", Parameter::PT_BOOL, nullptr, "false",
      "do not inspect FTP data channels" },

    { "ignore_telnet_erase_cmds", Parameter::PT_BOOL, nullptr, "false",
      "ignore erase character and erase line commands when normalizing" },

    { "print_cmds", Parameter::PT_BOOL, nullptr, "false",
      "print command configurations on start up" },

    { "telnet_cmds", Parameter::PT_BOOL, nullptr, "false",
      "detect Telnet escape sequences of FTP control channel" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

//-------------------------------------------------------------------------

static const RuleMap ftp_server_rules[] =
{
    { FTP_TELNET_CMD, FTP_TELNET_CMD_STR },
    { FTP_INVALID_CMD, FTP_INVALID_CMD_STR },
    { FTP_PARAMETER_LENGTH_OVERFLOW, FTP_PARAMETER_LENGTH_OVERFLOW_STR },
    { FTP_MALFORMED_PARAMETER, FTP_MALFORMED_PARAMETER_STR },
    { FTP_PARAMETER_STR_FORMAT, FTP_PARAMETER_STR_FORMAT_STR },
    { FTP_RESPONSE_LENGTH_OVERFLOW, FTP_RESPONSE_LENGTH_OVERFLOW_STR },
    { FTP_ENCRYPTED, FTP_ENCRYPTED_STR },
    { FTP_BOUNCE, FTP_BOUNCE_STR },
    { FTP_EVASIVE_TELNET_CMD, FTP_EVASIVE_TELNET_CMD_STR },

    { 0, nullptr }
};

static const PegInfo ftp_pegs[] =
{
    { CountType::SUM, "total_packets", "total packets" },
    { CountType::SUM, "total_bytes", "total number of bytes processed" },
    { CountType::NOW, "concurrent_sessions", "total concurrent FTP sessions" },
    { CountType::MAX, "max_concurrent_sessions", "maximum concurrent FTP sessions" },
    { CountType::SUM, "start_tls", "total STARTTLS events generated" },
    { CountType::SUM, "ssl_search_abandoned", "total SSL search abandoned" },
    { CountType::SUM, "ssl_srch_abandoned_early", "total SSL search abandoned too soon" },
    { CountType::SUM, "pkt_segment_size_changed", "total number of FTP data packets with segment size change" },
    { CountType::SUM, "flow_segment_size_changed", "total number of FTP sessions with segment size change" },
    { CountType::END, nullptr, nullptr }
};

//-------------------------------------------------------------------------

FtpServerModule::FtpServerModule() :
    Module(FTP_SERVER_NAME, ftp_server_help, ftp_server_params)
{ }

FtpServerModule::~FtpServerModule()
{
    if ( conf )
        delete conf;

    for ( auto p : cmds )
        delete p;
}

const RuleMap* FtpServerModule::get_rules() const
{ return ftp_server_rules; }

ProfileStats* FtpServerModule::get_profile() const
{ return &ftpPerfStats; }

void FtpServerModule::add_commands(
    Value& v, uint32_t flags, int num)
{
    string tok;
    v.set_first_token();

    while ( v.get_next_token(tok) )
        cmds.emplace_back(new FtpCmd(tok, flags, num));
}

const FtpCmd* FtpServerModule::get_cmd(unsigned idx)
{
    if ( idx < cmds.size() )
        return cmds[idx];
    else
        return nullptr;
}

FTP_SERVER_PROTO_CONF* FtpServerModule::get_data()
{
    FTP_SERVER_PROTO_CONF* tmp = conf;
    conf = nullptr;
    return tmp;
}

//-------------------------------------------------------------------------

bool FtpServerModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("check_encrypted") )
        conf->check_encrypted_data = v.get_bool();

    else if ( v.is("chk_str_fmt") )
        add_commands(v, CMD_CHECK);

    else if ( v.is("command") )
        names = v.get_string();

    else if ( v.is("commands") )
        names = v.get_string();

    else if ( v.is("data_chan_cmds") )
        add_commands(v, CMD_DATA);

    else if ( v.is("data_rest_cmds") )
        add_commands(v, CMD_REST);

    else if ( v.is("data_xfer_cmds") )
        add_commands(v, CMD_XFER);

    else if ( v.is("def_max_param_len") )
        conf->def_max_param_len = v.get_uint32();

    else if ( v.is("dir_cmd") )
        names = v.get_string();

    else if ( v.is("encr_cmds") )
        add_commands(v, CMD_ENCR);

    else if ( v.is("encrypted_traffic") )
        conf->detect_encrypted = v.get_bool();

    else if ( v.is("file_get_cmds") )
        add_commands(v, CMD_XFER|CMD_GET);

    else if ( v.is("file_put_cmds") )
        add_commands(v, CMD_XFER|CMD_PUT);

    else if ( v.is("format") )
        format = v.get_string();

    else if ( v.is("ftp_cmds") )
        add_commands(v, CMD_ALLOW);

    else if ( v.is("ignore_data_chan") )
        conf->data_chan = v.get_bool();

    else if ( v.is("ignore_telnet_erase_cmds") )
        conf->ignore_telnet_erase_cmds = v.get_bool();

    else if ( v.is("length") )
        number = v.get_uint32();

    else if ( v.is("login_cmds") )
        add_commands(v, CMD_LOGIN);

    else if ( v.is("print_cmds") )
        conf->print_commands = v.get_bool();

    else if ( v.is("rsp_code") )
        number = v.get_uint32();

    else if ( v.is("telnet_cmds") )
        conf->telnet_cmds = v.get_bool();

    return true;
}

//-------------------------------------------------------------------------

// Recursively sets nodes that allow strings to nodes that check
// for a string format attack within the FTP parameter validation tree

static void ResetStringFormat(FTP_PARAM_FMT* Fmt)
{
    int i;
    if (!Fmt)
        return;

    if (Fmt->type == e_unrestricted)
        Fmt->type = e_strformat;

    ResetStringFormat(Fmt->optional_fmt);
    for (i=0; i<Fmt->numChoices; i++)
    {
        ResetStringFormat(Fmt->choices[i]);
    }
    ResetStringFormat(Fmt->next_param_fmt);
}

static int ProcessFTPDataChanCmdsList(
    FTP_SERVER_PROTO_CONF* ServerConf, const FtpCmd* fc)
{
    const char* cmd = fc->name.c_str();
    int iRet = 0;

    FTP_CMD_CONF* FTPCmd =
        ftp_cmd_lookup_find(ServerConf->cmd_lookup, cmd, strlen(cmd), &iRet);

    if (FTPCmd == nullptr)
    {
        /* Add it to the list */
        // note that struct includes 1 byte for null, so just add len
        FTPCmd = (FTP_CMD_CONF*)snort_calloc(sizeof(FTP_CMD_CONF)+strlen(cmd));
        strncpy(FTPCmd->cmd_name, cmd, strlen(cmd) + 1);

        // FIXIT-L make sure pulled from server conf when used if not overridden
        //FTPCmd->max_param_len = ServerConf->def_max_param_len;

        ftp_cmd_lookup_add(ServerConf->cmd_lookup, cmd,
            strlen(cmd), FTPCmd);
        iRet = 0;
    }
    if ( fc->flags & CMD_DIR )
        FTPCmd->dir_response = fc->number;

    if ( fc->flags & CMD_LEN )
    {
        FTPCmd->max_param_len = fc->number;
        FTPCmd->max_param_len_overridden = 1;
    }
    if ( fc->flags & CMD_DATA )
        FTPCmd->data_chan_cmd = true;

    if ( fc->flags & CMD_REST )
        FTPCmd->data_rest_cmd = true;

    if ( fc->flags & CMD_XFER )
        FTPCmd->data_xfer_cmd = true;

    if ( fc->flags & CMD_PUT )
        FTPCmd->file_put_cmd = true;

    if ( fc->flags & CMD_GET )
        FTPCmd->file_get_cmd = true;

    if ( fc->flags & CMD_CHECK )
    {
        FTP_PARAM_FMT* Fmt = FTPCmd->param_format;
        if (Fmt)
        {
            ResetStringFormat(Fmt);
        }
        else
        {
            Fmt = (FTP_PARAM_FMT*)snort_calloc(sizeof(FTP_PARAM_FMT));
            Fmt->type = e_head;
            FTPCmd->param_format = Fmt;

            Fmt = (FTP_PARAM_FMT*)snort_calloc(sizeof(FTP_PARAM_FMT));
            Fmt->type = e_strformat;
            FTPCmd->param_format->next_param_fmt = Fmt;
            Fmt->prev_param_fmt = FTPCmd->param_format;
        }
        FTPCmd->check_validity = true;
    }
    if ( fc->flags & CMD_VALID && !fc->format.empty())
    {
        char err[1024];
        iRet = ProcessFTPCmdValidity(
            ServerConf, cmd, fc->format.c_str(), err, sizeof(err));
    }
    if ( fc->flags & CMD_ENCR )
        FTPCmd->encr_cmd = true;

    if ( fc->flags & CMD_PROT )
        FTPCmd->prot_cmd = true;

    if ( fc->flags & CMD_LOGIN )
        FTPCmd->login_cmd = true;

    return iRet;
}

bool FtpServerModule::begin(const char* fqn, int, SnortConfig*)
{
    names.clear();
    format.clear();
    number = -1;

    if ( !conf )
        conf = new FTP_SERVER_PROTO_CONF;

    if ( !strcmp(fqn, "ftp_server") )
    {
        for ( auto cmd : cmds )
             delete cmd;

        cmds.clear();
    }
    return true;
}

bool FtpServerModule::end(const char* fqn, int idx, SnortConfig*)
{

    if ( !idx && !strcmp(fqn, "ftp_server") )
    {
        cmds.emplace_back(new FtpCmd("PROT", CMD_PROT, 0));
        return std::none_of(cmds.cbegin(), cmds.cend(),
            [this](const FtpCmd* cmd)
            { return FTPP_SUCCESS !=  ProcessFTPDataChanCmdsList(conf, cmd); });
    }

    if ( !strcmp(fqn, "ftp_server.cmd_validity") )
        cmds.emplace_back(new FtpCmd(names, format, number));

    else if ( !strcmp(fqn, "ftp_server.directory_cmds") )
    {
        Value v(names.c_str());
        add_commands(v, CMD_DIR, number);
    }
    return true;
}

const PegInfo* FtpServerModule::get_pegs() const
{ return ftp_pegs; }

PegCount* FtpServerModule::get_counts() const
{ return (PegCount*)&ftstats; }


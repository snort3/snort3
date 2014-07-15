/*
 * Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License Version 2 as
 ** published by the Free Software Foundation.  You may not use, modify or
 ** distribute this program under any other version of the GNU General
 ** Public License.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program; if not, write to the Free Software
 ** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

// ftp_module.cc author Russ Combs <rucombs@cisco.com>

#include "ftp_module.h"
#include <sstream>
#include "main/snort_config.h"

using namespace std;

#define FTP_CLIENT "ftp_client"
#define FTP_SERVER "ftp_server"

//-------------------------------------------------------------------------
// client stuff
//-------------------------------------------------------------------------

static const Parameter client_bounce_params[] =
{
    { "address", Parameter::PT_ADDR, nullptr, nullptr,
      "allowed ip address in CIDR format" },

    { "port", Parameter::PT_PORT, "1:", nullptr,
      "allowed port" },

    { "last_port", Parameter::PT_PORT, "0:", nullptr,
      "optional allowed range from port to last_port inclusive" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter ftp_client_params[] =
{
    { "bounce", Parameter::PT_BOOL, nullptr, "false",
      "check for bounces" },

    { "bounce_to", Parameter::PT_TABLE, client_bounce_params, nullptr,
      "allow bounces to CIDRs / ports" },

    { "ignore_telnet_erase_cmds", Parameter::PT_BOOL, nullptr, "false",
      "ignore erase character and erase line commands when normalizing" },

    { "max_resp_len", Parameter::PT_INT, "-1:", "-1",
      "maximum ftp response accepted by client" },

    { "telnet_cmds", Parameter::PT_BOOL, nullptr, "false",
      "detect telnet escape sequences on ftp control channel" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

FtpClientModule::FtpClientModule() :
    Module(FTP_CLIENT, ftp_client_params)
{
    conf = nullptr;
}

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
        address = v.get_string();

    else if ( v.is("bounce") )
        conf->bounce = v.get_bool();

    else if ( v.is("ignore_telnet_erase_cmds") )
        conf->ignore_telnet_erase_cmds = v.get_bool();

    else if ( v.is("last_port") )
        last_port = v.get_long();

    else if ( v.is("max_resp_len") )
        conf->max_resp_len = v.get_long();

    else if ( v.is("port") )
        port = v.get_long();

    else if ( v.is("telnet_cmds") )
        conf->telnet_cmds = v.get_bool();

    else
        return false;

    return true;
}

BounceTo::BounceTo(string& a, Port l, Port h)
{
    address = a;
    low = l;
    high = h;
}

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

bool FtpClientModule::begin(const char*, int, SnortConfig*)
{
    if ( !conf )
        conf = new FTP_CLIENT_PROTO_CONF;

    address.clear();
    port = last_port = 0;
    return true;
}

bool FtpClientModule::end(const char* fqn, int, SnortConfig*)
{
    if ( strcmp(fqn, "ftp_client.bounce_to") )
        return true;

    if ( last_port && (port > last_port) )
        return false;

    bounce_to.push_back(new BounceTo(address, port, last_port));
    return true;
}

//-------------------------------------------------------------------------
// server stuff
//-------------------------------------------------------------------------

FtpCmd::FtpCmd(std::string& key, uint32_t flg, int num)
{
    name = key;
    flags = flg;
    number = num;
}

FtpCmd::FtpCmd(std::string& key, std::string& fmt, int num)
{
    name = key;
    format = fmt;

    flags = CMD_VALID;
    number = 0;

    if ( num >= 0 )
    {
        number = num;
        flags |= CMD_LEN;
    }
}

//-------------------------------------------------------------------------

#define FTP_TELNET_CMD_STR                       \
        "(ftp) TELNET CMD on FTP Command Channel"
#define FTP_INVALID_CMD_STR                      \
        "(ftp) Invalid FTP Command"
#define FTP_PARAMETER_LENGTH_OVERFLOW_STR        \
        "(ftp) FTP command parameters were too long"
#define FTP_MALFORMED_PARAMETER_STR              \
        "(ftp) FTP command parameters were malformed"
#define FTP_PARAMETER_STR_FORMAT_STR             \
        "(ftp) FTP command parameters contained potential string format"
#define FTP_RESPONSE_LENGTH_OVERFLOW_STR         \
        "(ftp) FTP response message was too long"
#define FTP_ENCRYPTED_STR                        \
        "(ftp) FTP traffic encrypted"
#define FTP_BOUNCE_STR                           \
        "(ftp) FTP bounce attempt"
#define FTP_EVASIVE_TELNET_CMD_STR               \
        "(ftp) Evasive (incomplete) TELNET CMD on FTP Command Channel"

// FIXIT convert to Lua and use as module default settings
#if 0
static const char* DEFAULT_FTP_CONF[] =
{
    "hardcoded_config "
    "def_max_param_len 100 "

    // FIXIT should not have to list commands more than once
    // eg must appear in at least one *_cmds parameter
    "ftp_cmds { USER PASS ACCT CWD CDUP SMNT QUIT REIN TYPE STRU"
              " MODE RETR STOR STOU APPE ALLO REST RNFR RNTO ABOR"
              " DELE RMD MKD PWD LIST NLST SITE SYST STAT HELP NOOP } "
    "ftp_cmds { AUTH ADAT PROT PBSZ CONF ENC } "
    "ftp_cmds { PORT PASV LPRT LPSV EPRT EPSV } "
    "ftp_cmds { FEAT OPTS } "
    "ftp_cmds { MDTM REST SIZE MLST MLSD } "

    "alt_max_param_len 0 { CDUP QUIT REIN PASV STOU ABOR PWD SYST NOOP } ",

    "cmd_validity MODE < char SBC > "
    "cmd_validity STRU < char FRPO [ string ] > "
    "cmd_validity ALLO < int [ char R int ] > "
    "cmd_validity TYPE < { char AE [ char NTC ] | char I | char L [ number ] } > "
    "cmd_validity PORT < host_port > "
    "cmd_validity LPRT < long_host_port > "
    "cmd_validity EPRT < extd_host_port > "
    "cmd_validity EPSV < [ { '1' | '2' | 'ALL' } ] > ",

    "data_chan_cmds { PORT PASV LPRT LPSV EPRT EPSV } "
    "data_xfer_cmds { RETR STOR STOU APPE LIST NLST } "
    "file_put_cmds { STOR STOU } "
    "file_get_cmds { RETR } "
    "login_cmds { USER PASS } "
    "dir_cmds { CWD 250 CDUP 250 PWD 257 } "
    "encr_cmds { AUTH } "
};
#endif

//-------------------------------------------------------------------------

static const Parameter ftp_server_validity_params[] =
{
    { "command", Parameter::PT_STRING, nullptr, nullptr,
      "command string" },

    { "format", Parameter::PT_STRING, nullptr, nullptr,
      "format specification" },

    { "length", Parameter::PT_INT, "0:", "0",
      "specify non-default maximum for command" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter ftp_directory_params[] =
{
    { "dir_cmd", Parameter::PT_STRING, nullptr, nullptr,
      "directory command" },

    { "rsp_code", Parameter::PT_INT, "200:", "0",
      "expected successful response code for command" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter ftp_server_params[] =
{
    { "chk_str_fmt", Parameter::PT_STRING, nullptr, nullptr,
      "check the formatting of the given commands" },

    { "data_chan_cmds", Parameter::PT_STRING, nullptr, nullptr,
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

    { "def_max_param_len", Parameter::PT_INT, "1:", "100",
      "default maximum length of commands handled by server; 0 is unlimited" },

    { "encrypted_traffic", Parameter::PT_BOOL, nullptr, "false",
      "check for encrypted telnet and ftp" },

    { "ftp_cmds", Parameter::PT_STRING, nullptr, nullptr,
      "specify additional commands supported by server beyond RFC 959" },

    { "ignore_data_chan", Parameter::PT_BOOL, nullptr, "false",
      "do not inspect ftp data channels" },

    { "ignore_telnet_erase_cmds", Parameter::PT_BOOL, nullptr, "false",
      "ignore erase character and erase line commands when normalizing" },

    { "print_cmds", Parameter::PT_BOOL, nullptr, "false",
      "print command configurations on start up" },

    { "telnet_cmds", Parameter::PT_BOOL, nullptr, "false",
      "detect telnet escape sequences of ftp control channel" },

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

//-------------------------------------------------------------------------

FtpServerModule::FtpServerModule() :
    Module(FTP_SERVER, ftp_server_params)
{
    conf = nullptr;
}

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
        cmds.push_back(new FtpCmd(tok, flags, num));
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
        conf->detect_encrypted = v.get_bool();

    else if ( v.is("chk_str_fmt") )
        add_commands(v, CMD_CHECK);

    else if ( v.is("command") )
        names = v.get_string();

    else if ( v.is("commands") )
        names = v.get_string();

    else if ( v.is("data_chan_cmds") )
        add_commands(v, CMD_DATA);

    else if ( v.is("data_xfer_cmds") )
        add_commands(v, CMD_XFER);

    else if ( v.is("def_max_param_len") )
        conf->def_max_param_len = v.get_long();

    else if ( v.is("dir_cmd") )
        names = v.get_string();

    else if ( v.is("encr_cmds") )
        add_commands(v, CMD_ENCR);

    else if ( v.is("encrypted_traffic") )
        conf->check_encrypted_data = v.get_bool();

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
        number = v.get_long();

    else if ( v.is("login_cmds") )
        add_commands(v, CMD_LOGIN);

    else if ( v.is("print_cmds") )
        conf->print_commands = v.get_bool();

    else if ( v.is("rsp_code") )
        number = v.get_long();

    else if ( v.is("telnet_cmds") )
        conf->telnet_cmds = v.get_bool();

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------

bool FtpServerModule::begin(const char*, int, SnortConfig*)
{
    names.clear();
    format.clear();
    number = -1;

    if ( !conf )
        conf = new FTP_SERVER_PROTO_CONF;

    return true;
}

bool FtpServerModule::end(const char* fqn, int idx, SnortConfig*)
{
    if ( !idx )
        return true;

    if ( !strcmp(fqn, "ftp_server.cmd_validity") )
        cmds.push_back(new FtpCmd(names, format, number));

    else if ( !strcmp(fqn, "ftp_server.directory_cmds") )
    {
        Value v(names.c_str());
        add_commands(v, CMD_DIR, number);
    }
    return true;
}

const char** FtpServerModule::get_pegs() const
{ return simple_pegs; }

PegCount* FtpServerModule::get_counts() const
{ return (PegCount*)&ftstats; }


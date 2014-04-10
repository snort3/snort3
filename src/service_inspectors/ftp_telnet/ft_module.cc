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

// ft_module.cc author Russ Combs <rucombs@cisco.com>

#include "ft_module.h"

#include "snort_config.h"

//-------------------------------------------------------------------------
// ft (ftp - telnet) modules
//-------------------------------------------------------------------------

static const Parameter ft_global_params[] =
{
    { "check_encrypted", Parameter::PT_BOOL, nullptr, "false",
      "check for end of encryption" },

    { "encrypted_traffic", Parameter::PT_BOOL, nullptr, "false",
      "check for encrypted telnet and ftp" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

FtGlobalModule::FtGlobalModule() :
    Module("ftp_telnet_global", ft_global_params) { }

bool FtGlobalModule::set(const char*, Value&, SnortConfig*)
{
    return true;
}

bool FtGlobalModule::begin(const char*, int, SnortConfig*)
{
    return true;
}

bool FtGlobalModule::end(const char*, int, SnortConfig*)
{
    return true;
}

//-------------------------------------------------------------------------

#define TELNET_AYT_OVERFLOW_STR                  \
        "(telnet) Consecutive Telnet AYT commands beyond threshold"
#define TELNET_ENCRYPTED_STR                     \
        "(telnet) Telnet traffic encrypted"
#define TELNET_SB_NO_SE_STR                      \
        "(telnet) Telnet Subnegotiation Begin Command without Subnegotiation End"

static const Parameter telnet_params[] =
{
    { "ayt_attack_thresh", Parameter::PT_INT, "-1:", "-1",
      "alert on this number of consecutive telnet AYT commands" },

    { "check_encrypted", Parameter::PT_BOOL, nullptr, "false",
      "check for end of encryption" },

    { "detect_anomalies", Parameter::PT_BOOL, nullptr, "false",
      "help" },

    { "encrypted_traffic", Parameter::PT_BOOL, nullptr, "false",
      "check for encrypted telnet and ftp" },

    { "normalize", Parameter::PT_BOOL, nullptr, "false",
      "eliminate escape sequences" },

    { "ports", Parameter::PT_BIT_LIST, "65535", "23",
      "specify known telnet ports" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap telnet_rules[] =
{
    { TELNET_AYT_OVERFLOW, TELNET_AYT_OVERFLOW_STR },
    { TELNET_ENCRYPTED, TELNET_ENCRYPTED_STR },
    { TELNET_SB_NO_SE, TELNET_SB_NO_SE_STR },

    { 0, nullptr }
};

TelnetModule::TelnetModule() :
    Module("telnet", telnet_params, telnet_rules) { }

bool TelnetModule::set(const char*, Value&, SnortConfig*)
{
    return true;
}

bool TelnetModule::begin(const char*, int, SnortConfig*)
{
    return true;
}

bool TelnetModule::end(const char*, int, SnortConfig*)
{
    return true;
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

static const Parameter ftp_server_alt_max_params[] =
{
    { "commands", Parameter::PT_STRING, nullptr, nullptr,
      "list of commands" },

    { "length", Parameter::PT_INT, "0:", "0",
      "specify non-default maximum for command" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter ftp_server_validity_params[] =
{
    { "command", Parameter::PT_STRING, nullptr, nullptr,
      "command string" },

    { "format", Parameter::PT_STRING, nullptr, nullptr,
      "format specification" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter ftp_server_params[] =
{
    { "alt_max_param", Parameter::PT_LIST, nullptr, ftp_server_alt_max_params,
      "specify non-default maximum command lengths" },

    { "chk_str_fmt", Parameter::PT_STRING, nullptr, nullptr,
      "check the formatting of the given commands" },

    { "cmd_validity", Parameter::PT_LIST, nullptr, ftp_server_validity_params,
      "specify command formats" },

    { "def_max_param_len", Parameter::PT_INT, "1:", "100",
      "default maximum length of commands handled by server; 0 is unlimited" },

    { "ftp_cmds", Parameter::PT_STRING, nullptr, nullptr,
      "specify additional commands supported by server beyond RFC 959" },

    { "ignore_data_chan", Parameter::PT_BOOL, nullptr, "false",
      "do not inspect ftp data channels" },

    { "ignore_telnet_erase_cmds", Parameter::PT_BOOL, nullptr, "false",
      "ignore erase character and erase line commands when normalizing" },

    { "ports", Parameter::PT_BIT_LIST, "65535", "21",
      "specify known ftp ports" },

    { "print_cmds", Parameter::PT_BOOL, nullptr, "false",
      "print command configurations on start up" },

    { "telnet_cmds", Parameter::PT_BOOL, nullptr, "false",
      "detect telnet escape sequences of ftp control channel" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

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

FtpServerModule::FtpServerModule() :
    Module("ftp_server", ftp_server_params, ftp_server_rules) { }

bool FtpServerModule::set(const char*, Value&, SnortConfig*)
{
    return true;
}

bool FtpServerModule::begin(const char*, int, SnortConfig*)
{
    return true;
}

bool FtpServerModule::end(const char*, int, SnortConfig*)
{
    return true;
}

//-------------------------------------------------------------------------

static const Parameter ftp_client_params[] =
{
    { "bounce", Parameter::PT_BOOL, nullptr, "false",
      "check for bounces" },

    { "bounce_to", Parameter::PT_STRING, nullptr, nullptr,
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
    Module("ftp_client", ftp_client_params) { }

bool FtpClientModule::set(const char*, Value&, SnortConfig*)
{
#if 0
    if ( v.is("name") )
        sc->pkt_cnt = v.get_long();

    else
        return false;
#endif

    return true;
}

bool FtpClientModule::begin(const char*, int, SnortConfig*)
{
    return true;
}

bool FtpClientModule::end(const char*, int, SnortConfig*)
{
    return true;
}


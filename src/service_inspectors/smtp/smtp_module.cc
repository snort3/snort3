//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// smtp_module.cc author Bhagyashree Bantwal <bbantwal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "smtp_module.h"

#include "log/messages.h"
#include "utils/util.h"

using namespace snort;
using namespace std;

SmtpCmd::SmtpCmd(std::string& key, uint32_t flg, int num)
{
    name = key;
    flags = flg;
    number = num;
}

SmtpCmd::SmtpCmd(std::string& key, int num)
{
    name = key;

    flags = PCMD_ALT;
    number = 0;

    if ( num >= 0 )
    {
        number = num;
        flags |= PCMD_LEN;
    }
}

static const Parameter smtp_command_params[] =
{
    { "command", Parameter::PT_STRING, nullptr, nullptr,
      "command string" },

    { "length", Parameter::PT_INT, "0:", "0",
      "specify non-default maximum for command" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter s_params[] =
{
    { "alt_max_command_line_len", Parameter::PT_LIST, smtp_command_params, nullptr,
      "overrides max_command_line_len for specific commands" },

    { "auth_cmds", Parameter::PT_STRING, nullptr, nullptr,
      "commands that initiate an authentication exchange" },

    { "b64_decode_depth", Parameter::PT_INT, "-1:65535", "1460",
      "depth used to decode the base64 encoded MIME attachments (-1 no limit)" },

    { "binary_data_cmds", Parameter::PT_STRING, nullptr, nullptr,
      "commands that initiate sending of data and use a length value after the command" },

    { "bitenc_decode_depth", Parameter::PT_INT, "-1:65535", "1460",
      "depth used to extract the non-encoded MIME attachments (-1 no limit)" },

    { "data_cmds", Parameter::PT_STRING, nullptr, nullptr,
      "commands that initiate sending of data with an end of data delimiter" },

    { "email_hdrs_log_depth", Parameter::PT_INT, "0:20480", "1464",
      "depth for logging email headers" },

    { "ignore_data", Parameter::PT_BOOL, nullptr, "false",
      "ignore data section of mail" },

    { "ignore_tls_data", Parameter::PT_BOOL, nullptr, "false",
      "ignore TLS-encrypted data when processing rules" },

    { "invalid_cmds", Parameter::PT_STRING, nullptr, nullptr,
      "alert if this command is sent from client side" },

    { "log_email_hdrs", Parameter::PT_BOOL, nullptr, "false",
      "log the SMTP email headers extracted from SMTP data" },

    { "log_filename", Parameter::PT_BOOL, nullptr, "false",
      "log the MIME attachment filenames extracted from the Content-Disposition header within"
      " the MIME body" },

    { "log_mailfrom", Parameter::PT_BOOL, nullptr, "false",
      "log the sender's email address extracted from the MAIL FROM command" },

    { "log_rcptto", Parameter::PT_BOOL, nullptr, "false",
      "log the recipient's email address extracted from the RCPT TO command" },

    { "max_auth_command_line_len", Parameter::PT_INT, "0:65535", "1000",
      "max auth command Line Length" },

    { "max_command_line_len", Parameter::PT_INT, "0:65535", "0",
      "max Command Line Length" },

    { "max_header_line_len", Parameter::PT_INT, "0:65535", "0",
      "max SMTP DATA header line" },

    { "max_response_line_len", Parameter::PT_INT, "0:65535", "0",
      "max SMTP response line" },

    { "normalize", Parameter::PT_ENUM, "none | cmds | all", "none",
      "turns on/off normalization" },

    { "normalize_cmds", Parameter::PT_STRING, nullptr, nullptr,
      "list of commands to normalize" },

    { "qp_decode_depth", Parameter::PT_INT, "-1:65535", "1460",
      "quoted-Printable decoding depth (-1 no limit)" },

    { "uu_decode_depth", Parameter::PT_INT, "-1:65535", "1460",
      "Unix-to-Unix decoding depth (-1 no limit)" },

    { "valid_cmds", Parameter::PT_STRING, nullptr, nullptr,
      "list of valid commands" },

    { "xlink2state", Parameter::PT_ENUM, "disable | alert | drop", "alert",
      "enable/disable xlink2state alert" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap smtp_rules[] =
{
    { SMTP_COMMAND_OVERFLOW, "attempted command buffer overflow" },
    { SMTP_DATA_HDR_OVERFLOW, "attempted data header buffer overflow" },
    { SMTP_RESPONSE_OVERFLOW, "attempted response buffer overflow" },
    { SMTP_SPECIFIC_CMD_OVERFLOW, "attempted specific command buffer overflow" },
    { SMTP_UNKNOWN_CMD, "unknown command" },
    { SMTP_ILLEGAL_CMD, "illegal command" },
    { SMTP_HEADER_NAME_OVERFLOW, "attempted header name buffer overflow" },
    { SMTP_XLINK2STATE_OVERFLOW, "attempted X-Link2State command buffer overflow" },
    { SMTP_B64_DECODING_FAILED, "base64 decoding failed" },
    { SMTP_QP_DECODING_FAILED, "quoted-printable decoding failed" },
    { SMTP_UU_DECODING_FAILED, "Unix-to-Unix decoding failed" },
    { SMTP_AUTH_ABORT_AUTH, "Cyrus SASL authentication attack" },
    { SMTP_AUTH_COMMAND_OVERFLOW, "attempted authentication command buffer overflow" },

    { 0, nullptr }
};

//-------------------------------------------------------------------------
// smtp module
//-------------------------------------------------------------------------

SmtpModule::SmtpModule() : Module(SMTP_NAME, SMTP_HELP, s_params)
{
    config = nullptr;
}

SmtpModule::~SmtpModule()
{
    if ( config )
    {
        if ( config->cmds )
        {
            for ( SMTPToken* tmp = config->cmds; tmp->name; tmp++)
                snort_free(const_cast<char *>(tmp->name));

            snort_free(config->cmds);
        }
        delete config;
    }

    for ( auto p : cmds )
        delete p;
}

const RuleMap* SmtpModule::get_rules() const
{ return smtp_rules; }

const PegInfo* SmtpModule::get_pegs() const
{ return smtp_peg_names; }

PegCount* SmtpModule::get_counts() const
{ return (PegCount*)&smtpstats; }

ProfileStats* SmtpModule::get_profile() const
{ return &smtpPerfStats; }

void SmtpModule::add_commands(
    Value& v, uint32_t flags)
{
    string tok;
    v.set_first_token();

    while ( v.get_next_token(tok) )
        cmds.push_back(new SmtpCmd(tok, flags, 0));
}

const SmtpCmd* SmtpModule::get_cmd(unsigned idx)
{
    if ( idx < cmds.size() )
        return cmds[idx];
    else
        return nullptr;
}

bool SmtpModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("auth_cmds") )
        add_commands(v, PCMD_AUTH);

    else if ( v.is("binary_data_cmds") )
        add_commands(v, PCMD_BDATA);

    else if ( v.is("b64_decode_depth") )
    {
        const long value = v.get_long();
        const long mime_value = (value > 0) ? value : -(value+1);
        config->decode_conf.set_b64_depth(mime_value);
    }

    else if ( v.is("bitenc_decode_depth") )
    {
        const long value = v.get_long();
        const long mime_value = (value > 0) ? value : -(value+1);
        config->decode_conf.set_bitenc_depth(mime_value);
    }

    else if ( v.is("command") )
        names = v.get_string();

    else if ( v.is("commands") )
        names = v.get_string();

    else if ( v.is("data_cmds"))
        add_commands(v, PCMD_DATA);

    else if ( v.is("email_hdrs_log_depth") )
        config->log_config.email_hdrs_log_depth = v.get_long();

    else if ( v.is("ignore_data") )
        config->decode_conf.set_ignore_data(v.get_bool());

    else if ( v.is("ignore_tls_data") )
        config->ignore_tls_data = v.get_bool();

    else if ( v.is("invalid_cmds"))
        add_commands(v, PCMD_INVALID);

    else if ( v.is("length") )
        number = v.get_long();

    else if ( v.is("log_filename") )
        config->log_config.log_filename =v.get_bool();

    else if ( v.is("log_mailfrom") )
        config->log_config.log_mailfrom = v.get_bool();

    else if ( v.is("log_rcptto"))
        config->log_config.log_rcptto = v.get_bool();

    else if ( v.is("log_email_hdrs"))
        config->log_config.log_email_hdrs = v.get_bool();

    else if ( v.is("max_auth_command_line_len") )
        config->max_auth_command_line_len = v.get_long();

    else if ( v.is("max_command_line_len") )
        config->max_command_line_len = v.get_long();

    else if ( v.is("max_header_line_len") )
        config->max_header_line_len = v.get_long();

    else if ( v.is("max_response_line_len") )
        config->max_response_line_len = v.get_long();

    else if ( v.is("normalize") )
        config->normalize = (NORM_TYPES)v.get_long();

    else if ( v.is("normalize_cmds"))
        add_commands(v, PCMD_NORM);

    else if ( v.is("qp_decode_depth") )
    {
        const long value = v.get_long();
        const long mime_value = (value > 0) ? value : -(value+1);
        config->decode_conf.set_qp_depth(mime_value);
    }

    else if ( v.is("valid_cmds"))
        add_commands(v, PCMD_VALID);

    else if ( v.is("uu_decode_depth") )
    {
        const long value = v.get_long();
        const long mime_value = (value > 0) ? value : -(value+1);
        config->decode_conf.set_uu_depth(mime_value);
    }

    else if ( v.is("xlink2state") )
        config->xlink2state = (XLINK2STATE)v.get_long();

    else
        return false;

    return true;
}

SMTP_PROTO_CONF* SmtpModule::get_data()
{
    SMTP_PROTO_CONF* tmp = config;
    config = nullptr;
    return tmp;
}

bool SmtpModule::begin(const char*, int, SnortConfig*)
{
    names.clear();
    number = -1;

    if(!config)
    {
        config = new SMTP_PROTO_CONF;
        config->xlink2state = ALERT_XLINK2STATE;
        config->decode_conf.set_ignore_data(config->ignore_tls_data = false);
        config->normalize = NORMALIZE_NONE;

        config->log_config.email_hdrs_log_depth = 1464;
    }

    return true;
}

bool SmtpModule::end(const char* fqn, int idx, SnortConfig*)
{
    if ( !idx )
        return true;

    if ( !strcmp(fqn, "smtp.alt_max_command_line_len") )
        cmds.push_back(new SmtpCmd(names, number));

    return true;
}


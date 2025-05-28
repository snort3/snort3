//--------------------------------------------------------------------------
// Copyright (C) 2015-2025 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "smtp.h"

#include <string>

#include "detection/detection_engine.h"
#include "js_norm/js_pdf_norm.h"
#include "log/messages.h"
#include "log/unified2.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "protocols/ssl.h"
#include "pub_sub/opportunistic_tls_event.h"
#include "stream/stream.h"
#include "utils/safec.h"
#include "utils/util.h"
#include "utils/util_cstring.h"

#include "smtp_module.h"
#include "smtp_normalize.h"
#include "smtp_paf.h"
#include "smtp_util.h"
#include "smtp_xlink2state.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

// Indices in the buffer array exposed by InspectApi
// Must remain synchronized with smtp_bufs
enum SmtpBufId
{
    SMTP_FILE_DATA_ID = 1, SMTP_VBA_DATA_ID, SMTP_JS_DATA_ID
};

THREAD_LOCAL ProfileStats smtpPerfStats;
THREAD_LOCAL SmtpStats smtpstats;
THREAD_LOCAL bool smtp_normalizing;

/* Globals ****************************************************************/

const SMTPToken smtp_known_cmds[] =
{
    { "ATRN",          4, CMD_ATRN, SMTP_CMD_TYPE_NORMAL },
    { "AUTH",          4, CMD_AUTH, SMTP_CMD_TYPE_AUTH },
    { "BDAT",          4, CMD_BDAT, SMTP_CMD_TYPE_BDATA },
    { "DATA",          4, CMD_DATA, SMTP_CMD_TYPE_DATA },
    { "DEBUG",         5, CMD_DEBUG, SMTP_CMD_TYPE_NORMAL },
    { "EHLO",          4, CMD_EHLO, SMTP_CMD_TYPE_NORMAL },
    { "EMAL",          4, CMD_EMAL, SMTP_CMD_TYPE_NORMAL },
    { "ESAM",          4, CMD_ESAM, SMTP_CMD_TYPE_NORMAL },
    { "ESND",          4, CMD_ESND, SMTP_CMD_TYPE_NORMAL },
    { "ESOM",          4, CMD_ESOM, SMTP_CMD_TYPE_NORMAL },
    { "ETRN",          4, CMD_ETRN, SMTP_CMD_TYPE_NORMAL },
    { "EVFY",          4, CMD_EVFY, SMTP_CMD_TYPE_NORMAL },
    { "EXPN",          4, CMD_EXPN, SMTP_CMD_TYPE_NORMAL },
    { "HELO",          4, CMD_HELO, SMTP_CMD_TYPE_NORMAL },
    { "HELP",          4, CMD_HELP, SMTP_CMD_TYPE_NORMAL },
    { "IDENT",         5, CMD_IDENT, SMTP_CMD_TYPE_NORMAL },
    { "MAIL",          4, CMD_MAIL, SMTP_CMD_TYPE_NORMAL },
    { "NOOP",          4, CMD_NOOP, SMTP_CMD_TYPE_NORMAL },
    { "ONEX",          4, CMD_ONEX, SMTP_CMD_TYPE_NORMAL },
    { "QUEU",          4, CMD_QUEU, SMTP_CMD_TYPE_NORMAL },
    { "QUIT",          4, CMD_QUIT, SMTP_CMD_TYPE_NORMAL },
    { "RCPT",          4, CMD_RCPT, SMTP_CMD_TYPE_NORMAL },
    { "RSET",          4, CMD_RSET, SMTP_CMD_TYPE_NORMAL },
    { "SAML",          4, CMD_SAML, SMTP_CMD_TYPE_NORMAL },
    { "SEND",          4, CMD_SEND, SMTP_CMD_TYPE_NORMAL },
    { "SIZE",          4, CMD_SIZE, SMTP_CMD_TYPE_NORMAL },
    { "STARTTLS",      8, CMD_STARTTLS, SMTP_CMD_TYPE_NORMAL },
    { "SOML",          4, CMD_SOML, SMTP_CMD_TYPE_NORMAL },
    { "TICK",          4, CMD_TICK, SMTP_CMD_TYPE_NORMAL },
    { "TIME",          4, CMD_TIME, SMTP_CMD_TYPE_NORMAL },
    { "TURN",          4, CMD_TURN, SMTP_CMD_TYPE_NORMAL },
    { "TURNME",        6, CMD_TURNME, SMTP_CMD_TYPE_NORMAL },
    { "VERB",          4, CMD_VERB, SMTP_CMD_TYPE_NORMAL },
    { "VRFY",          4, CMD_VRFY, SMTP_CMD_TYPE_NORMAL },
    { "X-EXPS",        6, CMD_X_EXPS, SMTP_CMD_TYPE_AUTH },
    { "XADR",          4, CMD_XADR, SMTP_CMD_TYPE_NORMAL },
    { "XAUTH",         5, CMD_XAUTH, SMTP_CMD_TYPE_AUTH },
    { "XCIR",          4, CMD_XCIR, SMTP_CMD_TYPE_NORMAL },
    { "XEXCH50",       7, CMD_XEXCH50, SMTP_CMD_TYPE_BDATA },
    { "XGEN",          4, CMD_XGEN, SMTP_CMD_TYPE_NORMAL },
    { "XLICENSE",      8, CMD_XLICENSE, SMTP_CMD_TYPE_NORMAL },
    { "X-LINK2STATE", 12, CMD_X_LINK2STATE, SMTP_CMD_TYPE_NORMAL },
    { "XQUE",          4, CMD_XQUE, SMTP_CMD_TYPE_NORMAL },
    { "XSTA",          4, CMD_XSTA, SMTP_CMD_TYPE_NORMAL },
    { "XTRN",          4, CMD_XTRN, SMTP_CMD_TYPE_NORMAL },
    { "XUSR",          4, CMD_XUSR, SMTP_CMD_TYPE_NORMAL },
    { "*",             1, CMD_ABORT, SMTP_CMD_TYPE_NORMAL },
    { nullptr,            0, 0, SMTP_CMD_TYPE_NORMAL }
};

const SMTPToken smtp_resps[] =
{
    { "220",  3,  RESP_220, SMTP_CMD_TYPE_NORMAL },  /* Service ready - initial response and
                                                        STARTTLS response */
    { "221",  3,  RESP_221, SMTP_CMD_TYPE_NORMAL },  /* Goodbye - response to QUIT */
    { "235",  3,  RESP_235, SMTP_CMD_TYPE_NORMAL },  /* Auth done response */
    { "250",  3,  RESP_250, SMTP_CMD_TYPE_NORMAL },  /* Requested mail action okay, completed */
    { "334",  3,  RESP_334, SMTP_CMD_TYPE_NORMAL },  /* Auth intermediate response */
    { "354",  3,  RESP_354, SMTP_CMD_TYPE_NORMAL },  /* Start mail input - data response */
    { "421",  3,  RESP_421, SMTP_CMD_TYPE_NORMAL },  /* Service not available - closes connection
                                                        */
    { "450",  3,  RESP_450, SMTP_CMD_TYPE_NORMAL },  /* Mailbox unavailable */
    { "451",  3,  RESP_451, SMTP_CMD_TYPE_NORMAL },  /* Local error in processing */
    { "452",  3,  RESP_452, SMTP_CMD_TYPE_NORMAL },  /* Insufficient system storage */
    { "454",  3,  RESP_454, SMTP_CMD_TYPE_NORMAL },  /* TLS not available due to temporary reason */
    { "500",  3,  RESP_500, SMTP_CMD_TYPE_NORMAL },  /* Command unrecognized */
    { "501",  3,  RESP_501, SMTP_CMD_TYPE_NORMAL },  /* Syntax error in parameters or arguments */
    { "502",  3,  RESP_502, SMTP_CMD_TYPE_NORMAL },  /* Command not implemented */
    { "503",  3,  RESP_503, SMTP_CMD_TYPE_NORMAL },  /* Bad sequence of commands */
    { "504",  3,  RESP_504, SMTP_CMD_TYPE_NORMAL },  /* Command parameter not implemented */
    { "535",  3,  RESP_535, SMTP_CMD_TYPE_NORMAL },  /* Authentication failed */
    { "550",  3,  RESP_550, SMTP_CMD_TYPE_NORMAL },  /* Action not taken - mailbox unavailable */
    { "551",  3,  RESP_551, SMTP_CMD_TYPE_NORMAL },  /* User not local; please try <forward-path>
                                                        */
    { "552",  3,  RESP_552, SMTP_CMD_TYPE_NORMAL },  /* Mail action aborted: exceeded storage
                                                        allocation */
    { "553",  3,  RESP_553, SMTP_CMD_TYPE_NORMAL },  /* Action not taken: mailbox name not allowed
                                                        */
    { "554",  3,  RESP_554, SMTP_CMD_TYPE_NORMAL },  /* Transaction failed */
    { nullptr,   0,  0, SMTP_CMD_TYPE_NORMAL }
};

typedef struct _SMTPAuth
{
    const char* name;
    int name_len;
} SMTPAuth;

/* Cyrus SASL authentication mechanisms ANONYMOUS, PLAIN and LOGIN
 * does not have context
 */
const SMTPAuth smtp_auth_no_ctx[] =
{
    { "ANONYMOUS", 9 },
    { "PLAIN", 5 },
    { "LOGIN", 5 },
    { nullptr, 0 }
};

SearchTool* smtp_resp_search_mpse = nullptr;

SMTPSearch smtp_resp_search[RESP_LAST];

static THREAD_LOCAL const SMTPSearch* smtp_current_search = nullptr;
static THREAD_LOCAL SMTPSearchInfo smtp_search_info;

const PegInfo smtp_peg_names[] =
{
    { CountType::SUM, "packets", "total packets processed" },
    { CountType::SUM, "total_bytes", "total number of bytes processed" },
    { CountType::SUM, "sessions", "total smtp sessions" },
    { CountType::NOW, "concurrent_sessions", "total concurrent smtp sessions" },
    { CountType::MAX, "max_concurrent_sessions", "maximum concurrent smtp sessions" },
    { CountType::SUM, "start_tls", "total STARTTLS events generated" },
    { CountType::SUM, "ssl_search_abandoned", "total SSL search abandoned" },
    { CountType::SUM, "ssl_srch_abandoned_early", "total SSL search abandoned too soon" },
    { CountType::SUM, "b64_attachments", "total base64 attachments decoded" },
    { CountType::SUM, "b64_decoded_bytes", "total base64 decoded bytes" },
    { CountType::SUM, "qp_attachments", "total quoted-printable attachments decoded" },
    { CountType::SUM, "qp_decoded_bytes", "total quoted-printable decoded bytes" },
    { CountType::SUM, "uu_attachments", "total uu attachments decoded" },
    { CountType::SUM, "uu_decoded_bytes", "total uu decoded bytes" },
    { CountType::SUM, "non_encoded_attachments", "total non-encoded attachments extracted" },
    { CountType::SUM, "non_encoded_bytes", "total non-encoded extracted bytes" },
    { CountType::SUM, "js_pdf_scripts", "total number of PDF files processed" },

    { CountType::END, nullptr, nullptr }
};

enum SMTPCmdGroup
{
    ALERT_CMDS = 0,
    AUTH_CMDS,
    BDATA_CMDS,
    DATA_CMDS,
    NORM_CMDS,
    VALID_CMDS,
    ALT_LEN_CMDS
};

static void snort_smtp(SmtpProtoConf* GlobalConf, Packet* p);
static void SMTP_ResetState(Flow*);
static void update_eol_state(SMTPEol new_eol, SMTPEol& curr_eol_state);

SmtpFlowData::SmtpFlowData() : FlowData(inspector_id)
{
    smtpstats.concurrent_sessions++;
    if (smtpstats.max_concurrent_sessions < smtpstats.concurrent_sessions)
        smtpstats.max_concurrent_sessions = smtpstats.concurrent_sessions;
}

SmtpFlowData::~SmtpFlowData()
{
    delete session.mime_ssn;
    delete session.jsn;
    snort_free(session.auth_name);

    assert(smtpstats.concurrent_sessions > 0);
    smtpstats.concurrent_sessions--;
}

unsigned SmtpFlowData::inspector_id = 0;

static SMTPData* get_session_data(Flow* flow)
{
    SmtpFlowData* fd = (SmtpFlowData*)flow->get_flow_data(SmtpFlowData::inspector_id);
    return fd ? &fd->session : nullptr;
}

static inline PDFJSNorm* acquire_js_ctx(SMTPData& smtp_ssn, const void* data, size_t len)
{
    auto reload_id = SnortConfig::get_conf()->get_reload_id();

    if (smtp_ssn.jsn and smtp_ssn.jsn->get_generation_id() == reload_id)
        return smtp_ssn.jsn;

    delete smtp_ssn.jsn;
    smtp_ssn.jsn = nullptr;

    JSNormConfig* cfg = get_inspection_policy()->jsn_config;
    if (cfg and PDFJSNorm::is_pdf(data, len))
    {
        smtp_ssn.jsn = new PDFJSNorm(cfg, reload_id);
        ++smtpstats.js_pdf_scripts;
    }

    return smtp_ssn.jsn;
}

static SMTPData* SetNewSMTPData(SmtpProtoConf* config, Packet* p)
{
    SMTPData* smtp_ssn;
    SmtpFlowData* fd = new SmtpFlowData;

    p->flow->set_flow_data(fd);
    smtp_ssn = &fd->session;

    smtpstats.sessions++;
    smtp_ssn->mime_ssn = new SmtpMime(p, &(config->decode_conf), &(config->log_config));
    smtp_ssn->mime_ssn->config = config;
    smtp_ssn->mime_ssn->set_mime_stats(&(smtpstats.mime_stats));

    if (Stream::is_midstream(p->flow))
    {
        smtp_ssn->state = STATE_UNKNOWN;
    }

    return smtp_ssn;
}

static void SMTP_InitCmds(SmtpProtoConf* config)
{
    if (config == nullptr)
        return;

    config->cmd_config = (SMTPCmdConfig*)snort_calloc(CMD_LAST, sizeof(*config->cmd_config));
    config->cmds = (SMTPToken*)snort_calloc((CMD_LAST + 1), sizeof(*config->cmds));

    for (const SMTPToken* tmp = &smtp_known_cmds[0]; tmp->name != nullptr; tmp++)
    {
        SMTPToken* tok = config->cmds + tmp->search_id;
        tok->name_len = tmp->name_len;
        tok->search_id = tmp->search_id;
        tok->name = snort_strdup(tmp->name);
        tok->type = tmp->type;
    }

    config->num_cmds = CMD_LAST;
}

static void SMTP_TermCmds(SmtpProtoConf* config)
{
    if (!config)
        return;
    if (config->cmds)
    {
        for ( int i = 0; i <= config->num_cmds; ++i )
            snort_free(const_cast<char*>(config->cmds[i].name));
        snort_free(config->cmds);
    }
    if (config->cmd_config)
        snort_free(config->cmd_config);
}

static void SMTP_CommandSearchInit(SmtpProtoConf* config)
{
    config->cmd_search_mpse = new SearchTool;
    config->cmd_search = (SMTPSearch*)snort_calloc(config->num_cmds, sizeof(*config->cmd_search));

    for ( const SMTPToken* tmp = config->cmds; tmp->name != nullptr; tmp++ )
    {
        config->cmd_search[tmp->search_id].name = tmp->name;
        config->cmd_search[tmp->search_id].name_len = tmp->name_len;
        config->cmd_search_mpse->add(tmp->name, tmp->name_len, tmp->search_id);
    }

    config->cmd_search_mpse->prep();
}

static void SMTP_CommandSearchTerm(SmtpProtoConf* config)
{
    if (config->cmd_search == nullptr)
        return;
    snort_free(config->cmd_search);
    delete config->cmd_search_mpse;
}

static void SMTP_ResponseSearchInit()
{
    const SMTPToken* tmp;

    if ( smtp_resp_search_mpse )
        return;

    smtp_resp_search_mpse = new SearchTool;

    for (tmp = &smtp_resps[0]; tmp->name != nullptr; tmp++)
    {
        smtp_resp_search[tmp->search_id].name = tmp->name;
        smtp_resp_search[tmp->search_id].name_len = tmp->name_len;
        smtp_resp_search_mpse->add(tmp->name, tmp->name_len, tmp->search_id);
    }
    smtp_resp_search_mpse->prep();
}

static void SMTP_SearchFree()
{
    if (smtp_resp_search_mpse != nullptr)
        delete smtp_resp_search_mpse;
}

static int AddCmd(SmtpProtoConf* config, const char* name, SMTPCmdTypeEnum type)
{
    SMTPToken* cmds;
    SMTPCmdConfig* cmd_config;

    config->num_cmds++;

    /* allocate enough memory for new command - alloc one extra for null entry */
    // FIXIT-L this constant reallocation is not necessary; use vector
    cmds = (SMTPToken*)snort_calloc((config->num_cmds + 1) * sizeof(*cmds));
    cmd_config = (SMTPCmdConfig*)snort_calloc((config->num_cmds + 1) * sizeof(*cmd_config));

    /* copy existing commands into newly allocated memory */
    memcpy_s(cmds, config->num_cmds * sizeof(*cmds),
        config->cmds, (config->num_cmds - 1) * sizeof(*cmds));

    memcpy_s(cmd_config, config->num_cmds * sizeof(*cmd_config),
        config->cmd_config, (config->num_cmds - 1) * sizeof(*cmd_config));

    /* add new command to cmds cmd_config doesn't need anything added - this
     * will probably be done by a calling function */

    SMTPToken* tok = cmds + config->num_cmds - 1;
    tok->name = snort_strdup(name);
    tok->name_len = strlen(name);
    tok->search_id = config->num_cmds - 1;

    if ( type )
        tok->type = type;

    /* free global memory structures */
    if ( config->cmds )
        snort_free(config->cmds);

    if ( config->cmd_config )
        snort_free(config->cmd_config);

    /* set globals to new memory */
    config->cmds = cmds;
    config->cmd_config = cmd_config;

    return config->num_cmds - 1;
}

/* Return id associated with a given command string */
static int GetCmdId(SmtpProtoConf* config, const char* name, SMTPCmdTypeEnum type)
{
    SMTPToken* cmd;

    for (cmd = config->cmds; cmd->name != nullptr; cmd++)
    {
        if (strcasecmp(cmd->name, name) == 0)
        {
            if (type && (type != cmd->type))
                cmd->type = type;

            return cmd->search_id;
        }
    }

    return AddCmd(config, name, type);
}

static std::string GetCmdGroup(const SMTPToken* cmd_tokens, const SMTPCmdConfig* cmd_config,
    SMTPCmdGroup group)
{
    std::string cmds;

    for (auto cmd = cmd_tokens; cmd->name; cmd++)
    {
        bool cond;

        if ( group == ALERT_CMDS )
            cond = cmd_config[cmd->search_id].alert;
        else if ( group == VALID_CMDS )
            cond = !cmd_config[cmd->search_id].alert;
        else if ( group == NORM_CMDS )
            cond = cmd_config[cmd->search_id].normalize;
        else if ( group == ALT_LEN_CMDS )
            cond = cmd_config[cmd->search_id].max_line_len;
        else if ( group == AUTH_CMDS )
            cond = (cmd->type == SMTP_CMD_TYPE_AUTH);
        else if ( group == BDATA_CMDS )
            cond = (cmd->type == SMTP_CMD_TYPE_BDATA);
        else if ( group == DATA_CMDS )
            cond = (cmd->type == SMTP_CMD_TYPE_DATA);
        else
            return cmds;

        if ( cond )
        {
            if ( group == ALT_LEN_CMDS )
            {
                std::string cmd_name = cmd->name;
                int len = cmd_config[cmd->search_id].max_line_len;
                cmds.append("{" + cmd_name + ", " + std::to_string(len) + "}");
                cmds.append(", ");
            }
            else
            {
                cmds.append(cmd->name);
                cmds.append(" ");
            }
        }
    }

    if ( !cmds.empty() )
    {
        if ( group == ALT_LEN_CMDS )
        {
            cmds.erase(cmds.end() - 2);
            cmds = "{ " + cmds + " }";
        }
        else
            cmds.pop_back();
    }
    else
        cmds.append("none");

    return cmds;
}

static const char* to_string(const SMTPNormType& normalize)
{
    switch (normalize)
    {
    case NORMALIZE_ALL:
        return "all";
    case NORMALIZE_NONE:
        return "none";
    case NORMALIZE_CMDS:
        return "cmds";
    }

    return "";
}

static const char* to_string(const SMTPXlinkState& mode)
{
    switch (mode)
    {
    case DISABLE_XLINK2STATE:
        return "disable";
    case ALERT_XLINK2STATE:
        return "alert";
    case DROP_XLINK2STATE:
        return "drop";
    }

    return "";
}

static void log_mail_show(const snort::MailLogConfig& conf)
{
    ConfigLogger::log_flag("log_mailfrom", conf.log_mailfrom);
    ConfigLogger::log_flag("log_rcptto", conf.log_rcptto);
    ConfigLogger::log_flag("log_filename", conf.log_filename);

    if ( ConfigLogger::log_flag("log_email_hdrs", conf.log_email_hdrs) )
        ConfigLogger::log_value("email_hdrs_log_depth", conf.email_hdrs_log_depth);
}

void SmtpProtoConf::show() const
{
    auto alt_len_cmds = GetCmdGroup(cmds, cmd_config, ALT_LEN_CMDS);
    auto alert_cmds = GetCmdGroup(cmds, cmd_config, ALERT_CMDS);
    auto auth_cmds = GetCmdGroup(cmds, cmd_config, AUTH_CMDS);
    auto bdata_cmds = GetCmdGroup(cmds, cmd_config, BDATA_CMDS);
    auto data_cmds = GetCmdGroup(cmds, cmd_config, DATA_CMDS);
    auto norm_cmds = GetCmdGroup(cmds, cmd_config, NORM_CMDS);
    auto valid_cmds = GetCmdGroup(cmds, cmd_config, VALID_CMDS);

    ConfigLogger::log_value("normalize", to_string(normalize));
    ConfigLogger::log_list("normalize_cmds", norm_cmds.c_str());

    ConfigLogger::log_flag("ignore_tls_data", ignore_tls_data);
    ConfigLogger::log_limit("max_command_line_len", max_command_line_len, 0);
    ConfigLogger::log_list("alt_max_command_line_len", alt_len_cmds.c_str());
    ConfigLogger::log_limit("max_header_line_len", max_header_line_len, 0);
    ConfigLogger::log_limit("max_auth_command_line_len", max_auth_command_line_len, 0);
    ConfigLogger::log_limit("max_response_line_length", max_response_line_len, 0);

    ConfigLogger::log_value("xlink2state", to_string(xlink2state));
    ConfigLogger::log_list("invalid_cmds", alert_cmds.c_str());

    ConfigLogger::log_list("auth_cmds", auth_cmds.c_str());
    ConfigLogger::log_list("binary_data_cmds", bdata_cmds.c_str());
    ConfigLogger::log_list("data_cmds", data_cmds.c_str());
    ConfigLogger::log_list("valid_cmds", valid_cmds.c_str());

    decode_conf.show(true);
    log_mail_show(log_config);
}

static void SMTP_ResetState(Flow* ssn)
{
    SMTPData* smtp_ssn = get_session_data(ssn);
    if( smtp_ssn )
    {
        smtp_ssn->state = STATE_COMMAND;
        smtp_ssn->state_flags = (smtp_ssn->state_flags & SMTP_FLAG_ABANDON_EVT) ? SMTP_FLAG_ABANDON_EVT : 0;

        delete smtp_ssn->jsn;
        smtp_ssn->jsn = nullptr;
    }
}

static inline int InspectPacket(Packet* p)
{
    return p->has_paf_payload();
}

/*
 * Do first-packet setup
 *
 * @param   p   standard Packet structure
 *
 * @return  none
 */
static int SMTP_Setup(Packet* p, SMTPData* ssn)
{
    int pkt_dir;

    /* Get the direction of the packet. */
    if ( p->is_from_server() )
        pkt_dir = SMTP_PKT_FROM_SERVER;
    else
        pkt_dir = SMTP_PKT_FROM_CLIENT;

    if (!(ssn->session_flags & SMTP_FLAG_CHECK_SSL))
        ssn->session_flags |= SMTP_FLAG_CHECK_SSL;
    /* Check to see if there is a reassembly gap.  If so, we won't know
     *      *      * what state we're in when we get the _next_ reassembled packet */

    /* Check to see if there is a reassembly gap.  If so, we won't know
     * what state we're in when we get the _next_ reassembled packet */
    if ((pkt_dir != SMTP_PKT_FROM_SERVER) &&
        (p->packet_flags & PKT_REBUILT_STREAM))
    {
        int missing_in_rebuilt =
            Stream::missing_in_reassembled(p->flow, SSN_DIR_FROM_CLIENT);

        if (ssn->session_flags & SMTP_FLAG_NEXT_STATE_UNKNOWN)
        {
            ssn->state = STATE_UNKNOWN;
            ssn->session_flags &= ~SMTP_FLAG_NEXT_STATE_UNKNOWN;
        }

        if (missing_in_rebuilt == SSN_MISSING_BEFORE)
        {
            ssn->state = STATE_UNKNOWN;
        }
    }

    return pkt_dir;
}

/*
 * Callback function for string search
 *
 * @param   id      id in array of search strings from smtp_config.cmds
 * @param   index   index in array of search strings from smtp_config.cmds
 * @param   data    buffer passed in to search function
 *
 * @return response
 * @retval 1        commands caller to stop searching
 */
static int SMTP_SearchStrFound(void* id, void*, int index, void*, void*)
{
    int search_id = (int)(uintptr_t)id;

    smtp_search_info.id = search_id;
    smtp_search_info.length = smtp_current_search[search_id].name_len;
    smtp_search_info.index = index - smtp_search_info.length;

    /* Returning non-zero stops search, which is okay since we only look for one at a time */
    return 1;
}

static bool SMTP_IsAuthCtxIgnored(const uint8_t* start, int length)
{
    const SMTPAuth* tmp;
    for (tmp = &smtp_auth_no_ctx[0]; tmp->name != nullptr; tmp++)
    {
        if ((tmp->name_len == length) && (!memcmp(start, tmp->name, length)))
            return true;
    }

    return false;
}

static bool SMTP_IsAuthChanged(SMTPData* smtp_ssn, const uint8_t* start_ptr, const
    uint8_t* end_ptr)
{
    const uint8_t* start = start_ptr;
    const uint8_t* end = end_ptr;

    while ((start < end) && isspace(*start))
        start++;
    while ((start < end) && isspace(*(end-1)))
        end--;

    if (start >= end)
        return false;

    int length = end - start;

    if (length > MAX_AUTH_NAME_LEN)
        return false;

    if (SMTP_IsAuthCtxIgnored(start, length))
        return false;

    /* if authentication mechanism is set, compare it with current one*/
    bool auth_changed = false;
    if (smtp_ssn->auth_name)
    {
        if (smtp_ssn->auth_name->length != length)
            auth_changed = true;
        else if (memcmp(start, smtp_ssn->auth_name->name, length))
            auth_changed = true;
    }
    else
        smtp_ssn->auth_name = (SMTPAuthName*)snort_calloc(sizeof(*(smtp_ssn->auth_name)));

    /* save the current authentication mechanism*/
    if (auth_changed || (!smtp_ssn->auth_name->length))
    {
        memcpy(smtp_ssn->auth_name->name, start, length);
        smtp_ssn->auth_name->length = length;
    }

    return auth_changed;
}

/*
 * Handle COMMAND state
 *
 * @param   p       standard Packet structure
 * @param   ptr     pointer into p->data buffer to start looking at data
 * @param   end     points to end of p->data buffer
 *
 * @return          pointer into p->data where we stopped looking at data
 *                  will be end of line or end of packet
 */
static const uint8_t* SMTP_HandleCommand(SmtpProtoConf* config, Packet* p, SMTPData* smtp_ssn,
    const uint8_t* ptr, const uint8_t* end)
{
    const uint8_t* eol;   /* end of line */
    const uint8_t* eolm;  /* end of line marker */
    int cmd_line_len;
    int ret;
    int cmd_found;
    char alert_long_command_line = 0;

    /* get end of line and end of line marker */
    SMTPEol new_eol = SMTP_GetEOL(ptr, end, &eol, &eolm);

    /* calculate length of command line */
    cmd_line_len = eol - ptr;

    /* check for command line exceeding maximum
     * do this before checking for a command since this could overflow
     * some server's buffers without the presence of a known command */
    if ((config->max_command_line_len != 0) &&
        (cmd_line_len > config->max_command_line_len))
    {
        alert_long_command_line = 1;
    }

    // FIXIT-M if the end of line marker coincides with the end of data we
    // can't be sure that we got a command and not a substring which we
    // could tell through inspection of the next packet. Maybe a command
    // pending state where the first char in the next packet is checked for
    // a space and end of line marker

    /* do not confine since there could be space chars before command */
    smtp_current_search = &config->cmd_search[0];
    cmd_found = config->cmd_search_mpse->find(
        (const char*)ptr, eolm - ptr, SMTP_SearchStrFound);
    /* see if we actually found a command and not a substring */
    if (cmd_found > 0)
    {
        if (!smtp_ssn->client_requested_starttls)
            ++smtp_ssn->pipelined_command_counter;

        const uint8_t* tmp = ptr;
        const uint8_t* cmd_start = ptr + smtp_search_info.index;
        const uint8_t* cmd_end = cmd_start + smtp_search_info.length;

        /* move past spaces up until start of command */
        while ((tmp < cmd_start) && isspace((int)*tmp))
            tmp++;

        /* if not all spaces before command, we found a
         * substring */
        if (tmp != cmd_start)
            cmd_found = 0;

        /* if we're before the end of line marker and the next
         * character is not whitespace, we found a substring */
        if ((cmd_end < eolm) && !isspace((int)*cmd_end))
            cmd_found = 0;

        /* there is a chance that end of command coincides with the end of data
         * in which case, it could be a substring, but for now, we will treat it as found */
    }

    /* if command not found, alert and move on */
    if (!cmd_found)
    {
        /* If we missed one or more packets we might not actually be in the command
         * state.  Check to see if we're encrypted */
        if (smtp_ssn->state == STATE_UNKNOWN)
        {
            /* check for encrypted */

            if ((smtp_ssn->session_flags & SMTP_FLAG_CHECK_SSL) &&
                (IsSSL(ptr, end - ptr, p->packet_flags)))
            {
                smtp_ssn->state = STATE_TLS_DATA;
                return end;
            }
            else
            {
                /* don't check for ssl again in this packet */
                if (smtp_ssn->session_flags & SMTP_FLAG_CHECK_SSL)
                    smtp_ssn->session_flags &= ~SMTP_FLAG_CHECK_SSL;

                smtp_ssn->state = STATE_DATA;
                smtp_ssn->mime_ssn->set_data_state(STATE_DATA_INIT);

                return ptr;
            }
        }
        else
        {
            if (smtp_ssn->state != STATE_AUTH)
            {
                DetectionEngine::queue_event(GID_SMTP,SMTP_UNKNOWN_CMD);

                if (alert_long_command_line)
                    DetectionEngine::queue_event(GID_SMTP, SMTP_COMMAND_OVERFLOW);
            }

            /* if normalizing, copy line to alt buffer */
            if (smtp_normalizing)
            {
                ret = SMTP_CopyToAltBuffer(p, ptr, eol - ptr);
                if (ret == -1)
                    return nullptr;
            }

            return eol;
        }
    }

    /* At this point we have definitely found a legitimate command */

    /* check if max command line length for a specific command is exceeded */
    if (config->cmd_config[smtp_search_info.id].max_line_len != 0)
    {
        if (cmd_line_len > config->cmd_config[smtp_search_info.id].max_line_len)
        {
            DetectionEngine::queue_event(GID_SMTP, SMTP_SPECIFIC_CMD_OVERFLOW);
        }
    }
    else if (alert_long_command_line)
    {
        DetectionEngine::queue_event(GID_SMTP, SMTP_COMMAND_OVERFLOW);
    }

    if (config->cmd_config[smtp_search_info.id].alert)
    {
        /* Are we alerting on this command? */
        DetectionEngine::queue_event(GID_SMTP, SMTP_ILLEGAL_CMD);
    }

    bool alert_on_command_injection = smtp_ssn->client_requested_starttls;

    switch (smtp_search_info.id)
    {
    /* unless we do our own parsing of MAIL and RCTP commands we have to assume they
     * are ok unless we got a server error in which case we flush and if this is a
     * reassembled packet, the last command in this packet will be the command that
     * caused the error */
    case CMD_MAIL:
        smtp_ssn->state_flags |= SMTP_FLAG_GOT_MAIL_CMD;
        if ( config->log_config.log_mailfrom )
        {
            smtp_ssn->mime_ssn->get_log_state()->log_email_id(ptr, eolm - ptr, EMAIL_SENDER);
        }

        break;

    case CMD_RCPT:
        if ((smtp_ssn->state_flags & SMTP_FLAG_GOT_MAIL_CMD) ||
            smtp_ssn->state == STATE_UNKNOWN)
        {
            smtp_ssn->state_flags |= SMTP_FLAG_GOT_RCPT_CMD;
        }

        if (config->log_config.log_rcptto)
        {
            smtp_ssn->mime_ssn->get_log_state()->log_email_id(ptr, eolm - ptr, EMAIL_RECIPIENT);
        }

        break;

    case CMD_RSET:
    case CMD_HELO:
    case CMD_EHLO:
    case CMD_QUIT:
        smtp_ssn->state_flags &= ~(SMTP_FLAG_GOT_MAIL_CMD | SMTP_FLAG_GOT_RCPT_CMD);
        smtp_ssn->client_requested_starttls = false;
        smtp_ssn->server_accepted_starttls = false;
        smtp_ssn->pipelined_command_counter = 0;
        alert_on_command_injection = false;

        break;

    case CMD_STARTTLS:
        /* if reassembled we flush after seeing a 220 so this should be the last
         * command in reassembled packet and if not reassembled it should be the
         * last line in the packet as you can't pipeline the tls hello */
        if (eol == end)
        {
            smtp_ssn->client_requested_starttls = true;
        }

        break;

    case CMD_X_LINK2STATE:
        if (config->xlink2state)
            ParseXLink2State(config, p, smtp_ssn, ptr + smtp_search_info.index);

        break;

    case CMD_AUTH:
        smtp_ssn->state = STATE_AUTH;
        if (SMTP_IsAuthChanged(smtp_ssn, ptr + smtp_search_info.index + smtp_search_info.length,
            eolm)
            && (smtp_ssn->state_flags & SMTP_FLAG_ABORT))
        {
            DetectionEngine::queue_event(GID_SMTP, SMTP_AUTH_ABORT_AUTH);
        }
        smtp_ssn->state_flags &= ~(SMTP_FLAG_ABORT);
        break;

    case CMD_ABORT:
        smtp_ssn->state_flags |= SMTP_FLAG_ABORT;
        break;

    default:
        switch (smtp_known_cmds[smtp_search_info.id].type)
        {
        case SMTP_CMD_TYPE_DATA:
            if ((smtp_ssn->state_flags & SMTP_FLAG_GOT_RCPT_CMD) ||
                smtp_ssn->state == STATE_UNKNOWN)
            {
                smtp_ssn->state = STATE_DATA;
                smtp_ssn->state_flags &= ~(SMTP_FLAG_GOT_MAIL_CMD | SMTP_FLAG_GOT_RCPT_CMD);
            }

            break;

        case SMTP_CMD_TYPE_BDATA:
            if ((smtp_ssn->state_flags & (SMTP_FLAG_GOT_RCPT_CMD | SMTP_FLAG_BDAT))
                || (smtp_ssn->state == STATE_UNKNOWN))
            {
                const uint8_t* begin_chunk;
                const uint8_t* end_chunk;
                const uint8_t* tmp;
                int num_digits;
                int ten_power;
                uint32_t dat_chunk = 0;

                begin_chunk = ptr + smtp_search_info.index + smtp_search_info.length;
                while ((begin_chunk < eolm) && isspace((int)*begin_chunk))
                    begin_chunk++;

                /* bad BDAT command - needs chunk argument */
                if (begin_chunk == eolm)
                    break;

                end_chunk = begin_chunk;
                while ((end_chunk < eolm) && isdigit((int)*end_chunk))
                    end_chunk++;

                /* didn't get all digits */
                if ((end_chunk < eolm) && !isspace((int)*end_chunk))
                    break;

                /* get chunk size */
                num_digits = end_chunk - begin_chunk;

                /* more than 9 digits could potentially overflow a 32 bit integer
                 * most servers won't accept this much in a chunk */
                if (num_digits > 9)
                    break;

                tmp = end_chunk;
                for (ten_power = 1, tmp--; tmp >= begin_chunk; ten_power *= 10, tmp--)
                    dat_chunk += (*tmp - '0') * ten_power;

                if (smtp_search_info.id == CMD_BDAT)
                {
                    /* got a valid chunk size - check to see if this is the last chunk */
                    const uint8_t* last = end_chunk;
                    bool bdat_last = false;

                    while ((last < eolm) && isspace((int)*last))
                        last++;

                    // cppcheck-suppress knownConditionTrueFalse
                    if (((eolm - last) >= 4)
                        && (strncasecmp("LAST", (const char*)last, 4) == 0))
                    {
                        bdat_last = true;
                    }

                    // cppcheck-suppress knownConditionTrueFalse
                    if (bdat_last || (dat_chunk == 0))
                        smtp_ssn->state_flags &= ~(SMTP_FLAG_BDAT);
                    else
                        smtp_ssn->state_flags |= SMTP_FLAG_BDAT;

                    smtp_ssn->state = STATE_BDATA;
                    smtp_ssn->state_flags &= ~(SMTP_FLAG_GOT_MAIL_CMD | SMTP_FLAG_GOT_RCPT_CMD);
                }
                else if (smtp_search_info.id == CMD_XEXCH50)
                {
                    smtp_ssn->state = STATE_XEXCH50;
                }
                else
                {
                    smtp_ssn->state = STATE_BDATA;
                    smtp_ssn->state_flags &= ~(SMTP_FLAG_GOT_MAIL_CMD | SMTP_FLAG_GOT_RCPT_CMD);
                }

                smtp_ssn->dat_chunk = dat_chunk;
            }

            break;

        case SMTP_CMD_TYPE_AUTH:
            smtp_ssn->state = STATE_AUTH;
            break;

        default:
            break;
        }
        break;
    }

    /* Since we found a command, if state is still unknown,
     * set to command state */
    if (smtp_ssn->state == STATE_UNKNOWN)
        smtp_ssn->state = STATE_COMMAND;

    /* normalize command line */
    if (config->normalize == NORMALIZE_ALL ||
        config->cmd_config[smtp_search_info.id].normalize)
    {
        ret = SMTP_NormalizeCmd(p, ptr, eolm, eol);
        if (ret == -1)
            return nullptr;
    }
    else if (smtp_normalizing) /* Already normalizing */
    {
        ret = SMTP_CopyToAltBuffer(p, ptr, eol - ptr);
        if (ret == -1)
            return nullptr;
    }

     /*If client sends another command after STARTTLS raise the alert of command injection
      STARTTLS command should be the last command when PIPELINING*/
    if (alert_on_command_injection)
    {
       DetectionEngine::queue_event(GID_SMTP, SMTP_STARTTLS_INJECTION_ATTEMPT);
    }

    update_eol_state(new_eol, smtp_ssn->client_eol);

    return eol;
}

/*
 * Process client packet
 *
 * @param   packet  standard Packet structure
 *
 * @return  none
 */
static void SMTP_ProcessClientPacket(SmtpProtoConf* config, Packet* p, SMTPData* smtp_ssn)
{
    const uint8_t* ptr = p->data;
    const uint8_t* end = p->data + p->dsize;

    if (smtp_ssn->state == STATE_CONNECT)
        smtp_ssn->state = STATE_COMMAND;

    while ((ptr != nullptr) && (ptr < end))
    {
        FilePosition position;
        int len = end - ptr;

        switch (smtp_ssn->state)
        {
        case STATE_COMMAND:
            ptr = SMTP_HandleCommand(config, p, smtp_ssn, ptr, end);
            break;
        case STATE_DATA:
        case STATE_BDATA:
            position = get_file_position(p);
            if (isFileStart(position))
            {
                delete smtp_ssn->jsn;
                smtp_ssn->jsn = nullptr;
            }
            ptr = smtp_ssn->mime_ssn->process_mime_data(p, ptr, len, true, position);
            //ptr = SMTP_HandleData(p, ptr, end, &(smtp_ssn->mime_ssn));
            if (smtp_ssn->jsn)
                smtp_ssn->jsn->tick();
            break;
        case STATE_XEXCH50:
            if (smtp_normalizing)
                (void)SMTP_CopyToAltBuffer(p, ptr, end - ptr);
            if (smtp_is_data_end (p->flow))
                smtp_ssn->state = STATE_COMMAND;
            return;
        case STATE_AUTH:
            ptr = SMTP_HandleCommand(config, p, smtp_ssn, ptr, end);
            break;
        case STATE_UNKNOWN:
            /* If state is unknown try command state to see if we can
             * regain our bearings */
            ptr = SMTP_HandleCommand(config, p, smtp_ssn, ptr, end);
            break;
        default:
            return;
        }
    }
}

/*
 * Process server packet
 *
 * @param   packet  standard Packet structure
 *
 * @return  None
 */
static void SMTP_ProcessServerPacket(
    SmtpProtoConf* config, Packet* p, SMTPData* smtp_ssn, int* next_state)
{
    *next_state = 0;

    const uint8_t* ptr = p->data;
    const uint8_t* end = p->data + p->dsize;

    if (smtp_ssn->state == STATE_TLS_SERVER_PEND)
    {
        if (IsTlsServerHello(ptr, end))
        {
            smtp_ssn->state = STATE_TLS_DATA;
            //TLS server hello received, reset flag
            smtp_ssn->server_accepted_starttls = false;
            smtp_ssn->client_requested_starttls = false;
        }
        else if ( !p->test_session_flags(SSNFLAG_MIDSTREAM)
            && !Stream::missed_packets(p->flow, SSN_DIR_BOTH))
        {
            smtp_ssn->state = STATE_COMMAND;
        }
    }

    if (smtp_ssn->state == STATE_TLS_CLIENT_PEND)
    {
        if (p->flow->flags.data_decrypted)
        {
            smtp_ssn->state = STATE_COMMAND;
            smtp_ssn->server_accepted_starttls = false;
            smtp_ssn->client_requested_starttls = false;
        }
        else
        {
            smtp_ssn->state = STATE_TLS_DATA;
        }
    }

    while (ptr < end)
    {
        const uint8_t* eol;
        const uint8_t* eolm;

        SMTPEol new_eol = SMTP_GetEOL(ptr, end, &eol, &eolm);

        int resp_line_len = eol - ptr;

        /* Check for response code */
        smtp_current_search = &smtp_resp_search[0];

        if (smtp_ssn->state != STATE_TLS_DATA or p->flow->flags.data_decrypted)
        {
            int resp_found = smtp_resp_search_mpse->find(
                (const char*)ptr, resp_line_len, SMTP_SearchStrFound);

            if (resp_found > 0)
            {
                switch (smtp_search_info.id)
                {
                case RESP_220:
                    /* This is either an initial server response or a STARTTLS response */
                    if (smtp_ssn->state == STATE_CONNECT)
                        smtp_ssn->state = STATE_COMMAND;
                    break;

                case RESP_250:
                case RESP_221:
                case RESP_334:
                case RESP_354:
                    if ((smtp_ssn->state == STATE_DATA or smtp_ssn->state == STATE_BDATA)
                        and !p->flow->flags.data_decrypted
                        and !(smtp_ssn->state_flags & SMTP_FLAG_ABANDON_EVT))
                    {
                        smtp_ssn->state_flags |= SMTP_FLAG_ABANDON_EVT;
                        DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::SSL_SEARCH_ABANDONED, p);
                        ++smtpstats.ssl_search_abandoned;
                    }
                    break;

                case RESP_235:
                    // Auth done
                    *next_state = STATE_COMMAND;
                    break;

                default:
                    if (smtp_ssn->state != STATE_COMMAND and smtp_ssn->state != STATE_TLS_DATA)
                    {
                        *next_state = STATE_COMMAND;
                    }
                    break;
                }
                //Count responses of client commands, reset starttls waiting flag if response to STARTTLS is not 220
                if (smtp_ssn->pipelined_command_counter > 0 and --smtp_ssn->pipelined_command_counter == 0 and smtp_ssn->client_requested_starttls)
                {
                    if (smtp_search_info.id != RESP_220)
                    {
                        smtp_ssn->client_requested_starttls = false;
                        smtp_ssn->server_accepted_starttls = false;
                    }
                    else
                    {
                        smtp_ssn->server_accepted_starttls = true;
                        smtp_ssn->state = STATE_TLS_CLIENT_PEND;

                        OpportunisticTlsEvent event(p, p->flow->service);
                        DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::OPPORTUNISTIC_TLS, event, p->flow);
                        ++smtpstats.starttls;
                        if (smtp_ssn->state_flags & SMTP_FLAG_ABANDON_EVT)
                            ++smtpstats.ssl_search_abandoned_too_soon;
                    }
                }
            }
            else
            {
                if ((smtp_ssn->session_flags & SMTP_FLAG_CHECK_SSL) &&
                    (IsSSL(ptr, end - ptr, p->packet_flags)))
                {
                    smtp_ssn->state = STATE_TLS_DATA;
                    return;
                }
                else if (smtp_ssn->session_flags & SMTP_FLAG_CHECK_SSL)
                {
                    smtp_ssn->session_flags &= ~SMTP_FLAG_CHECK_SSL;
                }
            }
        }

        if (smtp_ssn->state != STATE_TLS_DATA)
        {
            update_eol_state(new_eol, smtp_ssn->server_eol);
            if ((config->max_response_line_len != 0) &&
                (resp_line_len > config->max_response_line_len))
            DetectionEngine::queue_event(GID_SMTP, SMTP_RESPONSE_OVERFLOW);
        }

        ptr = eol;
    }
}

static void snort_smtp(SmtpProtoConf* config, Packet* p)
{
    int pkt_dir;

    /* Attempt to get a previously allocated SMTP block. */

    SMTPData* smtp_ssn = get_session_data(p->flow);

    if (smtp_ssn == nullptr)
    {
        /* Check the stream session. If it does not currently
         *          * have our SMTP data-block attached, create one.
         *                   */
        smtp_ssn = SetNewSMTPData(config, p);

        if ( !smtp_ssn )
        {
            /* Could not get/create the session data for this packet. */
            return;
        }
    }

    pkt_dir = SMTP_Setup(p, smtp_ssn);
    SMTP_ResetAltBuffer(p);

    /* reset normalization stuff */
    smtp_normalizing = false;
    smtpstats.total_bytes += p->dsize;
    if (smtp_ssn->jsn)
        smtp_ssn->jsn->flush_data();

    if (pkt_dir == SMTP_PKT_FROM_SERVER)
    {
        int next_state = 0;

        /* Process as a server packet */
        SMTP_ProcessServerPacket(config, p, smtp_ssn, &next_state);

        if (next_state)
            smtp_ssn->state = next_state;
    }
    else
    {
        /* This packet should be a tls client hello */
        if (smtp_ssn->server_accepted_starttls)
        {
            if (IsTlsClientHello(p->data, p->data + p->dsize))
            {
                smtp_ssn->state = STATE_TLS_SERVER_PEND;
            }
        }

        if(smtp_ssn->state == STATE_TLS_CLIENT_PEND)
            smtp_ssn->state = STATE_COMMAND;

        if ((smtp_ssn->state == STATE_TLS_DATA)
            || (smtp_ssn->state == STATE_TLS_SERVER_PEND))
        {
            /* if we're ignoring tls data, set a zero length alt buffer */
            if (config->ignore_tls_data)
            {
                Stream::stop_inspection(p->flow, p, SSN_DIR_BOTH, -1, 0);
                return;
            }
        }
        else
        {
            if ( !InspectPacket(p))
            {
                /* Packet will be rebuilt, so wait for it */
                return;
            }
            else if (!(p->packet_flags & PKT_REBUILT_STREAM))
            {
                /* If this isn't a reassembled packet and didn't get
                 * inserted into reassembly buffer, there could be a
                 * problem.  If we miss syn or syn-ack that had window
                 * scaling this packet might not have gotten inserted
                 * into reassembly buffer because it fell outside of
                 * window, because we aren't scaling it */
                smtp_ssn->session_flags |= SMTP_FLAG_GOT_NON_REBUILT;
                smtp_ssn->state = STATE_UNKNOWN;
            }
            else if ((smtp_ssn->session_flags & SMTP_FLAG_GOT_NON_REBUILT))
            {
                /* This is a rebuilt packet.  If we got previous packets
                 * that were not rebuilt, state is going to be messed up
                 * so set state to unknown. It's likely this was the
                 * beginning of the conversation so reset state */
                smtp_ssn->state = STATE_UNKNOWN;
                smtp_ssn->session_flags &= ~SMTP_FLAG_GOT_NON_REBUILT;
            }

            SMTP_ProcessClientPacket(config, p, smtp_ssn);
        }
    }

    SMTP_LogFuncs(config, p, smtp_ssn->mime_ssn);
}

/* Callback to return the MIME attachment filenames accumulated */
static int SMTP_GetFilename(Flow* flow, uint8_t** buf, uint32_t* len, uint32_t* type)
{
    SMTPData* ssn = get_session_data(flow);

    if (ssn == nullptr)
        return 0;

    ssn->mime_ssn->get_log_state()->get_file_name(buf, len);
    *type = EVENT_INFO_SMTP_FILENAME;
    return 1;
}

/* Callback to return the email addresses accumulated from the MAIL FROM command */
static int SMTP_GetMailFrom(Flow* flow, uint8_t** buf, uint32_t* len, uint32_t* type)
{
    SMTPData* ssn = get_session_data(flow);

    if (ssn == nullptr)
        return 0;

    ssn->mime_ssn->get_log_state()->get_email_id(buf, len, EMAIL_SENDER);
    *type = EVENT_INFO_SMTP_MAILFROM;
    return 1;
}

/* Callback to return the email addresses accumulated from the RCP TO command */
static int SMTP_GetRcptTo(Flow* flow, uint8_t** buf, uint32_t* len, uint32_t* type)
{
    SMTPData* ssn = get_session_data(flow);

    if (ssn == nullptr)
        return 0;

    ssn->mime_ssn->get_log_state()->get_email_id(buf, len, EMAIL_RECIPIENT);
    *type = EVENT_INFO_SMTP_RCPTTO;
    return 1;
}

/* Callback to return the email headers */
static int SMTP_GetEmailHdrs(Flow* flow, uint8_t** buf, uint32_t* len, uint32_t* type)
{
    SMTPData* ssn = get_session_data(flow);

    if (ssn == nullptr)
        return 0;

    ssn->mime_ssn->get_log_state()->get_email_hdrs(buf, len);
    *type = EVENT_INFO_SMTP_EMAIL_HDRS;
    return 1;
}

static void SMTP_RegXtraDataFuncs(SmtpProtoConf* config)
{
    config->xtra_filename_id = Stream::reg_xtra_data_cb(SMTP_GetFilename);
    config->xtra_mfrom_id = Stream::reg_xtra_data_cb(SMTP_GetMailFrom);
    config->xtra_rcptto_id = Stream::reg_xtra_data_cb(SMTP_GetRcptTo);
    config->xtra_ehdrs_id = Stream::reg_xtra_data_cb(SMTP_GetEmailHdrs);
}

static void update_eol_state(SMTPEol new_eol, SMTPEol& curr_eol_state)
{
    if (new_eol == EOL_NOT_SEEN or curr_eol_state == EOL_MIXED)
        return;

    if (curr_eol_state == EOL_NOT_SEEN)
    {
        curr_eol_state = new_eol;
        return;
    }

    if ((new_eol == EOL_LF and curr_eol_state == EOL_CRLF) or
        (new_eol == EOL_CRLF and curr_eol_state == EOL_LF))
    {
        curr_eol_state = EOL_MIXED;
        DetectionEngine::queue_event(GID_SMTP, SMTP_LF_CRLF_MIX);
    }
}

int SmtpMime::handle_header_line(
    const uint8_t* ptr, const uint8_t* eol, int max_header_len, Packet* p)
{
    /* get length of header line */
    int header_line_len = eol - ptr;

    if (max_header_len)
        DetectionEngine::queue_event(GID_SMTP, SMTP_HEADER_NAME_OVERFLOW);

    if ((config->max_header_line_len != 0) &&
        (header_line_len > config->max_header_line_len))
    {
        DetectionEngine::queue_event(GID_SMTP, SMTP_DATA_HDR_OVERFLOW);
    }

    /* Does VRT want data headers normalized?
     * currently the code does not normalize headers */
    if (smtp_normalizing)
    {
        int ret = SMTP_CopyToAltBuffer(p, ptr, eol - ptr);

        if (ret == -1)
            return (-1);
    }

    if (config->log_config.log_email_hdrs)
    {
        if (get_data_state() == STATE_DATA_HEADER)
        {
            get_log_state()->log_email_hdrs(ptr, eol - ptr);
        }
    }

    return 0;
}

int SmtpMime::normalize_data(const uint8_t* ptr, const uint8_t* data_end, Packet* p)
{
    /* if we're ignoring data and not already normalizing, copy everything
     * up to here into alt buffer so detection engine doesn't have
     * to look at the data; otherwise, if we're normalizing and not
     * ignoring data, copy all of the data into the alt buffer */
    /*if (config->decode_conf.ignore_data && !smtp_normalizing)
    {
        return SMTP_CopyToAltBuffer(nullptr, p->data, ptr - p->data);
    }
    else */
    if (!config->decode_conf.is_ignore_data() && smtp_normalizing)
    {
        return SMTP_CopyToAltBuffer(p, ptr, data_end - ptr);
    }

    return 0;
}

void SmtpMime::decode_alert()
{
    switch ( decode_state->get_decode_type() )
    {
    case DECODE_B64:
        DetectionEngine::queue_event(GID_SMTP, SMTP_B64_DECODING_FAILED);
        break;
    case DECODE_QP:
        DetectionEngine::queue_event(GID_SMTP, SMTP_QP_DECODING_FAILED);
        break;
    case DECODE_UU:
        DetectionEngine::queue_event(GID_SMTP, SMTP_UU_DECODING_FAILED);
        break;

    default:
        break;
    }
}

void SmtpMime::decompress_alert()
{
    DetectionEngine::queue_event(GID_SMTP, SMTP_FILE_DECOMP_FAILED);
}

void SmtpMime::reset_state(Flow* ssn)
{
    SMTP_ResetState(ssn);
}

bool SmtpMime::is_end_of_data(Flow* session)
{
    return smtp_is_data_end(session);
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Smtp : public Inspector
{
public:
    Smtp(SmtpProtoConf*);
    ~Smtp() override;

    bool configure(SnortConfig*) override;
    void show(const SnortConfig*) const override;

    void eval(Packet*) override;
    void clear(Packet*) override;

    StreamSplitter* get_splitter(bool c2s) override
    { return new SmtpSplitter(c2s, config->max_auth_command_line_len); }

    bool can_carve_files() const override
    { return true; }

    bool can_start_tls() const override
    { return true; }

    void ProcessSmtpCmdsList(const SmtpCmd*);

    bool get_buf(snort::InspectionBuffer::Type, snort::Packet*, snort::InspectionBuffer&) override;
    bool get_buf(unsigned id, snort::Packet* p, snort::InspectionBuffer& b) override;

private:
    SmtpProtoConf* config;
};

Smtp::Smtp(SmtpProtoConf* pc)
{
    config = pc;

    SMTP_InitCmds(config);
}

Smtp::~Smtp()
{
    SMTP_CommandSearchTerm(config);
    SMTP_TermCmds(config);

    delete config;
}

bool Smtp::configure(SnortConfig* sc)
{
    SMTP_RegXtraDataFuncs(config);

    config->decode_conf.sync_all_depths(sc);

    if (config->decode_conf.get_file_depth() > -1)
        config->log_config.log_filename = true;

    SMTP_ResponseSearchInit();
    SMTP_CommandSearchInit(config);
    return true;
}

void Smtp::show(const SnortConfig*) const
{
    if ( config )
        config->show();
}

void Smtp::eval(Packet* p)
{
    Profile profile(smtpPerfStats); // cppcheck-suppress unreadVariable

    // precondition - what we registered for
    assert(p->has_tcp_data());
    assert(p->flow);

    ++smtpstats.packets;

    snort_smtp(config, p);
}

void Smtp::clear(Packet* p)
{
    SMTP_ResetAltBuffer(p);
}

void Smtp::ProcessSmtpCmdsList(const SmtpCmd* sc)
{
    const char* cmd = sc->name.c_str();
    int id;
    SMTPCmdTypeEnum type;

    if ( sc->flags & PCMD_AUTH )
        type = SMTP_CMD_TYPE_AUTH;

    else if ( sc->flags & PCMD_BDATA )
        type = SMTP_CMD_TYPE_BDATA;

    else if ( sc->flags & PCMD_DATA )
        type = SMTP_CMD_TYPE_DATA;

    else
        type = SMTP_CMD_TYPE_NORMAL;

    id = GetCmdId(config, cmd, type);

    if ( sc->flags & PCMD_INVALID )
        config->cmd_config[id].alert = true;

    else if ( sc->flags & PCMD_NORM )
        config->cmd_config[id].normalize = true;

    else
        config->cmd_config[id].alert = false;

    if ( sc->flags & PCMD_ALT )
        config->cmd_config[id].max_line_len = sc->number;
}

bool Smtp::get_buf(InspectionBuffer::Type ibt, Packet* p, InspectionBuffer& b)
{
    SMTPData* smtp_ssn = get_session_data(p->flow);

    if (!smtp_ssn)
        return false;

    const void* dst = nullptr;
    size_t dst_len = 0;

    switch (ibt)
    {
    case InspectionBuffer::IBT_VBA:
    {
        const BufferData& vba_buf = smtp_ssn->mime_ssn->get_vba_inspect_buf();
        dst = vba_buf.data_ptr();
        dst_len = vba_buf.length();
        break;
    }

    case InspectionBuffer::IBT_JS_DATA:
    {
        auto& dp = DetectionEngine::get_file_data(p->context);
        auto jsn = acquire_js_ctx(*smtp_ssn, dp.data, dp.len);
        if (jsn)
        {
            jsn->get_data(dst, dst_len);
            if (dst and dst_len)
                break;
            jsn->normalize(dp.data, dp.len, dst, dst_len);
        }
        break;
    }

    default:
        return false;
    }

    b.data = (const uint8_t*)dst;
    b.len = dst_len;

    return dst && dst_len;
}

bool Smtp::get_buf(unsigned id, snort::Packet* p, snort::InspectionBuffer& b)
{
    switch (id)
    {
    case SMTP_FILE_DATA_ID:
        return false;
    case SMTP_VBA_DATA_ID:
        return get_buf(InspectionBuffer::IBT_VBA, p, b);
    case SMTP_JS_DATA_ID:
        return get_buf(InspectionBuffer::IBT_JS_DATA, p, b);
    default:
        return false;
    }
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new SmtpModule; }

static void mod_dtor(Module* m)
{ delete m; }

static void smtp_init()
{
    SmtpFlowData::init();
}

static void smtp_term()
{
    SMTP_SearchFree();
}

static Inspector* smtp_ctor(Module* m)
{
    SmtpModule* mod = (SmtpModule*)m;
    SmtpProtoConf* conf = mod->get_data();
    Smtp* smtp = new Smtp(conf);

    unsigned i = 0;
    const SmtpCmd* cmd;

    while ( (cmd = mod->get_cmd(i++)) )
        smtp->ProcessSmtpCmdsList(cmd);

    mod->clear_cmds();

    return smtp;
}

static void smtp_dtor(Inspector* p)
{
    delete p;
}

static const char* smtp_bufs[] =
{
    "file_data",
    "vba_data",
    "js_data",
    nullptr
};

const InspectApi smtp_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        SMTP_NAME,
        SMTP_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__PDU,
    smtp_bufs,
    "smtp",
    smtp_init,
    smtp_term,
    nullptr,                // tinit
    nullptr,                // tterm
    smtp_ctor,
    smtp_dtor,
    nullptr,                // ssn
    nullptr                 // reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &smtp_api.base,
    nullptr
};
#else
const BaseApi* sin_smtp = &smtp_api.base;
#endif

#ifdef UNIT_TEST
TEST_CASE("handle_header_line", "[smtp]")
{
    // Setup
    MailLogConfig log_config;
    DecodeConfig decode_conf;
    const SnortConfig* sc = SnortConfig::get_conf();
    SnortConfig::set_conf(sc);
    log_config.log_email_hdrs = false;
    Packet p;
    Flow flow;
    p.flow = &flow;
    p.context = new IpsContext(1);
    SmtpMime mime_ssn(&p, &decode_conf, &log_config);
    smtp_normalizing = true;
    SmtpProtoConf config;
    mime_ssn.config = &config;
    uint8_t ptr[68] = "Date: Tue, 1 Mar 2016 22:37:56 -0500\r\nFrom: acc2 <acc2@localhost>\r\n";
    uint8_t* eol = ptr + 38;
    SMTP_ResetAltBuffer(&p);
    int res = mime_ssn.handle_header_line(ptr, eol, 0, &p);
    REQUIRE((res == 0));
    unsigned len = 0;
    const uint8_t* header = SMTP_GetAltBuffer(&p, len);
    REQUIRE((len == 38));
    REQUIRE((memcmp(header, ptr, len)== 0));

    // Cleanup
    delete p.context;
}

TEST_CASE("normalize_data", "[smtp]")
{
    // Setup
    MailLogConfig log_config;
    DecodeConfig decode_conf;
    const SnortConfig* sc = SnortConfig::get_conf();
    SnortConfig::set_conf(sc);
    Packet p;
    Flow flow;
    p.flow =& flow;
    p.context = new IpsContext(1);
    SmtpMime mime_ssn(&p, &decode_conf, &log_config);
    smtp_normalizing = true;
    SmtpProtoConf config;
    mime_ssn.config = &config;
    uint8_t ptr[23] = "\r\n--wac7ysb48OaltWcw\r\n";
    uint8_t* data_end = ptr + 22;
    SMTP_ResetAltBuffer(&p);
    int res = mime_ssn.normalize_data(ptr, data_end, &p);
    REQUIRE((res == 0));
    unsigned len = 0;
    const uint8_t* data = SMTP_GetAltBuffer(&p, len);
    REQUIRE((len == 22));
    REQUIRE((memcmp(data, ptr, len)== 0));

    // Cleanup
    delete p.context;
}
#endif

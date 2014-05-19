/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2005-2013 Sourcefire, Inc.
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
 *
 ****************************************************************************/

// @file    sp_react.c
// @author  Russ Combs <rcombs@sourcefire.com>

/* The original Snort React Plugin was contributed by Maciej Szarpak, Warsaw
 * University of Technology.  The module has been entirely rewritten by
 * Sourcefire as part of the effort to overhaul active response.  Some of the
 * changes include:
 *
 * - elimination of unworkable warn mode
 * - elimination of proxy port (rule header has ports)
 * - integration with unified active response mechanism
 * - queuing of rule option responses so at most one is issued
 * - allow override by rule action when action is drop
 * - addition of http headers to default response
 * - added custom page option
 * - and other stuff
 *
 * This version will send a web page to the client and then reset both
 * ends of the session.  The web page may be configured or the default
 * may be used.  The web page can have the default warning message
 * inserted or the message from the rule.
 *
 * If you wish to just reset the session, use the resp keyword instead.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "snort_types.h"
#include "snort_debug.h"
#include "decode.h"
#include "managers/packet_manager.h"
#include "detection/detection_defines.h"
#include "parser.h"
#include "profiler.h"
#include "fpdetect.h"
#include "packet_io/active.h"
#include "sfhashfcn.h"
#include "snort.h"
#include "framework/ips_option.h"

static const char* s_name = "react";

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats reactPerfStats;

static PreprocStats* act_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &reactPerfStats;

    return nullptr;
}
#endif

static const char* MSG_KEY = "<>";
static const char* MSG_PERCENT = "%";

static const char* DEFAULT_HTTP =
    "HTTP/1.1 403 Forbidden\r\n"
    "Connection: close\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    "Content-Length: %d\r\n"
    "\r\n";

static const char* DEFAULT_HTML =
    "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\"\r\n"
    "    \"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\r\n"
    "<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\">\r\n"
    "<head>\r\n"
    "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />\r\n"
    "<title>Access Denied</title>\r\n"
    "</head>\r\n"
    "<body>\r\n"
    "<h1>Access Denied</h1>\r\n"
    "<p>%s</p>\r\n"
    "</body>\r\n"
    "</html>\r\n";

static const char* DEFAULT_MSG =
    "You are attempting to access a forbidden site.<br />"
    "Consult your system administrator for details.";

typedef struct _ReactData
{
    int rule_msg;        // 1=>use rule msg; 0=>use DEFAULT_MSG
    ssize_t buf_len;     // length of response
    char* resp_buf;      // response to send

} ReactData;

static int s_deprecated = 0;
static char* s_page = NULL;

class ReactOption : public IpsOption
{
public:
    ReactOption(ReactData* c) :
        IpsOption(s_name)
    { config = c; };

    ~ReactOption();

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;
    void action(Packet*);

private:
    ReactData* config;
};

static void React_Send(Packet*,  void*);

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

ReactOption::~ReactOption()
{
    if (config->resp_buf)
        free(config->resp_buf);

    free(config);
}

uint32_t ReactOption::hash() const
{
    uint32_t a,b,c;
    const ReactData *data = config;

    const char* s = data->resp_buf;
    unsigned n = data->buf_len;

    a = data->rule_msg;
    b = n;
    c = 0;

    mix(a,b,c);
    mix_str(a,b,c,s,n);
    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool ReactOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    ReactOption& rhs = (ReactOption&)ips;
    ReactData *left = config;
    ReactData *right = rhs.config;

    if (left->buf_len != right->buf_len)
        return false;

    if (memcmp(left->resp_buf, right->resp_buf, left->buf_len) != 0)
        return false;

    if (left->rule_msg != right->rule_msg)
        return false;

    return true;
}

void ReactOption::action(Packet* p)
{
    PROFILE_VARS;
    PREPROC_PROFILE_START(reactPerfStats);

    if ( Active_IsRSTCandidate(p) )
        Active_QueueResponse(React_Send, config);

    Active_DropSession();
    PREPROC_PROFILE_END(reactPerfStats);
}

//-------------------------------------------------------------------------
// implementation foo
//-------------------------------------------------------------------------

static void react_getpage (SnortConfig* sc)
{
    char* msg;
    char* percent_s;
    struct stat fs;
    FILE* fd;
    size_t n;

    if ( !sc )
        ParseError("Snort config for parsing is NULL.");

    if ( s_page || !sc->react_page ) return;

    if ( stat(sc->react_page, &fs) )
        ParseError("can't stat react page file '%s'.", sc->react_page);

    s_page = (char*)SnortAlloc(fs.st_size+1);
    fd = fopen(sc->react_page, "r");

    if ( !fd )
        ParseError("can't open react page file '%s'.", sc->react_page);

    n = fread(s_page, 1, fs.st_size, fd);
    fclose(fd);

    if ( n != (size_t)fs.st_size )
        ParseError("can't load react page file '%s'.", sc->react_page);

    s_page[n] = '\0';
    msg = strstr(s_page, MSG_KEY);
    if ( msg ) strncpy(msg, "%s", 2);

    // search for %
    percent_s = strstr(s_page, MSG_PERCENT);
    if (percent_s)
    {
        percent_s += strlen(MSG_PERCENT); // move past current
        // search for % again
        percent_s = strstr(percent_s, MSG_PERCENT);
        if (percent_s)
        {
            ParseError("can't specify more than one %%s or other "
                "printf style formatting characters in react page '%s'.",
                sc->react_page);
        }
    }
}

//--------------------------------------------------------------------

static void React_Send (Packet* p,  void* pv)
{
    ReactData* rd = (ReactData*)pv;
    EncodeFlags df = (p->packet_flags & PKT_FROM_SERVER) ? ENC_FLAG_FWD : 0;
    EncodeFlags rf = ENC_FLAG_SEQ | (ENC_FLAG_VAL & rd->buf_len);
    PROFILE_VARS;

    PREPROC_PROFILE_START(reactPerfStats);
    Active_IgnoreSession(p);

    Active_SendData(p, df, (uint8_t*)rd->resp_buf, rd->buf_len);
    Active_SendReset(p, rf);
    Active_SendReset(p, ENC_FLAG_FWD);

    PREPROC_PROFILE_END(reactPerfStats);
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

// format response buffer
static void react_config (ReactData* rd, OptTreeNode* otn)
{
    size_t body_len, head_len, total_len;
    char dummy;

    const char* head = DEFAULT_HTTP;
    const char* body = s_page ? s_page : DEFAULT_HTML;

    const char* msg = otn->sigInfo.message;
    if ( !msg || !rd->rule_msg ) msg = DEFAULT_MSG;

    body_len = snprintf(&dummy, 1, body, msg);
    head_len = snprintf(&dummy, 1, head, body_len);
    total_len = head_len + body_len + 1;

    rd->resp_buf = (char*)SnortAlloc(total_len);

    SnortSnprintf((char*)rd->resp_buf, head_len+1, head, body_len);
    SnortSnprintf((char*)rd->resp_buf+head_len, body_len+1, body, msg);

    // set actual length
    rd->resp_buf[total_len-1] = '\0';
    rd->buf_len = strlen(rd->resp_buf);
}

static void react_parse(char* data, ReactData* rd, OptTreeNode* otn)
{
    char* tok = NULL;
    char* lasts = nullptr;

    if ( data )
    {
        while(isspace((int)*data)) data++;

        tok = strtok_r(data, ",", &lasts);
    }
    while(tok)
    {
        /* parse the react option keywords */
        if (
            !strncasecmp(tok, "proxy", 5) ||
            !strcasecmp(tok, "block") ||
            !strcasecmp(tok, "warn") )
        {
            if ( !s_deprecated )
            {
                ParseWarning("proxy, block, and warn options are deprecated.\n");
                s_deprecated = 1;
            }
        }
        else if ( !strcasecmp(tok, "msg") )
        {
            if ( !otn->sigInfo.message )
                ParseError("react: msg mst follow rule msg");

            rd->rule_msg = 1;
        }
        else
            ParseError("invalid react option: %s", tok);

        tok = strtok_r(NULL, ",", &lasts);

        /* get rid of spaces */
        while ( tok && isspace((int)*tok) ) tok++;
    }
    rd->resp_buf = NULL;
    rd->buf_len = 0;
}

static IpsOption* react_ctor(
    SnortConfig*, char* data, OptTreeNode* otn)
{
    ReactData* rd = (ReactData*)SnortAlloc(sizeof(*rd));
    react_parse(data, rd, otn);
    react_config(rd, otn);

    ReactOption* opt = new ReactOption(rd);

    if ( otn_set_agent(otn, opt) )
        return opt;

    delete opt;
    ParseError("At most one action per rule is allowed");
    return nullptr;
}

static void react_dtor(IpsOption* p)
{
    delete p;
}

static void react_ginit(SnortConfig* sc)
{
    react_getpage(sc);
    Active_SetEnabled(1);

#ifdef PERF_PROFILING
    RegisterOtnProfile(s_name, &reactPerfStats, act_get_profile);
#endif
}

static void react_gterm(SnortConfig*)
{
    if ( s_page )
    {
        free(s_page);
        s_page = nullptr;
    }
}

static const IpsApi react_api =
{
    {
        PT_IPS_OPTION,
        s_name,
        IPSAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    OPT_TYPE_ACTION,
    1, PROTO_BIT__TCP,
    react_ginit,
    react_gterm,
    nullptr,
    nullptr,
    react_ctor,
    react_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &react_api.base,
    nullptr
};
#else
const BaseApi* ips_react = &react_api.base;
#endif


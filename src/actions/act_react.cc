//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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
// act_react.cc author Russ Combs <rucombs@cisco.com>

/* The original Snort React Plugin was contributed by Maciej Szarpak, Warsaw
 * University of Technology.  The module has been entirely rewritten by
 * Sourcefire as part of the effort to overhaul active response.  Some of the
 * changes include:
 *
 * - elimination of unworkable warn mode
 * - elimination of proxy port (rule header has ports)
 * - integration with unified active response mechanism
 * - queuing of rule action responses so at most one is issued
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
 * If you wish to just reset the session, use the reject keyword instead.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/stat.h>

#include "framework/ips_action.h"
#include "framework/module.h"
#include "log/messages.h"
#include "packet_io/active.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "utils/util.h"
#include "utils/util_cstring.h"

using namespace snort;

#define s_name "react"

#define s_help \
    "send response to client and terminate session"

static THREAD_LOCAL ProfileStats reactPerfStats;

#define MSG_KEY "<>"
#define MSG_PERCENT "%"

#define DEFAULT_HTTP \
    "HTTP/1.1 403 Forbidden\r\n" \
    "Connection: close\r\n" \
    "Content-Type: text/html; charset=utf-8\r\n" \
    "Content-Length: %d\r\n" \
    "\r\n"

#define DEFAULT_HTML \
    "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\"\r\n" \
    "    \"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\r\n" \
    "<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\">\r\n" \
    "<head>\r\n" \
    "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />\r\n" \
    "<title>Access Denied</title>\r\n" \
    "</head>\r\n" \
    "<body>\r\n" \
    "<h1>Access Denied</h1>\r\n" \
    "<p>%s</p>\r\n" \
    "</body>\r\n" \
    "</html>\r\n"

#define DEFAULT_MSG \
    "You are attempting to access a forbidden site.<br />" \
    "Consult your system administrator for details."

struct ReactData
{
    int rule_msg;        // 1=>use rule msg; 0=>use DEFAULT_MSG
    ssize_t buf_len;     // length of response
    char* resp_buf;      // response to send
    char* resp_page;
};

class ReactAction : public IpsAction
{
public:
    ReactAction(ReactData* c) : IpsAction(s_name, ACT_PROXY)
    { config = c; }

    ~ReactAction() override;

    void exec(Packet*) override;

private:
    void send(Packet*);

private:
    ReactData* config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

ReactAction::~ReactAction()
{
    if (config->resp_buf)
        snort_free(config->resp_buf);

    snort_free(config);
}

void ReactAction::exec(Packet* p)
{
    Profile profile(reactPerfStats);

    if ( Active::is_reset_candidate(p) )
        send(p);
}

void ReactAction::send(Packet* p)
{
    EncodeFlags df = (p->is_from_server()) ? ENC_FLAG_FWD : 0;
    EncodeFlags sent = config->buf_len;

    if ( p->packet_flags & PKT_STREAM_EST )
    {
        Active::send_data(p, df, (uint8_t*)config->resp_buf, config->buf_len);
        // Active::send_data() sends a FIN, so need to bump seq by 1.
        sent++;
    }

    EncodeFlags rf = ENC_FLAG_SEQ | (ENC_FLAG_VAL & sent);
    Active::send_reset(p, rf);
    Active::send_reset(p, ENC_FLAG_FWD);
}

//-------------------------------------------------------------------------
// implementation foo
//-------------------------------------------------------------------------


//--------------------------------------------------------------------

// format response buffer
static void react_config(ReactData* rd)
{
    int body_len, head_len, total_len;
    char dummy;

    const char* head = DEFAULT_HTTP;
    const char* body = rd->resp_page ? rd->resp_page : DEFAULT_HTML;
    const char* msg = DEFAULT_MSG;

    body_len = snprintf(&dummy, 1, body, msg);
    head_len = snprintf(&dummy, 1, head, body_len);
    total_len = head_len + body_len + 1;

    rd->resp_buf = (char*)snort_calloc(total_len);

    SnortSnprintf((char*)rd->resp_buf, head_len+1, head, body_len);
    SnortSnprintf((char*)rd->resp_buf+head_len, body_len+1, body, msg);

    // set actual length
    rd->resp_buf[total_len-1] = '\0';
    rd->buf_len = strlen(rd->resp_buf);
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "msg", Parameter::PT_BOOL, nullptr, "false",
      " use rule msg in response page instead of default message" },

    { "page", Parameter::PT_STRING, nullptr, nullptr,
      "file containing HTTP response (headers and body)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class ReactModule : public Module
{
public:
    ReactModule() : Module(s_name, s_help, s_params) { page = nullptr; }
    ~ReactModule() override { if (page) snort_free(page); }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &reactPerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    bool msg;
    char* page;
private:
    bool getpage(const char* file);
};

bool ReactModule::getpage(const char* file)
{
    char* msg;
    char* percent_s;
    struct stat fs;
    FILE* fd;
    size_t n;

    if ( stat(file, &fs) )
    {
        ParseError("can't stat react page file '%s'.", file);
        return false;
    }

    page = (char*)snort_calloc(fs.st_size+1);
    fd = fopen(file, "r");

    if ( !fd )
    {
        ParseError("can't open react page file '%s'.", file);
        return false;
    }

    n = fread(page, 1, fs.st_size, fd);
    fclose(fd);

    if ( n != (size_t)fs.st_size )
    {
        ParseError("can't load react page file '%s'.", file);
        return false;
    }

    page[n] = '\0';
    msg = strstr(page, MSG_KEY);
    if ( msg )
        strncpy(msg, "%s", 2);

    // search for %
    percent_s = strstr(page, MSG_PERCENT);
    if (percent_s)
    {
        percent_s += strlen(MSG_PERCENT); // move past current
        // search for % again
        percent_s = strstr(percent_s, MSG_PERCENT);
        if (percent_s)
        {
            ParseError("can't specify more than one %%s or other "
                "printf style formatting characters in react page '%s'.",
                file);
            return false;
        }
    }
    return true;
}

bool ReactModule::begin(const char*, int, SnortConfig*)
{
    msg = false;
    return true;
}

bool ReactModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("msg") )
        msg = v.get_bool();

    else if ( v.is("page") )
        return getpage(v.get_string());

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new ReactModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsAction* react_ctor(Module* p)
{
    ReactData* rd = (ReactData*)snort_calloc(sizeof(*rd));

    ReactModule* m = (ReactModule*)p;
    rd->rule_msg = m->msg;
    rd->resp_page = m->page;
    react_config(rd); // FIXIT-L this must be done per response
    Active::set_enabled();

    return new ReactAction(rd);
}

static void react_dtor(IpsAction* p)
{
    delete p;
}

static const ActionApi react_api =
{
    {
        PT_IPS_ACTION,
        sizeof(ActionApi),
        ACTAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    Actions::DROP,
    nullptr,  // pinit
    nullptr,  // pterm
    nullptr,  // tinit
    nullptr,  // tterm
    react_ctor,
    react_dtor,
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* act_react[] =
#endif
{
    &react_api.base,
    nullptr
};


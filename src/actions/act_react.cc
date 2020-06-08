//--------------------------------------------------------------------------
// Copyright (C) 2014-2020 Cisco and/or its affiliates. All rights reserved.
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

#include <fstream>
#include <string>

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

#define DEFAULT_HTTP \
    "HTTP/1.1 403 Forbidden\r\n" \
    "Connection: close\r\n" \
    "Content-Type: text/html; charset=utf-8\r\n" \
    "Content-Length: "

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
    "<p>You are attempting to access a forbidden site.<br />" \
    "Consult your system administrator for details.</p>\r\n" \
    "</body>\r\n" \
    "</html>\r\n"

class ReactData
{
public:

    ReactData(const std::string& page)
    {
        if ( page.empty())
        {
            resp_buf = DEFAULT_HTTP + std::to_string(sizeof(DEFAULT_HTML));
            resp_buf.append("\r\n\r\n");
            resp_buf.append(DEFAULT_HTML);
        }
        else
        {
            resp_buf = DEFAULT_HTTP + std::to_string(page.size());
            resp_buf.append("\r\n\r\n");
            resp_buf.append(page);
        }
    }

    ~ReactData() = default;

    size_t get_buf_len() const
    { return resp_buf.size(); }

    const char* get_resp_buf() const
    { return resp_buf.c_str(); }

private:
    std::string resp_buf;      // response to send
};


class ReactAction : public snort::IpsAction
{
public:
    ReactAction(ReactData* c)
        : IpsAction(s_name, ActionType::ACT_PROXY), config(c)
    { }

    ~ReactAction() override
    { delete config; }

    void exec(snort::Packet* p) override
    {
        Profile profile(reactPerfStats);

        if ( p->active->is_reset_candidate(p) )
            send(p);
    }

private:
    void send(snort::Packet* p)
    {
        EncodeFlags df = (p->is_from_server()) ? ENC_FLAG_FWD : 0;
        EncodeFlags sent = 0;

        Active* act = p->active;

        if ( p->packet_flags & PKT_STREAM_EST )
            sent = act->send_data(p, df, (const uint8_t*)config->get_resp_buf(), config->get_buf_len());

        EncodeFlags rf = ENC_FLAG_SEQ | (ENC_FLAG_VAL & sent);
        act->send_reset(p, rf);

        // block the flow in case the RST is lost.
        act->block_session(p);
    }

private:
    ReactData* config;
};

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "page", Parameter::PT_STRING, nullptr, nullptr,
      "file containing HTTP response (headers and body)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class ReactModule : public Module
{
public:
    ReactModule() : Module(s_name, s_help, s_params)
    { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &reactPerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    std::string page;

private:
    bool getpage(const char* file);
};

bool ReactModule::getpage(const char* file)
{
    std::ifstream ifs(file);
    if ( !ifs.good() )
    {
        ParseError("Failed to open custom react page file: %s.", file);
        return false;
    }

    page.assign((std::istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));
    return true;
}

bool ReactModule::begin(const char*, int, SnortConfig*)
{
    page.clear();
    return true;
}

bool ReactModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("page") )
        return getpage(v.get_string());
    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new ReactModule; }

static void mod_dtor(Module* m)
{ delete m; }

static IpsAction* react_ctor(Module* p)
{
    ReactModule* m = (ReactModule*)p;
    ReactData* rd = new ReactData(m->page);
    Active::set_enabled();

    return new ReactAction(rd);
}

static void react_dtor(IpsAction* p)
{ delete p; }

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


/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <syslog.h>
#include <stdlib.h>

#include <string>

#include "framework/logger.h"
#include "framework/module.h"
#include "protocols/packet.h"
#include "detect.h"
#include "event.h"
#include "rules.h"
#include "treenodes.h"
#include "snort_debug.h"
#include "parser.h"
#include "mstring.h"
#include "util.h"
#include "util_net.h"
#include "snort.h"
#include "packet_io/sfdaq.h"
#include "packet_io/intf.h"

#ifndef LOG_AUTHPRIV
#define LOG_AUTHPRIV LOG_AUTH
#endif

using namespace std;

//-------------------------------------------------------------------------
// translation stuff
//-------------------------------------------------------------------------

static const char* syslog_facilities =
    "auth | authpriv | daemon | user | "
    "local0 | local1 | local2 | local3 | "
    "local4 | local5 | local6 | local7";

static int get_facility(unsigned fac)
{
    switch ( fac )
    {
    case  0: return LOG_AUTH;
    case  1: return LOG_AUTHPRIV;
    case  2: return LOG_DAEMON;
    case  3: return LOG_USER;
    case  4: return LOG_LOCAL0;
    case  5: return LOG_LOCAL1;
    case  6: return LOG_LOCAL2;
    case  7: return LOG_LOCAL3;
    case  8: return LOG_LOCAL4;
    case  9: return LOG_LOCAL5;
    case 10: return LOG_LOCAL6;
    case 11: return LOG_LOCAL7;
    }
    return 0;
}

static const char* syslog_levels = 
    "emerg | alert | crit | err | warning | notice | info | debug";

static int get_level(unsigned lvl)
{
    switch ( lvl )
    {
    case 0: return LOG_EMERG;
    case 1: return LOG_ALERT;
    case 2: return LOG_CRIT;
    case 3: return LOG_ERR;
    case 4: return LOG_WARNING;
    case 5: return LOG_NOTICE;
    case 6: return LOG_INFO;
    case 7: return LOG_DEBUG;
    }
    return 0;
}

static const char* syslog_options =
    "cons | ndelay | perror | pid";

static int get_options(const char* s)
{
    int opts = 0;

    if ( strstr(s, "cons") )
        opts |= LOG_CONS;

    if ( strstr(s, "ndelay") )
        opts |= LOG_NDELAY;

    if ( strstr(s, "perror") )
        opts |= LOG_PERROR;

    if ( strstr(s, "pid") )
        opts |= LOG_PID;

    return opts;
}

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter syslog_params[] =
{
    { "facility", Parameter::PT_ENUM, syslog_facilities, "auth",
      "part of priority applied to each message" },

    { "level", Parameter::PT_ENUM, syslog_levels, "info",
      "part of priority applied to each message" },

    { "options", Parameter::PT_MULTI, syslog_options, nullptr,
      "used to open the syslog connection" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class SyslogModule : public Module
{
public:
    SyslogModule() : Module("alert_syslog", syslog_params) { };
    bool set(const char*, Value&, SnortConfig*);
    bool begin(const char*, int, SnortConfig*);
    bool end(const char*, int, SnortConfig*);

public:
    int facility;
    int level;
    int options;
};

bool SyslogModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("facility") )
        facility = get_facility(v.get_long());

    else if ( v.is("level") )
        level = get_level(v.get_long());

    else if ( v.is("options") )
        options = get_options(v.get_string());

    else
        return false;

    return true;
}

bool SyslogModule::begin(const char*, int, SnortConfig*)
{
    facility = LOG_AUTH;
    level = LOG_INFO;
    options = 0;
    return true;
}

bool SyslogModule::end(const char*, int, SnortConfig*)
{
    if ( ScDaemonMode() )
        options |= LOG_PID;

    return true;
}

//-------------------------------------------------------------------------
// alert foo
//-------------------------------------------------------------------------

// FIXIT can't message be put in Event?
static void AlertSyslog(
    int priority, Packet *p, const char *msg, Event *event)
{
    char event_string[STD_BUF];
    event_string[0] = '\0';

    if ((p != NULL) && IPH_IS_VALID(p))
    {
        if (event != NULL)
        {
            SnortSnprintfAppend(event_string, sizeof(event_string),
                    "[%lu:%lu:%lu] ",
                    (unsigned long)event->sig_info->generator,
                    (unsigned long)event->sig_info->id,
                    (unsigned long)event->sig_info->rev);
        }

        if (msg != NULL)
            SnortSnprintfAppend(event_string, sizeof(event_string), "%s ", msg);
        else
            SnortSnprintfAppend(event_string, sizeof(event_string), "ALERT ");

        if ( event )
        {
            if ((event->sig_info->classType != NULL)
                    && (event->sig_info->classType->name != NULL))
            {
                SnortSnprintfAppend(event_string, sizeof(event_string),
                        "[Classification: %s] ",
                        event->sig_info->classType->name);
            }

            if (event->sig_info->priority != 0)
            {
                SnortSnprintfAppend(event_string, sizeof(event_string),
                        "[Priority: %d] ", event->sig_info->priority);
            }
        }

        if (ScAlertInterface())
        {
            SnortSnprintfAppend(event_string, sizeof(event_string),
                    "<%s> ", PRINT_INTERFACE(DAQ_GetInterfaceSpec()));
        }

        if (protocol_names[GET_IPH_PROTO(p)] != NULL)
        {
            SnortSnprintfAppend(event_string, sizeof(event_string),
                    "{%s} ", protocol_names[GET_IPH_PROTO(p)]);
        }
        else
        {
            SnortSnprintfAppend(event_string, sizeof(event_string),
                    "{%d} ", GET_IPH_PROTO(p));
        }

        if ((p->decode_flags & DECODE__FRAG)
                || ((GET_IPH_PROTO(p) != IPPROTO_TCP)
                    && (GET_IPH_PROTO(p) != IPPROTO_UDP)))
        {
            const char *ip_fmt = "%s -> %s";

            if (ScObfuscate())
            {
                SnortSnprintfAppend(event_string, sizeof(event_string), ip_fmt,
                        ObfuscateIpToText(GET_SRC_ADDR(p)),
                        ObfuscateIpToText(GET_DST_ADDR(p)));
            }
            else
            {
                SnortSnprintfAppend(event_string, sizeof(event_string), ip_fmt,
                        inet_ntoax(GET_SRC_ADDR(p)), inet_ntoax(GET_DST_ADDR(p)));
            }
        }
        else
        {
            const char *ip_fmt = "%s:%d -> %s:%d";

            if (ScObfuscate())
            {
                SnortSnprintfAppend(event_string, sizeof(event_string), ip_fmt,
                        ObfuscateIpToText(GET_SRC_ADDR(p)), p->sp,
                        ObfuscateIpToText(GET_DST_ADDR(p)), p->dp);
            }
            else
            {
                SnortSnprintfAppend(event_string, sizeof(event_string), ip_fmt,
                        inet_ntoax(GET_SRC_ADDR(p)), p->sp,
                        inet_ntoax(GET_DST_ADDR(p)), p->dp);
            }
        }

        syslog(priority, "%s", event_string);
    }
    else
    {
        syslog(priority, "%s", msg == NULL ? "ALERT!" : msg);
    }
}

//-------------------------------------------------------------------------
// logger stuff
//-------------------------------------------------------------------------

class SyslogLogger : public Logger {
public:
    SyslogLogger(SyslogModule*);
    ~SyslogLogger();

    void alert(Packet*, const char* msg, Event*);

private:
    int priority;
};

// we open here since this is only one per process
// if used for messages (-M), no harm done
SyslogLogger::SyslogLogger(SyslogModule* m)
{
    priority = m->facility | m->level;
    openlog("snort", m->options, m->facility);
}

// do not closelog() here since it has other uses
SyslogLogger::~SyslogLogger()
{ }

void SyslogLogger::alert(Packet *p, const char *msg, Event *event)
{
    AlertSyslog(priority, p, msg, event);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new SyslogModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Logger* syslog_ctor(SnortConfig*, Module* mod)
{ return new SyslogLogger((SyslogModule*)mod); }

static void syslog_dtor(Logger* p)
{ delete p; }

static LogApi syslog_api
{
    {
        PT_LOGGER,
        "alert_syslog",
        LOGAPI_PLUGIN_V0,
        0,
        mod_ctor,
        mod_dtor
    },
    OUTPUT_TYPE_FLAG__ALERT,
    syslog_ctor,
    syslog_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &syslog_api.base,
    nullptr
};
#else
const BaseApi* alert_syslog = &syslog_api.base;
#endif


//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
// Copyright (C) 2000,2001 Andrew R. Baker <andrewb@uab.edu>
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

/* alert_full
 *
 * Purpose:  output plugin for full alerting
 *
 * Arguments:  alert file (eventually)
 *
 * Effect:
 *
 * Alerts are written to a file in the snort full alert format
 *
 * Comments:   Allows use of full alerts with other output plugin types
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#include <string>

#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "main/snort_config.h"
#include "framework/logger.h"
#include "framework/module.h"
#include "events/event.h"
#include "protocols/packet.h"
#include "parser/parser.h"
#include "utils/util.h"
#include "log/text_log.h"
#include "log/log_text.h"
#include "packet_io/sfdaq.h"
#include "packet_io/intf.h"

static THREAD_LOCAL TextLog* full_log = nullptr;

#define LOG_BUFFER (4*K_BYTES)

using namespace std;

#define S_NAME "alert_full"
#define F_NAME S_NAME ".txt"

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "file", Parameter::PT_BOOL, nullptr, "false",
      "output to " F_NAME " instead of stdout" },

    { "limit", Parameter::PT_INT, "0:", "0",
      "set limit (0 is unlimited)" },

    { "units", Parameter::PT_ENUM, "B | K | M | G", "B",
      "limit is in bytes | KB | MB | GB" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "output event with full packet dump"

class FullModule : public Module
{
public:
    FullModule() : Module(S_NAME, s_help, s_params) { }

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

public:
    bool file;
    unsigned long limit;
    unsigned units;
};

bool FullModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("file") )
        file = v.get_bool();

    else if ( v.is("limit") )
        limit = v.get_long();

    else if ( v.is("units") )
        units = v.get_long();

    else
        return false;

    return true;
}

bool FullModule::begin(const char*, int, SnortConfig*)
{
    file = false;
    limit = 0;
    units = 0;
    return true;
}

bool FullModule::end(const char*, int, SnortConfig*)
{
    while ( units-- )
        limit *= 1024;

    return true;
}

//-------------------------------------------------------------------------
// logger stuff
//-------------------------------------------------------------------------

class FullLogger : public Logger
{
public:
    FullLogger(FullModule*);

    void open() override;
    void close() override;

    void alert(Packet*, const char* msg, Event*) override;

private:
    string file;
    unsigned long limit;
};

FullLogger::FullLogger(FullModule* m)
{
    file = m->file ? F_NAME : "stdout";
    limit = m->limit;
}

void FullLogger::open()
{
    full_log = TextLog_Init(file.c_str(), LOG_BUFFER, limit);
}

void FullLogger::close()
{
    if ( full_log )
        TextLog_Term(full_log);
}

void FullLogger::alert(Packet* p, const char* msg, Event* event)
{
    {
        TextLog_Puts(full_log, "[**] ");

        if (event != NULL)
        {
            TextLog_Print(full_log, "[%lu:%lu:%lu] ",
                (unsigned long)event->sig_info->generator,
                (unsigned long)event->sig_info->id,
                (unsigned long)event->sig_info->rev);
        }

        if (SnortConfig::alert_interface())
        {
            const char* iface = PRINT_INTERFACE(SFDAQ::get_interface_spec());
            TextLog_Print(full_log, " <%s> ", iface);
        }

        if (msg != NULL)
        {
            TextLog_Puts(full_log, msg);
            TextLog_Puts(full_log, " [**]\n");
        }
        else
        {
            TextLog_Puts(full_log, "[**]\n");
        }
    }

    if (p && p->has_ip())
    {
        LogPriorityData(full_log, event, true);
    }

    DebugMessage(DEBUG_LOG, "Logging Alert data!\n");

    LogTimeStamp(full_log, p);
    TextLog_Putc(full_log, ' ');

    if (p && p->has_ip())
    {
        /* print the packet header to the alert file */

        if (SnortConfig::output_datalink())
        {
            Log2ndHeader(full_log, p);
        }

        LogIPHeader(full_log, p);

        /* if this isn't a fragment, print the other header info */
        if (!(p->is_fragment()))
        {
            switch (p->type())
            {
            case PktType::TCP:
                LogTCPHeader(full_log, p);
                break;

            case PktType::UDP:
                LogUDPHeader(full_log, p);
                break;

            case PktType::ICMP:
                LogICMPHeader(full_log, p);
                break;

            default:
                break;
            }
        }
        LogXrefs(full_log, event, 1);

        TextLog_Putc(full_log, '\n');
    } /* End of if(p) */
    else
    {
        TextLog_Puts(full_log, "\n\n");
    }
    TextLog_Flush(full_log);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new FullModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Logger* full_ctor(SnortConfig*, Module* mod)
{ return new FullLogger((FullModule*)mod); }

static void full_dtor(Logger* p)
{ delete p; }

static LogApi full_api
{
    {
        PT_LOGGER,
        sizeof(LogApi),
        LOGAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        S_NAME,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OUTPUT_TYPE_FLAG__ALERT,
    full_ctor,
    full_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &full_api.base,
    nullptr
};
#else
const BaseApi* alert_full = &full_api.base;
#endif


//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "detection/signature.h"
#include "events/event.h"
#include "framework/logger.h"
#include "framework/module.h"
#include "log/log_text.h"
#include "log/text_log.h"
#include "main/snort_config.h"
#include "packet_io/intf.h"
#include "packet_io/sfdaq.h"
#include "protocols/packet.h"

using namespace snort;
using namespace std;

static THREAD_LOCAL TextLog* full_log = nullptr;

#define LOG_BUFFER (4*K_BYTES)

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
      "set maximum size in MB before rollover (0 is unlimited)" },

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

    Usage get_usage() const override
    { return CONTEXT; }

public:
    bool file;
    unsigned long limit;
};

bool FullModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("file") )
        file = v.get_bool();

    else if ( v.is("limit") )
        limit = v.get_long() * 1024 * 1024;

    else
        return false;

    return true;
}

bool FullModule::begin(const char*, int, SnortConfig*)
{
    file = false;
    limit = 0;
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

    void alert(Packet*, const char* msg, const Event&) override;

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

void FullLogger::alert(Packet* p, const char* msg, const Event& event)
{
    TextLog_Puts(full_log, "[**] ");

    TextLog_Print(full_log, "[%u:%u:%u] ",
        event.sig_info->gid, event.sig_info->sid, event.sig_info->rev);

    if (SnortConfig::alert_interface())
    {
        const char* iface = PRINT_INTERFACE(SFDAQ::get_interface_spec());
        TextLog_Print(full_log, " <%s> ", iface);
    }

    if (msg != nullptr)
    {
        TextLog_Puts(full_log, msg);
        TextLog_Puts(full_log, " [**]\n");
    }
    else
    {
        TextLog_Puts(full_log, "[**]\n");
    }

    if (p && p->has_ip())
    {
        LogPriorityData(full_log, event);
        TextLog_NewLine(full_log);
        if ( LogAppID(full_log, p) )
            TextLog_NewLine(full_log);
    }

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
        LogXrefs(full_log, event);
    }
    TextLog_Puts(full_log, "\n");
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
#else
const BaseApi* alert_full[] =
#endif
{
    &full_api.base,
    nullptr
};


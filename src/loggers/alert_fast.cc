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

/* alert_fast
 *
 * Purpose:  output plugin for fast alerting
 *
 * Arguments:  alert file
 *
 * Effect:
 *
 * Alerts are written to a file in the snort fast alert format
 *
 * Comments:   Allows use of fast alerts with other output plugin types
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <string>

#include "main/snort_debug.h"
#include "main/snort_config.h"
#include "framework/logger.h"
#include "framework/module.h"
#include "protocols/packet.h"
#include "parser/parser.h"
#include "utils/util.h"
#include "log/text_log.h"
#include "log/log_text.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq.h"
#include "packet_io/intf.h"
#include "events/event.h"

/* full buf was chosen to allow printing max size packets
 * in hex/ascii mode:
 * each byte => 2 nibbles + space + ascii + overhead
 */
#define FULL_BUF (4*IP_MAXPACKET)
#define FAST_BUF (4*K_BYTES)

static THREAD_LOCAL TextLog* fast_log = nullptr;

using namespace std;

#define S_NAME "alert_fast"
#define F_NAME S_NAME ".txt"

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "file", Parameter::PT_BOOL, nullptr, "false",
      "output to " F_NAME " instead of stdout" },

    { "packet", Parameter::PT_BOOL, nullptr, "false",
      "output packet dump with alert" },

    { "limit", Parameter::PT_INT, "0:", "0",
      "set limit (0 is unlimited)" },

    { "units", Parameter::PT_ENUM, "B | K | M | G", "B",
      "bytes | KB | MB | GB" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "output event with brief text format"

class FastModule : public Module
{
public:
    FastModule() : Module(S_NAME, s_help, s_params) { }

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

public:
    bool file;
    unsigned long limit;
    unsigned units;
    bool packet;
};

bool FastModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("file") )
        file = v.get_bool();

    else if ( v.is("packet") )
        packet = v.get_bool();

    else if ( v.is("limit") )
        limit = v.get_long();

    else if ( v.is("units") )
        units = v.get_long();

    else
        return false;

    return true;
}

bool FastModule::begin(const char*, int, SnortConfig*)
{
    file = false;
    limit = 0;
    units = 0;
    packet = false;
    return true;
}

bool FastModule::end(const char*, int, SnortConfig*)
{
    while ( units-- )
        limit *= 1024;

    return true;
}

//-------------------------------------------------------------------------
// logger stuff
//-------------------------------------------------------------------------

class FastLogger : public Logger
{
public:
    FastLogger(FastModule*);

    void open() override;
    void close() override;

    void alert(Packet*, const char* msg, Event*) override;

private:
    string file;
    unsigned long limit;
    bool packet;
};

FastLogger::FastLogger(FastModule* m)
{
    file = m->file ? F_NAME : "stdout";
    limit = m->limit;
    packet = m->packet;
}

void FastLogger::open()
{
    unsigned sz = packet ? FULL_BUF : FAST_BUF;
    fast_log = TextLog_Init(file.c_str(), sz, limit);
}

void FastLogger::close()
{
    if ( fast_log )
        TextLog_Term(fast_log);
}

void FastLogger::alert(Packet* p, const char* msg, Event* event)
{
    LogTimeStamp(fast_log, p);

    if ( Active::get_action() > Active::ACT_PASS )
        TextLog_Print(fast_log, " [%s]", Active::get_action_string());

    {
        TextLog_Puts(fast_log, " [**] ");

        if ( event )
        {
            TextLog_Print(fast_log, "[%lu:%lu:%lu] ",
                (unsigned long)event->sig_info->generator,
                (unsigned long)event->sig_info->id,
                (unsigned long)event->sig_info->rev);
        }

        if (SnortConfig::alert_interface())
        {
            TextLog_Print(fast_log, " <%s> ", PRINT_INTERFACE(SFDAQ::get_interface_spec()));
        }

        if ( msg )
            TextLog_Puts(fast_log, msg);

        TextLog_Puts(fast_log, " [**] ");
    }

    /* print the packet header to the alert file */
    {
        LogPriorityData(fast_log, event, 0);
        TextLog_Print(fast_log, "{%s} ", p->get_type());
        LogIpAddrs(fast_log, p);
    }

    if ( packet || SnortConfig::output_app_data() )
    {
        TextLog_NewLine(fast_log);
        if (p->has_ip())
            LogIPPkt(fast_log, p);
        else
            LogNetData(fast_log, p->data, p->dsize, p);

#if 0
        else if (p->proto_bits & PROTO_BIT__ARP)
            LogArpHeader(fast_log, p);  // FIXIT-L unimplemented
#endif
    }
    TextLog_NewLine(fast_log);
    TextLog_Flush(fast_log);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new FastModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Logger* fast_ctor(SnortConfig*, Module* mod)
{ return new FastLogger((FastModule*)mod); }

static void fast_dtor(Logger* p)
{ delete p; }

static LogApi fast_api
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
    fast_ctor,
    fast_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &fast_api.base,
    nullptr
};
#else
const BaseApi* alert_fast = &fast_api.base;
#endif


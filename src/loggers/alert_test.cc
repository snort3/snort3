/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2007-2013 Sourcefire, Inc.
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

/* alert_test_
 *
 * Output is tab delimited in the following order:
 * packet count, gid, sid, rev, msg, session, rebuilt
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snort_types.h"
#include "framework/logger.h"
#include "framework/module.h"
#include "event.h"
#include "protocols/packet.h"
#include "snort_debug.h"
#include "parser.h"
#include "util.h"
#include "log/log_text.h"
#include "log/text_log.h"
#include "mstring.h"
#include "snort.h"
#include "utils/stats.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <string>

#define TEST_FLAG_MSG      0x01
#define TEST_FLAG_SESSION  0x02
#define TEST_FLAG_REBUILT  0x04

static THREAD_LOCAL TextLog* test_file = nullptr;

using namespace std;

//-------------------------------------------------------------------------
// alert_test module
//-------------------------------------------------------------------------

static const Parameter test_params[] =
{
    { "file", Parameter::PT_STRING, nullptr, "stdout",
      "name of tsv alert file or 'stdout'" },

    { "rebuilt", Parameter::PT_BOOL, nullptr, "false",
      "include type:count where type is S for stream and F for frag" },

    { "session", Parameter::PT_BOOL, nullptr, "false",
      "include src-dst each of form -addr:port" },

    { "msg", Parameter::PT_BOOL, nullptr, "false",
      "include alert msg" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class TestModule : public Module
{
public:
    TestModule() : Module("alert_test", test_params) { };
    bool set(const char*, Value&, SnortConfig*);
    bool begin(const char*, int, SnortConfig*);
    bool end(const char*, int, SnortConfig*);

public:
    string file;
    unsigned flags;
};

bool TestModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("file") )
        file = v.get_string();

    else if ( v.is("rebuilt") )
    {
        if ( v.get_bool() )
            flags |= TEST_FLAG_REBUILT;
    }
    else if ( v.is("session") )
    {
        if ( v.get_bool() )
            flags |= TEST_FLAG_SESSION;
    }
    else if ( v.is("msg") )
    {
        if ( v.get_bool() )
            flags |= TEST_FLAG_MSG;
    }
    else
        return false;

    return true;
}

bool TestModule::begin(const char*, int, SnortConfig*)
{
    file = "stdout";
    flags = 0;
    return true;
}

bool TestModule::end(const char*, int, SnortConfig*)
{
    return true;
}

//-------------------------------------------------------------------------

class TestLogger : public Logger {
public:
    TestLogger(TestModule*);

    void open();
    void close();

    void alert(Packet*, const char* msg, Event*);

private:
    string file;
    unsigned flags;
};

TestLogger::TestLogger(TestModule* m)
{
    file = m->file;
    flags = m->flags;
}

void TestLogger::open()
{
    test_file = TextLog_Init(file.c_str());
}

void TestLogger::close()
{
    TextLog_Term(test_file);
}

void TestLogger::alert(Packet *p, const char *msg, Event *event)
{
    TextLog_Print(test_file, "" STDu64 "\t", pc.total_from_daq);

    if (event != NULL)
    {
        TextLog_Print(test_file, "%lu\t%lu\t%lu\t",
                (unsigned long) event->sig_info->generator,
                (unsigned long) event->sig_info->id,
                (unsigned long) event->sig_info->rev);
    }

    if (flags & TEST_FLAG_MSG)
    {
        if (msg != NULL)
            TextLog_Print(test_file, "%s\t", msg);
    }

    if (flags & TEST_FLAG_SESSION)
        LogIpAddrs(test_file, p);

    if ( (flags & TEST_FLAG_REBUILT) && (p->packet_flags & PKT_PSEUDO) )
    {
        const char* s;
        switch ( p->pseudo_type )
        {
        case PSEUDO_PKT_IP: s = "ip-defrag"; break;
        case PSEUDO_PKT_TCP: s = "tcp-deseg"; break;
        case PSEUDO_PKT_DCE_RPKT: s = "dce-pkt"; break;
        case PSEUDO_PKT_DCE_SEG: s = "dce-deseg"; break;
        case PSEUDO_PKT_DCE_FRAG: s = "dec-defrag"; break;
        case PSEUDO_PKT_SMB_SEG: s = "smb-deseg"; break;
        case PSEUDO_PKT_SMB_TRANS: s = "smb-trans"; break;
        case PSEUDO_PKT_PS: s = "port_scan"; break;
        case PSEUDO_PKT_SDF: s = "sdf"; break;
        default: s = "pseudo pkt"; break;
        }
        TextLog_Print(test_file, "%s", s);
    }
    TextLog_Print(test_file, "\n");
    TextLog_Flush(test_file);
}

//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new TestModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Logger* test_ctor(SnortConfig*, Module* mod)
{ return new TestLogger((TestModule*)mod); }

static void test_dtor(Logger* p)
{ delete p; }

static LogApi test_api
{
    {
        PT_LOGGER,
        "alert_test",
        LOGAPI_PLUGIN_V0,
        0,
        mod_ctor,
        mod_dtor
    },
    OUTPUT_TYPE_FLAG__ALERT,
    test_ctor,
    test_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &test_api.base,
    nullptr
};
#else
const BaseApi* alert_test = &test_api.base;
#endif


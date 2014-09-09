/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2013-2013 Sourcefire, Inc.
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
// alert_codecs.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <string.h>

#include <algorithm>
#include <iostream>

#include "main/snort_types.h"
#include "framework/logger.h"
#include "framework/module.h"
#include "protocols/packet.h"
#include "protocols/packet_manager.h"
#include "detection/signature.h"
#include "log/text_log.h"


static THREAD_LOCAL TextLog* test_file = nullptr;

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

#define LOG_CODECS_NAME "log_codecs"
static const unsigned ALERT_FLAG_MSG = 0x01;

static const Parameter ex_params[] =
{
    { "file", Parameter::PT_STRING, nullptr, "stdout",
      "name of tsv alert file or 'stdout'" },

    { "msg", Parameter::PT_BOOL, nullptr, "false",
      "include alert msg" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

namespace
{

class LogCodecModule : public Module
{
public:
    LogCodecModule() : Module(LOG_CODECS_NAME, ex_params) { };
    bool set(const char*, Value&, SnortConfig*);
    bool begin(const char*, int, SnortConfig*);

public:
    std::string file;
    uint8_t flags;
};

} // namespace

bool LogCodecModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("file") )
        file = v.get_string();

    else if ( v.is("msg") )
    {
        if ( v.get_bool() )
            flags |= ALERT_FLAG_MSG;
    }

    else
        return false;

    return true;
}

bool LogCodecModule::begin(const char*, int, SnortConfig*)
{
    file = "stdout";
    flags = 0;
    return true;
}

//-------------------------------------------------------------------------
// logger stuff
//-------------------------------------------------------------------------

namespace
{

class CodecLogger : public Logger {
public:
    CodecLogger(LogCodecModule* m);

    void open();
    void close();
    virtual void log(Packet*, const char*, Event*);

public:
    std::string file;
    uint8_t flags;
};

} // namespace


CodecLogger::CodecLogger(LogCodecModule* m)
{
    file = m->file;
    flags = m->flags;
}

void CodecLogger::open()
{ test_file = TextLog_Init(file.c_str()); }

void CodecLogger::close()
{ TextLog_Term(test_file); }


void CodecLogger::log(Packet* p, const char* msg, Event* e)
{
    std::string s = std::string(msg);


    if (e != NULL)
    {
        TextLog_Print(test_file, "%lu\t%lu\t%lu\t",
                (unsigned long) e->sig_info->generator,
                (unsigned long) e->sig_info->id,
                (unsigned long) e->sig_info->rev);
    }

    if (flags & ALERT_FLAG_MSG)
    {
        if (msg != NULL)
            TextLog_Print(test_file, "%s\t", msg);
    }

    TextLog_NewLine(test_file);
    TextLog_Print(test_file, " **** DUMPING PACKET ****");
    TextLog_NewLine(test_file);
    PacketManager::log_protocols(test_file, p);
    TextLog_NewLine(test_file);
    TextLog_Print(test_file, " **** FINISHED DUMPING ****");
    TextLog_NewLine(test_file);
    TextLog_NewLine(test_file);
    TextLog_NewLine(test_file);
    TextLog_NewLine(test_file);

}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new LogCodecModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Logger* codec_log_ctor(SnortConfig*, Module* mod)
{ return new CodecLogger((LogCodecModule*)mod); }

static void codec_log_dtor(Logger* p)
{ delete p; }

static const LogApi log_codecs_api =
{
    {
        PT_LOGGER,
        LOG_CODECS_NAME,
        LOGAPI_PLUGIN_V0,
        0,
        mod_ctor,
        mod_dtor
    },
    OUTPUT_TYPE_FLAG__LOG,
    codec_log_ctor,
    codec_log_dtor
};


const BaseApi* log_codecs = &log_codecs_api.base;

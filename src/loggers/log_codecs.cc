//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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
// alert_codecs.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detection/ips_context.h"
#include "detection/signature.h"
#include "events/event.h"
#include "framework/logger.h"
#include "framework/module.h"
#include "log/log_text.h"
#include "log/text_log.h"
#include "main/snort_config.h"
#include "protocols/packet_manager.h"

using namespace snort;

static THREAD_LOCAL TextLog* test_file = nullptr;

#define S_NAME "log_codecs"
#define F_NAME S_NAME ".txt"
#define LOG_CODECS_HELP "log protocols in packet by layer"

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const unsigned ALERT_FLAG_MSG = 0x01;

static const Parameter ex_params[] =
{
    { "file", Parameter::PT_BOOL, nullptr, "false",
      "output to " F_NAME " instead of stdout" },

    { "msg", Parameter::PT_BOOL, nullptr, "false",
      "include alert msg" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

namespace
{
class LogCodecModule : public Module
{
public:
    LogCodecModule() : Module(S_NAME, LOG_CODECS_HELP, ex_params) { }

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;

    Usage get_usage() const override
    { return CONTEXT; }

public:
    bool print_to_file;
    uint8_t flags;
};
} // namespace

bool LogCodecModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("file") )
    {
        if ( v.get_bool() )
            print_to_file = true;
    }
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
    flags = 0;
    print_to_file = false;
    return true;
}

//-------------------------------------------------------------------------
// logger stuff
//-------------------------------------------------------------------------

namespace
{
class CodecLogger : public Logger
{
public:
    CodecLogger(LogCodecModule* m);

    void open() override;
    void close() override;
    void log(Packet*, const char*, Event*) override;

public:
    std::string file;
    uint8_t flags;
};
} // namespace

CodecLogger::CodecLogger(LogCodecModule* m)
{
    file = m->print_to_file ? F_NAME : "stdout";
    flags = m->flags;
}

void CodecLogger::open()
{
    test_file = TextLog_Init(file.c_str());
}

void CodecLogger::close()
{ TextLog_Term(test_file); }

void CodecLogger::log(Packet* p, const char* msg, Event* e)
{
    TextLog_Print(test_file, "pkt:" STDu64 "\t", p->context->packet_number);

    if (e != nullptr)
    {
        TextLog_Print(test_file, "    gid:%u    sid:%u    rev:%u\t",
            e->sig_info->gid, e->sig_info->sid, e->sig_info->rev);
    }

    if (flags & ALERT_FLAG_MSG)
    {
        if (msg != nullptr)
            TextLog_Print(test_file, "%s\t", msg);
    }

    TextLog_NewLine(test_file);
    PacketManager::log_protocols(test_file, p);
    TextLog_NewLine(test_file);

    if ( p->dsize and SnortConfig::output_app_data() )
        LogNetData(test_file, p->data, p->dsize, p);

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
        sizeof(LogApi),
        LOGAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        S_NAME,
        LOG_CODECS_HELP,
        mod_ctor,
        mod_dtor
    },
    OUTPUT_TYPE_FLAG__LOG,
    codec_log_ctor,
    codec_log_dtor
};

const BaseApi* log_codecs[] =
{
    &log_codecs_api.base,
    nullptr
};


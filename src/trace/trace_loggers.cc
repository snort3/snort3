//--------------------------------------------------------------------------
// Copyright (C) 2020-2025 Cisco and/or its affiliates. All rights reserved.
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
// trace_loggers.cc author Oleksandr Serhiienko <oserhiie@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "trace_loggers.h"

#include <cstdio>
#include <syslog.h>

#include "main/thread.h"
#include "protocols/packet.h"
#include "utils/util.h"

using namespace snort;

//-----------------------------------------------
//  Loggers
//-----------------------------------------------

static std::string get_ntuple(bool ntuple, const Packet* p)
{
    if ( !ntuple or !p or !p->has_ip() )
        return "";

    SfIpString src_addr;
    SfIpString dst_addr;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    std::stringstream ss;

    p->ptrs.ip_api.get_src()->ntop(src_addr);
    p->ptrs.ip_api.get_dst()->ntop(dst_addr);

    if ( p->proto_bits & (PROTO_BIT__TCP | PROTO_BIT__UDP) )
    {
        src_port = p->ptrs.sp;
        dst_port = p->ptrs.dp;
    }

    ss << src_addr << " " << src_port << " -> " << dst_addr << " " << dst_port << " ";
    ss << unsigned(p->get_ip_proto_next());
    ss << " AS=" << p->pkth->address_space_id;

    if (p->pkth->tenant_id)
        ss << " TN=" << p->pkth->tenant_id;

    // Delimits the header part and the trace message
    ss << " ";

    return ss.str();
}

static std::string get_timestamp(bool timestamp)
{
    if ( !timestamp )
        return "";

    char ts[TIMEBUF_SIZE];
    ts_print(nullptr, ts);

    return std::string(ts) + ":";
}

// Stdout

class StdoutTraceLogger : public TraceLogger
{
public:
    StdoutTraceLogger();

    void log(const char* log_msg, const char* name,
        uint8_t log_level, const char* trace_option, const Packet* p) override;

private:
    FILE* file;
    char thread_type;
    unsigned instance_id;
};

StdoutTraceLogger::StdoutTraceLogger()
    : file(stdout), instance_id(get_instance_id())
{
    auto t = get_thread_type();
    switch (t)
    {
    case STHREAD_TYPE_PACKET:
        thread_type = 'P';
        break;
    case STHREAD_TYPE_MAIN:
        thread_type = 'C';
        break;
    default:
        thread_type = 'O';
    }
}

void StdoutTraceLogger::log(const char* log_msg, const char* name,
    uint8_t log_level, const char* trace_option, const Packet* p)
{
    fprintf(file, "%s%c%u:%s%s:%s:%d: %s", get_timestamp(timestamp).c_str(),
        thread_type, instance_id, get_ntuple(ntuple, p).c_str(),
        name, trace_option, log_level, log_msg);
}

// Syslog

class SyslogTraceLogger : public TraceLogger
{
public:
    SyslogTraceLogger();

    void log(const char* log_msg, const char* name,
        uint8_t log_level, const char* trace_option, const Packet* p) override;

private:
    int priority;
};

SyslogTraceLogger::SyslogTraceLogger()
    : priority(LOG_DAEMON | LOG_DEBUG)
{ }

void SyslogTraceLogger::log(const char* log_msg, const char* name,
    uint8_t log_level, const char* trace_option, const Packet* p)
{
    syslog(priority, "%s%s:%s:%d: %s", get_ntuple(ntuple, p).c_str(),
        name, trace_option, log_level, log_msg);
}

//-----------------------------------------------
//  Logger factories
//-----------------------------------------------

// Stdout

TraceLogger* StdoutLoggerFactory::instantiate()
{
    return new StdoutTraceLogger();
}

// Syslog

TraceLogger* SyslogLoggerFactory::instantiate()
{
    return new SyslogTraceLogger();
}


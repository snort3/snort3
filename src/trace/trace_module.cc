//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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
// trace_module.cc author Serhii Vlasiuk <svlasiuk@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "trace_module.h"

#include <syslog.h>

#include "main/snort_config.h"

#include "trace_config.h"
#include "trace_log.h"

using namespace snort;

static const Parameter trace_params[] =
{
    { "output", Parameter::PT_ENUM, "stdout | syslog", nullptr,
      "output method for trace log messages" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define trace_help \
    "configure trace log messages"

TraceModule::TraceModule() : Module("trace", trace_help, trace_params, false)
{ }

TraceModule::~TraceModule()
{
    delete t_config;
}

bool TraceModule::begin(const char* fqn, int, SnortConfig* sc)
{
    if ( !strcmp(fqn, "trace") )
    {
        assert(!t_config);
        t_config = new TraceConfig();

        // Init default output type based on Snort run-mode
        if ( sc->test_mode() )
            log_output_type = OUTPUT_TYPE_NO_INIT;
        else if ( sc->daemon_mode() or sc->log_syslog() )
            log_output_type = OUTPUT_TYPE_SYSLOG;
        else
            log_output_type = OUTPUT_TYPE_STDOUT;
    }

    return true;
}

bool TraceModule::set(const char*, Value& v, SnortConfig* sc)
{
    if ( v.is("output") )
    {
        if ( sc->test_mode() )
            return true;

        switch ( v.get_uint8() )
        {
            case OUTPUT_TYPE_STDOUT:
                log_output_type = OUTPUT_TYPE_STDOUT;
                break;
            case OUTPUT_TYPE_SYSLOG:
                log_output_type = OUTPUT_TYPE_SYSLOG;
                break;
            default:
                return false;
        }

        return true;
    }

    return false;
}

bool TraceModule::end(const char* fqn, int, SnortConfig* sc)
{
    if ( !strcmp(fqn, "trace") )
    {
        switch ( log_output_type )
        {
            case OUTPUT_TYPE_STDOUT:
                t_config->logger_factory = new StdoutLoggerFactory();
                break;
            case OUTPUT_TYPE_SYSLOG:
                t_config->logger_factory = new SyslogLoggerFactory();
                break;
            case OUTPUT_TYPE_NO_INIT:
                t_config->logger_factory = nullptr;
                break;
        }

        delete sc->trace_config;

        sc->trace_config = t_config;
        t_config = nullptr;

        // "output=syslog" config override case
        // do not closelog() here since it will be closed in Snort::clean_exit()
        if ( !sc->log_syslog() and log_output_type == OUTPUT_TYPE_SYSLOG
             and !local_syslog )
        {
            local_syslog = true;
            openlog("snort", LOG_PID | LOG_CONS, LOG_DAEMON);
        }
    }

    return true;
}


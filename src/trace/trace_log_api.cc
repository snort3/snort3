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
// trace_log_api.cc author Oleksandr Serhiienko <oserhiie@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "trace_log_api.h"

#include "main/snort_config.h"
#include "main/thread.h"

#include "trace_config.h"
#include "trace_log_base.h"

using namespace snort;

static THREAD_LOCAL TraceLogger* g_trace_logger = nullptr;

void TraceLogApi::thread_init(SnortConfig* sc)
{
    if ( sc->trace_config and sc->trace_config->logger_factory )
        g_trace_logger = sc->trace_config->logger_factory->instantiate();
}

void TraceLogApi::thread_term()
{
    delete g_trace_logger;
    g_trace_logger = nullptr;
}

void TraceLogApi::log(const char* log_msg, const char* name,
    uint8_t log_level, const char* trace_option)
{
    if ( g_trace_logger )
        g_trace_logger->log(log_msg, name, log_level, trace_option);
}


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
// trace_log.h author Oleksandr Serhiienko <oserhiie@cisco.com>

#ifndef TRACE_LOG_H
#define TRACE_LOG_H

#include "trace_log_base.h"

//-----------------------------------------------
//  Logger factories
//-----------------------------------------------

class StdoutLoggerFactory : public snort::TraceLoggerFactory
{
public:
    StdoutLoggerFactory() = default;
    StdoutLoggerFactory(const StdoutLoggerFactory&) = delete;
    StdoutLoggerFactory& operator=(const StdoutLoggerFactory&) = delete;

    snort::TraceLogger* instantiate() override;
};

class SyslogLoggerFactory : public snort::TraceLoggerFactory
{
public:
    SyslogLoggerFactory() = default;
    SyslogLoggerFactory(const SyslogLoggerFactory&) = delete;
    SyslogLoggerFactory& operator=(const SyslogLoggerFactory&) = delete;

    snort::TraceLogger* instantiate() override;
};

#endif // TRACE_LOG_H


//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

/* This module is a NULL placeholder for people that want to turn off
 * logging for whatever reason.  Please note that logging is separate from
 * alerting, they are completely separate output facilities within Snort.
 */

#include "framework/logger.h"
#include "framework/module.h"

#define s_name "log_null"
#define s_help "disable logging of packets"

//-------------------------------------------------------------------------
// log_null module
//-------------------------------------------------------------------------

class NullLogger : public Logger
{
public:
    NullLogger() { }
};

static Logger* null_ctor(SnortConfig*, Module*)
{ return new NullLogger; }

static void null_dtor(Logger* p)
{ delete p; }

static LogApi null_api
{
    {
        PT_LOGGER,
        sizeof(LogApi),
        LOGAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        nullptr, // mod_ctor,
        nullptr  //mod_dtor
    },
    OUTPUT_TYPE_FLAG__LOG,
    null_ctor,
    null_dtor
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &null_api.base,
    nullptr
};


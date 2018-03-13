//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// logger.h author Russ Combs <rucombs@cisco.com>

#ifndef LOGGER_H
#define LOGGER_H

// Logger is used to log packets and events.  Events are thresholded before
// they reach the Logger.  Packets may be logged along with events or as a
// result of tagging.

#include "framework/base_api.h"
#include "main/snort_types.h"

struct Event;
namespace snort
{
struct Packet;

// this is the current version of the api
#define LOGAPI_VERSION ((BASE_API_VERSION << 16) | 0)

#define OUTPUT_TYPE_FLAG__NONE  0x0
#define OUTPUT_TYPE_FLAG__ALERT 0x1
#define OUTPUT_TYPE_FLAG__LOG   0x2

//-------------------------------------------------------------------------
// api for class
// ctor, dtor are in main thread
// other methods are packet thread specific
//-------------------------------------------------------------------------

struct LogApi;

class SO_PUBLIC Logger
{
public:
    virtual ~Logger() = default;

    virtual void open() { }
    virtual void close() { }
    virtual void reset() { }

    virtual void alert(Packet*, const char*, const Event&) { }
    virtual void log(Packet*, const char*, Event*) { }

    void set_api(const LogApi* p)
    { api = p; }

    const LogApi* get_api()
    { return api; }

protected:
    Logger() = default;

private:
    const LogApi* api;
};

typedef Logger* (* LogNewFunc)(struct SnortConfig*, class Module*);
typedef void (* LogDelFunc)(Logger*);

struct LogApi
{
    BaseApi base;
    unsigned flags;
    LogNewFunc ctor;
    LogDelFunc dtor;
};
}
#endif


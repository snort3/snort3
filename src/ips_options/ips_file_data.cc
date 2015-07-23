//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 1998-2013 Sourcefire, Inc.
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
// ips_filedata.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "time/profiler.h"
#include "detection/detection_defines.h"
#include "detection/detection_util.h"
#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"

#define s_name "file_data"

static THREAD_LOCAL ProfileStats fileDataPerfStats;

class FileDataOption : public IpsOption
{
public:
    FileDataOption() : IpsOption(s_name) { }
    ~FileDataOption() { }

    CursorActionType get_cursor_type() const override
    { return CAT_SET_FILE; }

    int eval(Cursor&, Packet*) override;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

int FileDataOption::eval(Cursor& c, Packet*)
{
    int rval = DETECTION_OPTION_NO_MATCH;
    uint8_t* data;
    uint16_t len;

    PROFILE_VARS;
    MODULE_PROFILE_START(fileDataPerfStats);

    data = g_file_data.data;
    len = g_file_data.len;

    if ( (data == NULL)|| (len == 0) )
    {
        MODULE_PROFILE_END(fileDataPerfStats);
        return rval;
    }

    c.set(s_name, data, len);
    rval = DETECTION_OPTION_MATCH;

    MODULE_PROFILE_END(fileDataPerfStats);
    return rval;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

#define s_help \
    "rule option to set detection cursor to file data"

class FileDataModule : public Module
{
public:
    FileDataModule() : Module(s_name, s_help) { }

    ProfileStats* get_profile() const override
    { return &fileDataPerfStats; }
};

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new FileDataModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* file_data_ctor(Module*, OptTreeNode*)
{
    return new FileDataOption;
}

static void file_data_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi file_data_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, 0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    file_data_ctor,
    file_data_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &file_data_api.base,
    nullptr
};
#else
const BaseApi* ips_file_data = &file_data_api.base;
#endif


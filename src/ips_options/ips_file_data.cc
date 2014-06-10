/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 ** Copyright (C) 1998-2013 Sourcefire, Inc.
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

#include "ips_file_data.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#include "snort_types.h"
#include "snort_bounds.h"
#include "protocols/packet.h"
#include "parser.h"
#include "snort_debug.h"
#include "util.h"
#include "mstring.h"
#include "snort.h"
#include "profiler.h"
#include "fpdetect.h"
#include "detection/detection_defines.h"
#include "detection/detection_util.h"
#include "framework/ips_option.h"

static const char* s_name = "file_data";

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats fileDataPerfStats;

static PreprocStats* fd_get_profile(const char* key)
{
    if ( !strcmp(key, s_name) )
        return &fileDataPerfStats;

    return nullptr;
}
#endif

typedef struct _FileData
{
    uint8_t mime_decode_flag;
} FileData;

class FileDataOption : public IpsOption
{
public:
    FileDataOption(const FileData& c) :
        IpsOption(s_name, RULE_OPTION_TYPE_FILE_DATA)
    { config = c; };

    ~FileDataOption() { };

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    int eval(Packet*);

    FileData* get_data()
    { return &config; };

private:
    FileData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t FileDataOption::hash() const
{
    uint32_t a,b,c;
    const FileData *data = &config;

    a = data->mime_decode_flag;
    b = 0;
    c = 0;

    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool FileDataOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    FileDataOption& rhs = (FileDataOption&)ips;
    FileData *left = (FileData*)&config;
    FileData *right = (FileData*)&rhs.config;

    if( left->mime_decode_flag == right->mime_decode_flag )
        return true;

    return false;
}

int FileDataOption::eval(Packet *p)
{
    int rval = DETECTION_OPTION_NO_MATCH;
    uint8_t *data;
    uint16_t len;
    FileData *idx;
    PROFILE_VARS;

    PREPROC_PROFILE_START(fileDataPerfStats);
    idx = (FileData *)&config;

    data = file_data_ptr.data;
    len = file_data_ptr.len;

    if ((p->dsize == 0) || (data == NULL)|| (len == 0) || !idx)
    {
        PREPROC_PROFILE_END(fileDataPerfStats);
        return rval;
    }

    if(idx->mime_decode_flag)
        mime_present = 1;
    else
        mime_present = 0;

    SetDoePtr(data,  DOE_BUF_STD);
    SetAltDetect(data, len);
    rval = DETECTION_OPTION_MATCH;

    PREPROC_PROFILE_END(fileDataPerfStats);
    return rval;
}

//-------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

bool decode_mime_file_data(void* v)
{
    FileDataOption* opt = (FileDataOption*)v;
    FileData* p = opt->get_data();
    return ( p->mime_decode_flag != 0 );
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

void file_data_parse(char *data, FileData *idx)
{

    if (IsEmptyStr(data))
    {
        idx->mime_decode_flag = 0;
    }
    else if(!strcasecmp("mime",data))
    {
        ParseWarning("The argument 'mime' to 'file_data' rule option is deprecated.\n");
    }
    else
    {
        ParseError("file_data: Invalid token %s", data);
    }

    return;

}

static IpsOption* file_data_ctor(
    SnortConfig*, char *data, OptTreeNode*)
{
    FileData idx;
    memset(&idx, 0, sizeof(idx));
    file_data_parse(data, &idx);
    return new FileDataOption(idx);
}

static void file_data_dtor(IpsOption* p)
{
    delete p;
}

static void file_data_ginit(SnortConfig*)
{
#ifdef PERF_PROFILING
    RegisterOtnProfile(s_name, &fileDataPerfStats, fd_get_profile);
#endif
}

static const IpsApi file_data_api =
{
    {
        PT_IPS_OPTION,
        s_name,
        IPSAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    OPT_TYPE_DETECTION,
    0, 0,
    file_data_ginit,
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


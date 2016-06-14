//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// output_file.cc author Sourcefire Inc.

#include "output_file.h"

#include <errno.h>
#include <string.h>
#include "log/messages.h"

FILE* openOutputFile(const char* const filename, time_t tstamp)
{
    FILE* fp;
    char output_fullpath[512];
    time_t curr_time;

    if (tstamp)
        curr_time = tstamp;
    else
        curr_time = time(nullptr);
    snprintf(output_fullpath, sizeof(output_fullpath), "%s.%lu", filename, curr_time);
    LogMessage("*** Opening %s for output\n",output_fullpath);
    if ((fp = fopen(output_fullpath, "w")) == nullptr)
    {
        ErrorMessage("Unable to open output file \"%s\": %s\n",output_fullpath, strerror(errno));
    }
    return fp;
}

FILE* rolloverOutputFile(const char* const filename, FILE* const oldfp, time_t tstamp)
{
    fclose(oldfp);

    return openOutputFile(filename, tstamp);
}


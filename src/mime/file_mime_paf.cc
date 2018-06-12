//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2012-2013 Sourcefire, Inc.
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

// file_mime_paf.cc author Hui Cao <huica@cisco.com>
// 9.25.2012 - Initial Source Code. Hui Cao

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_mime_paf.h"

#include <cctype>

#include "main/snort_debug.h"

using namespace snort;

static const char* boundary_str = "boundary=";

/* Save the boundary string into paf state*/
static inline bool store_boundary(MimeDataPafInfo* data_info,  uint8_t val)
{
    if (!data_info->boundary_search)
    {
        if ((val == '.') || isspace (val))
            data_info->boundary_search = boundary_str;
        return false;
    }

    if (*(data_info->boundary_search) == '=')
    {
        /*Skip spaces for the end of boundary*/
        if (val == '=')
            data_info->boundary_search++;
        else if (!isspace(val))
            data_info->boundary_search = nullptr;
    }
    else if (*(data_info->boundary_search) == '\0')
    {
        /*get boundary string*/
        if (isspace(val) || (val == '"'))
        {
            if (!data_info->boundary_len)
                return false;
            else
            {
                /*Found boundary string*/
                data_info->boundary[data_info->boundary_len] = '\0';
                return true;
            }
        }

        if (data_info->boundary_len < (int)sizeof(data_info->boundary))
        {
            data_info->boundary[data_info->boundary_len++] = val;
        }
        else
        {
            /*Found boundary string*/
            data_info->boundary[data_info->boundary_len -1] = '\0';
            return true;
        }
    }
    else if ((val == *(data_info->boundary_search))
        || (val == *(data_info->boundary_search) - 'a' + 'A'))
    {
        data_info->boundary_search++;
    }
    else
    {
        if ((val == '.') || isspace (val))
            data_info->boundary_search = boundary_str;
        else
            data_info->boundary_search = nullptr;
    }

    return false;
}

/* check the boundary string in the mail body*/
static inline bool check_boundary(MimeDataPafInfo* data_info,  uint8_t data)
{
    /* Search for boundary signature "--"*/
    switch (data_info->boundary_state)
    {
    case MIME_PAF_BOUNDARY_UNKNOWN:
        if (data == '-')
            data_info->boundary_state = MIME_PAF_BOUNDARY_HYPEN_FIRST;
        break;

    case MIME_PAF_BOUNDARY_HYPEN_FIRST:
        if (data == '-')
        {
            data_info->boundary_state = MIME_PAF_BOUNDARY_HYPEN_SECOND;
            data_info->boundary_search = data_info->boundary;
        }
        else
            data_info->boundary_state = MIME_PAF_BOUNDARY_UNKNOWN;
        break;

    case MIME_PAF_BOUNDARY_HYPEN_SECOND:
        /* Compare with boundary string stored */
        if (*(data_info->boundary_search) == '\0')
        {
            if (data == '\n')
            {
                /*reset boundary search etc.*/
                data_info->boundary_state = MIME_PAF_BOUNDARY_UNKNOWN;
                return true;
            }
            else if ((data != '\r') && ((data != '-')))
                data_info->boundary_state = MIME_PAF_BOUNDARY_UNKNOWN;
        }
        else if (*(data_info->boundary_search) == data)
            data_info->boundary_search++;
        else if (data == '-')
            data_info->boundary_state = MIME_PAF_BOUNDARY_HYPEN_FIRST;
        else
            data_info->boundary_state = MIME_PAF_BOUNDARY_UNKNOWN;
        break;
    }

    return false;
}

namespace snort
{
void reset_mime_paf_state(MimeDataPafInfo* data_info)
{
    data_info->boundary_search = nullptr;
    data_info->boundary_len = 0;
    data_info->boundary[0] = '\0';
    data_info->boundary_state = MIME_PAF_BOUNDARY_UNKNOWN;
    data_info->data_state = MIME_PAF_FINDING_BOUNDARY_STATE;
}

/*  Process data boundary and flush each file based on boundary*/
bool process_mime_paf_data(MimeDataPafInfo* data_info,  uint8_t data)
{
    switch (data_info->data_state)
    {
    case MIME_PAF_FINDING_BOUNDARY_STATE:
        /* Search for boundary Store boundary string in PAF state*/
        if (store_boundary(data_info, data))
        {
            /* End of boundary, move to MIME_PAF_FOUND_BOUNDARY_STATE*/
            data_info->data_state = MIME_PAF_FOUND_BOUNDARY_STATE;
        }
        break;

    case MIME_PAF_FOUND_BOUNDARY_STATE:
        if (check_boundary(data_info,  data))
        {
            /* End of boundary, move to MIME_PAF_FOUND_BOUNDARY_STATE*/
            return true;
        }
        break;

    default:
        break;
    }

    return false;
}

bool check_data_end(void* data_end_state,  uint8_t val)
{
    DataEndState state =  *((DataEndState*)data_end_state);

    switch (state)
    {
    case PAF_DATA_END_UNKNOWN:
        if (val == '\n')
        {
            state = PAF_DATA_END_FIRST_LF;
        }
        break;

    case PAF_DATA_END_FIRST_LF:
        if (val == '.')
        {
            state = PAF_DATA_END_DOT;
        }
        else if ((val != '\r') && (val != '\n'))
        {
            state = PAF_DATA_END_UNKNOWN;
        }
        break;
    case PAF_DATA_END_DOT:
        if (val == '\n')
        {
            *((DataEndState*)data_end_state) = PAF_DATA_END_UNKNOWN;
            return true;
        }
        else if (val != '\r')
        {
            state = PAF_DATA_END_UNKNOWN;
        }
        break;

    default:
        state = PAF_DATA_END_UNKNOWN;
        break;
    }

    *((DataEndState*)data_end_state) = state;
    return false;
}
} // namespace snort

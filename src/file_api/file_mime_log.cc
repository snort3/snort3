//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
/*
**  Author(s):  Hui Cao <huica@cisco.com>
**
**  NOTES
**  9.25.2012 - Initial Source Code. Hui Cao
*/

#include "file_mime_log.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "main/snort_types.h"
#include "utils/util.h"
#include "utils/snort_bounds.h"
#include "file_api.h"


/* Extract the filename from the header */
int MailLogState::extract_file_name(const char** start, int length, bool* disp_cont)
{
    const char* tmp = NULL;
    const char* end = *start+length;

    if (length <= 0)
        return -1;

    if (!(*disp_cont))
    {
        tmp = SnortStrcasestr(*start, length, "filename");

        if ( tmp == NULL )
            return -1;

        tmp = tmp + 8;
        while ( (tmp < end) && ((isspace(*tmp)) || (*tmp == '=') ))
        {
            tmp++;
        }
    }
    else
        tmp = *start;

    if (tmp < end)
    {
        if (*tmp == '"' || (*disp_cont))
        {
            if (*tmp == '"')
            {
                if (*disp_cont)
                {
                    *disp_cont = false;
                    return (tmp - *start);
                }
                tmp++;
            }
            *start = tmp;
            tmp = SnortStrnPbrk(*start,(end - tmp),"\"");
            if (tmp == NULL )
            {
                if ((end - tmp) > 0 )
                {
                    tmp = end;
                    *disp_cont = true;
                }
                else
                    return -1;
            }
            else
                *disp_cont = false;
            end = tmp;
        }
        else
        {
            *start = tmp;
        }
        return (end - *start);
    }
    else
    {
        return -1;
    }
}

/* accumulate MIME attachment filenames. The filenames are appended by commas */
int MailLogState::log_file_name(const uint8_t* start, int length, bool* disp_cont)
{
    uint8_t* alt_buf;
    int alt_size;
    uint16_t* alt_len;
    int ret=0;
    int cont =0;
    int log_avail = 0;

    if (!start || (length <= 0))
    {
        *disp_cont = false;
        return -1;
    }

    if (*disp_cont)
        cont = 1;

    ret = extract_file_name((const char**)(&start), length, disp_cont);

    if (ret == -1)
        return ret;

    length = ret;

    alt_buf = log_state.filenames;
    alt_size =  MAX_FILE;
    alt_len = &(log_state.file_logged);
    log_avail = alt_size - *alt_len;

    if (!alt_buf || (log_avail <= 0))
        return -1;

    if ( *alt_len > 0 && ((*alt_len + 1) < alt_size))
    {
        if (!cont)
        {
            alt_buf[*alt_len] = ',';
            *alt_len = *alt_len + 1;
        }
    }

    ret = SafeMemcpy(alt_buf + *alt_len, start, length, alt_buf, alt_buf + alt_size);

    if (ret != SAFEMEM_SUCCESS)
    {
        if (*alt_len != 0)
            *alt_len = *alt_len - 1;
        return -1;
    }

    log_state.file_current = *alt_len;
    *alt_len += length;

    return 0;
}


void MailLogState::set_file_name_from_log(void* pv)
{
    Flow* ssn = (Flow*)pv; // FIXIT-M eliminate need for cast

    if (log_state.file_logged > log_state.file_current)
    {
        file_api->set_file_name(ssn, log_state.filenames + log_state.file_current,
            log_state.file_logged -log_state.file_current);
    }
    else
    {
        file_api->set_file_name(ssn, NULL, 0);
    }
}

MailLogState::MailLogState(MailLogConfig* conf)
{
    if (conf && (conf->log_email_hdrs || conf->log_filename
        || conf->log_mailfrom || conf->log_rcptto))
    {
        uint32_t bufsz = (2* MAX_EMAIL) + MAX_FILE + conf->email_hdrs_log_depth;
        buf = (uint8_t*)SnortAlloc(bufsz);

        if (buf != NULL)
        {
            log_depth = conf->email_hdrs_log_depth;
            recipients = buf;
            rcpts_logged = 0;
            senders = buf + MAX_EMAIL;
            snds_logged = 0;
            log_state.filenames = buf + (2*MAX_EMAIL);
            log_state.file_logged = 0;
            log_state.file_current = 0;
            emailHdrs = buf + (2*MAX_EMAIL) + MAX_FILE;
            hdrs_logged = 0;
        }
    }
}

MailLogState::~MailLogState()
{
    if (buf != NULL)
        free(buf);
}

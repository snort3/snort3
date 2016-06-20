//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "smtp_paf.h"

#include <sys/types.h>

#include "main/snort_types.h"
#include "main/snort_debug.h"

#include "smtp.h"

/* State tracker for MIME PAF */
enum SmtpDataCMD
{
    SMTP_PAF_BDAT_CMD,
    SMTP_PAF_DATA_CMD,
    SMTP_PAF_XEXCH50_CMD,
    SMTP_PAF_STRARTTLS_CMD
};

struct SmtpPAFToken
{
    const char* name;
    int name_len;
    int search_id;
    bool has_length;
};

const SmtpPAFToken smtp_paf_tokens[] =
{
    { "BDAT",         4, SMTP_PAF_BDAT_CMD, true },
    { "DATA",         4, SMTP_PAF_DATA_CMD, true },
    { "XEXCH50",      7, SMTP_PAF_XEXCH50_CMD, true },
    { "STRARTTLS",    9, SMTP_PAF_STRARTTLS_CMD, false },
    { NULL,           0, 0, false }
};

/* State tracker for SMTP PAF */
enum SmtpPafDataLenStatus
{
    SMTP_PAF_LENGTH_INVALID,
    SMTP_PAF_LENGTH_CONTINUE,
    SMTP_PAF_LENGTH_DONE
};

static inline SmtpPafData* get_state(Flow* flow, bool c2s)
{
    if ( !flow )
        return nullptr;

    SmtpSplitter* s = (SmtpSplitter*)stream.get_splitter(flow, c2s);
    return s ? &s->state : nullptr;
}

/* Process responses from server, flushed at EOL*/

static inline void reset_data_states(SmtpPafData* pfdata)
{
    // reset MIME info
    reset_mime_paf_state(&(pfdata->data_info));

    pfdata->length = 0;
}

static inline StreamSplitter::Status smtp_paf_server(SmtpPafData* pfdata,
    const uint8_t* data, uint32_t len, uint32_t* fp)
{
    const char* pch;

    pfdata->smtp_state = SMTP_PAF_CMD_STATE;
    pch = (const char*)memchr (data, '\n', len);

    if (pch != NULL)
    {
        DebugMessage(DEBUG_SMTP, "Find end of line!\n");
        *fp = (uint32_t)(pch - (const char*)data) + 1;
        return StreamSplitter::FLUSH;
    }
    return StreamSplitter::SEARCH;
}

/* Initialize command search based on first byte of command*/
static inline char* init_cmd_search(SmtpCmdSearchInfo* search_info,  uint8_t ch)
{
    /* Use the first byte to choose data command)*/
    switch (ch)
    {
    case 'b':
    case 'B':
        search_info->search_state = &smtp_paf_tokens[SMTP_PAF_BDAT_CMD].name[1];
        search_info->search_id = SMTP_PAF_BDAT_CMD;
        break;
    case 'd':
    case 'D':
        search_info->search_state = &smtp_paf_tokens[SMTP_PAF_DATA_CMD].name[1];
        search_info->search_id = SMTP_PAF_DATA_CMD;
        break;
    case 'x':
    case 'X':
        search_info->search_state = &smtp_paf_tokens[SMTP_PAF_XEXCH50_CMD].name[1];
        search_info->search_id = SMTP_PAF_XEXCH50_CMD;
        break;
    case 's':
    case 'S':
        search_info->search_state = &smtp_paf_tokens[SMTP_PAF_STRARTTLS_CMD].name[1];
        search_info->search_id = SMTP_PAF_STRARTTLS_CMD;
        break;
    default:
        search_info->search_state = NULL;
        break;
    }
    return (char *)search_info->search_state;
}

/* Validate whether the command is a data command*/
static inline void validate_command(SmtpCmdSearchInfo* search_info,  uint8_t val)
{
    if (search_info->search_state )
    {
        uint8_t expected = *(search_info->search_state);

        if (toupper(val) == toupper(expected))
        {
            search_info->search_state++;
            /* Found data command, change to SMTP_PAF_CMD_DATA_LENGTH_STATE */
            if (*(search_info->search_state) == '\0')
            {
                search_info->search_state = NULL;
                search_info->cmd_state = SMTP_PAF_CMD_DATA_LENGTH_STATE;
                return;
            }
        }
        else
        {
            search_info->search_state = NULL;
            search_info->cmd_state = SMTP_PAF_CMD_UNKNOWN;
            return;
        }
    }
}

/* Get the length of data from data command
 *  */
static SmtpPafDataLenStatus get_length(char c, uint32_t* len)
{
    uint32_t length = *len;

    if (isblank(c))
    {
        if (length)
        {
            *len = length;
            return SMTP_PAF_LENGTH_DONE;
        }
    }
    else if (isdigit(c))
    {
        uint64_t tmp_len = (10 * length)  + (c - '0');
        if (tmp_len < UINT32_MAX)
            length = (uint32_t)tmp_len;
        else
        {
            *len = 0;
            return SMTP_PAF_LENGTH_INVALID;
        }
    }
    else
    {
        *len = 0;
        return SMTP_PAF_LENGTH_INVALID;
    }

    *len = length;
    return SMTP_PAF_LENGTH_CONTINUE;
}

/* Currently, we support "BDAT", "DATA", "XEXCH50", "STRARTTLS"
 *  * Each data command should start from offset 0,
 *   * since previous data have been flushed
 *    */
static inline bool process_command(SmtpPafData* pfdata,  uint8_t val)
{
    /*State unknown, start cmd search start from EOL, flush on EOL*/
    if (val == '\n')
    {
        if (pfdata->cmd_info.cmd_state == SMTP_PAF_CMD_DATA_END_STATE)
        {
            pfdata->smtp_state = SMTP_PAF_DATA_STATE;
            reset_data_states(pfdata);
            pfdata->end_of_data = false;
        }

        pfdata->cmd_info.cmd_state = SMTP_PAF_CMD_START;
        return 1;
    }

    switch (pfdata->cmd_info.cmd_state)
    {
    case SMTP_PAF_CMD_UNKNOWN:
        break;
    case SMTP_PAF_CMD_START:
        if (init_cmd_search(&(pfdata->cmd_info), val))
            pfdata->cmd_info.cmd_state = SMTP_PAF_CMD_DETECT;
        else
            pfdata->cmd_info.cmd_state = SMTP_PAF_CMD_UNKNOWN;
        break;
    case SMTP_PAF_CMD_DETECT:
        /* Search for data command */
        validate_command(&(pfdata->cmd_info), val);
        break;
    case SMTP_PAF_CMD_DATA_LENGTH_STATE:
        /* Continue finding the data length ...*/
        if (get_length(val, &pfdata->length) != SMTP_PAF_LENGTH_CONTINUE)
        {
            DebugFormat(DEBUG_SMTP, "Find data length: %u\n",
                pfdata->length);
            pfdata->cmd_info.cmd_state = SMTP_PAF_CMD_DATA_END_STATE;
        }
        break;
    case SMTP_PAF_CMD_DATA_END_STATE:
        /* Change to Data state at EOL*/
        break;
    default:
        break;
    }

    return 0;
}

/* Flush based on data length*/
static inline bool flush_based_length(SmtpPafData* pfdata)
{
    if (pfdata->length)
    {
        pfdata->length--;
        if (!pfdata->length)
            return true;
    }
    return false;
}

/* Process data length if specified, or end of data marker, flush at the end
 *  * or
 *   * Process data boundary and flush each file based on boundary*/
static inline bool process_data(SmtpPafData* pfdata,  uint8_t data)
{
    if (flush_based_length(pfdata)|| check_data_end(&(pfdata->data_end_state), data))
    {
        DebugMessage(DEBUG_SMTP, "End of data\n");
        /*Clean up states*/
        pfdata->smtp_state = SMTP_PAF_CMD_STATE;
        pfdata->end_of_data = true;
        reset_data_states(pfdata);
        return true;
    }

    return process_mime_paf_data(&(pfdata->data_info), data);
}

/* Process commands/data from client
 *  * For command, flush at EOL
 *   * For data, flush at boundary
 *    */
static inline StreamSplitter::Status smtp_paf_client(SmtpPafData* pfdata,
    const uint8_t* data, uint32_t len, uint32_t* fp)
{
    uint32_t i;
    uint32_t boundary_start = 0;

    DebugFormat(DEBUG_SMTP, "From client: %s \n", data);
    for (i = 0; i < len; i++)
    {
        uint8_t ch = data[i];
        switch (pfdata->smtp_state)
        {
        case SMTP_PAF_CMD_STATE:
            if (process_command(pfdata, ch))
            {
                DebugFormat(DEBUG_SMTP, "Flush command: %s \n", data);
                *fp = i + 1;
                return StreamSplitter::FLUSH;
            }
            break;
        case SMTP_PAF_DATA_STATE:
            if (process_data(pfdata, ch))
            {
                DebugMessage(DEBUG_SMTP, "Flush data!\n");
                *fp = i + 1;
                return StreamSplitter::FLUSH;
            }

            if (pfdata->data_info.boundary_state == MIME_PAF_BOUNDARY_UNKNOWN)
                boundary_start = i;
            break;
        default:
            break;
        }
    }

    if ( scanning_boundary(&pfdata->data_info, boundary_start, fp) )
        return StreamSplitter::LIMIT;

    return StreamSplitter::SEARCH;
}

//--------------------------------------------------------------------
// callback for stateful scanning of in-order raw payload
//--------------------------------------------------------------------

SmtpSplitter::SmtpSplitter(bool c2s) : StreamSplitter(c2s)
{
    memset(&state, 0, sizeof(state));
    reset_data_states(&state);
}

SmtpSplitter::~SmtpSplitter() { }

/* Function: smtp_paf()

   Purpose: SMTP PAF callback.
            Inspects smtp traffic.  Checks client traffic for the current command
            and sets correct server termination sequence. Client side data will
            flush after receiving CRLF ("\r\n").  Server data flushes after
            finding set termination sequence.

   Arguments:
     void * - stream5 session pointer
     void ** - DNP3 state tracking structure
     const uint8_t * - payload data to inspect
     uint32_t - length of payload data
     uint32_t - flags to check whether client or server
     uint32_t * - pointer to set flush point

   Returns:
    StreamSplitter::Status - StreamSplitter::FLUSH if flush point found, StreamSplitter::SEARCH otherwise
*/

StreamSplitter::Status SmtpSplitter::scan(
    Flow* , const uint8_t* data, uint32_t len,
    uint32_t flags, uint32_t* fp)
{
    SmtpPafData* pfdata = &state;

    if (flags & PKT_FROM_SERVER)
    {
        DebugMessage(DEBUG_SMTP, "PAF: From server.\n");
        return smtp_paf_server(pfdata, data, len, fp);
    }
    else
    {
        DebugMessage(DEBUG_SMTP, "PAF: From client.\n");
        return smtp_paf_client(pfdata, data, len, fp);
    }
}

bool smtp_is_data_end(Flow* ssn)
{
    SmtpPafData* s = get_state(ssn, true);
    return s ? s->end_of_data : false;
}


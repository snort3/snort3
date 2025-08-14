//--------------------------------------------------------------------------
// Copyright (C) 2015-2025 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "imap_paf.h"

#include "protocols/packet.h"
#include "stream/stream.h"

#include "imap.h"

using namespace snort;

extern IMAPToken imap_resps[];

static inline ImapPafData* get_state(Flow* flow, bool c2s)
{
    if ( !flow )
        return nullptr;

    ImapSplitter* s = (ImapSplitter*)Stream::get_splitter(flow, c2s);
    return (s and s->is_paf()) ? &s->state : nullptr;
}

static inline void reset_data_states(ImapPafData* pfdata)
{
    // reset MIME info
    reset_mime_paf_state(&(pfdata->mime_info));

    // reset server info
    pfdata->imap_state = IMAP_PAF_CMD_IDENTIFIER;
    pfdata->data_end_state = IMAP_PAF_DATA_END_UNKNOWN;
    pfdata->end_of_data = false;

    // reset fetch data information
    pfdata->imap_data_info.paren_cnt = 0;
    pfdata->imap_data_info.next_letter = nullptr;
    pfdata->imap_data_info.found_len = false;
    pfdata->imap_data_info.length = 0;
    pfdata->imap_data_info.esc_nxt_char = false;
    pfdata->imap_data_info.cmd = nullptr;
}

static inline bool is_untagged(const uint8_t ch)
{
    return (ch == '*' || ch == '+');
}

static bool parse_literal_length(const uint8_t ch, uint32_t* len)
{
    uint32_t length = *len;

    if (isdigit(ch))
    {
        uint64_t tmp_len = (10 * length)  + (ch - '0');
        if (tmp_len < UINT32_MAX)
        {
            *len = (uint32_t)tmp_len;
            return false;
        }
        else
        {
            *len = 0;
        }
    }
    else if (ch != '}')
        *len = 0;                      //  ALERT!!  character should be a digit or ''}''

    return true;
}

static void parse_fetch_header(const uint8_t ch, ImapPafData* pfdata)
{
    if (pfdata->imap_data_info.esc_nxt_char)
    {
        pfdata->imap_data_info.esc_nxt_char = false;
    }
    else
    {
        switch (ch)
        {
        case '{':
            pfdata->imap_state = IMAP_PAF_DATA_LEN_STATE;
            break;
        case '(':
            pfdata->imap_data_info.paren_cnt++;
            break;

        case ')':
            if (pfdata->imap_data_info.paren_cnt > 0)
                pfdata->imap_data_info.paren_cnt--;
            break;

        case '\n':
            if (pfdata->imap_data_info.paren_cnt)
            {
                pfdata->imap_state = IMAP_PAF_DATA_STATE;
            }
            else
            {
                reset_data_states(pfdata);
            }
            break;

        case '\\':
            pfdata->imap_data_info.esc_nxt_char = true;
            break;

        default:
            break;
        }
    }
}

/*
 * Statefully search for the single line termination sequence LF ("\n").
 *
 * PARAMS:
 *        const uint8_t ch - the next character to analyze.
 *        ImapPafData *pfdata - the struct containing all imap paf information
 *
 * RETURNS:
 *        false - if termination sequence not found
 *        true - if termination sequence found
 */
static bool find_data_end_single_line(const uint8_t ch, ImapPafData* pfdata)
{
    if (ch == '\n')
    {
        reset_data_states(pfdata);
        return true;
    }
    return false;
}

/* Flush based on data length*/
static inline bool literal_complete(ImapPafData* pfdata)
{
    if (pfdata->imap_data_info.length)
    {
        pfdata->imap_data_info.length--;
        if (pfdata->imap_data_info.length)
            return false;
    }

    return true;
}

static bool check_imap_data_end(ImapDataEnd* data_end_state,  uint8_t val)
{
    switch (*data_end_state)
    {
    case IMAP_PAF_DATA_END_UNKNOWN:
        if (val == ')')
            *data_end_state = IMAP_PAF_DATA_END_PAREN;
        break;

    case IMAP_PAF_DATA_END_PAREN:
        if (val == '\n')
        {
            *data_end_state = IMAP_PAF_DATA_END_UNKNOWN;
            return true;
        }
        else if (val != '\r')
        {
            *data_end_state = IMAP_PAF_DATA_END_UNKNOWN;
        }
        break;

    default:
        break;
    }

    return false;
}

/*
 * Statefully search for the data termination sequence or a MIME boundary.
 *
 * PARAMS:
 *        const uint8_t ch - the next character to analyze.
 *        ImapPafData *pfdata - the struct containing all imap paf information
 *
 * RETURNS:
 *        false - if termination sequence not found
 *        true - if termination sequence found
 */
static bool find_data_end_mime_data(const uint8_t ch, ImapPafData* pfdata)
{
    if (literal_complete(pfdata)
        && check_imap_data_end(&(pfdata->data_end_state), ch))
    {
        reset_data_states(pfdata);
        return true;
    }

    // check for mime flush point
    if (process_mime_paf_data(&(pfdata->mime_info), ch))
        return true;

    return false;
}

/*
 * This function only does something when the character is a blank or a CR/LF.
 * In those specific cases, this function will set the appropriate next
 * state information
 *
 * PARAMS:
 *        const uint8_t ch - the next character to analyze.
 *        ImapPafData *pfdata - the struct containing all imap paf information
 *        ImapPafData base_state - if a space is not found, revert to this state
 *        ImapPafData next_state - if a space is found, go to this state
 * RETURNS:
 *        true - if the status has been eaten
 *        false - if a CR or LF has been found
 */
static inline void eat_character(const uint8_t ch, ImapPafData* pfdata,
    ImapPafState base_state, ImapPafState next_state)
{
    switch (ch)
    {
    case ' ':
    case '\t':
    case '[':
        pfdata->imap_state = next_state;
        break;

    case '\r':
    case '\n':
        pfdata->imap_state = base_state;
        break;
    }
}

/*
 * Initial command processing function.  Determine if this command
 * may be analyzed irregularly ( which currently means if emails
 * and email attachments need to be analyzed).
 *
 * PARAMS:
 *        const uint8_t ch - the next character to analyze.
 *        ImapPafData *pfdata - the struct containing all imap paf information
 */
static inline void init_command_search(const uint8_t ch, const uint8_t next_ch, ImapPafData* pfdata)
{
    switch (ch)
    {
    case '[':
         eat_character(ch, pfdata, IMAP_PAF_REG_STATE, IMAP_PAF_CMD_SEARCH);
         break;
    case 'F':
    case 'f':
        if (pfdata->imap_state == IMAP_PAF_CMD_STATUS)
        {
            pfdata->imap_data_info.next_letter = &(imap_resps[RESP_FLAGS].name[1]);
        }
        else if (pfdata->imap_state == IMAP_PAF_CMD_SEARCH)
        {
            pfdata->imap_data_info.next_letter = &(imap_resps[RESP_FETCH].name[1]);
            pfdata->imap_data_info.cmd = imap_resps[RESP_FETCH].name;
        }
        break;

    case 'N':
    case 'n':
        if (imap_resps[RESP_NAMESPACE].name[1] == next_ch)
        {
            pfdata->imap_data_info.next_letter = &(imap_resps[RESP_NAMESPACE].name[1]);
        }
        break; 

    case 'L':
    case 'l':
            if (imap_resps[RESP_LIST].name[1] == next_ch)
            {
                pfdata->imap_data_info.next_letter = &(imap_resps[RESP_LIST].name[1]);
            }
            else if (imap_resps[RESP_LSUB].name[1] == next_ch)
            {
                pfdata->imap_data_info.next_letter = &(imap_resps[RESP_LSUB].name[1]);
            }
        break;

    case 'S':
    case 's':
            if (imap_resps[RESP_SEARCH].name[1] == next_ch)
            {
                pfdata->imap_data_info.next_letter = &(imap_resps[RESP_SEARCH].name[1]);
            }
            else if (imap_resps[RESP_STATUS].name[1] == next_ch)
            {
                pfdata->imap_data_info.next_letter = &(imap_resps[RESP_STATUS].name[1]);
            }
            else if (imap_resps[RESP_SUBSCRIBE].name[1] == next_ch)
            {
                pfdata->imap_data_info.next_letter = &(imap_resps[RESP_SUBSCRIBE].name[1]);
            }
        break;

    case 'C':
    case 'c':
            if (imap_resps[RESP_CREATE].name[1] == next_ch)
            {
                pfdata->imap_data_info.next_letter = &(imap_resps[RESP_CREATE].name[1]);
            }
            else if (imap_resps[RESP_CAPABILITY].name[1] == next_ch) 
            {
                pfdata->imap_data_info.next_letter = &(imap_resps[RESP_CAPABILITY].name[1]);
            }
        break;

    case 'D':
    case 'd':
            if (imap_resps[RESP_DELETE].name[1] == next_ch)
            {
                pfdata->imap_data_info.next_letter = &(imap_resps[RESP_DELETE].name[1]);
            }
        break;
    
    case 'E':
    case 'e':
            if (imap_resps[RESP_EXISTS].name[1] == next_ch)
            {
                pfdata->imap_data_info.next_letter = &(imap_resps[RESP_EXISTS].name[1]);
            }
            else if (imap_resps[RESP_EXPUNGE].name[1] == next_ch)
            {
                pfdata->imap_data_info.next_letter = &(imap_resps[RESP_EXPUNGE].name[1]);
            }

        break;
    
    case 'R':
    case 'r':
            if (imap_resps[RESP_RENAME].name[1] == next_ch)
            {
                pfdata->imap_data_info.next_letter = &(imap_resps[RESP_RENAME].name[1]);
            }
        break;

    case 'A':
    case 'a':
            if (imap_resps[RESP_APPEND].name[1] == next_ch)
            {
                pfdata->imap_data_info.next_letter = &(imap_resps[RESP_APPEND].name[1]);
            }
        break;

    case 'B':
    case 'b':
            if (imap_resps[RESP_BAD].name[1] == next_ch)
            {
                pfdata->imap_data_info.next_letter = &(imap_resps[RESP_BAD].name[1]);
            }
            else if (imap_resps[RESP_BYE].name[1] == next_ch)
            {
                pfdata->imap_data_info.next_letter = &(imap_resps[RESP_BYE].name[1]);
            }
        break;

    case 'O':
    case 'o':
        pfdata->imap_data_info.next_letter = &(imap_resps[RESP_OK].name[1]);
        break;
    
    case 'U':
    case 'u':
            if (imap_resps[RESP_UID].name[1] == next_ch)
            {
                pfdata->imap_data_info.next_letter = &(imap_resps[RESP_UID].name[1]);
            }
        break;

    default:
        // this is not a data command. Search for regular end of line.
        pfdata->imap_state = IMAP_PAF_REG_STATE;
    }
}

/*
 * Confirms every character in the current sequence is part of the expected
 * command. After confirmation is complete, IMAP PAF will begin searching
 * for data. If any character is unexpected, searches for the default
 * termination sequence.
 *
 * PARAMS:
 *        const uint8_t ch - the next character to analyze.
 *        ImapPafData *pfdata - the struct containing all imap paf information
 */
static inline void parse_command(const uint8_t ch, ImapPafData* pfdata)
{
    char val = *(pfdata->imap_data_info.next_letter);

    if (val == '\0' && isblank(ch))
    {
        if (pfdata->imap_state == IMAP_PAF_CMD_STATUS)
        {
            pfdata->imap_state = IMAP_PAF_CMD_SEARCH;
            pfdata->imap_data_info.next_letter = nullptr;
            return;
        }
        
        if (pfdata->imap_state == IMAP_PAF_CMD_SEARCH)
        {
            pfdata->imap_state = (pfdata->imap_data_info.cmd == imap_resps[RESP_FETCH].name) 
                ? IMAP_PAF_DATA_HEAD_STATE 
                : IMAP_PAF_VAL_STATE;
        }
    }
    else if (toupper(ch) == toupper(val))
        pfdata->imap_data_info.next_letter++;

    else
        pfdata->imap_state = IMAP_PAF_REG_STATE;
}

/*
 * Wrapper function for the command parser.  Determines whether this is the
 * first letter being processed and calls the appropriate processing
 * function.
 *
 * PARAMS:
 *        const uint8_t ch - the next character to analyze.
 *        ImapPafData *pfdata - the struct containing all imap paf information
 */
static inline void process_command(const uint8_t ch, const uint8_t next_ch, ImapPafData* pfdata)
{
    if (pfdata->imap_data_info.next_letter)
        parse_command(ch, pfdata);
    else
        init_command_search(ch, next_ch, pfdata);
}

static inline void process_second_argument(const uint8_t ch, const uint8_t next_ch, ImapPafData* pfdata)
{
    if (isdigit(ch))
        return;
    else if (isblank(ch))
    {
        pfdata->imap_state = IMAP_PAF_CMD_SEARCH;
        return;
    }

    if (pfdata->imap_data_info.next_letter)
        parse_command(ch, pfdata);
    else
        init_command_search(ch, next_ch, pfdata);
}

static inline void eat_response_identifier(const uint8_t ch, ImapPafData* pfdata)
{
    eat_character(ch, pfdata, IMAP_PAF_REG_STATE, IMAP_PAF_CMD_STATUS);
}

/*
 * Analyzes the current data for a correct flush point.  Flushes when
 * a command is complete or a MIME boundary is found.
 *
 * PARAMS:
 *    ImapPafData *pfdata - ImapPaf state tracking structure
 *    const uint8_t *data - payload data to inspect
 *    uint32_t len - length of payload data
 *    uint32_t * fp- pointer to set flush point
 *
 * RETURNS:
 *    StreamSplitter::Status - StreamSplitter::FLUSH if flush point found,
 *    StreamSplitter::SEARCH otherwise
 */
static StreamSplitter::Status imap_paf_server(ImapPafData* pfdata,
    const uint8_t* data, uint32_t len, uint32_t* fp)
{
    uint32_t i;
    uint32_t flush_len = 0;
    uint32_t boundary_start = 0;

    pfdata->end_of_data = false;

    bool saw_reg_state = false;
    for (i = 0; i < len; i++)
    {
        uint8_t ch = data[i];
        uint8_t next_ch = 0;
        if(i+1 < len)
            next_ch = data[i+1];

        switch (pfdata->imap_state)
        {
        case IMAP_PAF_CMD_IDENTIFIER:
            // can be '+', '*', or a tag
            if (is_untagged(ch))
            {
                // continue checking for fetch command
                pfdata->imap_state = IMAP_PAF_CMD_TAG;
            }
            else
            {
                // end of a command.  flush at end of line.
                pfdata->imap_state = IMAP_PAF_FLUSH_STATE;
            }
            break;

        case IMAP_PAF_CMD_TAG:
            eat_response_identifier(ch, pfdata);
            break;

        case IMAP_PAF_CMD_STATUS:
            // can be a command name, msg sequence number, msg count, etc...
            process_second_argument(ch, next_ch, pfdata);
            find_data_end_single_line(ch, pfdata);

            break;

        case IMAP_PAF_CMD_SEARCH:
            process_command(ch, next_ch, pfdata);
            find_data_end_single_line(ch, pfdata);
            break;
        
        case IMAP_PAF_VAL_STATE:
            pfdata->server_bytes_seen = 0;
            reset_data_states(pfdata);
            return StreamSplitter::SEARCH;

        case IMAP_PAF_REG_STATE:
            saw_reg_state = true;
            find_data_end_single_line(ch, pfdata); // data reset when end of line hit
            break;

        case IMAP_PAF_DATA_HEAD_STATE:
            parse_fetch_header(ch, pfdata); // function will change state
            break;

        case IMAP_PAF_DATA_LEN_STATE:
            if (parse_literal_length(ch, &(pfdata->imap_data_info.length)))
            {
                pfdata->imap_state = IMAP_PAF_DATA_HEAD_STATE;
            }
            break;

        case IMAP_PAF_DATA_STATE:
            if (find_data_end_mime_data(ch, pfdata))
            {
                // if not a boundary, wait for end of
                // the server's response before flushing
                if (pfdata->imap_state == IMAP_PAF_DATA_STATE)
                {
                    *fp = i + 1;
                    return StreamSplitter::FLUSH;
                }
            }
            if (pfdata->mime_info.boundary_state == MIME_PAF_BOUNDARY_UNKNOWN)
                boundary_start = i;
            break;

        case IMAP_PAF_FLUSH_STATE:
            if (find_data_end_single_line(ch, pfdata))
            {
                flush_len = i +1;
            }
            break;
        }
    }

    if( saw_reg_state )
    {
        pfdata->server_bytes_seen += len;
        if (pfdata->server_bytes_seen > IMAP_MAX_OCTETS)
        {
            return StreamSplitter::ABORT;
        }
    }
    else 
    {
        pfdata->server_bytes_seen = 0;
    }

    if (flush_len)
    {
        // flush at the final termination sequence
        *fp = flush_len;
        return StreamSplitter::FLUSH;
    }

    if ( scanning_boundary(&pfdata->mime_info, boundary_start, fp) )
        return StreamSplitter::LIMIT;

    return StreamSplitter::SEARCH;
}

/*
 * Searches through the current data for a LF.  All client
 * commands end with this termination sequence
 *
 * PARAMS:
 *    ImapPafData *pfdata - ImapPaf state tracking structure
 *    const uint8_t *data - payload data to inspect
 *    uint32_t len - length of payload data
 *    uint32_t * fp- pointer to set flush point
 *
 * RETURNS:
 *    StreamSplitter::Status - StreamSplitter::FLUSH if flush point found,
 *    StreamSplitter::SEARCH otherwise
 */

static StreamSplitter::Status imap_paf_client(ImapPafData* pfdata, const uint8_t* data, uint32_t len, uint32_t* fp)
{
    uint32_t i;
    uint32_t flush_len = 0;
    ImapClientState client_state = IMAP_CLIENT_FIRST_CHAR;
    bool is_valid_command = false;
    bool is_valid_base64 = len >= MIN_BASE64_LEN;
    bool found_space = false;
    
    for (i = 0; i < len; i++)
    {
        uint8_t ch = data[i];
        
        if (ch == '\n')
        {
            flush_len = i + 1;
            break;
        }
        else if (ch == '\r')
        {
            continue;
        }

        switch (client_state)
        {
        case IMAP_CLIENT_FIRST_CHAR:
            if (isalnum(ch))
            {
                is_valid_command = true;
                client_state = IMAP_CLIENT_COMMAND_TAG;
            }
            else
            {
                is_valid_command = false;
                client_state = is_valid_base64 ? IMAP_CLIENT_BASE64_CHECK : IMAP_CLIENT_FLUSH_LINE;
            }
            break;

        case IMAP_CLIENT_COMMAND_TAG:
            if (ch == ' ')
            {
                found_space = true;
                client_state = IMAP_CLIENT_FLUSH_LINE;
            }
            else if (!isalnum(ch) && ch != '-')
            {
                is_valid_command = false;
                client_state = is_valid_base64 ? IMAP_CLIENT_BASE64_CHECK : IMAP_CLIENT_FLUSH_LINE;
            }
            break;

        case IMAP_CLIENT_BASE64_CHECK:
            if (i < MIN_BASE64_LEN)
            {
                if (!(isalnum(ch) || ch == '+' || ch == '/' || ch == '='))
                {
                    is_valid_base64 = false;
                    client_state = IMAP_CLIENT_FLUSH_LINE;
                }
            }
            break;

        case IMAP_CLIENT_FLUSH_LINE:
            break;
        }
    }

    is_valid_command = is_valid_command && found_space;
    bool is_valid = is_valid_command || is_valid_base64;
    uint32_t check_len = flush_len ? flush_len : len;

    if (is_valid)
    {
        pfdata->client_bytes_seen = 0;
    }
    else
    {
        pfdata->client_bytes_seen += check_len;
        
        if (pfdata->client_bytes_seen > IMAP_MAX_OCTETS)
        {
            pfdata->client_bytes_seen = 0;
            return StreamSplitter::ABORT;
        }
    }
    
    if (flush_len)
    {
        *fp = flush_len;
        return StreamSplitter::FLUSH;
    }
    return StreamSplitter::SEARCH;
}

//--------------------------------------------------------------------
// callback for stateful scanning of in-order raw payload
//--------------------------------------------------------------------

ImapSplitter::ImapSplitter(bool c2s) : StreamSplitter(c2s)
{
    memset(&state, 0, sizeof(state));
    reset_data_states(&state);
}


/* Function: imap_paf()

   Purpose: IMAP PAF callback.
            Inspects imap traffic.  Checks client traffic for the current command
            and sets correct server termination sequence. Client side data will
            flush after receiving CRLF ("\r\n").  Server data flushes after
            finding set termination sequence.

   Arguments:
     void * - stream5 session pointer
     void ** - IMAP state tracking structure
     const uint8_t * - payload data to inspect
     uint32_t - length of payload data
     uint32_t - flags to check whether client or server
     uint32_t * - pointer to set flush point

   Returns:
    StreamSplitter::Status - StreamSplitter::FLUSH if flush point found, StreamSplitter::SEARCH otherwise
*/

StreamSplitter::Status ImapSplitter::scan(
    Packet*, const uint8_t* data, uint32_t len,
    uint32_t flags, uint32_t* fp)
{
    ImapPafData* pfdata = &state;

    if (flags & PKT_FROM_SERVER)
        return imap_paf_server(pfdata, data, len, fp);
    else
        return imap_paf_client(pfdata, data, len, fp);
}

bool imap_is_data_end(Flow* ssn)
{
    ImapPafData* s = get_state(ssn, true);
    return s ? s->end_of_data : false;
}


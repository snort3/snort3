//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "pop_paf.h"

#include "protocols/packet.h"
#include "stream/stream.h"

#include "pop.h"

using namespace snort;

extern POPToken pop_known_cmds[];

static inline PopPafData* get_state(Flow* flow, bool c2s)
{
    if ( !flow )
        return nullptr;

    PopSplitter* s = (PopSplitter*)Stream::get_splitter(flow, c2s);
    return (s and s->is_paf()) ? &s->state : nullptr;
}

/*
 *  read process_command() description below
 */
static bool search_for_command(PopPafData* pfdata, const uint8_t ch)
{
    char val = *(pfdata->cmd_state.next_letter);

    // if end of command && data contains a space or newline
    if (val == '\0'  && (isblank(ch) || ch == '\r' || ch == '\n'))
    {
        if (pfdata->cmd_state.exp_resp == POP_PAF_HAS_ARG)
        {
            pfdata->cmd_state.status = POP_CMD_ARG;
        }
        else
        {
            pfdata->cmd_state.status = POP_CMD_FIN;
            pfdata->pop_state = pfdata->cmd_state.exp_resp;
            return true;
        }
    }
    else if (toupper(ch) == toupper(val) )
    {
        pfdata->cmd_state.next_letter++;
    }
    else
    {
        pfdata->cmd_state.status = POP_CMD_FIN;
    }

    return false;
}

/*
 *  read process_command() description below
 */
static bool init_command_search(PopPafData* pfdata, const uint8_t ch)
{
    pfdata->pop_state = POP_PAF_SINGLE_LINE_STATE;

    switch (ch)
    {
    case 'c':
    case 'C':
        pfdata->cmd_state.exp_resp = POP_PAF_MULTI_LINE_STATE;
        pfdata->cmd_state.next_letter = &(pop_known_cmds[CMD_CAPA].name[1]);
        break;
    case 'l':
    case 'L':
        pfdata->cmd_state.exp_resp = POP_PAF_HAS_ARG;
        pfdata->cmd_state.next_letter = &(pop_known_cmds[CMD_LIST].name[1]);
        break;
    case 'r':
    case 'R':
        pfdata->cmd_state.exp_resp = POP_PAF_DATA_STATE;
        pfdata->cmd_state.next_letter = &(pop_known_cmds[CMD_RETR].name[1]);
        break;
    case 't':
    case 'T':
        pfdata->cmd_state.exp_resp = POP_PAF_DATA_STATE;
        pfdata->cmd_state.next_letter = &(pop_known_cmds[CMD_TOP].name[1]);
        break;
    case 'u':
    case 'U':
        pfdata->cmd_state.exp_resp = POP_PAF_HAS_ARG;
        pfdata->cmd_state.next_letter = &(pop_known_cmds[CMD_UIDL].name[1]);
        break;
    default:
        pfdata->cmd_state.status = POP_CMD_FIN;
    }

    return false;
}

/*
 * Attempts to determine the current command based upon the given character
 * If another character is required to determine the current command,
 * sets the function pointer to the correct next state
 *
 * PARAMS:
 *         pop_cmd - a pointer to the struct containing all of the
 *                     relevant parsing info
 *         ch      - the first character from the clients command
 * RETURNS
 *         true  - if the expected response is NOT a single line
 *         false - otherwise
 */
static inline bool process_command(PopPafData* pfdata, const uint8_t ch)
{
    if (pfdata->cmd_state.next_letter)
        return search_for_command(pfdata, ch);
    else
        return init_command_search(pfdata, ch);
}

static inline void reset_data_states(PopPafData* pfdata)
{
    // reset MIME info
    reset_mime_paf_state(&(pfdata->data_info));

    // reset general pop fields
    pfdata->cmd_continued = false;
    pfdata->end_state = PAF_DATA_END_UNKNOWN;
    pfdata->pop_state = POP_PAF_SINGLE_LINE_STATE;
}

/*
 *  Checks if the current data is a valid response.
 *  According to RFC 1939, every response begins with either
 *     +OK
 *     -ERR.
 *
 *  RETURNS:
 *           true - if the character is a +
 *           false - if the character is anything else
 */
static inline int valid_response(const uint8_t data)
{
    return (data == '+');
}

/*
 * Client PAF calls this command to set the server's state.  This is the
 * function which ensures the server know the correct expected
 * DATA
 */
static inline void set_server_state(Flow* ssn, PopExpectedResp state)
{
    PopPafData* server_data = get_state(ssn, false);

    if (server_data)
    {
        reset_data_states(server_data);
        server_data->end_of_data = false;
        server_data->pop_state = state;
    }
}

/*
 * A helper function to reset the client's command parsing
 * information
 */
static inline void reset_client_cmd_info(PopPafData* pfdata)
{
    pfdata->cmd_state.next_letter = nullptr;
    pfdata->cmd_state.status = POP_CMD_SEARCH;
}

/*
 * Statefully search for the termination sequence CRCL.CRLF ("\r\n.\r\n").
 *
 * PARAMS:
 *        mime_data : true if this is mime_data.
 *
 * RETURNS:
 *         0 - if termination sequence not found
 *         1 - if termination sequence found
 */
static bool find_data_end_multi_line(PopPafData* pfdata, const uint8_t ch, bool mime_data)
{
    // FIXIT-M this will currently flush on MIME boundary, and one line later at end of PDU

    if (check_data_end(&(pfdata->end_state), ch))
    {
        pfdata->end_of_data = true;
        pfdata->pop_state = POP_PAF_SINGLE_LINE_STATE;
        reset_data_states(pfdata);
        return true;
    }

    // if this is a data command, search for MIME ending
    if (mime_data)
    {
        if (process_mime_paf_data(&(pfdata->data_info), ch))
        {
            pfdata->cmd_continued = true;
            return true;
        }
    }

    return false;
}

/*
 * Statefully search for the termination sequence LF ("\n").  Will also
 * set the correct response state.
 *
 * PARAMS:
 *
 * RETURNS:
 *         0 - if termination sequence not found
 *         1 - if termination sequence found
 */
static inline bool find_data_end_single_line(PopPafData* pfdata, const uint8_t ch, bool client)
{
    if (ch == '\n')
    {
        // reset the correct information
        if (client)
            reset_client_cmd_info(pfdata);
        else
            reset_data_states(pfdata);

        return true;
    }

    return false;
}

static StreamSplitter::Status pop_paf_server(PopPafData* pfdata,
    const uint8_t* data, uint32_t len, uint32_t* fp)
{
    uint32_t i;
    uint32_t boundary_start = 0;

    // if a negative response was received, it will be a one line response.
    if (!pfdata->cmd_continued && !valid_response(*data))
        pfdata->pop_state = POP_PAF_SINGLE_LINE_STATE;

    for (i = 0; i < len; i++)
    {
        uint8_t ch = data[i];

        // find the termination sequence based upon the current state
        switch (pfdata->pop_state)
        {
        case POP_PAF_MULTI_LINE_STATE:
            if ( find_data_end_multi_line(pfdata, ch, false) )
            {
                *fp = i + 1;
                return StreamSplitter::FLUSH;
            }
            break;

        case POP_PAF_DATA_STATE:
            // FIXIT-M statefully get length
            if ( find_data_end_multi_line(pfdata, ch, true) )
            {
                *fp = i + 1;
                return StreamSplitter::FLUSH;
            }

            if (pfdata->data_info.boundary_state == MIME_PAF_BOUNDARY_UNKNOWN)
                boundary_start = i;

            break;

        case POP_PAF_SINGLE_LINE_STATE:
        default:
            if ( find_data_end_single_line(pfdata, ch, false) )
            {
                *fp = i + 1;
                return StreamSplitter::FLUSH;
            }
            break;
        }
    }

    pfdata->cmd_continued = true;

    if ( scanning_boundary(&pfdata->data_info, boundary_start, fp) )
        return StreamSplitter::LIMIT;

    return StreamSplitter::SEARCH;
}

/*
 * Determine the Client's command and set the response state.
 * Flush data when "\r\n" is received
 */
static StreamSplitter::Status pop_paf_client(Flow* ssn, PopPafData* pfdata,
    const uint8_t* data, uint32_t len, uint32_t* fp)
{
    uint32_t i;

    // FIXIT-M ensure current command is smaller than max command length

    for (i = 0; i < len; i++)
    {
        uint8_t ch = data[i];

        switch (pfdata->cmd_state.status)
        {
        case POP_CMD_SEARCH:
            if (process_command(pfdata, ch) )
            {
                set_server_state(ssn, pfdata->pop_state);
            }

            // both cases should check for a LF.
            // fallthrough

        case POP_CMD_FIN:
            if (find_data_end_single_line(pfdata, ch, true) )
            {
                // reset command parsing data
                *fp = i + 1;
                return StreamSplitter::FLUSH;
            }
            break;

        case POP_CMD_ARG:
            if (find_data_end_single_line(pfdata, ch, true))
            {
                set_server_state(ssn, POP_PAF_MULTI_LINE_STATE);
                *fp = i + 1;
                return StreamSplitter::FLUSH;
            }
            else if (isdigit(ch))
            {
                pfdata->cmd_state.status = POP_CMD_FIN;
            }
        }
    }

    return StreamSplitter::SEARCH;
}

//--------------------------------------------------------------------
// callback for stateful scanning of in-order raw payload
//--------------------------------------------------------------------

PopSplitter::PopSplitter(bool c2s) : StreamSplitter(c2s)
{
    memset(&state, 0, sizeof(state));
    reset_data_states(&state);
}


/* Function: pop_paf()

   Purpose: POP PAF callback.
            Inspects pop traffic.  Checks client traffic for the current command
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

StreamSplitter::Status PopSplitter::scan(
    Flow* ssn, const uint8_t* data, uint32_t len,
    uint32_t flags, uint32_t* fp)
{
    PopPafData* pfdata = &state;

    if (flags & PKT_FROM_SERVER)
        return pop_paf_server(pfdata, data, len, fp);
    else
        return pop_paf_client(ssn, pfdata, data, len, fp);
}

bool pop_is_data_end(Flow* ssn)
{
    PopPafData* s = get_state(ssn, false);
    return s ? s->end_of_data : false;
}


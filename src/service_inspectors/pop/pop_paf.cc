//--------------------------------------------------------------------------
// Copyright (C) 2015-2026 Cisco and/or its affiliates. All rights reserved.
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
extern POPToken pop_resps[];

static inline PopPafData* get_state(Flow* flow, bool c2s)
{
    if ( !flow )
        return nullptr;

    PopSplitter* s = static_cast<PopSplitter*>(Stream::get_splitter(flow, c2s));
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
    else if (toupper(ch) == toupper(val) && val != '\0')
    {
        pfdata->cmd_state.next_letter++;
    }
    else
    {
        pfdata->cmd_state.status = POP_CMD_INVALID;
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
    case 'a':
    case 'A':
        pfdata->cmd_state.exp_resp = POP_PAF_SINGLE_LINE_STATE;
        pfdata->cmd_state.next_letter = &(pop_known_cmds[CMD_APOP].name[1]);
        break;
    case 'd':
    case 'D':
        pfdata->cmd_state.exp_resp = POP_PAF_SINGLE_LINE_STATE;
        pfdata->cmd_state.next_letter = &(pop_known_cmds[CMD_DELE].name[1]);
        break;
    case 'p':
    case 'P':
        pfdata->cmd_state.exp_resp = POP_PAF_SINGLE_LINE_STATE;
        pfdata->cmd_state.next_letter = &(pop_known_cmds[CMD_PASS].name[1]);
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
    case 'n':
    case 'N':
        pfdata->cmd_state.exp_resp = POP_PAF_SINGLE_LINE_STATE;
        pfdata->cmd_state.next_letter = &(pop_known_cmds[CMD_NOOP].name[1]);
        break;
    case 'q':
    case 'Q':
        pfdata->cmd_state.exp_resp = POP_PAF_SINGLE_LINE_STATE;
        pfdata->cmd_state.next_letter = &(pop_known_cmds[CMD_QUIT].name[1]);
        break;
    case 's':
    case 'S':
        pfdata->cmd_state.exp_resp = POP_PAF_SINGLE_LINE_STATE;
        pfdata->cmd_state.next_letter = &(pop_known_cmds[CMD_STAT].name[1]);
        break;
    default:
        pfdata->cmd_state.status = POP_CMD_INVALID;
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
    pfdata->resp_state = POP_RESP_SEARCH;
    pfdata->resp_next_letter = nullptr;
    pfdata->resp_invalid = false;
}

/*
 *  Classifies the first byte of a new response line by walking pop_resps[]
 *  the same way process_command() walks pop_known_cmds[] for client
 *  commands.  According to RFC 1939, every response begins with either
 *     +OK
 *     -ERR
 *  Anything else - including a bare LF - can never be a real response, so
 *  it is treated like -ERR: forced into the single-line state, where the
 *  invalid-byte budget (server_bytes_seen) applies.
 */
static void init_resp_search(PopPafData* pfdata, const uint8_t ch)
{
    for (const POPToken* tok = &pop_resps[0]; tok->name; tok++)
    {
        if (ch == (uint8_t)tok->name[0])
        {
            pfdata->resp_next_letter = &tok->name[1];
            pfdata->resp_state = POP_RESP_MATCH;

            if (tok->search_id == RESP_ERR)
                pfdata->pop_state = POP_PAF_SINGLE_LINE_STATE;

            return;
        }
    }

    pfdata->pop_state = POP_PAF_SINGLE_LINE_STATE;
    pfdata->resp_invalid = true;
    pfdata->resp_state = POP_RESP_SCAN;
}

/*
 *  Continues matching the current response line against the token chosen
 *  by init_resp_search().  Once the token is fully matched, or a byte fails
 *  to match, moves to POP_RESP_SCAN: anything may follow a confirmed "+OK"
 *  or "-ERR", and an already-invalid line needs no further checking.
 */
static inline void resp_search_for_token(PopPafData* pfdata, const uint8_t ch)
{
    char val = *(pfdata->resp_next_letter);

    if (val == '\0')
    {
        pfdata->resp_state = POP_RESP_SCAN;
        return;
    }

    if (toupper(ch) == toupper(val))
        pfdata->resp_next_letter++;
    else
    {
        pfdata->resp_invalid = true;
        pfdata->resp_state = POP_RESP_SCAN;
    }
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

    for (i = 0; i < len; i++)
    {
        uint8_t ch = data[i];

        if (!pfdata->tls_data)
        {
            switch (pfdata->resp_state)
            {
            case POP_RESP_SEARCH:
                init_resp_search(pfdata, ch);
                break;
            case POP_RESP_MATCH:
                resp_search_for_token(pfdata, ch);
                break;
            case POP_RESP_SCAN:
            default:
                break;
            }
        }

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
                if ( pfdata->data_info.paf_abort )
                    return StreamSplitter::ABORT;

                *fp = i + 1;
                return StreamSplitter::FLUSH;
            }

            if (pfdata->data_info.boundary_state == MIME_PAF_BOUNDARY_UNKNOWN)
                boundary_start = i;

            break;

        case POP_PAF_SINGLE_LINE_STATE:
        default:
        {
            bool line_invalid = !pfdata->tls_data && pfdata->resp_invalid;
            if ( find_data_end_single_line(pfdata, ch, false) )
            {
                if (line_invalid)
                {
                    pfdata->server_bytes_seen += i + 1;
                    if (pfdata->server_bytes_seen > POP_MAX_OCTETS)
                    {
                        pfdata->server_bytes_seen = 0;
                        reset_data_states(pfdata);
                        return StreamSplitter::ABORT;
                    }
                }
                else
                    pfdata->server_bytes_seen = 0;

                *fp = i + 1;
                return StreamSplitter::FLUSH;
            }
            break;
        }
        }
    }

    pfdata->cmd_continued = true;

    if ( scanning_boundary(&pfdata->data_info, boundary_start, fp) )
        return StreamSplitter::LIMIT;

    return StreamSplitter::SEARCH;
}

static inline StreamSplitter::Status flush_client_cmd_line(PopPafData* pfdata,
    bool invalid, uint32_t flush_point, uint32_t* fp)
{
    if (invalid)
    {
        pfdata->client_bytes_seen += flush_point;
        if (pfdata->client_bytes_seen > POP_MAX_OCTETS)
        {
            pfdata->client_bytes_seen = 0;
            reset_client_cmd_info(pfdata);
            return StreamSplitter::ABORT;
        }
    }
    else
        pfdata->client_bytes_seen = 0;

    *fp = flush_point;
    return StreamSplitter::FLUSH;
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

        if (pfdata->tls_data)
        {
            if (find_data_end_single_line(pfdata, ch, true))
                return flush_client_cmd_line(pfdata, false, i + 1, fp);
            continue;
        }

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
        {
            bool invalid = (pfdata->cmd_state.status == POP_CMD_INVALID);
            if (find_data_end_single_line(pfdata, ch, true) )
                return flush_client_cmd_line(pfdata, invalid, i + 1, fp);
            break;
        }

        case POP_CMD_INVALID:
            if (find_data_end_single_line(pfdata, ch, true))
                return flush_client_cmd_line(pfdata, true, i + 1, fp);
            break;
        case POP_CMD_ARG:
            if (find_data_end_single_line(pfdata, ch, true))
            {
                set_server_state(ssn, POP_PAF_MULTI_LINE_STATE);
                return flush_client_cmd_line(pfdata, false, i + 1, fp);
            }
            else if (isdigit(ch))
            {
                pfdata->cmd_state.status = POP_CMD_FIN;
            }
        }
    }

    if (!pfdata->tls_data)
    {
        pfdata->client_bytes_seen += len;
        if(pfdata->client_bytes_seen > POP_MAX_OCTETS)
        {
            reset_client_cmd_info(pfdata);
            return StreamSplitter::ABORT;
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
    reset_client_cmd_info(&state);
}


/* Function: PopSplitter::scan()

   Purpose: POP PAF callback.
            Inspects pop traffic.  Checks client traffic for the current command
            and sets correct server termination sequence. Client side data will
            flush after receiving CRLF ("\r\n").  Server data flushes after
            finding set termination sequence.

   Arguments:
     Packet* - packet carrying the flow this data belongs to
     const uint8_t* - payload data to inspect
     uint32_t - length of payload data
     uint32_t - flags to check whether client or server
     uint32_t* - pointer to set flush point

   Returns:
    StreamSplitter::Status - StreamSplitter::FLUSH if flush point found, StreamSplitter::SEARCH otherwise
*/

StreamSplitter::Status PopSplitter::scan(
    Packet* pkt, const uint8_t* data, uint32_t len,
    uint32_t flags, uint32_t* fp)
{
    PopPafData* pfdata = &state;

    if (flags & PKT_FROM_SERVER)
        return pop_paf_server(pfdata, data, len, fp);
    else
        return pop_paf_client(pkt->flow, pfdata, data, len, fp);
}

bool pop_is_data_end(Flow* ssn)
{
    const PopPafData* s = get_state(ssn, false);
    return s ? s->end_of_data : false;
}

void pop_paf_set_tls_data(Flow* ssn)
{
    if (PopPafData* client_state = get_state(ssn, true))
        client_state->tls_data = true;

    if (PopPafData* server_state = get_state(ssn, false))
        server_state->tls_data = true;
}

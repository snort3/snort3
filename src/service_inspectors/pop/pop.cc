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

// pop.cc author Bhagyashree Bantwal < bbantwal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pop.h"

#include "detection/detection_engine.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "protocols/ssl.h"
#include "search_engines/search_tool.h"
#include "stream/stream.h"
#include "utils/util_cstring.h"

#include "pop_module.h"
#include "pop_paf.h"

using namespace snort;

THREAD_LOCAL ProfileStats popPerfStats;
THREAD_LOCAL PopStats popstats;

POPToken pop_known_cmds[] =
{
    { "APOP",          4, CMD_APOP },
    { "AUTH",          4, CMD_AUTH },
    { "CAPA",          4, CMD_CAPA },
    { "DELE",          4, CMD_DELE },
    { "LIST",          4, CMD_LIST },
    { "NOOP",          4, CMD_NOOP },
    { "PASS",          4, CMD_PASS },
    { "QUIT",          4, CMD_QUIT },
    { "RETR",          4, CMD_RETR },
    { "RSET",          4, CMD_RSET },
    { "STAT",          4, CMD_STAT },
    { "STLS",          4, CMD_STLS },
    { "TOP",           3, CMD_TOP },
    { "UIDL",          4, CMD_UIDL },
    { "USER",          4, CMD_USER },
    { nullptr,            0, 0 }
};

POPToken pop_resps[] =
{
    { "+OK",   3,  RESP_OK },   /* SUCCESS */
    { "-ERR",  4,  RESP_ERR },  /* FAILURE */
    { nullptr,   0,  0 }
};

SearchTool* pop_resp_search_mpse = nullptr;
SearchTool* pop_cmd_search_mpse = nullptr;

POPSearch pop_resp_search[RESP_LAST];
POPSearch pop_cmd_search[CMD_LAST];

static THREAD_LOCAL const POPSearch* pop_current_search = nullptr;
static THREAD_LOCAL POPSearchInfo pop_search_info;

const PegInfo pop_peg_names[] =
{
    { CountType::SUM, "packets", "total packets processed" },
    { CountType::SUM, "sessions", "total pop sessions" },
    { CountType::NOW, "concurrent_sessions", "total concurrent pop sessions" },
    { CountType::MAX, "max_concurrent_sessions", "maximum concurrent pop sessions" },
    { CountType::SUM, "b64_attachments", "total base64 attachments decoded" },
    { CountType::SUM, "b64_decoded_bytes", "total base64 decoded bytes" },
    { CountType::SUM, "qp_attachments", "total quoted-printable attachments decoded" },
    { CountType::SUM, "qp_decoded_bytes", "total quoted-printable decoded bytes" },
    { CountType::SUM, "uu_attachments", "total uu attachments decoded" },
    { CountType::SUM, "uu_decoded_bytes", "total uu decoded bytes" },
    { CountType::SUM, "non_encoded_attachments", "total non-encoded attachments extracted" },
    { CountType::SUM, "non_encoded_bytes", "total non-encoded extracted bytes" },

    { CountType::END, nullptr, nullptr }
};


static void snort_pop(POP_PROTO_CONF* GlobalConf, Packet* p);
static void POP_ResetState(Flow*);

PopFlowData::PopFlowData() : FlowData(inspector_id)
{
    memset(&session, 0, sizeof(session));
    popstats.concurrent_sessions++;
    if(popstats.max_concurrent_sessions < popstats.concurrent_sessions)
        popstats.max_concurrent_sessions = popstats.concurrent_sessions;
}

PopFlowData::~PopFlowData()
{
    if (session.mime_ssn)
        delete(session.mime_ssn);

    assert(popstats.concurrent_sessions > 0);
    popstats.concurrent_sessions--;
}

unsigned PopFlowData::inspector_id = 0;
static POPData* get_session_data(Flow* flow)
{
    PopFlowData* fd = (PopFlowData*)flow->get_flow_data(PopFlowData::inspector_id);
    return fd ? &fd->session : nullptr;
}

static POPData* SetNewPOPData(POP_PROTO_CONF* config, Packet* p)
{
    POPData* pop_ssn;
    PopFlowData* fd = new PopFlowData;

    p->flow->set_flow_data(fd);
    pop_ssn = &fd->session;

    popstats.sessions++;
    pop_ssn->mime_ssn = new PopMime( &(config->decode_conf), &(config->log_config));
    pop_ssn->mime_ssn->set_mime_stats(&(popstats.mime_stats));

    if (p->packet_flags & SSNFLAG_MIDSTREAM)
    {
        pop_ssn->state = STATE_UNKNOWN;
    }

    return pop_ssn;
}

static void POP_SearchInit()
{
    const POPToken* tmp;
    if ( pop_cmd_search_mpse )
        return;
    pop_cmd_search_mpse = new SearchTool;

    for (tmp = &pop_known_cmds[0]; tmp->name != nullptr; tmp++)
    {
        pop_cmd_search[tmp->search_id].name = tmp->name;
        pop_cmd_search[tmp->search_id].name_len = tmp->name_len;
        pop_cmd_search_mpse->add(tmp->name, tmp->name_len, tmp->search_id);
    }
    pop_cmd_search_mpse->prep();
    pop_resp_search_mpse = new SearchTool;

    for (tmp = &pop_resps[0]; tmp->name != nullptr; tmp++)
    {
        pop_resp_search[tmp->search_id].name = tmp->name;
        pop_resp_search[tmp->search_id].name_len = tmp->name_len;
        pop_resp_search_mpse->add(tmp->name, tmp->name_len, tmp->search_id);
    }
    pop_resp_search_mpse->prep();
}

static void POP_SearchFree()
{
    if (pop_cmd_search_mpse != nullptr)
        delete pop_cmd_search_mpse;

    if (pop_resp_search_mpse != nullptr)
        delete pop_resp_search_mpse;
}

static void POP_ResetState(Flow* ssn)
{
    POPData* pop_ssn = get_session_data(ssn);
    pop_ssn->state = STATE_COMMAND;
    pop_ssn->prev_response = 0;
    pop_ssn->state_flags = 0;
}

static void POP_GetEOL(const uint8_t* ptr, const uint8_t* end,
    const uint8_t** eol, const uint8_t** eolm)
{
    assert(ptr and end and eol and eolm);

    const uint8_t* tmp_eol;
    const uint8_t* tmp_eolm;

    tmp_eol = (uint8_t*)memchr(ptr, '\n', end - ptr);
    if (tmp_eol == nullptr)
    {
        tmp_eol = end;
        tmp_eolm = end;
    }
    else
    {
        /* end of line marker (eolm) should point to marker and
         *          * end of line (eol) should point to end of marker */
        if ((tmp_eol > ptr) && (*(tmp_eol - 1) == '\r'))
        {
            tmp_eolm = tmp_eol - 1;
        }
        else
        {
            tmp_eolm = tmp_eol;
        }

        /* move past newline */
        tmp_eol++;
    }

    *eol = tmp_eol;
    *eolm = tmp_eolm;
}

static void PrintPopConf(POP_PROTO_CONF* config)
{
    if (config == nullptr)
        return;

    LogMessage("POP config: \n");

    config->decode_conf.print_decode_conf();

    LogMessage("\n");

}

static inline int InspectPacket(Packet* p)
{
    return p->has_paf_payload();
}

static int POP_Setup(Packet* p, POPData* ssn)
{
    int pkt_dir;

    /* Get the direction of the packet. */
    if ( p->is_from_server() )
        pkt_dir = POP_PKT_FROM_SERVER;
    else
        pkt_dir = POP_PKT_FROM_CLIENT;

    if (!(ssn->session_flags & POP_FLAG_CHECK_SSL))
        ssn->session_flags |= POP_FLAG_CHECK_SSL;
    /* Check to see if there is a reassembly gap.  If so, we won't know
     *      * what state we're in when we get the _next_ reassembled packet */
    if ((pkt_dir != POP_PKT_FROM_SERVER) &&
        (p->packet_flags & PKT_REBUILT_STREAM))
    {
        int missing_in_rebuilt =
            Stream::missing_in_reassembled(p->flow, SSN_DIR_FROM_CLIENT);

        if (ssn->session_flags & POP_FLAG_NEXT_STATE_UNKNOWN)
        {
            ssn->state = STATE_UNKNOWN;
            ssn->session_flags &= ~POP_FLAG_NEXT_STATE_UNKNOWN;
        }

        if (missing_in_rebuilt == SSN_MISSING_BEFORE)
        {
            ssn->state = STATE_UNKNOWN;
        }
    }

    return pkt_dir;
}

static int POP_SearchStrFound(void* id, void* , int index, void* , void* )
{
    int search_id = (int)(uintptr_t)id;

    pop_search_info.id = search_id;
    pop_search_info.length = pop_current_search[search_id].name_len;
    pop_search_info.index = index - pop_search_info.length;

    /* Returning non-zero stops search, which is okay since we only look for one at a time */
    return 1;
}

/*
 * Handle COMMAND state
 *
 * @param   p       standard Packet structure
 * @param   ptr     pointer into p->data buffer to start looking at data
 * @param   end     points to end of p->data buffer
 *
 * @return          pointer into p->data where we stopped looking at data
 *                  will be end of line or end of packet
 */
static const uint8_t* POP_HandleCommand(Packet* p, POPData* pop_ssn, const uint8_t* ptr, const
    uint8_t* end)
{
    const uint8_t* eol;   /* end of line */
    const uint8_t* eolm;  /* end of line marker */
    int cmd_found;

    /* get end of line and end of line marker */
    POP_GetEOL(ptr, end, &eol, &eolm);

    // FIXIT-M If the end of line marker coincides with the end of data we
    // can't be sure that we got a command and not a substring which we
    // could tell through inspection of the next packet. Maybe a command
    // pending state where the first char in the next packet is checked for
    // a space and end of line marker

    /* do not confine since there could be space chars before command */
    pop_current_search = &pop_cmd_search[0];
    cmd_found = pop_cmd_search_mpse->find(
        (const char*)ptr, eolm - ptr, POP_SearchStrFound);
    /* see if we actually found a command and not a substring */
    if (cmd_found > 0)
    {
        const uint8_t* tmp = ptr;
        const uint8_t* cmd_start = ptr + pop_search_info.index;
        const uint8_t* cmd_end = cmd_start + pop_search_info.length;

        /* move past spaces up until start of command */
        while ((tmp < cmd_start) && isspace((int)*tmp))
            tmp++;

        /* if not all spaces before command, we found a
         * substring */
        if (tmp != cmd_start)
            cmd_found = 0;

        /* if we're before the end of line marker and the next
         * character is not whitespace, we found a substring */
        if ((cmd_end < eolm) && !isspace((int)*cmd_end))
            cmd_found = 0;

        /* there is a chance that end of command coincides with the end of data
         * in which case, it could be a substring, but for now, we will treat it as found */
    }

    /* if command not found, alert and move on */
    if (!cmd_found)
    {
        if (pop_ssn->state == STATE_UNKNOWN)
        {
            /* check for encrypted */
            if ((pop_ssn->session_flags & POP_FLAG_CHECK_SSL) &&
                (IsSSL(ptr, end - ptr, p->packet_flags)))
            {
                pop_ssn->state = STATE_TLS_DATA;

                /* Ignore data */
                return end;
            }
            else
            {
                /* don't check for ssl again in this packet */
                if (pop_ssn->session_flags & POP_FLAG_CHECK_SSL)
                    pop_ssn->session_flags &= ~POP_FLAG_CHECK_SSL;

                pop_ssn->state = STATE_DATA;
                //pop_ssn->data_state = STATE_DATA_UNKNOWN;

                return ptr;
            }
        }
        else
        {
            DetectionEngine::queue_event(GID_POP, POP_UNKNOWN_CMD);
            return eol;
        }
    }
    else if (pop_search_info.id == CMD_TOP)
    {
        pop_ssn->state = STATE_DATA;
    }
    else
    {
        if (pop_ssn->state == STATE_UNKNOWN)
            pop_ssn->state = STATE_COMMAND;
    }

    if (pop_search_info.id == CMD_STLS)
    {
        if (eol == end)
            pop_ssn->state = STATE_TLS_CLIENT_PEND;
    }

    return eol;
}

/*
 * Process client packet
 *
 * @param   packet  standard Packet structure
 *
 * @return  none
 */
static void POP_ProcessClientPacket(Packet* p, POPData* pop_ssn)
{
    const uint8_t* ptr = p->data;
    const uint8_t* end = p->data + p->dsize;

    POP_HandleCommand(p, pop_ssn, ptr, end);
}

/*
 * Process server packet
 *
 * @param   packet  standard Packet structure
 *
 */
static void POP_ProcessServerPacket(Packet* p, POPData* pop_ssn)
{
    int resp_found;
    const uint8_t* ptr;
    const uint8_t* end;
    const uint8_t* eolm;
    const uint8_t* eol;
    int resp_line_len;
    const char* tmp = nullptr;

    ptr = p->data;
    end = p->data + p->dsize;

    while (ptr < end)
    {
        if (pop_ssn->state == STATE_DATA)
        {
            //ptr = POP_HandleData(p, ptr, end);
            FilePosition position = get_file_position(p);
            int len = end - ptr;
            ptr = pop_ssn->mime_ssn->process_mime_data(p->flow, ptr, len, false, position);
            continue;
        }
        POP_GetEOL(ptr, end, &eol, &eolm);

        resp_line_len = eol - ptr;

        /* Check for response code */
        pop_current_search = &pop_resp_search[0];
        resp_found = pop_resp_search_mpse->find(
            (const char*)ptr, resp_line_len, POP_SearchStrFound);

        if (resp_found > 0)
        {
            const uint8_t* cmd_start = ptr + pop_search_info.index;
            switch (pop_search_info.id)
            {
            case RESP_OK:
                tmp = SnortStrcasestr((const char*)cmd_start, (eol - cmd_start), "octets");
                if (tmp != nullptr)
                    pop_ssn->state = STATE_DATA;
                else
                {
                    pop_ssn->prev_response = RESP_OK;
                    pop_ssn->state = STATE_UNKNOWN;
                }
                break;

            default:
                break;
            }
        }
        else
        {
            if ((pop_ssn->session_flags & POP_FLAG_CHECK_SSL) &&
                (IsSSL(ptr, end - ptr, p->packet_flags)))
            {
                pop_ssn->state = STATE_TLS_DATA;
                return;
            }
            else if (pop_ssn->session_flags & POP_FLAG_CHECK_SSL)
            {
                pop_ssn->session_flags &= ~POP_FLAG_CHECK_SSL;
            }
            if (pop_ssn->prev_response == RESP_OK)
            {
                {
                    pop_ssn->state = STATE_DATA;
                    pop_ssn->prev_response = 0;
                    continue;
                }
            }
            else if (*ptr == '+')
            {
                DetectionEngine::queue_event(GID_POP, POP_UNKNOWN_RESP);
            }
        }

        ptr = eol;
    }
}

/* Main runtime entry point for POP preprocessor.
 * Analyzes POP packets for anomalies/exploits.
 *
 * PARAMETERS:
 *
 * p:    Pointer to current packet to process.
 * contextp:    Pointer to context block, not used.
 *
 * RETURNS:     Nothing.
 */
static void snort_pop(POP_PROTO_CONF* config, Packet* p)
{
    /* Attempt to get a previously allocated POP block. */
    POPData* pop_ssn = get_session_data(p->flow);

    if (pop_ssn == nullptr)
    {
        /* Check the stream session. If it does not currently
         * have our POP data-block attached, create one.
         */
        pop_ssn = SetNewPOPData(config, p);

        if ( !pop_ssn )
        {
            /* Could not get/create the session data for this packet. */
            return;
        }
    }

    int pkt_dir = POP_Setup(p, pop_ssn);

    if (pkt_dir == POP_PKT_FROM_CLIENT)
    {
        /* This packet should be a tls client hello */
        if (pop_ssn->state == STATE_TLS_CLIENT_PEND)
        {
            if (IsTlsClientHello(p->data, p->data + p->dsize))
            {
                pop_ssn->state = STATE_TLS_SERVER_PEND;
                return;
            }
            else
            {
                /* reset state - server may have rejected STARTTLS command */
                pop_ssn->state = STATE_UNKNOWN;
            }
        }
        if ((pop_ssn->state == STATE_TLS_DATA)
            || (pop_ssn->state == STATE_TLS_SERVER_PEND))
        {
            return;
        }
        POP_ProcessClientPacket(p, pop_ssn);
    }
    else
    {
        if (pop_ssn->state == STATE_TLS_SERVER_PEND)
        {
            if (IsTlsServerHello(p->data, p->data + p->dsize))
            {
                pop_ssn->state = STATE_TLS_DATA;
            }
            else if ( !p->test_session_flags(SSNFLAG_MIDSTREAM)
                && !Stream::missed_packets(p->flow, SSN_DIR_BOTH))
            {
                /* revert back to command state - assume server didn't accept STARTTLS */
                pop_ssn->state = STATE_UNKNOWN;
            }
            else
                return;
        }

        if (pop_ssn->state == STATE_TLS_DATA)
        {
            return;
        }
        if ( !InspectPacket(p))
        {
            /* Packet will be rebuilt, so wait for it */
            return;
        }
        else if (!(p->packet_flags & PKT_REBUILT_STREAM))
        {
            /* If this isn't a reassembled packet and didn't get
             * inserted into reassembly buffer, there could be a
             * problem.  If we miss syn or syn-ack that had window
             * scaling this packet might not have gotten inserted
             * into reassembly buffer because it fell outside of
             * window, because we aren't scaling it */
            pop_ssn->session_flags |= POP_FLAG_GOT_NON_REBUILT;
            pop_ssn->state = STATE_UNKNOWN;
        }
        else if (pop_ssn->session_flags & POP_FLAG_GOT_NON_REBUILT)
        {
            /* This is a rebuilt packet.  If we got previous packets
             * that were not rebuilt, state is going to be messed up
             * so set state to unknown. It's likely this was the
             * beginning of the conversation so reset state */
            pop_ssn->state = STATE_UNKNOWN;
            pop_ssn->session_flags &= ~POP_FLAG_GOT_NON_REBUILT;
        }
        /* Process as a server packet */
        POP_ProcessServerPacket(p, pop_ssn);
    }
}

void PopMime::decode_alert()
{
    switch ( decode_state->get_decode_type() )
    {
    case DECODE_B64:
        DetectionEngine::queue_event(GID_POP, POP_B64_DECODING_FAILED);
        break;
    case DECODE_QP:
        DetectionEngine::queue_event(GID_POP, POP_QP_DECODING_FAILED);
        break;
    case DECODE_UU:
        DetectionEngine::queue_event(GID_POP, POP_UU_DECODING_FAILED);
        break;

    default:
        break;
    }
}

void PopMime::reset_state(Flow* ssn)
{
    POP_ResetState(ssn);
}


bool PopMime::is_end_of_data(Flow* session)
{
    return pop_is_data_end(session);
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Pop : public Inspector
{
public:
    Pop(POP_PROTO_CONF*);
    ~Pop() override;

    bool configure(SnortConfig*) override;
    void show(SnortConfig*) override;
    void eval(Packet*) override;

    StreamSplitter* get_splitter(bool c2s) override
    { return new PopSplitter(c2s); }

private:
    POP_PROTO_CONF* config;
};

Pop::Pop(POP_PROTO_CONF* pc)
{
    config = pc;
}

Pop::~Pop()
{
    if ( config )
        delete config;
}

bool Pop::configure(SnortConfig* )
{
    config->decode_conf.sync_all_depths();

    if (config->decode_conf.get_file_depth() > -1)
        config->log_config.log_filename = 1;

    POP_SearchInit();
    return true;
}

void Pop::show(SnortConfig*)
{
    PrintPopConf(config);
}

void Pop::eval(Packet* p)
{
    Profile profile(popPerfStats);

    // precondition - what we registered for
    assert(p->has_tcp_data());
    assert(p->flow);

    ++popstats.packets;

    snort_pop(config, p);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new PopModule; }

static void mod_dtor(Module* m)
{ delete m; }

static void pop_init()
{
    PopFlowData::init();
}

static void pop_term()
{
    POP_SearchFree();
}

static Inspector* pop_ctor(Module* m)
{
    PopModule* mod = (PopModule*)m;
    return new Pop(mod->get_data());
}

static void pop_dtor(Inspector* p)
{
    delete p;
}

const InspectApi pop_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        POP_NAME,
        POP_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__PDU,
    nullptr, // buffers
    "pop3",
    pop_init,
    pop_term, // pterm
    nullptr, // tinit
    nullptr, // tterm
    pop_ctor,
    pop_dtor,
    nullptr, // ssn
    nullptr  // reset
};

#undef BUILDING_SO  // FIXIT-L can't be linked dynamically yet

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &pop_api.base,
    nullptr
};
#else
const BaseApi* sin_pop = &pop_api.base;
#endif


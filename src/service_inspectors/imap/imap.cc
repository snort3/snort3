//--------------------------------------------------------------------------
// Copyright (C) 2015-2024 Cisco and/or its affiliates. All rights reserved.
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

// imap.cc author Bhagyashree Bantwal <bbantwal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "imap.h"

#include "detection/detection_engine.h"
#include "js_norm/js_pdf_norm.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "protocols/ssl.h"
#include "pub_sub/opportunistic_tls_event.h"
#include "search_engines/search_tool.h"
#include "stream/stream.h"
#include "utils/util_cstring.h"

#include "imap_module.h"
#include "imap_paf.h"

using namespace snort;

// Indices in the buffer array exposed by InspectApi
// Must remain synchronized with imap_bufs
enum ImapBufId
{
    IMAP_FILE_DATA_ID = 1, IMAP_VBA_DATA_ID, IMAP_JS_DATA_ID
};

THREAD_LOCAL ProfileStats imapPerfStats;
THREAD_LOCAL ImapStats imapstats;

IMAPToken imap_known_cmds[] =
{
    { "APPEND",          6, CMD_APPEND },
    { "AUTHENTICATE",    12, CMD_AUTHENTICATE },
    { "CAPABILITY",      10, CMD_CAPABILITY },
    { "CHECK",           5, CMD_CHECK },
    { "CLOSE",           5, CMD_CLOSE },
    { "COMPARATOR",      10, CMD_COMPARATOR },
    { "COMPRESS",        8, CMD_COMPRESS },
    { "CONVERSIONS",     11, CMD_CONVERSIONS },
    { "COPY",            4, CMD_COPY },
    { "CREATE",          6, CMD_CREATE },
    { "DELETE",          6, CMD_DELETE },
    { "DELETEACL",       9, CMD_DELETEACL },
    { "DONE",            4, CMD_DONE },
    { "EXAMINE",         7, CMD_EXAMINE },
    { "EXPUNGE",         7, CMD_EXPUNGE },
    { "FETCH",           5, CMD_FETCH },
    { "GETACL",          6, CMD_GETACL },
    { "GETMETADATA",     11, CMD_GETMETADATA },
    { "GETQUOTA",        8, CMD_GETQUOTA },
    { "GETQUOTAROOT",    12, CMD_GETQUOTAROOT },
    { "IDLE",            4, CMD_IDLE },
    { "LIST",            4, CMD_LIST },
    { "LISTRIGHTS",      10, CMD_LISTRIGHTS },
    { "LOGIN",           5, CMD_LOGIN },
    { "LOGOUT",          6, CMD_LOGOUT },
    { "LSUB",            4, CMD_LSUB },
    { "MYRIGHTS",        8, CMD_MYRIGHTS },
    { "NOOP",            4, CMD_NOOP },
    { "NOTIFY",          6, CMD_NOTIFY },
    { "RENAME",          6, CMD_RENAME },
    { "SEARCH",          6, CMD_SEARCH },
    { "SELECT",          6, CMD_SELECT },
    { "SETACL",          6, CMD_SETACL },
    { "SETMETADATA",     11, CMD_SETMETADATA },
    { "SETQUOTA",        8, CMD_SETQUOTA },
    { "SORT",            4, CMD_SORT },
    { "STARTTLS",        8, CMD_STARTTLS },
    { "STATUS",          6, CMD_STATUS },
    { "STORE",           5, CMD_STORE },
    { "SUBSCRIBE",       9, CMD_SUBSCRIBE },
    { "THREAD",          6, CMD_THREAD },
    { "UID",             3, CMD_UID },
    { "UNSELECT",        8, CMD_UNSELECT },
    { "UNSUBSCRIBE",     11, CMD_UNSUBSCRIBE },
    { "X",               1, CMD_X },
    { nullptr,              0, 0 }
};

IMAPToken imap_resps[] =
{
    { "CAPABILITY",      10, RESP_CAPABILITY },
    { "LIST",            4, RESP_LIST },
    { "LSUB",            4, RESP_LSUB },
    { "STATUS",          6, RESP_STATUS },
    { "SEARCH",          6, RESP_SEARCH },
    { "FLAGS",           5, RESP_FLAGS },
    { "EXISTS",          6, RESP_EXISTS },
    { "RECENT",          6, RESP_RECENT },
    { "EXPUNGE",         7, RESP_EXPUNGE },
    { "FETCH",           5, RESP_FETCH },
    { "BAD",             3, RESP_BAD },
    { "BYE",             3, RESP_BYE },
    { "NO",              2, RESP_NO },
    { "OK",              2, RESP_OK },
    { "PREAUTH",         7, RESP_PREAUTH },
    { "ENVELOPE",        8, RESP_ENVELOPE },
    { "UID",             3, RESP_UID },
    { nullptr,   0,  0 }
};

SearchTool* imap_resp_search_mpse = nullptr;
SearchTool* imap_cmd_search_mpse = nullptr;

IMAPSearch imap_resp_search[RESP_LAST];
IMAPSearch imap_cmd_search[CMD_LAST];

static THREAD_LOCAL const IMAPSearch* imap_current_search = nullptr;
static THREAD_LOCAL IMAPSearchInfo imap_search_info;

const PegInfo imap_peg_names[] =
{
    { CountType::SUM, "packets", "total packets processed" },
    { CountType::SUM, "sessions", "total imap sessions" },
    { CountType::NOW, "concurrent_sessions", "total concurrent imap sessions" },
    { CountType::MAX, "max_concurrent_sessions", "maximum concurrent imap sessions" },
    { CountType::SUM, "start_tls", "total STARTTLS events generated" },
    { CountType::SUM, "ssl_search_abandoned", "total SSL search abandoned" },
    { CountType::SUM, "ssl_srch_abandoned_early", "total SSL search abandoned too soon" },
    { CountType::SUM, "b64_attachments", "total base64 attachments decoded" },
    { CountType::SUM, "b64_decoded_bytes", "total base64 decoded bytes" },
    { CountType::SUM, "qp_attachments", "total quoted-printable attachments decoded" },
    { CountType::SUM, "qp_decoded_bytes", "total quoted-printable decoded bytes" },
    { CountType::SUM, "uu_attachments", "total uu attachments decoded" },
    { CountType::SUM, "uu_decoded_bytes", "total uu decoded bytes" },
    { CountType::SUM, "non_encoded_attachments", "total non-encoded attachments extracted" },
    { CountType::SUM, "non_encoded_bytes", "total non-encoded extracted bytes" },
    { CountType::SUM, "js_pdf_scripts", "total number of PDF files processed" },

    { CountType::END, nullptr, nullptr }
};

ImapFlowData::ImapFlowData() : FlowData(inspector_id)
{
    memset(&session, 0, sizeof(session));
    imapstats.concurrent_sessions++;
    if(imapstats.max_concurrent_sessions < imapstats.concurrent_sessions)
        imapstats.max_concurrent_sessions = imapstats.concurrent_sessions;
}

ImapFlowData::~ImapFlowData()
{
    delete session.mime_ssn;
    delete session.jsn;

    assert(imapstats.concurrent_sessions > 0);
    imapstats.concurrent_sessions--;
}

unsigned ImapFlowData::inspector_id = 0;

static IMAPData* get_session_data(Flow* flow)
{
    ImapFlowData* fd = (ImapFlowData*)flow->get_flow_data(ImapFlowData::inspector_id);
    return fd ? &fd->session : nullptr;
}

static inline PDFJSNorm* acquire_js_ctx(IMAPData& imap_ssn, const void* data, size_t len)
{
    auto reload_id = SnortConfig::get_conf()->get_reload_id();

    if (imap_ssn.jsn and imap_ssn.jsn->get_generation_id() == reload_id)
        return imap_ssn.jsn;

    delete imap_ssn.jsn;
    imap_ssn.jsn = nullptr;

    JSNormConfig* cfg = get_inspection_policy()->jsn_config;
    if (cfg and PDFJSNorm::is_pdf(data, len))
    {
        imap_ssn.jsn = new PDFJSNorm(cfg, reload_id);
        ++imapstats.js_pdf_scripts;
    }

    return imap_ssn.jsn;
}

static IMAPData* SetNewIMAPData(IMAP_PROTO_CONF* config, Packet* p)
{
    IMAPData* imap_ssn;
    ImapFlowData* fd = new ImapFlowData;

    p->flow->set_flow_data(fd);
    imap_ssn = &fd->session;

    imapstats.sessions++;
    imap_ssn->mime_ssn= new ImapMime(p, &(config->decode_conf), &(config->log_config));
    imap_ssn->mime_ssn->set_mime_stats(&(imapstats.mime_stats));

    if (p->packet_flags & SSNFLAG_MIDSTREAM)
        imap_ssn->state = STATE_UNKNOWN;

    imap_ssn->body_read = imap_ssn->body_len = 0;

    return imap_ssn;
}

static void IMAP_SearchInit()
{
    const IMAPToken* tmp;
    if ( imap_cmd_search_mpse )
        return;
    imap_cmd_search_mpse = new SearchTool;

    for (tmp = &imap_known_cmds[0]; tmp->name != nullptr; tmp++)
    {
        imap_cmd_search[tmp->search_id].name = tmp->name;
        imap_cmd_search[tmp->search_id].name_len = tmp->name_len;
        imap_cmd_search_mpse->add(tmp->name, tmp->name_len, tmp->search_id);
    }
    imap_cmd_search_mpse->prep();
    imap_resp_search_mpse = new SearchTool;

    for (tmp = &imap_resps[0]; tmp->name != nullptr; tmp++)
    {
        imap_resp_search[tmp->search_id].name = tmp->name;
        imap_resp_search[tmp->search_id].name_len = tmp->name_len;
        imap_resp_search_mpse->add(tmp->name, tmp->name_len, tmp->search_id);
    }
    imap_resp_search_mpse->prep();
}

static void IMAP_SearchFree()
{
    if (imap_cmd_search_mpse != nullptr)
        delete imap_cmd_search_mpse;

    if (imap_resp_search_mpse != nullptr)
        delete imap_resp_search_mpse;
}

static void IMAP_ResetState(Flow* ssn)
{
    IMAPData* imap_ssn = get_session_data(ssn);
    imap_ssn->state = STATE_COMMAND;
    imap_ssn->state_flags = 0;
    imap_ssn->body_read = imap_ssn->body_len = 0;

    delete imap_ssn->jsn;
    imap_ssn->jsn = nullptr;
}

static void IMAP_GetEOL(const uint8_t* ptr, const uint8_t* end,
    const uint8_t** eol, const uint8_t** eolm)
{
    assert(ptr and end and eol and eolm);

    const uint8_t* tmp_eol;
    const uint8_t* tmp_eolm;

    tmp_eol = (const uint8_t*)memchr(ptr, '\n', end - ptr);
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

static inline int InspectPacket(Packet* p)
{
    return p->has_paf_payload();
}

static int IMAP_Setup(Packet* p, IMAPData* ssn)
{
    int pkt_dir;

    /* Get the direction of the packet. */
    if ( p->is_from_server() )
        pkt_dir = IMAP_PKT_FROM_SERVER;
    else
        pkt_dir = IMAP_PKT_FROM_CLIENT;

    if (!(ssn->session_flags & IMAP_FLAG_CHECK_SSL))
        ssn->session_flags |= IMAP_FLAG_CHECK_SSL;
    /* Check to see if there is a reassembly gap.  If so, we won't know
     *      * what state we're in when we get the _next_ reassembled packet */
    if ((pkt_dir != IMAP_PKT_FROM_SERVER) &&
        (p->packet_flags & PKT_REBUILT_STREAM))
    {
        int missing_in_rebuilt =
            Stream::missing_in_reassembled(p->flow, SSN_DIR_FROM_CLIENT);

        if (ssn->session_flags & IMAP_FLAG_NEXT_STATE_UNKNOWN)
        {
            ssn->state = STATE_UNKNOWN;
            ssn->session_flags &= ~IMAP_FLAG_NEXT_STATE_UNKNOWN;
        }

        if (missing_in_rebuilt == SSN_MISSING_BEFORE)
        {
            ssn->state = STATE_UNKNOWN;
        }
    }

    return pkt_dir;
}

static int IMAP_SearchStrFound(void* id, void* , int index, void* , void* )
{
    int search_id = (int)(uintptr_t)id;

    imap_search_info.id = search_id;
    imap_search_info.length = imap_current_search[search_id].name_len;
    imap_search_info.index = index - imap_search_info.length;

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
static const uint8_t* IMAP_HandleCommand(Packet* p, IMAPData* imap_ssn, const uint8_t* ptr, const
    uint8_t* end)
{
    const uint8_t* eol;   /* end of line */
    const uint8_t* eolm;  /* end of line marker */
    int cmd_found;

    /* get end of line and end of line marker */
    IMAP_GetEOL(ptr, end, &eol, &eolm);

    /* FIXIT-M If the end of line marker coincides with the end of data we can't be
     * sure that we got a command and not a substring which we could tell through
     * inspection of the next packet. Maybe a command pending state where the first
     * char in the next packet is checked for a space and end of line marker */

    /* do not confine since there could be space chars before command */
    imap_current_search = &imap_cmd_search[0];
    cmd_found = imap_cmd_search_mpse->find(
        (const char*)ptr, eolm - ptr, IMAP_SearchStrFound);

    /* if command not found, alert and move on */
    if (!cmd_found)
    {
        if (imap_ssn->state == STATE_UNKNOWN)
        {
            /* check for encrypted */

            if ((imap_ssn->session_flags & IMAP_FLAG_CHECK_SSL) &&
                (IsSSL(ptr, end - ptr, p->packet_flags)))
            {
                imap_ssn->state = STATE_TLS_DATA;

                /* Ignore data */
                return end;
            }
            else
            {
                /* don't check for ssl again in this packet */
                if (imap_ssn->session_flags & IMAP_FLAG_CHECK_SSL)
                    imap_ssn->session_flags &= ~IMAP_FLAG_CHECK_SSL;

                imap_ssn->state = STATE_DATA;
                //imap_ssn->data_state = STATE_DATA_UNKNOWN;

                return ptr;
            }
        }
        else
        {
            DetectionEngine::queue_event(GID_IMAP, IMAP_UNKNOWN_CMD);
            return eol;
        }
    }
    else
    {
        if (imap_ssn->state == STATE_UNKNOWN)
            imap_ssn->state = STATE_COMMAND;
    }

    if (imap_search_info.id == CMD_STARTTLS)
    {
        if (eol == end)
            imap_ssn->state = STATE_TLS_CLIENT_PEND;
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
static void IMAP_ProcessClientPacket(Packet* p, IMAPData* imap_ssn)
{
    const uint8_t* ptr = p->data;
    const uint8_t* end = p->data + p->dsize;

    IMAP_HandleCommand(p, imap_ssn, ptr, end);
}

/*
 * Process server packet
 *
 * @param   packet  standard Packet structure
 *
 */
static void IMAP_ProcessServerPacket(Packet* p, IMAPData* imap_ssn)
{
    int resp_found;
    const uint8_t *ptr;
    const uint8_t *end;
    const uint8_t *data_end;
    const uint8_t *eolm;
    const uint8_t *eol;
    int resp_line_len;
    const char *tmp = nullptr;
    const uint8_t *body_start = nullptr;
    char *eptr;

    ptr = p->data;
    end = p->data + p->dsize;

    while (ptr < end)
    {
        if (imap_ssn->state == STATE_DATA)
        {
            if (imap_ssn->body_len > imap_ssn->body_read)
            {
                int len = imap_ssn->body_len - imap_ssn->body_read;

                if ((end - ptr) < len)
                {
                    data_end = end;
                    len = data_end - ptr;
                }
                else
                    data_end = ptr + len;

                FilePosition position = get_file_position(p);
                int data_len = end - ptr;

                if (isFileStart(position))
                {
                    delete imap_ssn->jsn;
                    imap_ssn->jsn = nullptr;
                }

                ptr = imap_ssn->mime_ssn->process_mime_data(p, ptr, data_len, false, position);
                if (imap_ssn->jsn)
                    imap_ssn->jsn->tick();
                if (ptr < data_end)
                    len = len - (data_end - ptr);

                imap_ssn->body_read += len;

                continue;
            }
            else
            {
                imap_ssn->body_len = imap_ssn->body_read = 0;
                IMAP_ResetState(p->flow);
            }
        }
        IMAP_GetEOL(ptr, end, &eol, &eolm);

        resp_line_len = eol - ptr;

        /* Check for response code */
        imap_current_search = &imap_resp_search[0];
        resp_found = imap_resp_search_mpse->find(
            (const char*)ptr, resp_line_len, IMAP_SearchStrFound);

        if (resp_found > 0)
        {
            const uint8_t* cmd_start = ptr + imap_search_info.index;
            switch (imap_search_info.id)
            {
            case RESP_FETCH:
                imap_ssn->body_len = imap_ssn->body_read = 0;
                if (!(imap_ssn->session_flags & IMAP_FLAG_ABANDON_EVT)
                    and !p->flow->flags.data_decrypted)
                {
                    imap_ssn->session_flags |= IMAP_FLAG_ABANDON_EVT;
                    DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::SSL_SEARCH_ABANDONED, p);
                    imapstats.ssl_search_abandoned++;
                }
                imap_ssn->state = STATE_DATA;
                tmp = SnortStrcasestr((const char*)cmd_start, (eol - cmd_start), "BODY");
                if (tmp != nullptr)
                    imap_ssn->state = STATE_DATA;
                else
                {
                    tmp = SnortStrcasestr((const char*)cmd_start, (eol - cmd_start), "RFC822");
                    if (tmp != nullptr)
                        imap_ssn->state = STATE_DATA;
                    else
                        imap_ssn->state = STATE_UNKNOWN;
                }
                break;
            case RESP_OK:
                if (imap_ssn->state == STATE_TLS_CLIENT_PEND)
                {
                    if ((imap_ssn->session_flags & IMAP_FLAG_ABANDON_EVT)
                        and !p->flow->flags.data_decrypted)
                    {
                        imapstats.ssl_srch_abandoned_early++;
                    }

                    OpportunisticTlsEvent event(p, p->flow->service);
                    DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::OPPORTUNISTIC_TLS, event, p->flow);
                    imapstats.start_tls++;
                    imap_ssn->state = STATE_DECRYPTION_REQ;
                }
            default:
                break;
            }
            if (imap_ssn->state == STATE_DATA)
            {
                body_start = (const uint8_t*)memchr((const char*)ptr, '{', (eol - ptr));
                if (body_start == nullptr)
                {
                    imap_ssn->state = STATE_UNKNOWN;
                }
                else
                {
                    if ((body_start + 1) < eol)
                    {
                        uint32_t len =
                            (uint32_t)SnortStrtoul((const char*)(body_start + 1), &eptr, 10);

                        if (*eptr != '}')
                        {
                            imap_ssn->state = STATE_UNKNOWN;
                        }
                        else
                            imap_ssn->body_len = len;
                    }
                    else
                        imap_ssn->state = STATE_UNKNOWN;
                }
            }
        }
        else
        {
            if ((imap_ssn->session_flags & IMAP_FLAG_CHECK_SSL) &&
                (IsSSL(ptr, end - ptr, p->packet_flags)))
            {
                imap_ssn->state = STATE_TLS_DATA;
                return;
            }
            else if (imap_ssn->session_flags & IMAP_FLAG_CHECK_SSL)
            {
                imap_ssn->session_flags &= ~IMAP_FLAG_CHECK_SSL;
            }
            if ((*ptr != '*') && (*ptr != '+') && (*ptr != '\r') && (*ptr != '\n'))
            {
                DetectionEngine::queue_event(GID_IMAP, IMAP_UNKNOWN_RESP);
            }
        }

        ptr = eol;
    }
}

// Analyzes IMAP packets for anomalies/exploits.

static void snort_imap(IMAP_PROTO_CONF* config, Packet* p)
{
    /* Attempt to get a previously allocated IMAP block. */
    IMAPData* imap_ssn = get_session_data(p->flow);

    if (imap_ssn == nullptr)
    {
        /* Check the stream session. If it does not currently
         * have our IMAP data-block attached, create one.
         */
        imap_ssn = SetNewIMAPData(config, p);

        if ( !imap_ssn )
        {
            /* Could not get/create the session data for this packet. */
            return;
        }
    }

    int pkt_dir = IMAP_Setup(p, imap_ssn);

    if (imap_ssn->jsn)
        imap_ssn->jsn->flush_data();

    if (pkt_dir == IMAP_PKT_FROM_CLIENT)
    {
        /* This packet should be a tls client hello */
        if ((imap_ssn->state == STATE_TLS_CLIENT_PEND)
            || (imap_ssn->state == STATE_DECRYPTION_REQ))
        {
            if (IsTlsClientHello(p->data, p->data + p->dsize))
            {
                imap_ssn->state = STATE_TLS_SERVER_PEND;
                return;
            }
            else
            {
                /* reset state - server may have rejected STARTTLS command */
                imap_ssn->state = STATE_UNKNOWN;
            }
        }
        if ((imap_ssn->state == STATE_TLS_DATA)
            || (imap_ssn->state == STATE_TLS_SERVER_PEND))
        {
            return;
        }
        IMAP_ProcessClientPacket(p, imap_ssn);
    }
    else
    {
        if (imap_ssn->state == STATE_TLS_SERVER_PEND)
        {
            if (IsTlsServerHello(p->data, p->data + p->dsize))
            {
                imap_ssn->state = STATE_TLS_DATA;
            }
            else if ( !p->test_session_flags(SSNFLAG_MIDSTREAM)
                && !Stream::missed_packets(p->flow, SSN_DIR_BOTH))
            {
                /* revert back to command state - assume server didn't accept STARTTLS */
                imap_ssn->state = STATE_UNKNOWN;
            }
            else
                return;
        }

        if (imap_ssn->state == STATE_TLS_DATA)
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
            imap_ssn->session_flags |= IMAP_FLAG_GOT_NON_REBUILT;
            imap_ssn->state = STATE_UNKNOWN;
        }
        else if (imap_ssn->session_flags & IMAP_FLAG_GOT_NON_REBUILT)
        {
            /* This is a rebuilt packet.  If we got previous packets
             * that were not rebuilt, state is going to be messed up
             * so set state to unknown. It's likely this was the
             * beginning of the conversation so reset state */
            imap_ssn->state = STATE_UNKNOWN;
            imap_ssn->session_flags &= ~IMAP_FLAG_GOT_NON_REBUILT;
        }
        /* Process as a server packet */
        IMAP_ProcessServerPacket(p, imap_ssn);
    }
}

void ImapMime::decode_alert()
{
    switch ( decode_state->get_decode_type() )
    {
    case DECODE_B64:
        DetectionEngine::queue_event(GID_IMAP, IMAP_B64_DECODING_FAILED);
        break;
    case DECODE_QP:
        DetectionEngine::queue_event(GID_IMAP, IMAP_QP_DECODING_FAILED);
        break;
    case DECODE_UU:
        DetectionEngine::queue_event(GID_IMAP, IMAP_UU_DECODING_FAILED);
        break;

    default:
        break;
    }
}

void ImapMime::decompress_alert()
{
    DetectionEngine::queue_event(GID_IMAP, IMAP_FILE_DECOMP_FAILED);
}

void ImapMime::reset_state(Flow* ssn)
{
    IMAP_ResetState(ssn);
}


bool ImapMime::is_end_of_data(Flow* session)
{
    return imap_is_data_end(session);
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Imap : public Inspector
{
public:
    Imap(IMAP_PROTO_CONF*);
    ~Imap() override;

    bool configure(SnortConfig*) override;
    void show(const SnortConfig*) const override;
    void eval(Packet*) override;

    StreamSplitter* get_splitter(bool c2s) override
    { return new ImapSplitter(c2s); }

    bool can_carve_files() const override
    { return true; }

    bool can_start_tls() const override
    { return true; }

    bool get_buf(InspectionBuffer::Type, Packet*, InspectionBuffer&) override;
    bool get_fp_buf(snort::InspectionBuffer::Type ibt, snort::Packet* p,
        snort::InspectionBuffer& b) override;
    bool get_buf(unsigned id, snort::Packet* p, snort::InspectionBuffer& b) override;

private:
    IMAP_PROTO_CONF* config;
};

Imap::Imap(IMAP_PROTO_CONF* pc)
{
    config = pc;
}

Imap::~Imap()
{
    if ( config )
        delete config;
}

bool Imap::configure(SnortConfig* sc)
{
    config->decode_conf.sync_all_depths(sc);

    if (config->decode_conf.get_file_depth() > -1)
        config->log_config.log_filename = true;

    IMAP_SearchInit();
    return true;
}

void Imap::show(const SnortConfig*) const
{
    if ( config )
        config->decode_conf.show();
}

void Imap::eval(Packet* p)
{
    // cppcheck-suppress unreadVariable
    Profile profile(imapPerfStats);

    // precondition - what we registered for
    assert(p->has_tcp_data());
    assert(p->flow);

    ++imapstats.packets;

    snort_imap(config, p);
}

bool Imap::get_buf(InspectionBuffer::Type ibt, Packet* p, InspectionBuffer& b)
{
    IMAPData* imap_ssn = get_session_data(p->flow);

    if (!imap_ssn)
        return false;

    const void* dst = nullptr;
    size_t dst_len = 0;

    switch (ibt)
    {
    case InspectionBuffer::IBT_VBA:
    {
        const BufferData& vba_buf = imap_ssn->mime_ssn->get_vba_inspect_buf();
        dst = vba_buf.data_ptr();
        dst_len = vba_buf.length();
        break;
    }

    case InspectionBuffer::IBT_JS_DATA:
    {
        auto& dp = DetectionEngine::get_file_data(p->context);
        auto jsn = acquire_js_ctx(*imap_ssn, dp.data, dp.len);
        if (jsn)
        {
            jsn->get_data(dst, dst_len);
            if (dst and dst_len)
                break;
            jsn->normalize(dp.data, dp.len, dst, dst_len);
        }
        break;
    }

    default:
        return false;
    }

    b.data = (const uint8_t*)dst;
    b.len = dst_len;

    return dst && dst_len;
}

bool Imap::get_fp_buf(InspectionBuffer::Type ibt, Packet* p, InspectionBuffer& b)
{
    // Fast pattern buffers only supplied at specific times
    return get_buf(ibt, p, b);
}

bool Imap::get_buf(unsigned id, snort::Packet* p, snort::InspectionBuffer& b)
{
    switch (id)
    {
    case IMAP_FILE_DATA_ID:
        return false;
    case IMAP_VBA_DATA_ID:
        return get_buf(InspectionBuffer::IBT_VBA, p, b);
    case IMAP_JS_DATA_ID:
        return get_buf(InspectionBuffer::IBT_JS_DATA, p, b);
    default:
        return false;
    }
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new ImapModule; }

static void mod_dtor(Module* m)
{ delete m; }

static void imap_init()
{
    ImapFlowData::init();
}

static void imap_term()
{
    IMAP_SearchFree();
}

static Inspector* imap_ctor(Module* m)
{
    ImapModule* mod = (ImapModule*)m;
    return new Imap(mod->get_data());
}

static void imap_dtor(Inspector* p)
{
    delete p;
}

static const char* imap_bufs[] =
{
    "file_data",
    "vba_data",
    "js_data",
    nullptr
};

const InspectApi imap_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        IMAP_NAME,
        IMAP_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__PDU,
    imap_bufs,
    "imap",
    imap_init,
    imap_term, // pterm
    nullptr, // tinit
    nullptr, // tterm
    imap_ctor,
    imap_dtor,
    nullptr, // ssn
    nullptr  // reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &imap_api.base,
    nullptr
};
#else
const BaseApi* sin_imap = &imap_api.base;
#endif

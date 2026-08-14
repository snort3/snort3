//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

/* rpc_decode
 *
 * Purpose:
 *
 * This inspector normalizes the RPC requests from remote machines by
 * converting all fragments into one continuous stream.
 * This is very useful for doing things like defeating hostile attackers
 * trying to stealth themselves from IDSs by fragmenting the request so the
 * string 0186A0 is broken up.
 *
 * Effect:
 *
 * Changes the data in the packet payload and changes
 * p->dsize to reflect the new (smaller) payload size.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstring>

#include "detection/detection_buf.h"
#include "detection/detection_engine.h"
#include "framework/data_bus.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "pub_sub/intrinsic_event_ids.h"
#include "stream/stream.h"
#include "stream/stream_splitter.h"
#include "utils/safec.h"
#include "utils/util.h"

#include "rpc_module.h"

using namespace snort;
using namespace std;

#define RPC_FRAG_HDR_SIZE  sizeof(uint32_t)
#define MAX_INSPECT_DEPTH  16384
#define NODE_SIZE  80
// Minimum new body bytes between partial alt-buffer serializations.
#define RPC_PARTIAL_FLUSH_QUANTUM  256

static_assert(MAX_INSPECT_DEPTH <= DataBuffer::decode_blen,
    "MAX_INSPECT_DEPTH must fit in the alt decode buffer");

static uint32_t rpc_frag_len(const uint8_t* data)
{
    uint32_t value;
    std::memcpy(&value, data, sizeof(value));
    return ntohl(value) & 0x7FFFFFFF;
}

struct RpcChunkNode
{
    uint8_t* data;
    uint32_t len;
    uint32_t allocated;
    RpcChunkNode* next;
};

struct RpcSsnData
{
    int active;
    int events;
    uint32_t cur_frag_len;
    uint32_t cur_frag_received;
    RpcChunkNode* chunks_head;
    RpcChunkNode* chunks_tail;
    uint32_t body_buffered;
    uint32_t partial_serialized;
    bool skip_record;
    bool has_non_last_frag;
    bool record_complete;
    uint8_t hdr_buf[RPC_FRAG_HDR_SIZE];
    uint8_t hdr_bytes_buffered;
};

class RpcFlowData : public FlowData
{
public:
    RpcFlowData();
    ~RpcFlowData() override;

    static void init()
    { inspector_id = FlowData::create_flow_data_id(); }

public:
    static unsigned inspector_id;
    RpcSsnData session;
};

unsigned RpcFlowData::inspector_id = 0;

typedef enum _RpcStatus
{
    RPC_STATUS__SUCCESS,
    RPC_STATUS__ERROR,
    RPC_STATUS__DEFRAG
} RpcStatus;

struct RpcStats
{
    PegCount total_packets;
    PegCount concurrent_sessions;
    PegCount max_concurrent_sessions;
    PegCount oversized_records;
    PegCount partial_flushes;
};

#define mod_name "rpc_decode"
#define mod_help "RPC inspector"

THREAD_LOCAL ProfileStats rpcdecodePerfStats;
THREAD_LOCAL RpcStats rdstats;

static int ConvertRPC(RpcSsnData*, Packet*);

static RpcSsnData* RpcSsnDataNew(Packet*);
static inline void RpcSsnClean(RpcSsnData*);
static inline void RpcSsnSetInactive(RpcSsnData*, Packet*);
static inline int RpcSsnIsActive(const RpcSsnData*);

static RpcStatus RpcStatefulInspection(RpcSsnData*, Packet*);
static inline void RpcPreprocEvent(RpcSsnData*, int);
static RpcStatus RpcChunkAppend(RpcSsnData*, const uint8_t*, uint32_t);
static void RpcChunksClear(RpcSsnData*);
static RpcStatus RpcFlushToAlt(RpcSsnData*, Packet*);
static RpcStatus RpcPrepPartial(RpcSsnData*, Packet*);
static RpcStatus RpcPrepRaw(const uint8_t*, uint32_t, Packet*);

static inline void RpcPreprocEvent(RpcSsnData* rsdata, int event)
{
    if (rsdata != nullptr)
    {
        /* Only log one event of the same type per session */
        if (rsdata->events & (1 << event))
            return;

        rsdata->events |= (1 << event);
    }

    switch (event)
    {
    case RPC_FRAG_TRAFFIC:
        DetectionEngine::queue_event(GID_RPC_DECODE, RPC_FRAG_TRAFFIC);
        break;

    case RPC_MULTIPLE_RECORD:
        DetectionEngine::queue_event(GID_RPC_DECODE, RPC_MULTIPLE_RECORD);
        break;

    case RPC_LARGE_FRAGSIZE:
        DetectionEngine::queue_event(GID_RPC_DECODE, RPC_LARGE_FRAGSIZE);
        break;

    case RPC_INCOMPLETE_SEGMENT:
        DetectionEngine::queue_event(GID_RPC_DECODE, RPC_INCOMPLETE_SEGMENT);
        break;

    case RPC_ZERO_LENGTH_FRAGMENT:
        DetectionEngine::queue_event(GID_RPC_DECODE, RPC_ZERO_LENGTH_FRAGMENT);
        break;

    case RPC_INSPECT_DEPTH_EXCEEDED:
        DetectionEngine::queue_event(GID_RPC_DECODE, RPC_INSPECT_DEPTH_EXCEEDED);
        break;

    default:
        break;
    }
}

// Publish a synchronous ALT_PACKET pass for a reassembled record.
static void RpcPublishAltPacket(Packet* p, const uint8_t* record, uint32_t record_len)
{
    if (!record || record_len <= RPC_FRAG_HDR_SIZE || record_len > Packet::max_dsize)
        return;

    const uint8_t* saved_data = p->data;
    const uint16_t saved_dsize = p->dsize;

    p->data = record;
    p->dsize = (uint16_t)record_len;

    DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::ALT_PACKET, p);

    p->data = saved_data;
    p->dsize = saved_dsize;
}

static RpcStatus RpcChunkAppend(RpcSsnData* rsdata, const uint8_t* data, uint32_t dsize)
{
    if (rsdata->body_buffered >= (MAX_INSPECT_DEPTH - RPC_FRAG_HDR_SIZE))
        return RPC_STATUS__SUCCESS;

    while (dsize > 0)
    {
        uint32_t remaining_budget = (MAX_INSPECT_DEPTH - RPC_FRAG_HDR_SIZE) - rsdata->body_buffered;
        if (remaining_budget == 0)
            break;

        assert(dsize <= remaining_budget);
        if (dsize > remaining_budget)
            dsize = remaining_budget;

        if (rsdata->chunks_tail != nullptr && rsdata->chunks_tail->len < rsdata->chunks_tail->allocated)
        {
            RpcChunkNode* node = rsdata->chunks_tail;
            uint32_t avail = node->allocated - node->len;
            uint32_t to_copy = dsize < avail ? dsize : avail;

            memcpy_s(node->data + node->len, avail, data, to_copy);
            node->len += to_copy;
            rsdata->body_buffered += to_copy;
            data += to_copy;
            dsize -= to_copy;
        }
        else
        {
            uint32_t alloc_size = dsize > NODE_SIZE ? dsize : NODE_SIZE;
            if (alloc_size > remaining_budget)
                alloc_size = remaining_budget;

            RpcChunkNode* node = (RpcChunkNode*)snort_calloc(sizeof(RpcChunkNode));
            node->data = (uint8_t*)snort_calloc(alloc_size);
            node->allocated = alloc_size;
            node->next = nullptr;

            if (rsdata->chunks_tail != nullptr)
                rsdata->chunks_tail->next = node;
            else
                rsdata->chunks_head = node;

            rsdata->chunks_tail = node;

            uint32_t to_copy = dsize < alloc_size ? dsize : alloc_size;
            memcpy_s(node->data, alloc_size, data, to_copy);
            node->len = to_copy;
            rsdata->body_buffered += to_copy;
            data += to_copy;
            dsize -= to_copy;
        }
    }

    return RPC_STATUS__SUCCESS;
}

static void RpcChunksClear(RpcSsnData* rsdata)
{
    RpcChunkNode* node = rsdata->chunks_head;

    while (node != nullptr)
    {
        RpcChunkNode* next = node->next;
        snort_free(node->data);
        snort_free(node);
        node = next;
    }

    rsdata->chunks_head = nullptr;
    rsdata->chunks_tail = nullptr;
    rsdata->body_buffered = 0;
    rsdata->partial_serialized = 0;
}

static RpcStatus RpcPrepChunkBuffer(RpcSsnData* rsdata, DataBuffer& buf, bool mark_last)
{
    if (rsdata->body_buffered + RPC_FRAG_HDR_SIZE > buf.decode_blen)
    {
        RpcChunksClear(rsdata);
        return RPC_STATUS__ERROR;
    }

    uint32_t fraghdr = htonl(rsdata->body_buffered);
    memcpy_s(buf.data, buf.decode_blen, &fraghdr, sizeof(fraghdr));
    if (mark_last)
        buf.data[0] |= 0x80;

    uint32_t offset = RPC_FRAG_HDR_SIZE;
    for (RpcChunkNode* node = rsdata->chunks_head; node != nullptr; node = node->next)
    {
        memcpy_s(buf.data + offset, buf.decode_blen - offset, node->data, node->len);
        offset += node->len;
    }

    buf.len = offset;
    return RPC_STATUS__SUCCESS;
}

static RpcStatus RpcFlushToAlt(RpcSsnData* rsdata, Packet* p)
{
    DataBuffer& buf = DetectionEngine::acquire_alt_buffer(p);

    if (RpcPrepChunkBuffer(rsdata, buf, true) != RPC_STATUS__SUCCESS)
        return RPC_STATUS__ERROR;

    RpcPublishAltPacket(p, buf.data, buf.len);
    return RPC_STATUS__SUCCESS;
}

static RpcStatus RpcPrepPartial(RpcSsnData* rsdata, Packet* p)
{
    DataBuffer& buf = DetectionEngine::acquire_alt_buffer(p);
    return RpcPrepChunkBuffer(rsdata, buf, rsdata->record_complete);
}

static inline void RpcResetRecordState(RpcSsnData* rsdata)
{
    rsdata->cur_frag_len = 0;
    rsdata->cur_frag_received = 0;
    rsdata->has_non_last_frag = false;
    rsdata->record_complete = false;
    rsdata->hdr_bytes_buffered = 0;
    rsdata->skip_record = false;
}

static RpcStatus RpcStatefulInspection(RpcSsnData* rsdata, Packet* p)
{
    const uint8_t* data = p->data;
    uint16_t dsize = p->dsize;

    // Consume remaining fragment bytes without buffering after depth cap.
    if (rsdata->skip_record)
    {
        uint32_t frag_remaining = rsdata->cur_frag_len - rsdata->cur_frag_received;
        if (dsize < frag_remaining)
        {
            rsdata->cur_frag_received += dsize;
            return RPC_STATUS__SUCCESS;
        }
    }

    // Allow multiple detection passes on the same packet.
    p->packet_flags |= PKT_ALLOW_MULTIPLE_DETECT;

    while (dsize > 0)
    {
        if (rsdata->cur_frag_len > 0 && rsdata->cur_frag_received < rsdata->cur_frag_len)
        {
            uint32_t remaining_in_frag = rsdata->cur_frag_len - rsdata->cur_frag_received;
            uint32_t body_to_consume = remaining_in_frag < dsize ? remaining_in_frag : dsize;

            if (!rsdata->skip_record)
            {
                uint32_t available = (MAX_INSPECT_DEPTH - RPC_FRAG_HDR_SIZE) - rsdata->body_buffered;
                uint32_t to_append = body_to_consume < available ? body_to_consume : available;

                if (to_append > 0)
                {
                    // cppcheck-suppress knownConditionTrueFalse ; defensive for future RpcChunkAppend errors
                    if (RpcChunkAppend(rsdata, data, to_append) != RPC_STATUS__SUCCESS)
                        return RPC_STATUS__ERROR;
                }

                // cppcheck-suppress knownConditionTrueFalse ; depth cap when body exceeds remaining budget
                if (to_append < body_to_consume)
                {
                    if (rsdata->chunks_head != nullptr)
                    {
                        if (RpcFlushToAlt(rsdata, p) != RPC_STATUS__SUCCESS)
                            return RPC_STATUS__ERROR;

                        RpcChunksClear(rsdata);
                    }
                    RpcPreprocEvent(rsdata, RPC_INSPECT_DEPTH_EXCEEDED);
                    ++rdstats.oversized_records;
                    rsdata->skip_record = true;
                }
            }

            rsdata->cur_frag_received += body_to_consume;
            data += body_to_consume;
            dsize -= (uint16_t)body_to_consume;

            if (rsdata->cur_frag_received == rsdata->cur_frag_len)
            {
                if (rsdata->record_complete)
                {
                    if (!rsdata->skip_record && rsdata->chunks_head != nullptr)
                    {
                        if (RpcFlushToAlt(rsdata, p) != RPC_STATUS__SUCCESS)
                            return RPC_STATUS__ERROR;

                        RpcChunksClear(rsdata);
                    }

                    if (dsize > 0)
                        RpcPreprocEvent(rsdata, RPC_MULTIPLE_RECORD);

                    RpcResetRecordState(rsdata);
                }
                else
                {
                    rsdata->cur_frag_received = 0;
                    rsdata->cur_frag_len = 0;
                }
            }
        }
        else
        {
            const uint8_t* hdr_ptr = nullptr;
            bool hdr_in_packet = false;

            if (rsdata->hdr_bytes_buffered > 0)
            {
                uint32_t need = RPC_FRAG_HDR_SIZE - rsdata->hdr_bytes_buffered;
                uint32_t avail = need < dsize ? need : dsize;

                memcpy_s(rsdata->hdr_buf + rsdata->hdr_bytes_buffered,
                    sizeof(rsdata->hdr_buf) - rsdata->hdr_bytes_buffered, data, avail);

                rsdata->hdr_bytes_buffered += avail;
                data += avail;
                dsize -= (uint16_t)avail;

                if (rsdata->hdr_bytes_buffered < RPC_FRAG_HDR_SIZE)
                {
                    RpcPreprocEvent(rsdata, RPC_INCOMPLETE_SEGMENT);
                    break;
                }

                hdr_ptr = rsdata->hdr_buf;
                rsdata->hdr_bytes_buffered = 0;
            }
            else if (dsize < RPC_FRAG_HDR_SIZE)
            {
                memcpy_s(rsdata->hdr_buf, sizeof(rsdata->hdr_buf), data, dsize);
                rsdata->hdr_bytes_buffered = dsize;
                RpcPreprocEvent(rsdata, RPC_INCOMPLETE_SEGMENT);
                break;
            }
            else
            {
                hdr_ptr = data;
                hdr_in_packet = true;
                data += RPC_FRAG_HDR_SIZE;
                dsize -= RPC_FRAG_HDR_SIZE;
            }

            rsdata->cur_frag_len = rpc_frag_len(hdr_ptr);
            rsdata->cur_frag_received = 0;

            if (rsdata->cur_frag_len == 0)
                RpcPreprocEvent(rsdata, RPC_ZERO_LENGTH_FRAGMENT);

            if (hdr_ptr[0] & 0x80)
                rsdata->record_complete = true;
            else
            {
                RpcPreprocEvent(rsdata, RPC_FRAG_TRAFFIC);
                rsdata->has_non_last_frag = true;
            }

            // Fast path: complete unfragmented record in one segment.
            if (!rsdata->skip_record
                && hdr_in_packet
                && rsdata->record_complete
                && rsdata->chunks_head == nullptr
                && !rsdata->has_non_last_frag
                && rsdata->cur_frag_len <= (MAX_INSPECT_DEPTH - RPC_FRAG_HDR_SIZE)
                && dsize >= rsdata->cur_frag_len)
            {
                const uint8_t* frag_start = data - RPC_FRAG_HDR_SIZE;

                rsdata->cur_frag_received = rsdata->cur_frag_len;
                data += rsdata->cur_frag_len;
                dsize -= (uint16_t)rsdata->cur_frag_len;

                if ((dsize != 0) || (frag_start != p->data))
                {
                    if (RpcPrepRaw(frag_start, rsdata->cur_frag_len, p) != RPC_STATUS__SUCCESS)
                        return RPC_STATUS__ERROR;

                    RpcPublishAltPacket(p, frag_start, RPC_FRAG_HDR_SIZE + rsdata->cur_frag_len);
                }

                if (dsize > 0)
                    RpcPreprocEvent(rsdata, RPC_MULTIPLE_RECORD);

                RpcResetRecordState(rsdata);
            }
            else if (rsdata->cur_frag_len == 0 && rsdata->record_complete)
            {
                if (!rsdata->skip_record && rsdata->chunks_head != nullptr)
                {
                    if (RpcFlushToAlt(rsdata, p) != RPC_STATUS__SUCCESS)
                        return RPC_STATUS__ERROR;

                    RpcChunksClear(rsdata);
                }

                if (dsize > 0)
                    RpcPreprocEvent(rsdata, RPC_MULTIPLE_RECORD);

                RpcResetRecordState(rsdata);
            }
        }
    }

    if (!rsdata->skip_record
        && rsdata->cur_frag_len > 0
        && rsdata->cur_frag_received < rsdata->cur_frag_len)
    {
        RpcPreprocEvent(rsdata, RPC_INCOMPLETE_SEGMENT);
    }

    // Partial alt-buffer flush once per RPC_PARTIAL_FLUSH_QUANTUM new body bytes.
    if (rsdata->chunks_head != nullptr)
    {
        const uint32_t since_partial = rsdata->body_buffered - rsdata->partial_serialized;
        const bool at_inspect_budget =
            rsdata->body_buffered >= (MAX_INSPECT_DEPTH - RPC_FRAG_HDR_SIZE);

        if (since_partial >= RPC_PARTIAL_FLUSH_QUANTUM
            || (at_inspect_budget && since_partial > 0))
        {
            if (RpcPrepPartial(rsdata, p) != RPC_STATUS__SUCCESS)
                return RPC_STATUS__ERROR;

            rsdata->partial_serialized = rsdata->body_buffered;
            ++rdstats.partial_flushes;
        }
    }
    else if (rsdata->skip_record)
        DetectionEngine::reset_alt_buffer(p);

    return RPC_STATUS__SUCCESS;
}

static RpcStatus RpcPrepRaw(const uint8_t* data, uint32_t fraglen, Packet* p)
{
    DataBuffer& buf = DetectionEngine::acquire_alt_buffer(p);

    if (RPC_FRAG_HDR_SIZE + fraglen > buf.decode_blen)
        return RPC_STATUS__ERROR;

    memcpy_s(buf.data, buf.decode_blen, data, RPC_FRAG_HDR_SIZE + fraglen);
    buf.len = (RPC_FRAG_HDR_SIZE + fraglen);

    return RPC_STATUS__SUCCESS;
}

static inline void RpcSsnSetInactive(RpcSsnData* rsdata, Packet*)
{
    if (rsdata == nullptr)
        return;

    RpcSsnClean(rsdata);
}

static inline int RpcSsnIsActive(const RpcSsnData* rsdata)
{
    if (rsdata == nullptr)
        return 0;
    return rsdata->active;
}

static inline void RpcSsnClean(RpcSsnData* rsdata)
{
    if (rsdata == nullptr)
        return;

    rsdata->active = 0;
    RpcChunksClear(rsdata);
    RpcResetRecordState(rsdata);
}

RpcFlowData::RpcFlowData() : FlowData(inspector_id)
{
    memset(&session, 0, sizeof(session));
    rdstats.concurrent_sessions++;
    if(rdstats.max_concurrent_sessions < rdstats.concurrent_sessions)
        rdstats.max_concurrent_sessions = rdstats.concurrent_sessions;
}

RpcFlowData::~RpcFlowData()
{
    RpcSsnClean(&session);
    assert(rdstats.concurrent_sessions > 0);
    rdstats.concurrent_sessions--;
}

static RpcSsnData* RpcSsnDataNew(Packet* p)
{
    RpcFlowData* fd = new RpcFlowData;
    RpcSsnData* rsdata = &fd->session;
    rsdata->active = 1;

    p->flow->set_flow_data(fd);

    return rsdata;
}

/* most significant bit */
#define MSB 0x80000000

/*
 * For proto ref, see rfc1831 section 10 and page 445 UNP vol2
 *
 * check to make sure we've got enough data to process a record
 *
 * Where did the original 16 come from?  It seems that it could be
 * a last frag of 0 length according to spec.
 *
 * The minimum "valid" packet for us is 8 fields * 4 bytes
 *
 * This decoder is ignorant of TCP state so we'll have to assume
 * that reassembled TCP stuff is reinjected to the inspector
 * chain
 *
 * This decoder is also ignorant of multiple RPC requests in a
 * single stream.  To compensate, we can configure alerts
 *
 * Additionally, we don't do anything to verify that this is
 * really an RPC service port so we don't decode anything that
 * happens as a result
 *
 * From rfc1831:
 *
 *  Fragment Header ( 1 flag bit, 31 bit uint )
 *     RPC Body
 *
 *        unsigned int xid
 *        struct call_body {
 *             unsigned int rpcvers;  // must be equal to two (2)
 *             unsigned int prog;
 *             unsigned int vers;
 *             unsigned int proc;
 *             opaque_auth  cred;
 *             opaque_auth  verf;
 *        }
 */

#define MIN_CALL_BODY_SZ 32

static int ConvertRPC(RpcSsnData* rsdata, Packet* p)
{
    const uint8_t* data = p->data;
    uint32_t psize = p->dsize;
    uint8_t* norm_index;
    const uint8_t* data_index;     /* this is the index pointer to walk thru the data */
    const uint8_t* data_end;       /* points to the end of the payload for loop control */
    uint32_t length;          /* length of current fragment */
    int last_fragment = 0; /* have we seen the last fragment sign? */
    uint32_t decoded_len; /* our decoded length is always at least a 0 byte header */
    uint32_t fraghdr;   /* Used to store the RPC fragment header data */
    int fragcount = 0;   /* How many fragment counters have we seen? */

    DataBuffer& buf = DetectionEngine::acquire_alt_buffer(p);
    size_t decode_buf_rem = buf.decode_blen;

    if (psize < MIN_CALL_BODY_SZ)
    {
        return 0;
    }

    /* on match, normalize the data */

    std::memcpy(&fraghdr, data, sizeof(fraghdr));

    /* The fragment header is 4 bytes in network byte order */
    fraghdr = ntohl(fraghdr);
    length = fraghdr & 0x7FFFFFFF;

    /* Check to see if we are on the last fragment */
    if (fraghdr & MSB)
    {
        /* on match, normalize the data */
        if ((length + 4 != psize) && !(p->packet_flags & PKT_REBUILT_STREAM))
        {
            return RPC_MULTIPLE_RECORD;
        }
        else if ( length == 0 )
        {
            return RPC_ZERO_LENGTH_FRAGMENT;
        }
        return 0;
    }
    else
    {
        RpcPreprocEvent(rsdata, RPC_FRAG_TRAFFIC);
    }

    norm_index = buf.data;
    data_index = (const uint8_t*)data;
    data_end = (const uint8_t*)data + psize;

    /* now we know it's in fragmented records, 4 bytes of
     * header(of which the most sig bit fragment (0=yes 1=no).
     * The header is followed by the value move pointer up 4
     * bytes, we need to stuff header in first 4 bytes.
     * But the header has the total length...we don't know
     * until the end
     */

    /* This is where decoded data will be written */
    norm_index += 4;
    decoded_len = 4;
    decode_buf_rem -= 4;

    /* always make sure that we have enough data to process at least
     * the header and that we only process at most, one fragment
     */

    while (((data_end - data_index) >= 4) && (last_fragment == 0))
    {
        /* get the fragment length (31 bits) and move the pointer to
           the start of the actual data */

        std::memcpy(&fraghdr, data_index, sizeof(fraghdr));

        fraghdr = ntohl(fraghdr);
        length = fraghdr & 0x7FFFFFFF;

        if (length == 0)
            break;

        /* move the current index into the packet past the
           fragment header */
        data_index += 4;

        if (fraghdr & MSB)
        {
            last_fragment = 1;
        }

        if ((length + decoded_len) < decoded_len)
        {
            /* don't allow integer overflow to confuse us.  Should be
             * caught by length > psize but who knows when weird
             * psize's might be allowed */
            return RPC_LARGE_FRAGSIZE;
        }

        decoded_len += length;

        if (length > psize)
        {
            return RPC_INCOMPLETE_SEGMENT;
        }
        else if (decoded_len > psize)
        {
            /* The entire request is larger than our current packet
             *  size
             */
            return RPC_LARGE_FRAGSIZE;
        }
        else if ((data_index + length) > data_end)
        {
            return RPC_LARGE_FRAGSIZE;
        }
        else
        {
            fragcount++;
            if (decode_buf_rem >= length)
            {
                memcpy_s(norm_index, decode_buf_rem, data_index, length);

                norm_index += length;
                data_index += length;
                decode_buf_rem -= length;
            }
        }
    }

    /* rewrite the header on the request packet
       move the fragment header back onto the data */

    fraghdr = ntohl(decoded_len); /* size */

    std::memcpy(buf.data, &fraghdr, sizeof(fraghdr));

    buf.data[0] |=  0x80;             /* Mark as unfragmented */

    /* is there another request encoded that is trying to evade us by doing
     *
     * frag last frag [ more data ]?
     */
    if (decoded_len + ((fragcount - 1) * 4) != psize)
    {
        return RPC_MULTIPLE_RECORD;
    }

    buf.len = (uint16_t)decoded_len;
    return 0;
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class RpcDecode : public Inspector
{
public:
    RpcDecode(RpcDecodeModule*);

    void eval(Packet*) override;
    void clear(Packet*) override;

    StreamSplitter* get_splitter(bool c2s) override
    { return c2s ? new LogSplitter(c2s) : nullptr; }
};

RpcDecode::RpcDecode(RpcDecodeModule*)
{
}

/*
 * Purpose: Inspects the packet's payload for fragment records and
 *          converts them into one unfragmented record.
 */
void RpcDecode::eval(Packet* p)
{
    Profile profile(rpcdecodePerfStats);    // cppcheck-suppress unreadVariable

    // preconditions - what we registered for
    assert(p->has_tcp_data());

    // Stateful mode inspects client packets only.
    if ( !p->is_from_client() )
        return;

    RpcSsnData* rsdata = nullptr;

    if ( p->flow )
    {
        RpcFlowData* fd = static_cast<RpcFlowData*>(
            p->flow->get_flow_data(RpcFlowData::inspector_id));

        if ( fd )
            rsdata = &fd->session;
    }

    ++rdstats.total_packets;

    if ( !rsdata && p->flow && !Stream::is_midstream(p->flow) )
        rsdata = RpcSsnDataNew(p);

    if ( RpcSsnIsActive(rsdata) and (p->packet_flags & PKT_REBUILT_STREAM) )
    {
        RpcStatus ret = RpcStatefulInspection(rsdata, p);

        if (ret == RPC_STATUS__SUCCESS)
            return;

        if (ret == RPC_STATUS__ERROR)
            RpcSsnSetInactive(rsdata, p);
    }
    RpcPreprocEvent(rsdata, ConvertRPC(rsdata, p));
}

void RpcDecode::clear(Packet* p)
{
    DetectionEngine::reset_alt_buffer(p);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new RpcDecodeModule; }

static void mod_dtor(Module* m)
{ delete m; }

static void rd_init()
{
    RpcFlowData::init();
}

static Inspector* rd_ctor(Module* m)
{
    return new RpcDecode(static_cast<RpcDecodeModule*>(m));
}

static void rd_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi rd_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        PLUGIN_SO_RELOAD,
        API_OPTIONS,
        mod_name,
        mod_help,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__PDU,
    nullptr, // buffers
    "sunrpc",
    rd_init,
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    rd_ctor,
    rd_dtor,
    nullptr, // ssn
    nullptr  // reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &rd_api.base,
    nullptr
};
#else
const BaseApi* sin_rpc_decode = &rd_api.base;
#endif

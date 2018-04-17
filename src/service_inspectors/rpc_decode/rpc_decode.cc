//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
 * This preprocessor normalizes the RPC requests from remote machines by
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

#include "detection/detection_util.h"
#include "detection/detection_engine.h"
#include "framework/data_bus.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "stream/stream.h"
#include "stream/stream_splitter.h"
#include "utils/safec.h"
#include "utils/util.h"

#include "rpc_module.h"

using namespace snort;
using namespace std;

#define RPC_MAX_BUF_SIZE   256
#define RPC_FRAG_HDR_SIZE  sizeof(uint32_t)
#define RPC_FRAG_LEN(ptr)  (ntohl(*((const uint32_t*)(ptr))) & 0x7FFFFFFF)

struct RpcDecodeConfig
{
    int dummy;
};

struct RpcBuffer
{
    uint8_t* data;
    uint32_t len;
    uint32_t size;
};

struct RpcSsnData
{
    int active;
    int events;
    uint32_t frag_len;
    uint32_t ignore;
    RpcBuffer seg;
    RpcBuffer frag;
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
};

static const uint32_t flush_size = 28;

#define mod_name "rpc_decode"
#define mod_help "RPC inspector"

THREAD_LOCAL ProfileStats rpcdecodePerfStats;
THREAD_LOCAL RpcStats rdstats;

static int ConvertRPC(RpcDecodeConfig*, RpcSsnData*, Packet*);

static RpcSsnData* RpcSsnDataNew(Packet*);
static inline void RpcSsnClean(RpcSsnData*);
static inline void RpcSsnSetInactive(RpcSsnData*, Packet*);
static inline int RpcSsnIsActive(RpcSsnData*);

static RpcStatus RpcStatefulInspection(RpcDecodeConfig*, RpcSsnData*, Packet*);
static inline void RpcPreprocEvent(RpcDecodeConfig*, RpcSsnData*, int);
static RpcStatus RpcHandleFrag(RpcDecodeConfig*, RpcSsnData*, const uint8_t*);
static RpcStatus RpcPrepRaw(const uint8_t*, uint32_t, Packet*);
static RpcStatus RpcPrepFrag(RpcSsnData*, Packet*);
static RpcStatus RpcPrepSeg(RpcSsnData*, Packet*);
static inline uint32_t RpcBufLen(RpcBuffer*);
static inline uint8_t* RpcBufData(RpcBuffer*);
static RpcStatus RpcBufAdd(RpcBuffer*, const uint8_t*, uint32_t);
static inline void RpcBufClean(RpcBuffer*);

static inline void RpcPreprocEvent(
    RpcDecodeConfig* rconfig, RpcSsnData* rsdata, int event)
{
    if (rconfig == nullptr)
        return;

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

    default:
        break;
    }
}

static RpcStatus RpcStatefulInspection(RpcDecodeConfig* rconfig,
    RpcSsnData* rsdata, Packet* p)
{
    const uint8_t* data = p->data;
    uint16_t dsize = p->dsize;
    int need;
    RpcStatus status;

    if (rsdata->ignore)
    {
        if (dsize < rsdata->ignore)
        {
            rsdata->ignore -= dsize;
            return RPC_STATUS__SUCCESS;
        }

        dsize -= (uint16_t)rsdata->ignore;
        data += rsdata->ignore;
        rsdata->ignore = 0;
    }

    /* Might need to evaluate same packet, different decode buffer
     * more than once and detection option tree won't let us do that
     * by default */
    p->packet_flags |= PKT_ALLOW_MULTIPLE_DETECT;

    while (dsize > 0)
    {
        if (RpcBufLen(&rsdata->seg) == 0)
        {
            if (dsize < RPC_FRAG_HDR_SIZE)
            {
                RpcPreprocEvent(rconfig, rsdata, RPC_INCOMPLETE_SEGMENT);

                if (RpcBufAdd(&rsdata->seg, data, dsize) != RPC_STATUS__SUCCESS)
                    return RPC_STATUS__ERROR;

                break;
            }

            rsdata->frag_len = RPC_FRAG_LEN(data);
            if (dsize < (RPC_FRAG_HDR_SIZE + rsdata->frag_len))
            {
                RpcPreprocEvent(rconfig, rsdata, RPC_INCOMPLETE_SEGMENT);

                if (RpcBufAdd(&rsdata->seg, data, dsize) != RPC_STATUS__SUCCESS)
                    return RPC_STATUS__ERROR;

                break;
            }

            dsize -= (RPC_FRAG_HDR_SIZE + rsdata->frag_len);

            status = RpcHandleFrag(rconfig, rsdata, data);

            if (status == RPC_STATUS__ERROR)
                return RPC_STATUS__ERROR;

            if (status == RPC_STATUS__DEFRAG)
            {
                if ((dsize != 0) || (data != p->data))
                {
                    /* Only do this if there is more than one fragment in
                     * the data we got */
                    if (RpcPrepRaw(data, rsdata->frag_len, p) != RPC_STATUS__SUCCESS)
                        return RPC_STATUS__ERROR;

                    DataBus::publish(PACKET_EVENT, p);
                }

                if ( (dsize > 0) )
                    RpcPreprocEvent(rconfig, rsdata, RPC_MULTIPLE_RECORD);
            }

            data += (RPC_FRAG_HDR_SIZE + rsdata->frag_len);
        }
        else
        {
            if (RpcBufLen(&rsdata->seg) < RPC_FRAG_HDR_SIZE)
            {
                need = RPC_FRAG_HDR_SIZE - RpcBufLen(&rsdata->seg);
                if (dsize < need)
                {
                    RpcPreprocEvent(rconfig, rsdata, RPC_INCOMPLETE_SEGMENT);

                    if (RpcBufAdd(&rsdata->seg, data, dsize) != RPC_STATUS__SUCCESS)
                        return RPC_STATUS__ERROR;

                    break;
                }

                if (RpcBufAdd(&rsdata->seg, data, need) != RPC_STATUS__SUCCESS)
                    return RPC_STATUS__ERROR;

                data += need;
                dsize -= need;

                rsdata->frag_len = RPC_FRAG_LEN(RpcBufData(&rsdata->seg));
            }

            need = rsdata->frag_len - (RpcBufLen(&rsdata->seg) - RPC_FRAG_HDR_SIZE);
            if (dsize < need)
            {
                RpcPreprocEvent(rconfig, rsdata, RPC_INCOMPLETE_SEGMENT);

                if (RpcBufAdd(&rsdata->seg, data, dsize) != RPC_STATUS__SUCCESS)
                    return RPC_STATUS__ERROR;

                break;
            }

            if (RpcBufAdd(&rsdata->seg, data, need) != RPC_STATUS__SUCCESS)
                return RPC_STATUS__ERROR;

            data += need;
            dsize -= need;

            status = RpcHandleFrag(rconfig, rsdata, RpcBufData(&rsdata->seg));

            if (status == RPC_STATUS__ERROR)
                return RPC_STATUS__ERROR;

            if (status == RPC_STATUS__DEFRAG)
            {
                if (RpcBufLen(&rsdata->frag) != 0)
                {
                    if (RpcPrepFrag(rsdata, p) != RPC_STATUS__SUCCESS)
                        return RPC_STATUS__ERROR;
                }
                else
                {
                    if (RpcPrepSeg(rsdata, p) != RPC_STATUS__SUCCESS)
                        return RPC_STATUS__ERROR;
                }

                if ( (dsize > 0) )
                    RpcPreprocEvent(rconfig, rsdata, RPC_MULTIPLE_RECORD);

                DataBus::publish(PACKET_EVENT, p);
                RpcBufClean(&rsdata->frag);
            }

            RpcBufClean(&rsdata->seg);
        }
    }

    if (RpcBufLen(&rsdata->frag) != 0)
    {
        if (RpcPrepFrag(rsdata, p) != RPC_STATUS__SUCCESS)
            return RPC_STATUS__ERROR;
    }
    else if (RpcBufLen(&rsdata->seg) != 0)
    {
        if (RpcPrepSeg(rsdata, p) != RPC_STATUS__SUCCESS)
            return RPC_STATUS__ERROR;
    }

    return RPC_STATUS__SUCCESS;
}

static RpcStatus RpcPrepRaw(const uint8_t* data, uint32_t fraglen, Packet* p)
{
    DataBuffer& buf = DetectionEngine::get_alt_buffer(p);

    if (RPC_FRAG_HDR_SIZE + fraglen > sizeof(buf.data))
        return RPC_STATUS__ERROR;

    memcpy_s(buf.data, sizeof(buf.data), data, RPC_FRAG_HDR_SIZE + fraglen);
    buf.len = (RPC_FRAG_HDR_SIZE + fraglen);

    return RPC_STATUS__SUCCESS;
}

static RpcStatus RpcPrepFrag(RpcSsnData* rsdata, Packet* p)
{
    DataBuffer& buf = DetectionEngine::get_alt_buffer(p);
    uint32_t fraghdr = htonl(RpcBufLen(&rsdata->frag));

    buf.data[0] = *((uint8_t*)&fraghdr);
    buf.data[1] = *(((uint8_t*)&fraghdr) + 1);
    buf.data[2] = *(((uint8_t*)&fraghdr) + 2);
    buf.data[3] = *(((uint8_t*)&fraghdr) + 3);

    buf.data[0] |= 0x80;

    if (RpcBufLen(&rsdata->frag) > sizeof(buf.data) - 4)
    {
        RpcBufClean(&rsdata->frag);
        return RPC_STATUS__ERROR;
    }

    memcpy_s(buf.data + 4, sizeof(buf.data) - 4,
        RpcBufData(&rsdata->frag), RpcBufLen(&rsdata->frag));

    if (RpcBufLen(&rsdata->frag) > RPC_MAX_BUF_SIZE)
        RpcBufClean(&rsdata->frag);

    buf.len = RpcBufLen(&rsdata->frag);

    return RPC_STATUS__SUCCESS;
}

static RpcStatus RpcPrepSeg(RpcSsnData* rsdata, Packet* p)
{
    DataBuffer& buf = DetectionEngine::get_alt_buffer(p);

    if (RpcBufLen(&rsdata->seg) > sizeof(buf.data))
    {
        RpcBufClean(&rsdata->seg);
        return RPC_STATUS__ERROR;
    }
    memcpy_s(buf.data, sizeof(buf.data),
        RpcBufData(&rsdata->seg), RpcBufLen(&rsdata->seg));

    if (RpcBufLen(&rsdata->seg) > RPC_MAX_BUF_SIZE)
    {
        rsdata->ignore = (sizeof(uint32_t) + rsdata->frag_len) - RpcBufLen(&rsdata->seg);
        RpcBufClean(&rsdata->seg);
    }

    buf.len = (uint16_t)RpcBufLen(&rsdata->seg);

    return RPC_STATUS__SUCCESS;
}

static RpcStatus RpcHandleFrag(RpcDecodeConfig* rconfig,
    RpcSsnData* rsdata, const uint8_t* fragment)
{
    int last_frag = fragment[0] & 0x80;
    uint32_t frag_len = RPC_FRAG_LEN(fragment);

    if (frag_len == 0)
        RpcPreprocEvent(rconfig, rsdata, RPC_ZERO_LENGTH_FRAGMENT);

    if (!last_frag)
        RpcPreprocEvent(rconfig, rsdata, RPC_FRAG_TRAFFIC);

    if ((RpcBufLen(&rsdata->frag) == 0) && last_frag)
        return RPC_STATUS__DEFRAG;

    if (RpcBufAdd(&rsdata->frag,
        fragment + sizeof(uint32_t), frag_len) != RPC_STATUS__SUCCESS)
    {
        return RPC_STATUS__ERROR;
    }

    if (last_frag)
        return RPC_STATUS__DEFRAG;

    return RPC_STATUS__SUCCESS;
}

static inline uint32_t RpcBufLen(RpcBuffer* buf)
{
    return buf == nullptr ? 0 : buf->len;
}

static inline uint8_t* RpcBufData(RpcBuffer* buf)
{
    return buf == nullptr ? nullptr : buf->data;
}

static RpcStatus RpcBufAdd(RpcBuffer* buf, const uint8_t* data, uint32_t dsize)
{
    const uint32_t min_alloc = flush_size;
    uint32_t alloc_size = dsize;

    if (buf == nullptr)
        return RPC_STATUS__ERROR;

    if (dsize == 0)
        return RPC_STATUS__SUCCESS;

    if (alloc_size < min_alloc)
        alloc_size = min_alloc;

    if (buf->data == nullptr)
    {
        buf->data = (uint8_t*)snort_calloc(alloc_size);
        buf->size = alloc_size;
    }
    else if ((buf->len + dsize) > buf->size)
    {
        uint32_t new_size = buf->len + alloc_size;
        uint8_t* tmp = (uint8_t*)snort_calloc(new_size);

        if (buf->len > new_size)
        {
            snort_free(buf->data);
            buf->data = tmp;
            buf->size = new_size;

            RpcBufClean(buf);
            return RPC_STATUS__ERROR;
        }
        memcpy_s(tmp, new_size, buf->data, buf->len);

        snort_free(buf->data);
        buf->data = tmp;
        buf->size = new_size;
    }

    if (dsize > buf->size - buf->len)
    {
        RpcBufClean(buf);
        return RPC_STATUS__ERROR;
    }

    memcpy_s(buf->data + buf->len, buf->size - buf->len, data, dsize);

    buf->len += dsize;

    return RPC_STATUS__SUCCESS;
}

static inline void RpcBufClean(RpcBuffer* buf)
{
    if (buf->data != nullptr)
    {
        snort_free(buf->data);
        buf->data = nullptr;
    }

    buf->len = 0;
    buf->size = 0;
}

static inline void RpcSsnSetInactive(RpcSsnData* rsdata, Packet*)
{
    if (rsdata == nullptr)
        return;

    RpcSsnClean(rsdata);
}

static inline int RpcSsnIsActive(RpcSsnData* rsdata)
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
    rsdata->frag_len = 0;
    rsdata->ignore = 0;
    RpcBufClean(&rsdata->seg);
    RpcBufClean(&rsdata->frag);
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
 * that reassembled TCP stuff is reinjected to the preprocessor
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

static int ConvertRPC(RpcDecodeConfig* rconfig, RpcSsnData* rsdata, Packet* p)
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

    DataBuffer& buf = DetectionEngine::get_alt_buffer(p);
    size_t decode_buf_rem = sizeof(buf.data);

    if (psize < MIN_CALL_BODY_SZ)
    {
        return 0;
    }

    /* on match, normalize the data */

    /* cheesy alignment safe fraghdr = *(uint32_t *) data*/
    *((uint8_t*)&fraghdr)      = data[0];
    *(((uint8_t*)&fraghdr) + 1) = data[1];
    *(((uint8_t*)&fraghdr) + 2) = data[2];
    *(((uint8_t*)&fraghdr) + 3) = data[3];

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
        RpcPreprocEvent(rconfig, rsdata, RPC_FRAG_TRAFFIC);
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

        *((uint8_t*)&fraghdr)       = data_index[0];
        *(((uint8_t*)&fraghdr) + 1) = data_index[1];
        *(((uint8_t*)&fraghdr) + 2) = data_index[2];
        *(((uint8_t*)&fraghdr) + 3) = data_index[3];

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

    buf.data[0] = *((uint8_t*)&fraghdr);
    buf.data[1] = *(((uint8_t*)&fraghdr) + 1);
    buf.data[2] = *(((uint8_t*)&fraghdr) + 2);
    buf.data[3] = *(((uint8_t*)&fraghdr) + 3);

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
// splitter stuff:
//
// see above comments on MIN_CALL_BODY_SZ
// why flush_point == 28 instead of 32 IDK
//
// we don't set a flush point to flush_point (= 28 above) because that will
// cause the request to be segmented at that point.
//
// by setting max instead, we get the actual tcp segment(s) that total 32
// or more bytes which is closer to the old set_flush_point() result (2 or
// more segments totaling at least 28 bytes)
//
// obviously, the correct way to do this is to look at the actual data and
// extract/determine the actual PDU lengths.  TBD
//-------------------------------------------------------------------------

class RpcSplitter : public StreamSplitter
{
public:
    RpcSplitter(bool c2s) : StreamSplitter(c2s) { }

    Status scan(Flow*, const uint8_t*, uint32_t,
        uint32_t, uint32_t*) override
    { return SEARCH; }

    unsigned max(Flow*) override { return MIN_CALL_BODY_SZ; }
};

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class RpcDecode : public Inspector
{
public:
    RpcDecode(RpcDecodeModule*);

    void show(SnortConfig*) override;

    void eval(Packet*) override;
    void clear(Packet*) override;

    bool get_buf(InspectionBuffer::Type, Packet*, InspectionBuffer&) override;

    StreamSplitter* get_splitter(bool c2s) override
    { return c2s ? new RpcSplitter(c2s) : nullptr; }

private:
    RpcDecodeConfig config;
};

RpcDecode::RpcDecode(RpcDecodeModule*)
{
}

void RpcDecode::show(SnortConfig*)
{
    LogMessage("rpc_decode\n");
}

/*
 * Purpose: Inspects the packet's payload for fragment records and
 *          converts them into one unfragmented record.
 */
void RpcDecode::eval(Packet* p)
{
    Profile profile(rpcdecodePerfStats);

    // preconditions - what we registered for
    assert(p->has_tcp_data());

    // If we're stateful that means stream has been configured.
    // In this case we don't look at server packets.
    // There is the case were stream configuration requires a 3 way handshake.
    // If no 3 way, then the packet flags won't be set, so don't look at it
    // since we won't be able to determine who's the client and who's the
    // server.
    if ( !p->is_from_client() )
        return;

    RpcSsnData* rsdata = nullptr;

    if ( p->flow )
    {
        RpcFlowData* fd = (RpcFlowData*)p->flow->get_flow_data(RpcFlowData::inspector_id);

        if ( fd )
            rsdata = &fd->session;
    }

    ++rdstats.total_packets;

    if ( !rsdata && p->flow && !Stream::is_midstream(p->flow) )
        rsdata = RpcSsnDataNew(p);

    if ( RpcSsnIsActive(rsdata) and (p->packet_flags & PKT_REBUILT_STREAM) )
    {
        RpcStatus ret = RpcStatefulInspection(&config, rsdata, p);

        if (ret == RPC_STATUS__SUCCESS)
            return;

        // Something went wrong - deactivate session tracking
        // and decode normally
        if (ret == RPC_STATUS__ERROR)
            RpcSsnSetInactive(rsdata, p);
    }
    RpcPreprocEvent(&config, rsdata, ConvertRPC(&config, rsdata, p));
}

bool RpcDecode::get_buf(InspectionBuffer::Type ibt, Packet* p, InspectionBuffer& b)
{
    if ( ibt != InspectionBuffer::IBT_ALT )
        return false;

    DataBuffer& buf = DetectionEngine::get_alt_buffer(p);
    b.len = buf.len;
    b.data = (b.len > 0) ? buf.data : nullptr;

    return (b.data != nullptr);
}

void RpcDecode::clear(Packet* p)
{
    DataBuffer& buf = DetectionEngine::get_alt_buffer(p);
    buf.len = 0;
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
    return new RpcDecode((RpcDecodeModule*)m);
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
        API_RESERVED,
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


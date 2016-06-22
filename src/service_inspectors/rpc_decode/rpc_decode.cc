//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
 * converting all fragments into one continous stream.
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

#include <assert.h>
#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>

#include "parser/parser.h"
#include "main/snort_debug.h"
#include "detection/detect.h"
#include "log/log.h"
#include "profiler/profiler.h"
#include "utils/util.h"
#include "detection/detection_util.h"
#include "stream/stream_api.h"
#include "stream/stream_splitter.h"
#include "target_based/snort_protocols.h"
#include "protocols/tcp.h"
#include "protocols/packet.h"
#include "framework/data_bus.h"
#include "framework/inspector.h"
#include "utils/safec.h"

#include "rpc_module.h"

#define RPC_MAX_BUF_SIZE   256
#define RPC_FRAG_HDR_SIZE  sizeof(uint32_t)
#define RPC_FRAG_LEN(ptr)  (ntohl(*((uint32_t*)ptr)) & 0x7FFFFFFF)

static THREAD_LOCAL DataBuffer DecodeBuffer;

using namespace std;

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
    ~RpcFlowData();

    static void init()
    { flow_id = FlowData::get_flow_id(); }

public:
    static unsigned flow_id;
    RpcSsnData session;
};

unsigned RpcFlowData::flow_id = 0;

typedef enum _RpcStatus
{
    RPC_STATUS__SUCCESS,
    RPC_STATUS__ERROR,
    RPC_STATUS__DEFRAG
} RpcStatus;

static THREAD_LOCAL const uint32_t flush_size = 28;
static THREAD_LOCAL const uint32_t rpc_memcap = 1048510;
static THREAD_LOCAL uint32_t rpc_memory = 0;

#define mod_name "rpc_decode"
#define mod_help "RPC inspector"

THREAD_LOCAL ProfileStats rpcdecodePerfStats;
THREAD_LOCAL SimpleStats rdstats;

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

static inline void* RpcAlloc(uint32_t);
static inline void RpcFree(void*, uint32_t);

static inline void RpcPreprocEvent(
    RpcDecodeConfig* rconfig, RpcSsnData* rsdata, int event)
{
    if (rconfig == NULL)
        return;

    if (rsdata != NULL)
    {
        /* Only log one event of the same type per session */
        if (rsdata->events & (1 << event))
            return;

        rsdata->events |= (1 << event);
    }

    switch (event)
    {
    case RPC_FRAG_TRAFFIC:
        SnortEventqAdd(GID_RPC_DECODE, RPC_FRAG_TRAFFIC);
        break;

    case RPC_MULTIPLE_RECORD:
        SnortEventqAdd(GID_RPC_DECODE, RPC_MULTIPLE_RECORD);
        break;

    case RPC_LARGE_FRAGSIZE:
        SnortEventqAdd(GID_RPC_DECODE, RPC_LARGE_FRAGSIZE);
        break;

    case RPC_INCOMPLETE_SEGMENT:
        SnortEventqAdd(GID_RPC_DECODE, RPC_INCOMPLETE_SEGMENT);
        break;

    case RPC_ZERO_LENGTH_FRAGMENT:
        SnortEventqAdd(GID_RPC_DECODE, RPC_ZERO_LENGTH_FRAGMENT);
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

    DebugMessage(DEBUG_RPC,
        "STATEFUL: Start *******************************\n");
    DebugFormat(DEBUG_RPC,
        "STATEFUL: Ssn: %p\n", (void*) rsdata);

    if (rsdata->ignore)
    {
        if (dsize < rsdata->ignore)
        {
            DebugFormat(DEBUG_RPC,
                "STATEFUL: Ignoring %hu bytes\n", dsize);

            rsdata->ignore -= dsize;

            DebugFormat(DEBUG_RPC,
                "STATEFUL: Bytes left to ignore: %u \n", rsdata->ignore);

            return RPC_STATUS__SUCCESS;
        }

        DebugFormat(DEBUG_RPC,
            "STATEFUL: Ignoring %u bytes\n", rsdata->ignore);

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
                DebugFormat(DEBUG_RPC,
                    "STATEFUL: Not enough data for frag header: %hu\n",
                    dsize);

                RpcPreprocEvent(rconfig, rsdata, RPC_INCOMPLETE_SEGMENT);

                if (RpcBufAdd(&rsdata->seg, data, dsize) != RPC_STATUS__SUCCESS)
                    return RPC_STATUS__ERROR;

                break;
            }

            rsdata->frag_len = RPC_FRAG_LEN(data);

            DebugFormat(DEBUG_RPC,
                "STATEFUL: Fragment length: %u\n", rsdata->frag_len);

            if (dsize < (RPC_FRAG_HDR_SIZE + rsdata->frag_len))
            {
                DebugFormat(DEBUG_RPC,
                    "STATEFUL: Not enough data for fragment: %hu\n",
                    dsize);

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
                DebugMessage(DEBUG_RPC,
                    "STATEFUL: Last frag - calling detect\n");

                if ((dsize != 0) || (data != p->data))
                {
                    /* Only do this if there is more than one fragment in
                     * the data we got */
                    if (RpcPrepRaw(data, rsdata->frag_len, p) != RPC_STATUS__SUCCESS)
                        return RPC_STATUS__ERROR;

                    get_data_bus().publish(PACKET_EVENT, p);
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
                    DebugFormat(DEBUG_RPC,
                        "STATEFUL: Not enough data for frag header "
                        "(%d): %hu\n", need, dsize);

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

                DebugFormat(DEBUG_RPC,
                    "STATEFUL: Fragment length: %u\n", rsdata->frag_len);
            }

            need = rsdata->frag_len - (RpcBufLen(&rsdata->seg) - RPC_FRAG_HDR_SIZE);
            if (dsize < need)
            {
                DebugFormat(DEBUG_RPC,
                    "STATEFUL: Not enough data for fragment (%d): %hu\n",
                    need, dsize);

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

                DebugMessage(DEBUG_RPC,
                    "STATEFUL: Last frag - calling detect\n");

                if ( (dsize > 0) )
                    RpcPreprocEvent(rconfig, rsdata, RPC_MULTIPLE_RECORD);

                get_data_bus().publish(PACKET_EVENT, p);
                RpcBufClean(&rsdata->frag);
            }

            RpcBufClean(&rsdata->seg);
        }
    }

    if (RpcBufLen(&rsdata->frag) != 0)
    {
        DebugFormat(DEBUG_RPC,
            "STATEFUL: Prepping Frag data: %u\n",
            RpcBufLen(&rsdata->frag));

        if (RpcPrepFrag(rsdata, p) != RPC_STATUS__SUCCESS)
            return RPC_STATUS__ERROR;
    }
    else if (RpcBufLen(&rsdata->seg) != 0)
    {
        DebugFormat(DEBUG_RPC,
            "STATEFUL: Prepping Seg data: %u\n",
            RpcBufLen(&rsdata->seg));

        if (RpcPrepSeg(rsdata, p) != RPC_STATUS__SUCCESS)
            return RPC_STATUS__ERROR;
    }

    DebugMessage(DEBUG_RPC,
        "STATEFUL: Success *****************************\n");

    return RPC_STATUS__SUCCESS;
}

static RpcStatus RpcPrepRaw(const uint8_t* data, uint32_t fraglen, Packet*)
{
    if (RPC_FRAG_HDR_SIZE + fraglen > sizeof(DecodeBuffer.data))
        return RPC_STATUS__ERROR;

    memcpy_s(DecodeBuffer.data, sizeof(DecodeBuffer.data), data, RPC_FRAG_HDR_SIZE + fraglen);

    DecodeBuffer.len = (RPC_FRAG_HDR_SIZE + fraglen);

    return RPC_STATUS__SUCCESS;
}

static RpcStatus RpcPrepFrag(RpcSsnData* rsdata, Packet*)
{
    uint32_t fraghdr = htonl(RpcBufLen(&rsdata->frag));

    DecodeBuffer.data[0] = *((uint8_t*)&fraghdr);
    DecodeBuffer.data[1] = *(((uint8_t*)&fraghdr) + 1);
    DecodeBuffer.data[2] = *(((uint8_t*)&fraghdr) + 2);
    DecodeBuffer.data[3] = *(((uint8_t*)&fraghdr) + 3);

    DecodeBuffer.data[0] |= 0x80;

    if (RpcBufLen(&rsdata->frag) > sizeof(DecodeBuffer.data) - 4)
    {
        RpcBufClean(&rsdata->frag);
        return RPC_STATUS__ERROR;
    }

    memcpy_s(DecodeBuffer.data + 4, sizeof(DecodeBuffer.data) - 4,
        RpcBufData(&rsdata->frag), RpcBufLen(&rsdata->frag));

    if (RpcBufLen(&rsdata->frag) > RPC_MAX_BUF_SIZE)
        RpcBufClean(&rsdata->frag);

    DecodeBuffer.len = RpcBufLen(&rsdata->frag);

    return RPC_STATUS__SUCCESS;
}

static RpcStatus RpcPrepSeg(RpcSsnData* rsdata, Packet*)
{
    if (RpcBufLen(&rsdata->seg) > sizeof(DecodeBuffer.data))
    {
        RpcBufClean(&rsdata->seg);
        return RPC_STATUS__ERROR;
    }
    memcpy_s(DecodeBuffer.data, sizeof(DecodeBuffer.data),
        RpcBufData(&rsdata->seg), RpcBufLen(&rsdata->seg));

    if (RpcBufLen(&rsdata->seg) > RPC_MAX_BUF_SIZE)
    {
        rsdata->ignore = (sizeof(uint32_t) + rsdata->frag_len) - RpcBufLen(&rsdata->seg);
        DebugFormat(DEBUG_RPC,
            "STATEFUL: Ignoring %u bytes\n", rsdata->ignore);
        RpcBufClean(&rsdata->seg);
    }

    DecodeBuffer.len = (uint16_t)RpcBufLen(&rsdata->seg);

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

    DebugFormat(DEBUG_RPC,
        "STATEFUL: Adding %u bytes to frag buffer\n", frag_len);

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
    return buf == NULL ? 0 : buf->len;
}

static inline uint8_t* RpcBufData(RpcBuffer* buf)
{
    return buf == NULL ? NULL : buf->data;
}

static RpcStatus RpcBufAdd(RpcBuffer* buf, const uint8_t* data, uint32_t dsize)
{
    const uint32_t min_alloc = flush_size;
    uint32_t alloc_size = dsize;

    if (buf == NULL)
        return RPC_STATUS__ERROR;

    if (dsize == 0)
        return RPC_STATUS__SUCCESS;

    if (alloc_size < min_alloc)
        alloc_size = min_alloc;

    if (buf->data == NULL)
    {
        buf->data = (uint8_t*)RpcAlloc(alloc_size);
        if (buf->data == NULL)
        {
            DebugMessage(DEBUG_RPC,
                "STATEFUL: Failed to allocate buffer data\n");
            return RPC_STATUS__ERROR;
        }

        buf->size = alloc_size;
    }
    else if ((buf->len + dsize) > buf->size)
    {
        uint32_t new_size = buf->len + alloc_size;
        uint8_t* tmp = (uint8_t*)RpcAlloc(new_size);

        if (tmp == NULL)
        {
            DebugMessage(DEBUG_RPC,
                "STATEFUL: Failed to reallocate buffer data\n");
            RpcBufClean(buf);
            return RPC_STATUS__ERROR;
        }

        if (buf->len > new_size)
        {
            RpcFree(buf->data, buf->size);
            buf->data = tmp;
            buf->size = new_size;

            RpcBufClean(buf);
            return RPC_STATUS__ERROR;
        }
        memcpy_s(tmp, new_size, buf->data, buf->len);

        RpcFree(buf->data, buf->size);
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
    if (buf->data != NULL)
    {
        RpcFree(buf->data, buf->size);
        buf->data = NULL;
    }

    buf->len = 0;
    buf->size = 0;
}

static inline void* RpcAlloc(uint32_t size)
{
    if ((rpc_memory + size) > rpc_memcap)
    {
        DebugMessage(DEBUG_RPC, "STATEFUL: Memcap exceeded\n");
        return NULL;
    }

    rpc_memory += size;
    return snort_calloc(size);
}

static inline void RpcFree(void* data, uint32_t size)
{
    if (data == NULL)
        return;

    if (rpc_memory < size)
        rpc_memory = 0;
    else
        rpc_memory -= size;

    snort_free(data);
}

static inline void RpcSsnSetInactive(RpcSsnData* rsdata, Packet*)
{
    if (rsdata == NULL)
        return;

    DebugFormat(DEBUG_RPC, "STATEFUL: Deactivating session: %p\n",
        (void*) rsdata);

    RpcSsnClean(rsdata);
}

static inline int RpcSsnIsActive(RpcSsnData* rsdata)
{
    if (rsdata == NULL)
        return 0;
    return rsdata->active;
}

static inline void RpcSsnClean(RpcSsnData* rsdata)
{
    if (rsdata == NULL)
        return;

    rsdata->active = 0;
    rsdata->frag_len = 0;
    rsdata->ignore = 0;
    RpcBufClean(&rsdata->seg);
    RpcBufClean(&rsdata->frag);
}

RpcFlowData::RpcFlowData() : FlowData(flow_id)
{
    memset(&session, 0, sizeof(session));
}

RpcFlowData::~RpcFlowData()
{
    RpcSsnClean(&session);
}

static RpcSsnData* RpcSsnDataNew(Packet* p)
{
    RpcFlowData* fd = new RpcFlowData;
    RpcSsnData* rsdata = &fd->session;
    rsdata->active = 1;

    p->flow->set_application_data(fd);

    DebugFormat(DEBUG_RPC, "STATEFUL: Created new session: " "%p\n", (void*) rsdata);
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
    uint8_t* data_index;     /* this is the index pointer to walk thru the data */
    uint8_t* data_end;       /* points to the end of the payload for loop control */
    uint32_t length;          /* length of current fragment */
    int last_fragment = 0; /* have we seen the last fragment sign? */
    uint32_t decoded_len; /* our decoded length is always atleast a 0 byte header */
    uint32_t fraghdr;   /* Used to store the RPC fragment header data */
    int fragcount = 0;   /* How many fragment counters have we seen? */
    size_t decode_buf_rem = sizeof(DecodeBuffer.data);

    if (psize < MIN_CALL_BODY_SZ)
    {
        DebugFormat(DEBUG_RPC, "Not enough data to decode: %u\n",
            psize);
        return 0;
    }

    /* on match, normalize the data */
    DebugFormat(DEBUG_RPC, "Got RPC traffic (%u bytes)!\n", psize);

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
        DebugFormat(DEBUG_RPC, "Found Last Fragment: %u!\n", length);

        if ((length + 4 != psize) && !(p->packet_flags & PKT_REBUILT_STREAM))
        {
            DebugFormat(DEBUG_RPC, "It's not the only thing in this buffer!"
                " length: %u psize: %u!\n", length, psize);
            return RPC_MULTIPLE_RECORD;
        }
        else if ( length == 0 )
        {
            DebugFormat(DEBUG_RPC, "Zero-length RPC fragment detected."
                " length: %u psize: %u.\n", length, psize);
            return RPC_ZERO_LENGTH_FRAGMENT;
        }
        return 0;
    }
    else
    {
        RpcPreprocEvent(rconfig, rsdata, RPC_FRAG_TRAFFIC);
    }

    norm_index = DecodeBuffer.data;
    data_index = (uint8_t*)data;
    data_end = (uint8_t*)data + psize;

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

    /* always make sure that we have enough data to process atleast
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
            DebugMessage(DEBUG_RPC, "Last Fragment detected\n");
            last_fragment = 1;
        }

        if ((length + decoded_len) < decoded_len)
        {
            /* don't allow integer overflow to confuse us.  Should be
             * caught by length > psize but who knows when weird
             * psize's might be allowed */

            DebugFormat(DEBUG_RPC, "Integer Overflow"
                " field(%u) exceeds packet size(%u)\n",
                length, psize);
            return RPC_LARGE_FRAGSIZE;
        }

        decoded_len += length;

        if (length > psize)
        {
            DebugFormat(DEBUG_RPC, "Length of"
                " field(%u) exceeds packet size(%u)\n",
                length, psize);
            return RPC_INCOMPLETE_SEGMENT;
        }
        else if (decoded_len > psize)
        {
            /* The entire request is larger than our current packet
             *  size
             */
            DebugFormat(DEBUG_RPC, " Decoded Length (%u)"
                "exceeds packet size(%u)\n",
                decoded_len, psize);
            return RPC_LARGE_FRAGSIZE;
        }
        else if ((data_index + length) > data_end)
        {
            DebugMessage(DEBUG_RPC,
                "returning LARGE_FRAGSIZE"
                "since we'd read past our end\n");
            return RPC_LARGE_FRAGSIZE;
        }
        else
        {
            fragcount++;

            DebugFormat(DEBUG_RPC,
                "length: %u size: %u decoded_len: %u\n",
                length, psize, decoded_len);

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

    DecodeBuffer.data[0] = *((uint8_t*)&fraghdr);
    DecodeBuffer.data[1] = *(((uint8_t*)&fraghdr) + 1);
    DecodeBuffer.data[2] = *(((uint8_t*)&fraghdr) + 2);
    DecodeBuffer.data[3] = *(((uint8_t*)&fraghdr) + 3);

    DecodeBuffer.data[0] |=  0x80;             /* Mark as unfragmented */

    /* is there another request encoded that is trying to evade us by doing
     *
     * frag last frag [ more data ]?
     */
    if (decoded_len + ((fragcount - 1) * 4) != psize)
    {
        DebugFormat(DEBUG_RPC, "decoded len does not compute: %u\n",
            decoded_len);
        return RPC_MULTIPLE_RECORD;
    }

    DebugFormat(DEBUG_RPC, "New size: %u\n", decoded_len);
        DebugMessage(DEBUG_RPC, "converted data:\n");
    //LogNetData(data, decoded_len, p);

    DecodeBuffer.len = (uint16_t)decoded_len;
    return 0;
}

//-------------------------------------------------------------------------
// splitter stuff:
//
// see above commments on MIN_CALL_BODY_SZ
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
    ~RpcSplitter() { }

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
    bool get_buf(InspectionBuffer::Type, Packet*, InspectionBuffer&) override;

    void clear(Packet*) override
    { DecodeBuffer.len = 0; }


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
 *          converts them into one infragmented record.
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
    // since we won't be able to determeine who's the client and who's the
    // server.
    if ( !p->is_from_client() )
        return;

    RpcSsnData* rsdata = nullptr;

    if ( p->flow )
    {
        RpcFlowData* fd = (RpcFlowData*)p->flow->get_application_data(
            RpcFlowData::flow_id);

        if ( fd )
            rsdata = &fd->session;
    }

    ++rdstats.total_packets;

    if ( !rsdata && p->flow && !stream.is_midstream(p->flow) )
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

    DebugMessage(DEBUG_RPC,"Stateless inspection\n");

    RpcPreprocEvent(&config, rsdata, ConvertRPC(&config, rsdata, p));
}

bool RpcDecode::get_buf(InspectionBuffer::Type ibt, Packet*, InspectionBuffer& b)
{
    if ( ibt != InspectionBuffer::IBT_ALT )
        return false;

    b.len = DecodeBuffer.len;
    b.data = (b.len > 0) ? DecodeBuffer.data : nullptr;

    return (b.data != nullptr);
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
    (uint16_t)PktType::PDU,
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


//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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
 * @file    stream_tcp.c
 * @author  Martin Roesch <roesch@sourcefire.com>
 * @author  Steven Sturges <ssturges@sourcefire.com>
 */

/*
 * TODOs:
 * - midstream ssn pickup (done, SAS 10/14/2005)
 * - syn flood protection (done, SAS 9/27/2005)
 *
 * - review policy anomaly detection
 *   + URG pointer (TODO)
 *   + data on SYN (done, SAS 10/12/2005)
 *   + data on FIN (done, SAS 10/12/2005)
 *   + data after FIN (done, SAS 10/13/2005)
 *   + window scaling/window size max (done, SAS 10/13/2005)
 *   + PAWS, TCP Timestamps (done, SAS 10/12/2005)
 *
 * - session shutdown/Reset handling (done, SAS)
 * - flush policy for Window/Consumed
 * - limit on number of overlapping packets (done, SAS)
 */

#include "tcp_session.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <assert.h>

#include "stream_tcp.h"
#include "tcp_module.h"
#include "main/analyzer.h"
#include "perf_monitor/perf.h"
#include "snort_types.h"
#include "snort_debug.h"
#include "detect.h"
#include "sfxhash.h"
#include "util.h"
#include "sflsq.h"
#include "snort_bounds.h"
#include "snort_config.h"
#include "time/packet_time.h"
#include "protocols/packet.h"
#include "protocols/packet_manager.h"
#include "protocols/tcp_options.h"
#include "log_text.h"
#include "packet_io/active.h"
#include "normalize/normalize.h"
#include "stream/stream.h"
#include "flow/flow_control.h"
#include "flow/session.h"
#include "profiler.h"
#include "fpdetect.h"
#include "detection_util.h"
#include "file_api/file_api.h"
#include "tcp_module.h"
#include "stream/stream_splitter.h"
#include "sfip/sf_ip.h"
#include "protocols/tcp.h"
#include "protocols/eth.h"
#include "network_inspectors/normalize/normalize.h"
#include "filters/sfrf.h"

using namespace tcp;

THREAD_LOCAL ProfileStats s5TcpPerfStats;
THREAD_LOCAL ProfileStats s5TcpNewSessPerfStats;
THREAD_LOCAL ProfileStats s5TcpStatePerfStats;
THREAD_LOCAL ProfileStats s5TcpDataPerfStats;
THREAD_LOCAL ProfileStats s5TcpInsertPerfStats;
THREAD_LOCAL ProfileStats s5TcpPAFPerfStats;
THREAD_LOCAL ProfileStats s5TcpFlushPerfStats;
THREAD_LOCAL ProfileStats s5TcpBuildPacketPerfStats;
THREAD_LOCAL ProfileStats s5TcpProcessRebuiltPerfStats;

struct TcpStats
{
    PegCount sessions;
    PegCount timeouts;
    PegCount resyns;
    PegCount discards;
    PegCount events;
    PegCount sessions_ignored;
    PegCount no_pickups;
    PegCount sessions_on_syn;
    PegCount sessions_on_syn_ack;
    PegCount sessions_on_3way;
    PegCount sessions_on_data;
    PegCount trackers_created;
    PegCount trackers_released;
    PegCount segs_queued;
    PegCount segs_released;
    PegCount segs_split;
    PegCount segs_used;
    PegCount rebuilt_packets;
    PegCount rebuilt_buffers;
    PegCount overlaps;
    PegCount gaps;
    PegCount max_segs;
    PegCount max_bytes;
    PegCount internalEvents;
    PegCount s5tcp1;
    PegCount s5tcp2;
};

const PegInfo tcp_pegs[] =
{
    { "sessions", "total sessions" },
    { "timeouts", "sessions timed out" },
    { "resyns", "SYN received on established session" },
    { "discards", "tcp packets discarded" },
    { "events", "events generated" },
    { "ignored", "tcp packets ignored" },
    { "untracked", "tcp packets not tracked" },
    { "syn trackers", "tcp session tracking started on syn" },
    { "syn-ack trackers", "tcp session tracking started on syn-ack" },
    { "3way trackers", "tcp session tracking started on ack" },
    { "data trackers", "tcp session tracking started on data" },
    { "trackers created", "tcp session trackers created" },
    { "trackers released", "tcp session trackers released" },
    { "segs queued", "total segments queued" },
    { "segs released", "total segments released" },
    { "segs split", "tcp segments split when reassembling PDUs" },
    { "segs used", "queued tcp segments applied to reassembled PDUs" },
    { "rebuilt packets", "total reassembled PDUs" },
    { "rebuilt buffers", "rebuilt PDU sections" },
    { "overlaps", "overlapping segments queued" },
    { "gaps", "missing data between PDUs" },
    { "max segs", "number of times the maximum queued segment limit was reached" },
    { "max bytes", "number of times the maximum queued byte limit was reached" },
    { "internal events", "135:X events generated" },
    { "client cleanups", "number of times data from server was flushed when session released" },
    { "server cleanups", "number of times data from client was flushed when session released" },
    { nullptr, nullptr }
};

THREAD_LOCAL TcpStats tcpStats;
THREAD_LOCAL Memcap* tcp_memcap = nullptr;

/*  M A C R O S  **************************************************/

/* TCP states */
#define TCP_STATE_NONE         0
#define TCP_STATE_LISTEN       1
#define TCP_STATE_SYN_RCVD     2
#define TCP_STATE_SYN_SENT     3
#define TCP_STATE_ESTABLISHED  4
#define TCP_STATE_CLOSE_WAIT   5
#define TCP_STATE_LAST_ACK     6
#define TCP_STATE_FIN_WAIT_1   7
#define TCP_STATE_CLOSING      8
#define TCP_STATE_FIN_WAIT_2   9
#define TCP_STATE_TIME_WAIT   10
#define TCP_STATE_CLOSED      11

#ifndef MIN
# define MIN(a,b)  (((a)<(b)) ? (a) : (b))
#endif
#ifndef MAX
# define MAX(a,b)  (((a)>(b)) ? (a) : (b))
#endif

#define PAWS_WINDOW         60
#define PAWS_24DAYS         2073600         /* 24 days in seconds */

/* for state transition queuing */
#define CHK_SEQ         0
#define NO_CHK_SEQ      1

#define STREAM_UNALIGNED       0
#define STREAM_ALIGNED         1

/* actions */
#define ACTION_NOTHING                  0x00000000
#define ACTION_FLUSH_SENDER_STREAM      0x00000001
#define ACTION_FLUSH_RECEIVER_STREAM    0x00000002
#define ACTION_DROP_SESSION             0x00000004
#define ACTION_ACK_SENDER_DATA          0x00000008
#define ACTION_ACK_RECEIVER_DATA        0x00000010
#define ACTION_SET_SSN                  0x00000040
#define ACTION_COMPLETE_TWH             0x00000080
#define ACTION_RST                      0x00000100
#define ACTION_BAD_SEQ                  0x00000200
#define ACTION_BAD_PKT                  0x00000400
#define ACTION_LWSSN_CLOSED             0x00000800
#define ACTION_DISABLE_INSPECTION       0x00001000

/* events */
#define EVENT_SYN_ON_EST                0x00000001
#define EVENT_DATA_ON_SYN               0x00000002
#define EVENT_DATA_ON_CLOSED            0x00000004
#define EVENT_BAD_TIMESTAMP             0x00000008
#define EVENT_WINDOW_TOO_LARGE          0x00000010
#define EVENT_DATA_AFTER_RESET          0x00000020
#define EVENT_SESSION_HIJACK_CLIENT     0x00000040
#define EVENT_SESSION_HIJACK_SERVER     0x00000080
#define EVENT_DATA_WITHOUT_FLAGS        0x00000100
#define EVENT_4WHS                      0x00000200
#define EVENT_NO_TIMESTAMP              0x00000400
#define EVENT_BAD_RST                   0x00000800
#define EVENT_BAD_FIN                   0x00001000
#define EVENT_BAD_ACK                   0x00002000
#define EVENT_DATA_AFTER_RST_RCVD       0x00004000
#define EVENT_WINDOW_SLAM               0x00008000
#define EVENT_NO_3WHS                   0x00010000

#define TF_NONE                     0x0000
#define TF_WSCALE                   0x0001
#define TF_TSTAMP                   0x0002
#define TF_TSTAMP_ZERO              0x0004
#define TF_MSS                      0x0008
#define TF_FORCE_FLUSH              0x0010
#define TF_PKT_MISSED               0x0020  // sticky
#define TF_MISSING_PKT              0x0040  // used internally
#define TF_MISSING_PREV_PKT         0x0080  // reset for each reassembled
#define TF_FIRST_PKT_MISSING        0x0100

#define STREAM_INSERT_OK            0
#define STREAM_INSERT_ANOMALY       1
#define STREAM_INSERT_TIMEOUT       2
#define STREAM_INSERT_FAILED        3

#define STREAM_DEFAULT_TCP_PACKET_MEMCAP  8388608  /* 8MB */
#define STREAM_MIN_OVERLAP_LIMIT 0
#define STREAM_MAX_OVERLAP_LIMIT 255
#define STREAM_MAX_FLUSH_FACTOR 2048

/* target-based policy types */
// changes to this enum require changes to stream_api.h::TCP_POLICIES
#define STREAM_POLICY_FIRST       1
#define STREAM_POLICY_LAST        2
#define STREAM_POLICY_LINUX       3
#define STREAM_POLICY_OLD_LINUX   4
#define STREAM_POLICY_BSD         5
#define STREAM_POLICY_MACOS       6
#define STREAM_POLICY_SOLARIS     7
#define STREAM_POLICY_IRIX        8
#define STREAM_POLICY_HPUX11      9
#define STREAM_POLICY_HPUX10     10
#define STREAM_POLICY_WINDOWS    11
#define STREAM_POLICY_WINDOWS2K3 12
#define STREAM_POLICY_VISTA      13
#define STREAM_POLICY_PROXY      14
#define STREAM_POLICY_DEFAULT    STREAM_POLICY_BSD

#define REASSEMBLY_POLICY_FIRST       1
#define REASSEMBLY_POLICY_LAST        2
#define REASSEMBLY_POLICY_LINUX       3
#define REASSEMBLY_POLICY_OLD_LINUX   4
#define REASSEMBLY_POLICY_BSD         5
#define REASSEMBLY_POLICY_MACOS       6
#define REASSEMBLY_POLICY_SOLARIS     7
#define REASSEMBLY_POLICY_IRIX        8
#define REASSEMBLY_POLICY_HPUX11      9
#define REASSEMBLY_POLICY_HPUX10     10
#define REASSEMBLY_POLICY_WINDOWS    11
#define REASSEMBLY_POLICY_WINDOWS2K3 12
#define REASSEMBLY_POLICY_VISTA      13
#define REASSEMBLY_POLICY_DEFAULT    REASSEMBLY_POLICY_BSD

#define STREAM_MAX_MAX_WINDOW       0x3FFFc000 /* max window allowed by TCP */
/* 65535 << 14 (max wscale) */
#define STREAM_MIN_MAX_WINDOW       0

#define MAX_PORTS_TO_PRINT      20

#define STREAM_DEFAULT_MAX_QUEUED_BYTES 1048576 /* 1 MB */
#define STREAM_MIN_MAX_QUEUED_BYTES 1024       /* Don't let this go below 1024 */
#define STREAM_MAX_MAX_QUEUED_BYTES 0x40000000 /* 1 GB, most we could reach within
                                            * largest window scale */
#define AVG_PKT_SIZE            400
#define STREAM_DEFAULT_MAX_QUEUED_SEGS (STREAM_DEFAULT_MAX_QUEUED_BYTES/AVG_PKT_SIZE)
#define STREAM_MIN_MAX_QUEUED_SEGS  2          /* Don't let this go below 2 */
#define STREAM_MAX_MAX_QUEUED_SEGS  0x40000000 /* 1 GB worth of one-byte segments */

#define STREAM_DEFAULT_MAX_SMALL_SEG_SIZE 0    /* disabled */
#define STREAM_MAX_MAX_SMALL_SEG_SIZE 2048     /* 2048 bytes in single packet, uh, not small */
#define STREAM_MIN_MAX_SMALL_SEG_SIZE 0        /* 0 means disabled */

#define STREAM_DEFAULT_CONSEC_SMALL_SEGS 0     /* disabled */
#define STREAM_MAX_CONSEC_SMALL_SEGS 2048      /* 2048 single byte packets without acks is alot */
#define STREAM_MIN_CONSEC_SMALL_SEGS 0         /* 0 means disabled */

#define SUB_SYN_SENT  0x01
#define SUB_ACK_SENT  0x02
#define SUB_SETUP_OK  0x03
#define SUB_RST_SENT  0x04
#define SUB_FIN_SENT  0x08

#define SLAM_MAX 4

//#define DEBUG_STREAM_EX
#ifdef DEBUG_STREAM_EX
#define STREAM_DEBUG_WRAP(x) DEBUG_WRAP(x)
#else
#define STREAM_DEBUG_WRAP(x)
#endif

#define SL_BUF_FLUSHED 1

struct TcpDataBlock
{
    uint32_t seq;
    uint32_t ack;
    uint32_t win;
    uint32_t end_seq;
    uint32_t ts;
};

Session* get_tcp_session(Flow* lwssn)
{
    return new TcpSession(lwssn);
}

static inline int SetupOK (const TcpTracker* st)
{
    return ( (st->s_mgr.sub_state & SUB_SETUP_OK) == SUB_SETUP_OK );
}

static inline uint32_t SegsToFlush (const TcpTracker* st, unsigned max)
{
    uint32_t n = st->seg_count - st->flush_count;
    TcpSegment* s;

    if ( !n || max == 1 )
        return n;

    n = 0;
    s = st->seglist;

    while ( s )
    {
        if ( !s->buffered && SEQ_LT(s->seq, st->r_win_base) )
            n++;

        if ( max && n == max )
            return n;

        s = s->next;
    }
    return n;
}

static inline bool DataToFlush (const TcpTracker* st)
{
    // needed by stream_reassemble:action disable; can fire on rebuilt
    // packets, yanking the splitter out from under us :(
    if ( !st->flush_policy )
        return false;

    if (
        st->flush_policy == STREAM_FLPOLICY_ON_DATA ||
        st->splitter->is_paf()
        )
        return ( SegsToFlush(st, 1) > 0 );

    return ( SegsToFlush(st, 2) > 1 );  // FIXIT-L return false?
}

/*  P R O T O T Y P E S  ********************************************/

static int ProcessTcp(Flow*, Packet*, TcpDataBlock*, StreamTcpConfig*);

static inline int CheckFlushPolicyOnData(
    TcpSession *, TcpTracker *, TcpTracker *, Packet *);

static inline int CheckFlushPolicyOnAck(
    TcpSession *, TcpTracker *, TcpTracker *, Packet *);

static void StreamSeglistAddNode(TcpTracker *, TcpSegment *, TcpSegment *);
static int StreamSeglistDeleteNode(TcpTracker*, TcpSegment*);
static int StreamSeglistDeleteNodeTrim(TcpTracker*, TcpSegment*, uint32_t flush_seq);

static int DupStreamNode(
    Packet*, TcpTracker*, TcpSegment* left, TcpSegment** retSeg);

static uint32_t StreamGetTcpTimestamp(Packet*, uint32_t*, int strip);

/*  G L O B A L S  **************************************************/

static const char* const reassembly_policy_names[] =
{
    "no policy",
    "first",
    "last",
    "linux",
    "old_linux",
    "bsd",
    "macos",
    "solaris",
    "irix",
    "hpux11",
    "hpux10",
    "windows",
    "win_2003",
    "vista",
    "proxy"
};

#ifdef DEBUG_STREAM_EX
static const char* const state_names[] =
{
    "none",
    "listen",
    "syn_rcvd",
    "syn_sent",
    "established",
    "close_wait",
    "last_ack",
    "fin_wait_1",
    "closing",
    "fin_wait_2",
    "time_wait",
    "closed"
};

static const char* const flush_policy_names[] =
{
    "ignore",
    "on-ack",
    "on-data"
};
#endif

static THREAD_LOCAL Packet* s5_pkt = nullptr;

//-------------------------------------------------------------------------
// TcpSegment stuff
//-------------------------------------------------------------------------

TcpSegment* TcpSegment::init(
    Packet* p, const struct timeval& tv, const uint8_t* data, unsigned dsize)
{
    TcpSegment* ss;
    unsigned size = sizeof(*ss);

    if ( dsize > 0 )
        size += dsize - 1;  // ss contains 1st byte

    tcp_memcap->alloc(size);

    if ( tcp_memcap->at_max() )
    {
        sfBase.iStreamFaults++;

        // FIXIT eliminate the packet dependency?
        if ( p )
            flow_con->prune_flows(PktType::TCP, p);
    }

    ss = (TcpSegment*)malloc(size);

    if ( !ss )
        return nullptr;

    ss->tv = tv;
    memcpy(ss->data, data, dsize);
    ss->orig_dsize = dsize;

    ss->payload = ss->data;
    ss->prev = ss->next = nullptr;
    ss->ts = ss->seq = 0;
    ss->size = ss->orig_dsize;
    ss->urg_offset = 0;
    ss->buffered = 0;

    return ss;
}

void TcpSegment::term(TcpSegment* seg)
{
    unsigned dropped = sizeof(TcpSegment);

    if ( seg->size > 0 )
        dropped += seg->size - 1;  // seg contains 1st byte

    tcp_memcap->dealloc(dropped);
    free(seg);
    tcpStats.segs_released++;
}

bool TcpSegment::is_retransmit(const uint8_t* rdata, uint16_t rsize, uint32_t rseq)
{
    // retransmit must have same payload at same place
    if ( !SEQ_EQ(seq, rseq) )
        return false;

    if ( ((size <= rsize) and !memcmp(data, rdata, size)) or
        ((size > rsize) and !memcmp(data, rdata, rsize)) )
        return true;

    return false;
}

//-------------------------------------------------------------------------
// flush policy stuff
//-------------------------------------------------------------------------

static inline void init_flush_policy(Flow*, TcpTracker* trk)
{
    if ( !trk->splitter )
        trk->flush_policy = STREAM_FLPOLICY_IGNORE;

    else if ( !Normalize_IsEnabled(NORM_TCP_IPS) )
        trk->flush_policy = STREAM_FLPOLICY_ON_ACK;

    else
        trk->flush_policy = STREAM_FLPOLICY_ON_DATA;
}

void StreamUpdatePerfBaseState(SFBASE *sf_base, Flow *lwssn, char newState)
{
    if (!lwssn)
    {
        return;
    }

    switch (newState)
    {
    case TCP_STATE_SYN_SENT:
        if (!(lwssn->ssn_state.session_flags & SSNFLAG_COUNTED_INITIALIZE))
        {
            sf_base->iSessionsInitializing++;
            lwssn->ssn_state.session_flags |= SSNFLAG_COUNTED_INITIALIZE;
        }
        break;
    case TCP_STATE_ESTABLISHED:
        if (!(lwssn->ssn_state.session_flags & SSNFLAG_COUNTED_ESTABLISH))
        {
            sf_base->iSessionsEstablished++;

            if (perfmon_config && (perfmon_config->perf_flags & SFPERF_FLOWIP))
                UpdateFlowIPState(&sfFlow, &lwssn->client_ip, &lwssn->server_ip,
                    SFS_STATE_TCP_ESTABLISHED);

            lwssn->ssn_state.session_flags |= SSNFLAG_COUNTED_ESTABLISH;

            if ((lwssn->ssn_state.session_flags & SSNFLAG_COUNTED_INITIALIZE) &&
                !(lwssn->ssn_state.session_flags & SSNFLAG_COUNTED_CLOSING))
            {
                assert(sf_base->iSessionsInitializing);
                sf_base->iSessionsInitializing--;
            }
        }
        break;
    case TCP_STATE_CLOSING:
        if (!(lwssn->ssn_state.session_flags & SSNFLAG_COUNTED_CLOSING))
        {
            sf_base->iSessionsClosing++;
            lwssn->ssn_state.session_flags |= SSNFLAG_COUNTED_CLOSING;
            if (lwssn->ssn_state.session_flags & SSNFLAG_COUNTED_ESTABLISH)
            {
                assert(sf_base->iSessionsEstablished);
                sf_base->iSessionsEstablished--;

                if (perfmon_config && (perfmon_config->perf_flags & SFPERF_FLOWIP))
                    UpdateFlowIPState(&sfFlow, &lwssn->client_ip, &lwssn->server_ip,
                        SFS_STATE_TCP_CLOSED);
            }
            else if (lwssn->ssn_state.session_flags & SSNFLAG_COUNTED_INITIALIZE)
            {
                assert(sf_base->iSessionsInitializing);
                sf_base->iSessionsInitializing--;
            }
        }
        break;
    case TCP_STATE_CLOSED:
        if (lwssn->ssn_state.session_flags & SSNFLAG_COUNTED_CLOSING)
        {
            assert(sf_base->iSessionsClosing);
            sf_base->iSessionsClosing--;
        }
        else if (lwssn->ssn_state.session_flags & SSNFLAG_COUNTED_ESTABLISH)
        {
            assert(sf_base->iSessionsEstablished);
            sf_base->iSessionsEstablished--;

            if (perfmon_config && (perfmon_config->perf_flags & SFPERF_FLOWIP))
                UpdateFlowIPState(&sfFlow, &lwssn->client_ip, &lwssn->server_ip,
                    SFS_STATE_TCP_CLOSED);
        }
        else if (lwssn->ssn_state.session_flags & SSNFLAG_COUNTED_INITIALIZE)
        {
            assert(sf_base->iSessionsInitializing);
            sf_base->iSessionsInitializing--;
        }
        break;
    default:
        break;
    }
    sf_base->stream_mem_in_use = tcp_memcap->used();
}

//-------------------------------------------------------------------------
// policy translation
//-------------------------------------------------------------------------

static inline uint16_t GetTcpReassemblyPolicy(int os_policy)
{
    switch (os_policy)
    {
    case STREAM_POLICY_FIRST:
        return REASSEMBLY_POLICY_FIRST;
    case STREAM_POLICY_LINUX:
        return REASSEMBLY_POLICY_LINUX;
    case STREAM_POLICY_BSD:
        return REASSEMBLY_POLICY_BSD;
    case STREAM_POLICY_OLD_LINUX:
        return REASSEMBLY_POLICY_OLD_LINUX;
    case STREAM_POLICY_LAST:
        return REASSEMBLY_POLICY_LAST;
    case STREAM_POLICY_WINDOWS:
        return REASSEMBLY_POLICY_WINDOWS;
    case STREAM_POLICY_SOLARIS:
        return REASSEMBLY_POLICY_SOLARIS;
    case STREAM_POLICY_WINDOWS2K3:
        return REASSEMBLY_POLICY_WINDOWS2K3;
    case STREAM_POLICY_VISTA:
        return REASSEMBLY_POLICY_VISTA;
    case STREAM_POLICY_HPUX11:
        return REASSEMBLY_POLICY_HPUX11;
    case STREAM_POLICY_HPUX10:
        return REASSEMBLY_POLICY_HPUX10;
    case STREAM_POLICY_IRIX:
        return REASSEMBLY_POLICY_IRIX;
    case STREAM_POLICY_MACOS:
        return REASSEMBLY_POLICY_MACOS;
    case STREAM_POLICY_PROXY:
        return REASSEMBLY_POLICY_FIRST;
    default:
        return REASSEMBLY_POLICY_DEFAULT;
    }
}

//-------------------------------------------------------------------------
// config methods
//-------------------------------------------------------------------------

StreamTcpConfig::StreamTcpConfig()
{
    policy = STREAM_POLICY_DEFAULT;
    reassembly_policy = REASSEMBLY_POLICY_DEFAULT;

    flags = 0;
    flush_factor = 0;

    session_timeout = STREAM_DEFAULT_SSN_TIMEOUT;
    max_window = 0;
    overlap_limit = 0;

    max_queued_bytes = STREAM_DEFAULT_MAX_QUEUED_BYTES;
    max_queued_segs = STREAM_DEFAULT_MAX_QUEUED_SEGS;

    max_consec_small_segs = STREAM_DEFAULT_CONSEC_SMALL_SEGS;
    max_consec_small_seg_size = STREAM_DEFAULT_MAX_SMALL_SEG_SIZE;

    hs_timeout = -1;
    footprint = 0;
    paf_max = 16384;
}

inline bool StreamTcpConfig::require_3whs()
{ return hs_timeout >= 0; }

inline bool StreamTcpConfig::midstream_allowed(Packet* p)
{
    if ( (hs_timeout < 0) ||
        (p->pkth->ts.tv_sec - packet_first_time() < hs_timeout) )
    {
        return true;
    }
    return false;
}

//-------------------------------------------------------------------------
// when client ports are configured, that means c2s and is stored on the
// client side; when the session starts, the server policy is obtained from
// the client side because segments are stored on the receiving side.
//
// this could be improved further by storing the c2s policy on the server
// side and then obtaining server policy from the server on session
// startup.
//
// either way, this client / server distinction must be kept in mind to
// make sense of the code in this file.
//-------------------------------------------------------------------------

static void StreamPrintTcpConfig(StreamTcpConfig* config)
{
    LogMessage("Stream TCP Policy config:\n");
    LogMessage("    Reassembly Policy: %s\n",
        reassembly_policy_names[config->reassembly_policy]);
    LogMessage("    Timeout: %d seconds\n", config->session_timeout);
    if (config->max_window != 0)
        LogMessage("    Max TCP Window: %u\n", config->max_window);
    if (config->overlap_limit)
        LogMessage("    Limit on TCP Overlaps: %d\n", config->overlap_limit);
    if (config->max_queued_bytes != 0)
    {
        LogMessage("    Maximum number of bytes to queue per session: %d\n",
            config->max_queued_bytes);
    }
    if (config->max_queued_segs != 0)
    {
        LogMessage("    Maximum number of segs to queue per session: %d\n",
            config->max_queued_segs);
    }
    if (config->flags)
    {
        LogMessage("    Options:\n");
        if (config->flags & STREAM_CONFIG_IGNORE_ANY)
        {
            LogMessage("        Ignore Any -> Any Rules: YES\n");
        }
        if (config->flags & STREAM_CONFIG_NO_ASYNC_REASSEMBLY)
        {
            LogMessage("        Don't queue packets on one-sided sessions: YES\n");
        }
    }
    if (config->hs_timeout < 0)
        LogMessage("    Require 3-Way Handshake: NO\n");
    else
        LogMessage("    Require 3-Way Handshake: after %d seconds\n",
            config->hs_timeout);

#ifdef REG_TEST
    LogMessage("    TCP Session Size: %lu\n",sizeof(TcpSession));
#endif
}

//-------------------------------------------------------------------------
// attribute table foo
//-------------------------------------------------------------------------

int StreamVerifyTcpConfig(SnortConfig*, StreamTcpConfig*)
{
    return 0;
}

#ifdef DEBUG_STREAM_EX
static void PrintStateMgr(StateMgr* s)
{
    LogMessage("StateMgr:\n");
    LogMessage("    state:          %s\n", state_names[s->state]);
    LogMessage("    state_queue:    %s\n", state_names[s->state_queue]);
    LogMessage("    expected_flags: 0x%X\n", s->expected_flags);
    LogMessage("    transition_seq: 0x%X\n", s->transition_seq);
    LogMessage("    stq_get_seq:    %d\n", s->stq_get_seq);
}

static void PrintTcpTracker(TcpTracker *s)
{
    LogMessage(" + TcpTracker +\n");
    LogMessage("    isn:                0x%X\n", s->isn);
    LogMessage("    ts_last:            %u\n", s->ts_last);
    LogMessage("    wscale:             %u\n", s->wscale);
    LogMessage("    mss:                0x%08X\n", s->mss);
    LogMessage("    l_unackd:           %X\n", s->l_unackd);
    LogMessage("    l_nxt_seq:          %X\n", s->l_nxt_seq);
    LogMessage("    l_window:           %u\n", s->l_window);
    LogMessage("    r_nxt_ack:          %X\n", s->r_nxt_ack);
    LogMessage("    r_win_base:         %X\n", s->r_win_base);
    LogMessage("    seglist_base_seq:   %X\n", s->seglist_base_seq);
    LogMessage("    seglist:            %p\n", (void*)s->seglist);
    LogMessage("    seglist_tail:       %p\n", (void*)s->seglist_tail);
    LogMessage("    seg_count:          %d\n", s->seg_count);
    LogMessage("    seg_bytes_total:    %d\n", s->seg_bytes_total);
    LogMessage("    seg_bytes_logical:  %d\n", s->seg_bytes_logical);

    PrintStateMgr(&s->s_mgr);
}

static void PrintTcpSession(TcpSession* ts)
{
    char buf[64];

    LogMessage("TcpSession:\n");
    sfip_ntop(&ts->flow->server_ip, buf, sizeof(buf));
    LogMessage("    server IP:          %s\n", buf);
    sfip_ntop(&ts->flow->client_ip, buf, sizeof(buf));
    LogMessage("    client IP:          %s\n", buf);

    LogMessage("    server port:        %d\n", ts->flow->server_port);
    LogMessage("    client port:        %d\n", ts->flow->client_port);

    LogMessage("    flags:              0x%X\n", ts->flow->ssn_state.session_flags);

    LogMessage("Client Tracker:\n");
    PrintTcpTracker(&ts->client);
    LogMessage("Server Tracker:\n");
    PrintTcpTracker(&ts->server);
}

static void PrintTcpDataBlock(TcpDataBlock* tdb)
{
    LogMessage("TcpDataBlock:\n");
    LogMessage("    seq:    0x%08X\n", tdb->seq);
    LogMessage("    ack:    0x%08X\n", tdb->ack);
    LogMessage("    win:    %d\n", tdb->win);
    LogMessage("    end:    0x%08X\n", tdb->end_seq);
}

static void PrintFlushMgr(FlushMgr* fm)
{
    if (fm == NULL)
        return;

    switch (fm->flush_policy)
    {
    case STREAM_FLPOLICY_IGNORE:
        STREAM_DEBUG_WRAP(DebugMessage(
            DEBUG_STREAM_STATE, "    IGNORE\n"); );
        break;

    case STREAM_FLPOLICY_ON_ACK:
        STREAM_DEBUG_WRAP(DebugMessage(
            DEBUG_STREAM_STATE, "    PROTOCOL\n"); );
        break;

    case STREAM_FLPOLICY_ON_DATA:
        STREAM_DEBUG_WRAP(DebugMessage(
            DEBUG_STREAM_STATE, "    PROTOCOL_IPS\n"); );
        break;
    }
}

#endif  // DEBUG_STREAM_EX

static inline void Discard()
{
    tcpStats.discards++;
}

static inline void EventSynOnEst()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_SYN_ON_EST);
    tcpStats.events++;
}

static inline void EventExcessiveOverlap()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_EXCESSIVE_TCP_OVERLAPS);
    tcpStats.events++;
}

static inline void EventBadTimestamp()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_BAD_TIMESTAMP);
    tcpStats.events++;
}

static inline void EventWindowTooLarge()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_WINDOW_TOO_LARGE);
    tcpStats.events++;
}

static inline void EventDataOnSyn()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_DATA_ON_SYN);
    tcpStats.events++;
}

static inline void EventDataOnClosed()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_DATA_ON_CLOSED);
    tcpStats.events++;
}

static inline void EventDataAfterReset()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_DATA_AFTER_RESET);
    tcpStats.events++;
}

static inline void EventBadSegment()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_BAD_SEGMENT);
    tcpStats.events++;
}

static inline void EventSessionHijackedClient()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_SESSION_HIJACKED_CLIENT);
    tcpStats.events++;
}

static inline void EventSessionHijackedServer()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_SESSION_HIJACKED_SERVER);
    tcpStats.events++;
}

static inline void EventDataWithoutFlags()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_DATA_WITHOUT_FLAGS);
    tcpStats.events++;
}

static inline void EventMaxSmallSegsExceeded()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_SMALL_SEGMENT);
    tcpStats.events++;
}

static inline void Event4whs()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_4WAY_HANDSHAKE);
    tcpStats.events++;
}

static inline void EventNoTimestamp()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_NO_TIMESTAMP);
    tcpStats.events++;
}

static inline void EventBadReset()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_BAD_RST);
    tcpStats.events++;
}

static inline void EventBadFin()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_BAD_FIN);
    tcpStats.events++;
}

static inline void EventBadAck()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_BAD_ACK);
    tcpStats.events++;
}

static inline void EventDataAfterRstRcvd()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_DATA_AFTER_RST_RCVD);
    tcpStats.events++;
}

static inline void EventInternal(uint32_t eventSid)
{
    if ( !InternalEventIsEnabled(snort_conf->rate_filter_config, eventSid) )
        return;

    tcpStats.internalEvents++;

    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "Stream raised internal event %d\n", eventSid); );

    SnortEventqAdd(GENERATOR_INTERNAL, eventSid);
}

static inline void EventWindowSlam()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_WINDOW_SLAM);
    tcpStats.events++;
}

static inline void EventNo3whs()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_NO_3WHS);
    tcpStats.events++;
}

/*
 *  Utility functions for TCP stuff
 */
enum PegCounts
{
    PC_TCP_TRIM_SYN,
    PC_TCP_TRIM_RST,
    PC_TCP_TRIM_WIN,
    PC_TCP_TRIM_MSS,
    PC_TCP_ECN_SSN,
    PC_TCP_TS_NOP,
    PC_TCP_IPS_DATA,
    PC_TCP_BLOCK,
    PC_MAX
};

static THREAD_LOCAL PegCount normStats[PC_MAX][NORM_MODE_MAX];

static const PegInfo pegName[] =
{
    { "tcp trim syn", "tcp segments trimmed on SYN" },
    { "tcp trim rst", "RST packets with data trimmed" },
    { "tcp trim win", "data trimed to window" },
    { "tcp trim mss", "data trimmed to MSS" },
    { "tcp ecn session", "ECN bits cleared" },
    { "tcp ts nop", "timestamp options cleared" },
    { "tcp ips data", "normalized segments" },
    { "tcp block", "blocked segments" },
    { nullptr, nullptr }
};

const PegInfo* Stream_GetNormPegs()
{ return pegName; }

NormPegs Stream_GetNormCounts(unsigned& c)
{
    c = PC_MAX;
    return normStats;
}

//-----------------------------------------------------------------------
// instead of centralizing all these normalizations so that
// Normalize_IsEnabled() is called only once, the checks and
// normalizations are localized.  this should lead to many
// fewer total checks.  however, it is best to minimize
// configuration checks on a per packet basis so there is
// still room for improvement.
static inline bool NormalDropPacketIf(Packet* p, NormFlags f)
{
    const NormMode mode = Normalize_GetMode(f);

    normStats[PC_TCP_BLOCK][mode]++;
    sfBase.iPegs[PERF_COUNT_TCP_BLOCK][mode]++;

    if ( mode == NORM_MODE_ON )
    {
        Active_DropPacket(p);
        return true;
    }
    return false;
}

static inline bool NormalStripTimeStamp(Packet* p, const TcpOption* opt, NormMode mode)
{
    normStats[PC_TCP_TS_NOP][mode]++;
    sfBase.iPegs[PERF_COUNT_TCP_TS_NOP][mode]++;

    if ( mode == NORM_MODE_ON )
    {
        // set raw option bytes to nops
        memset((uint8_t*)(opt), (uint8_t)tcp::TcpOptCode::NOP, TCPOLEN_TIMESTAMP);
        p->packet_flags |= PKT_MODIFIED;
        return true;
    }
    return false;
}

static inline void NormalTrimPayload(
    Packet* p, uint16_t max, TcpDataBlock* tdb)
{
    uint16_t fat = p->dsize - max;
    p->dsize = max;
    p->packet_flags |= (PKT_MODIFIED|PKT_RESIZED);
    tdb->end_seq -= fat;
}

static inline void NormalTrimPayloadIf(
    Packet* p, uint32_t max, TcpDataBlock* tdb,
    NormFlags flag, PegCounts peg, PerfCounts perf)
{
    const NormMode mode = Normalize_GetMode(flag);

    if ( mode == NORM_MODE_ON )
        NormalTrimPayload(p, max, tdb);

    normStats[peg][mode]++;
    sfBase.iPegs[perf][mode]++;
}

static inline void NormalTrimPayloadIfSyn(
    Packet* p, uint32_t max, TcpDataBlock* tdb)
{
    if ( p->dsize > max )
        NormalTrimPayloadIf(p, max, tdb,
            NORM_TCP_TRIM_SYN, PC_TCP_TRIM_SYN, PERF_COUNT_TCP_TRIM_SYN);
}

static inline void NormalTrimPayloadIfRst(
    Packet* p, uint32_t max, TcpDataBlock* tdb)
{
    if ( p->dsize > max )
        NormalTrimPayloadIf(p, max, tdb,
            NORM_TCP_TRIM_RST, PC_TCP_TRIM_RST, PERF_COUNT_TCP_TRIM_RST);
}

static inline void NormalTrimPayloadIfWin(
    Packet* p, uint32_t max, TcpDataBlock* tdb)
{
    if ( p->dsize > max )
        NormalTrimPayloadIf(p, max, tdb,
            NORM_TCP_TRIM_WIN, PC_TCP_TRIM_WIN, PERF_COUNT_TCP_TRIM_WIN);
}

static inline void NormalTrimPayloadIfMss(
    Packet* p, uint32_t max, TcpDataBlock* tdb)
{
    if ( p->dsize > max )
        NormalTrimPayloadIf(p, max, tdb,
            NORM_TCP_TRIM_MSS, PC_TCP_TRIM_MSS, PERF_COUNT_TCP_TRIM_MSS);
}

static inline void NormalTrackECN(TcpSession* s, TCPHdr* tcph, int req3way)
{
    if ( !s )
        return;

    if ( tcph->is_syn_ack() )
    {
        if ( !req3way || s->ecn )
            s->ecn = ((tcph->th_flags & (TH_ECE|TH_CWR)) == TH_ECE);
    }
    else if ( tcph->is_syn() )
        s->ecn = tcph->are_flags_set(TH_ECE|TH_CWR);
}

static inline void NormalCheckECN(TcpSession* s, Packet* p)
{
    if ( !s->ecn && (p->ptrs.tcph->th_flags & (TH_ECE|TH_CWR)) )
    {
        const NormMode mode = Normalize_GetMode(NORM_TCP_ECN_STR);

        if ( mode == NORM_MODE_ON )
        {
            ((TCPHdr*)p->ptrs.tcph)->th_flags &= ~(TH_ECE|TH_CWR);
            p->packet_flags |= PKT_MODIFIED;
        }
        normStats[PC_TCP_ECN_SSN][mode]++;
        sfBase.iPegs[PERF_COUNT_TCP_ECN_SSN][mode]++;
    }
}

//-------------------------------------------------------------------------
// ssn ingress is client; ssn egress is server

#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
static inline void SetPacketHeaderFoo(TcpSession* tcpssn, const Packet* p)
{
    if ( tcpssn->daq_flags & DAQ_PKT_FLAG_NOT_FORWARDING )
    {
        tcpssn->ingress_index = p->pkth->ingress_index;
        tcpssn->ingress_group = p->pkth->ingress_group;
        // ssn egress may be unknown, but will be correct
        tcpssn->egress_index = p->pkth->egress_index;
        tcpssn->egress_group = p->pkth->egress_group;
    }
    else if ( p->packet_flags & PKT_FROM_CLIENT )
    {
        tcpssn->ingress_index = p->pkth->ingress_index;
        tcpssn->ingress_group = p->pkth->ingress_group;
        // ssn egress not always correct here
    }
    else
    {
        // ssn ingress not always correct here
        tcpssn->egress_index = p->pkth->ingress_index;
        tcpssn->egress_group = p->pkth->ingress_group;
    }
    tcpssn->daq_flags = p->pkth->flags;
    tcpssn->address_space_id = p->pkth->address_space_id;
}

static inline void GetPacketHeaderFoo(
    const TcpSession* tcpssn, DAQ_PktHdr_t* pkth, uint32_t dir)
{
    if ( (dir & PKT_FROM_CLIENT) || (tcpssn->daq_flags & DAQ_PKT_FLAG_NOT_FORWARDING) )
    {
        pkth->ingress_index = tcpssn->ingress_index;
        pkth->ingress_group = tcpssn->ingress_group;
        pkth->egress_index = tcpssn->egress_index;
        pkth->egress_group = tcpssn->egress_group;
    }
    else
    {
        pkth->ingress_index = tcpssn->egress_index;
        pkth->ingress_group = tcpssn->egress_group;
        pkth->egress_index = tcpssn->ingress_index;
        pkth->egress_group = tcpssn->ingress_group;
    }
#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
    pkth->opaque = 0;
#endif
    pkth->flags = tcpssn->daq_flags;
    pkth->address_space_id = tcpssn->address_space_id;
}

static inline void SwapPacketHeaderFoo(TcpSession* tcpssn)
{
    if ( tcpssn->egress_index != DAQ_PKTHDR_UNKNOWN )
    {
        int32_t ingress_index;
        int32_t ingress_group;

        ingress_index = tcpssn->ingress_index;
        ingress_group = tcpssn->ingress_group;
        tcpssn->ingress_index = tcpssn->egress_index;
        tcpssn->ingress_group = tcpssn->egress_group;
        tcpssn->egress_index = ingress_index;
        tcpssn->egress_group = ingress_group;
    }
}

#endif

//-------------------------------------------------------------------------

static inline int IsBetween(uint32_t low, uint32_t high, uint32_t cur)
{
    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "(%X, %X, %X) = (low, high, cur)\n", low,high,cur); );

    /* If we haven't seen anything, ie, low & high are 0, return true */
    if ((low == 0) && (low == high))
        return 1;

    return (SEQ_GEQ(cur, low) && SEQ_LEQ(cur, high));
}

static inline uint32_t StreamGetWindow(
    Flow* lwssn, TcpTracker* st, TcpDataBlock* tdb)
{
    int32_t window;

    if ( st->l_window )
    {
        // don't use the window if we may have missed scaling
        if ( !(lwssn->session_state & STREAM_STATE_MIDSTREAM) )
            return st->l_window;
    }
    // one way zero window is unitialized
    // two way zero window is actually closed (regardless of scaling)
    else if ( lwssn->two_way_traffic() )
        return st->l_window;

    // ensure the data is in the window
    window = tdb->end_seq - st->r_win_base;

    if ( window <  0 )
        window = 0;

    return (uint32_t)window;
}

// ack number must ack syn
static inline int ValidRstSynSent(TcpTracker *st, TcpDataBlock *tdb)
{
    return tdb->ack == st->l_unackd;
}

// per rfc 793 a rst is valid if the seq number is in window
// for all states but syn-sent (handled above).  however, we
// validate here based on how various implementations actually
// handle a rst.
static inline int ValidRst(
    Flow* lwssn, TcpTracker *st, TcpDataBlock *tdb)
{
    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "Checking end_seq (%X) > r_win_base (%X) && "
        "seq (%X) < r_nxt_ack(%X)\n",
        tdb->end_seq, st->r_win_base, tdb->seq,
        st->r_nxt_ack+StreamGetWindow(lwssn, st, tdb)); );

    switch (st->os_policy)
    {
    case STREAM_POLICY_HPUX11:
        if (SEQ_GEQ(tdb->seq, st->r_nxt_ack))
        {
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "rst is valid seq (>= next seq)!\n"); );
            return 1;
        }
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "rst is not valid seq (>= next seq)!\n"); );
        return 0;
        break;
    case STREAM_POLICY_FIRST:
    case STREAM_POLICY_LAST:
    case STREAM_POLICY_MACOS:
    case STREAM_POLICY_WINDOWS:
    case STREAM_POLICY_VISTA:
    case STREAM_POLICY_WINDOWS2K3:
    case STREAM_POLICY_HPUX10:
    case STREAM_POLICY_IRIX:
        if (SEQ_EQ(tdb->seq, st->r_nxt_ack))
        {
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "rst is valid seq (next seq)!\n"); );
            return 1;
        }
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "rst is not valid seq (next seq)!\n"); );
        return 0;
        break;
    case STREAM_POLICY_BSD:
    case STREAM_POLICY_LINUX:
    case STREAM_POLICY_OLD_LINUX:
    case STREAM_POLICY_SOLARIS:
        if (SEQ_GEQ(tdb->end_seq, st->r_win_base))
        {
            // reset must be admitted when window closed
            if ( SEQ_LEQ(tdb->seq, st->r_win_base+StreamGetWindow(lwssn, st, tdb)) )
            {
                STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "rst is valid seq (within window)!\n"); );
                return 1;
            }
        }

        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "rst is not valid seq (within window)!\n"); );
        return 0;
        break;
    }

    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "rst is not valid!\n"); );
    return 0;
}

static inline int ValidTimestamp(
    TcpTracker *talker, TcpTracker *listener, TcpDataBlock *tdb,
    Packet *p, int *eventcode, int *got_ts)
{
    if ( p->ptrs.tcph->th_flags & TH_RST or
        listener->config->policy == STREAM_POLICY_PROXY )
        return ACTION_NOTHING;

#if 0
    if ( p->ptrs.tcph->th_flags & TH_ACK &&
        Normalize_IsEnabled(NORM_TCP_OPT) )
    {
        // FIXIT-L validate tsecr here (check that it was previously sent)
        // checking for the most recent ts is easy enough must check if
        // ts are up to date in retransmitted packets
    }
#endif
    /*
     * check PAWS
     */
    if ((talker->flags & TF_TSTAMP) && (listener->flags & TF_TSTAMP))
    {
        char validate_timestamp = 1;
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Checking timestamps for PAWS\n"); );

        *got_ts = StreamGetTcpTimestamp(p, &tdb->ts, 0);

        if (*got_ts)
        {
            if (listener->config->policy == STREAM_POLICY_HPUX11)
            {
                /* HPUX 11 ignores timestamps for out of order segments */
                if ((listener->flags & TF_MISSING_PKT) ||
                    !SEQ_EQ(listener->r_nxt_ack, tdb->seq))
                {
                    validate_timestamp = 0;
                }
            }

            if (talker->flags & TF_TSTAMP_ZERO)
            {
                /* Handle the case where the 3whs used a 0 timestamp.  Next packet
                 * from that endpoint should have a valid timestamp... */
                if ((listener->config->policy == STREAM_POLICY_LINUX) ||
                    (listener->config->policy == STREAM_POLICY_WINDOWS2K3))
                {
                    /* Linux, Win2k3 et al.  do not support timestamps if
                     * the 3whs used a 0 timestamp. */
                    talker->flags &= ~TF_TSTAMP;
                    listener->flags &= ~TF_TSTAMP;
                    validate_timestamp = 0;
                }
                else if ((listener->config->policy == STREAM_POLICY_OLD_LINUX) ||
                    (listener->config->policy == STREAM_POLICY_WINDOWS) ||
                    (listener->config->policy == STREAM_POLICY_VISTA))
                {
                    /* Older Linux (2.2 kernel & earlier), Win32 (non 2K3)
                     * allow the 3whs to use a 0 timestamp. */
                    talker->flags &= ~TF_TSTAMP_ZERO;
                    if (SEQ_EQ(listener->r_nxt_ack, tdb->seq))
                    {
                        talker->ts_last = tdb->ts;
                        validate_timestamp = 0; /* Ignore the timestamp for this
                                                 * first packet, next one will
                                                 * checked. */
                    }
                }
            }

            if (validate_timestamp)
            {
                int result = 0;
                if (listener->config->policy == STREAM_POLICY_LINUX)
                {
                    /* Linux 2.6 accepts timestamp values that are off
                     * by one. */
                    result = (int)((tdb->ts - talker->ts_last) + 1);
                }
                else
                {
                    result = (int)(tdb->ts - talker->ts_last);
                }

                if (result < 0)
                {
                    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "Packet outside PAWS window, dropping\n"); );
                    /* bail, we've got a packet outside the PAWS window! */
                    //Discard();
                    *eventcode |= EVENT_BAD_TIMESTAMP;
                    NormalDropPacketIf(p, NORM_TCP_OPT);
                    return ACTION_BAD_PKT;
                }
                else if ((talker->ts_last != 0) &&
                    ((uint32_t)p->pkth->ts.tv_sec > talker->ts_last_pkt+PAWS_24DAYS))
                {
                    /* this packet is from way too far into the future */
                    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "packet PAWS timestamp way too far ahead of"
                        "last packet %d %d...\n", p->pkth->ts.tv_sec,
                        talker->ts_last_pkt); );
                    //Discard();
                    *eventcode |= EVENT_BAD_TIMESTAMP;
                    NormalDropPacketIf(p, NORM_TCP_OPT);
                    return ACTION_BAD_PKT;
                }
                else
                {
                    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "packet PAWS ok...\n"); );
                }
            }
        }
        else
        {
            /* we've got a packet with no timestamp, but 3whs indicated talker
             * was doing timestamps.  This breaks protocol, however, some servers
             * still ack the packet with the missing timestamp.  Log an alert,
             * but continue to process the packet
             */
            *eventcode |= EVENT_NO_TIMESTAMP;
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "packet no timestamp, had one earlier from this side...ok for now...\n"); );

            if (listener->config->policy == STREAM_POLICY_SOLARIS)
            {
                /* Solaris stops using timestamps if it receives a packet
                 * without a timestamp and there were timestamps in use.
                 */
                listener->flags &= ~TF_TSTAMP;
            }
            NormalDropPacketIf(p, NORM_TCP_OPT);
        }
    }
    else if ( p->ptrs.tcph->is_syn_only() )
    {
        *got_ts = StreamGetTcpTimestamp(p, &tdb->ts, 0);
        if ( *got_ts )
            talker->flags |= TF_TSTAMP;
    }
    else
    {
        // if we are not handling timestamps, and this isn't a syn
        // (only), and we have seen a valid 3way setup, then we strip
        // (nop) the timestamp option.  this includes the cases where
        // we disable timestamp handling.
        int strip = ( SetupOK(talker) && SetupOK(listener) );
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "listener not doing timestamps...\n"); );
        *got_ts = StreamGetTcpTimestamp(p, &tdb->ts, strip);

        if (*got_ts)
        {
            if (!(talker->flags & TF_TSTAMP))
            {
                /* Since we skipped the SYN, may have missed the talker's
                 * timestamp there, so set it now.
                 */
                talker->flags |= TF_TSTAMP;
                if (tdb->ts == 0)
                {
                    talker->flags |= TF_TSTAMP_ZERO;
                }
            }

            /* Only valid to test this if listener is using timestamps.
             * Otherwise, timestamp in this packet is not used, regardless
             * of its value. */
            if ((tdb->ts == 0) && (listener->flags & TF_TSTAMP))
            {
                switch (listener->os_policy)
                {
                case STREAM_POLICY_WINDOWS:
                case STREAM_POLICY_VISTA:
                case STREAM_POLICY_WINDOWS2K3:
                case STREAM_POLICY_OLD_LINUX:
                case STREAM_POLICY_SOLARIS:
                    /* Old Linux & Windows allows a 0 timestamp value. */
                    break;
                default:
                    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "Packet with 0 timestamp, dropping\n"); );
                    //Discard();
                    /* bail */
                    *eventcode |= EVENT_BAD_TIMESTAMP;
                    return ACTION_BAD_PKT;
                }
            }
        }
    }
    return ACTION_NOTHING;
}

#ifdef S5_PEDANTIC
// From RFC 793:
//
//    Segment Receive  Test
//    Length  Window
//    ------- -------  -------------------------------------------
//
//       0       0     SEG.SEQ = RCV.NXT
//
//       0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
//
//      >0       0     not acceptable
//
//      >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
//                     or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
//
static inline int ValidSeq(
    const Packet* p, Flow* lwssn, TcpTracker *st, TcpDataBlock *tdb)
{
    uint32_t win = StreamGetWindow(lwssn, st, tdb);

    if ( !p->dsize )
    {
        if ( !win )
        {
            return ( tdb->seq == st->r_win_base );
        }
        return SEQ_LEQ(st->r_win_base, tdb->seq) &&
               SEQ_LT(tdb->seq, st->r_win_base+win);
    }
    if ( !win )
        return 0;

    if ( SEQ_LEQ(st->r_win_base, tdb->seq) &&
        SEQ_LT(tdb->seq, st->r_win_base+win) )
        return 1;

    return SEQ_LEQ(st->r_win_base, tdb->end_seq) &&
           SEQ_LT(tdb->end_seq, st->r_win_base+win);
}

#else
static inline int ValidSeq(
    const Packet* p, Flow* lwssn, TcpTracker *st, TcpDataBlock *tdb)
{
    int right_ok;
    uint32_t left_seq;

    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "Checking end_seq (%X) > r_win_base (%X) && "
        "seq (%X) < r_nxt_ack(%X)\n",
        tdb->end_seq, st->r_win_base, tdb->seq,
        st->r_nxt_ack+StreamGetWindow(lwssn, st, tdb)); );

    if ( SEQ_LT(st->r_nxt_ack, st->r_win_base) )
        left_seq = st->r_nxt_ack;
    else
        left_seq = st->r_win_base;

    if ( p->dsize )
        right_ok = SEQ_GT(tdb->end_seq, left_seq);
    else
        right_ok = SEQ_GEQ(tdb->end_seq, left_seq);

    if ( right_ok )
    {
        uint32_t win = StreamGetWindow(lwssn, st, tdb);

        if ( SEQ_LEQ(tdb->seq, st->r_win_base+win) )
        {
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "seq is within window!\n"); );
            return 1;
        }
        else
        {
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "seq is past the end of the window!\n"); );
        }
    }
    else
    {
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "end_seq is before win_base\n"); );
    }
    return 0;
}

#endif

static inline void UpdateSsn(
    Packet*, TcpTracker *rcv, TcpTracker *snd, TcpDataBlock *tdb)
{
#if 0
    if (
        // FIXIT-L these checks are a hack to avoid off by one normalization
        // due to FIN ... if last segment filled a hole, r_nxt_ack is not at
        // end of data, FIN is ignored so sequence isn't bumped, and this
        // forces seq-- on ACK of FIN.  :(
        rcv->s_mgr.state == TCP_STATE_ESTABLISHED &&
        rcv->s_mgr.state_queue == TCP_STATE_NONE &&
        Normalize_IsEnabled(NORM_TCP_IPS) )
    {
        // walk the seglist until a gap or tdb->ack whichever is first
        // if a gap exists prior to ack, move ack back to start of gap
        TcpSegment* seg = snd->seglist;

        // FIXIT-L must check ack oob with empty seglist
        // FIXIT-L add lower gap bound to tracker for efficiency?
        while ( seg )
        {
            uint32_t seq = seg->seq + seg->size;
            if ( SEQ_LEQ(tdb->ack, seq) )
                break;

            seg = seg->next;

            if ( !seg || seg->seq > seq )
            {
                // normalize here
                tdb->ack = seq;
                ((TCPHdr*)p->ptrs.tcph)->th_ack = htonl(seq);
                p->packet_flags |= PKT_MODIFIED;
                break;
            }
        }
    }
#endif
    // ** if we don't see a segment, we can't track seq at ** below
    // so we update the seq by the ack if it is beyond next expected
    if (SEQ_GT(tdb->ack, rcv->l_unackd))
        rcv->l_unackd = tdb->ack;

    // ** this is how we track the last seq number sent
    // as is l_unackd is the "last left" seq recvd
    snd->l_unackd = tdb->seq;

    if (SEQ_GT(tdb->end_seq, snd->l_nxt_seq))
        snd->l_nxt_seq = tdb->end_seq;

    if (!SEQ_EQ(snd->r_win_base, tdb->ack))
    {
        snd->small_seg_count = 0;
    }
#ifdef S5_PEDANTIC
    if ( SEQ_GT(tdb->ack, snd->r_win_base) &&
        SEQ_LEQ(tdb->ack, snd->r_nxt_ack) )
#else
    if (SEQ_GT(tdb->ack, snd->r_win_base))
#endif
        snd->r_win_base = tdb->ack;

    snd->l_window = tdb->win;
}

void tcp_sinit()
{
    s5_pkt = PacketManager::encode_new();
    tcp_memcap = new Memcap(26214400); // FIXIT-M replace with session memcap
    //AtomSplitter::init();  // FIXIT-L PAF implement
}

void tcp_sterm()
{
    if (s5_pkt)
    {
        PacketManager::encode_delete(s5_pkt);
        s5_pkt = nullptr;
    }

    delete tcp_memcap;
    tcp_memcap = nullptr;
}

static inline void SetupTcpDataBlock(TcpDataBlock* tdb, Packet* p)
{
    tdb->seq = ntohl(p->ptrs.tcph->th_seq);
    tdb->ack = ntohl(p->ptrs.tcph->th_ack);
    tdb->win = ntohs(p->ptrs.tcph->th_win);
    tdb->end_seq = tdb->seq + (uint32_t)p->dsize;
    tdb->ts = 0;

    if (p->ptrs.tcph->th_flags & TH_SYN)
    {
        tdb->end_seq++;
        if (!(p->ptrs.tcph->th_flags & TH_ACK))
            EventInternal(INTERNAL_EVENT_SYN_RECEIVED);
    }
    // don't bump end_seq for fin here
    // we will bump if/when fin is processed

#ifdef DEBUG_STREAM_EX
    PrintTcpDataBlock(&tdb);
#endif
}

static void DeleteSeglist(TcpSegment *listhead)
{
    TcpSegment *idx = listhead;
    TcpSegment *dump_me;
    int i = 0;

    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "In DeleteSeglist\n"); );
    while (idx)
    {
        i++;
        dump_me = idx;
        idx = idx->next;
        TcpSegment::term(dump_me);
    }

    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "Dropped %d segments\n", i); );
}

static inline int purge_alerts(
    TcpTracker *st, uint32_t /*flush_seq*/, Flow* flow)
{
    int i;
    int new_count = 0;

    for (i=0; i<st->alert_count; i++)
    {
        StreamAlertInfo* ai = st->alerts + i;

        //if (SEQ_LT(ai->seq, flush_seq) )
        {
            stream.log_extra_data(
                flow, st->xtradata_mask, ai->event_id, ai->event_second);

            memset(ai, 0, sizeof(*ai));
        }
#if 0
        else
        {
            if (new_count != i)
            {
                st->alerts[new_count] = st->alerts[i];
            }
            new_count++;
        }
#endif
    }
    st->alert_count = new_count;

    return new_count;
}

static inline int purge_to_seq(TcpSession *tcpssn, TcpTracker *st, uint32_t flush_seq)
{
    TcpSegment *ss = NULL;
    TcpSegment *dump_me = NULL;
    int purged_bytes = 0;
    uint32_t last_ts = 0;

    if (st->seglist == NULL)
    {
        if ( SEQ_LT(st->seglist_base_seq, flush_seq) )
        {
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "setting st->seglist_base_seq to 0x%X\n", flush_seq); );
            st->seglist_base_seq = flush_seq;
        }
        return 0;
    }

    ss = st->seglist;

    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "In purge_to_seq, start seq = 0x%X end seq = 0x%X delta %d\n",
        ss->seq, flush_seq, flush_seq-ss->seq); );
    while (ss)
    {
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "s: %X  sz: %d\n", ss->seq, ss->size); );
        dump_me = ss;

        ss = ss->next;
        if (SEQ_LT(dump_me->seq, flush_seq))
        {
            if (dump_me->ts > last_ts)
            {
                last_ts = dump_me->ts;
            }
            purged_bytes += StreamSeglistDeleteNodeTrim(st, dump_me, flush_seq);
        }
        else
            break;
    }

    if ( SEQ_LT(st->seglist_base_seq, flush_seq) )
    {
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "setting st->seglist_base_seq to 0x%X\n", flush_seq); );
        st->seglist_base_seq = flush_seq;
    }
    if ( SEQ_LT(st->r_nxt_ack, flush_seq) )
        st->r_nxt_ack = flush_seq;

    purge_alerts(st, flush_seq, tcpssn->flow);

    if (st->seglist == NULL)
    {
        st->seglist_tail = NULL;
    }

    /* Update the "last" time stamp seen from the other side
     * to be the most recent timestamp (largest) that was removed
     * from the queue.  This will ensure that as we go forward,
     * last timestamp is the highest one that we had stored and
     * purged and handle the case when packets arrive out of order,
     * such as:
     * P1: seq 10, length 10, timestamp 10
     * P3: seq 30, length 10, timestamp 30
     * P2: seq 20, length 10, timestamp 20
     *
     * Without doing it this way, the timestamp would be 20.  With
     * the next packet to arrive (P4, seq 40), the ts_last value
     * wouldn't be updated for the talker in ProcessTcp() since that
     * code specificially looks for the NEXT sequence number.
     */
    if ( !last_ts )
        return purged_bytes;

    if (st == &tcpssn->client)
    {
        int32_t delta = last_ts - tcpssn->server.ts_last;
        if (delta > 0)
            tcpssn->server.ts_last = last_ts;
    }
    else if (st == &tcpssn->server)
    {
        int32_t delta = last_ts - tcpssn->client.ts_last;
        if (delta > 0)
            tcpssn->client.ts_last = last_ts;
    }

    return purged_bytes;
}

static inline void purge_all (TcpTracker *st)
{
    DeleteSeglist(st->seglist);
    st->seglist = st->seglist_tail = st->seglist_next = NULL;
    st->seg_count = st->flush_count = 0;
    st->seg_bytes_total = st->seg_bytes_logical = 0;
}

// purge_flushed_ackd():
// * must only purge flushed and acked bytes
// * we may flush partial segments
// * must adjust seq->seq and seg->size when a flush gets only the
//   initial part of a segment
// * FIXIT-L need flag to mark any reassembled packets that have a gap
//   (if we reassemble such)
static inline int purge_flushed_ackd (TcpSession *tcpssn, TcpTracker *st)
{
    TcpSegment* seg = st->seglist;
    uint32_t seq;

    if ( !st->seglist )
        return 0;

    seq = st->seglist->seq;

    while ( seg && seg->buffered )
    {
        uint32_t end = seg->seq + seg->size;

        if ( SEQ_GT(end, st->r_win_base) )
        {
            seq = st->r_win_base;
            break;
        }
        seq = end;
        seg = seg->next;
    }
    if ( seq != st->seglist->seq )
        return purge_to_seq(tcpssn, st, seq);

    return 0;
}

#define SEPARATOR \
    "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="

static void ShowRebuiltPacket(TcpSession* ssn, Packet* pkt)
{
    if ( (ssn->client.config->flags & STREAM_CONFIG_SHOW_PACKETS) ||
        (ssn->server.config->flags & STREAM_CONFIG_SHOW_PACKETS) )
    {
        LogFlow(pkt);
        LogNetData(pkt->data, pkt->dsize, pkt);
    }
}

static inline unsigned int getSegmentFlushSize(
    TcpTracker* st,
    TcpSegment *ss,
    uint32_t to_seq,
    unsigned int flushBufSize)
{
    unsigned int flushSize = ss->size;

    //copy only till flush buffer gets full
    if ( flushSize > flushBufSize )
        flushSize = flushBufSize;

    // copy only to flush point
    if ( paf_active(&st->paf_state) && SEQ_GT(ss->seq + flushSize, to_seq) )
        flushSize = to_seq - ss->seq;

    return flushSize;
}

/*
 * flush the client seglist up to the most recently acked segment
 */
static int FlushStream(
    Packet* p, TcpTracker *st, uint32_t toSeq, uint8_t *flushbuf,
    const uint8_t *flushbuf_end)
{
    uint16_t bytes_flushed = 0;
    STREAM_DEBUG_WRAP(uint32_t bytes_queued = st->seg_bytes_logical; );
    uint32_t segs = 0;
    uint32_t flags = PKT_PDU_HEAD;
    PROFILE_VARS;

    assert(st->seglist_next);
    MODULE_PROFILE_START(s5TcpBuildPacketPerfStats);

    uint32_t total = toSeq - st->seglist_next->seq;

    while ( SEQ_LT(st->seglist_next->seq, toSeq) )
    {
        TcpSegment* ss = st->seglist_next, * sr;
        unsigned flushbuf_size = flushbuf_end - flushbuf;
        unsigned bytes_to_copy = getSegmentFlushSize(st, ss, toSeq, flushbuf_size);
        unsigned bytes_copied = 0;
        assert(bytes_to_copy);

        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Flushing %u bytes from %X\n", bytes_to_copy, ss->seq));

        if (
            !ss->next || (bytes_to_copy < ss->size) ||
            SEQ_EQ(ss->seq + bytes_to_copy,  toSeq)
            )
            flags |= PKT_PDU_TAIL;

        const StreamBuffer* sb = st->splitter->reassemble(
            p->flow, total, bytes_flushed, ss->payload, bytes_to_copy, flags, bytes_copied);

        flags = 0;

        if ( sb )
        {
            s5_pkt->data = sb->data;
            s5_pkt->dsize = sb->length;
            assert(sb->length <= s5_pkt->max_dsize);

            // FIXIT-M flushbuf should be eliminated from this function
            // since we are actually using the stream splitter buffer
            flushbuf = (uint8_t*)s5_pkt->data;

            // ensure we stop here
            bytes_to_copy = bytes_copied;
        }
        assert(bytes_to_copy == bytes_copied);

        flushbuf += bytes_to_copy;
        bytes_flushed += bytes_to_copy;

        if ( bytes_to_copy < ss->size &&
            DupStreamNode(NULL, st, ss, &sr) == STREAM_INSERT_OK )
        {
            ss->size = bytes_to_copy;
            sr->seq += bytes_to_copy;
            sr->size -= bytes_to_copy;
            sr->payload += bytes_to_copy;
        }
        ss->buffered = SL_BUF_FLUSHED;
        st->flush_count++;
        segs++;

        if ( flushbuf >= flushbuf_end )
            break;

        if ( SEQ_EQ(ss->seq + bytes_to_copy,  toSeq) )
            break;

        /* Check for a gap/missing packet */
        // FIXIT-L PAF should account for missing data and resume
        // scanning at the start of next PDU instead of aborting.
        // FIXIT-L FIN may be in toSeq causing bogus gap counts.
        if ( ((ss->next && (ss->seq + ss->size != ss->next->seq)) ||
            (!ss->next && (ss->seq + ss->size < toSeq))) &&
            !(st->flags & TF_FIRST_PKT_MISSING) )
        {
            if ( ss->next )
                st->seglist_next = ss->next;

            st->flags |= TF_MISSING_PKT;
            break;
        }
        st->seglist_next = ss->next;

        if ( sb || !st->seglist_next )
            break;
    }

    STREAM_DEBUG_WRAP(bytes_queued -= bytes_flushed; );
    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "flushed %d bytes / %d segs on stream, "
        "%d still queued\n",
        bytes_flushed, segs, bytes_queued); );

    MODULE_PROFILE_END(s5TcpBuildPacketPerfStats);
    return bytes_flushed;
}

// FIXIT-L consolidate encode format, update, and this into new function?
static void prep_s5_pkt(Flow* flow, Packet* p, uint32_t pkt_flags)
{
    s5_pkt->ptrs.set_pkt_type(PktType::USER);
    s5_pkt->proto_bits |= PROTO_BIT__TCP;
    s5_pkt->packet_flags |= (pkt_flags & PKT_PDU_FULL);
    s5_pkt->flow = flow;

    if ( p == s5_pkt )
    {
        // final
        if ( pkt_flags & PKT_FROM_SERVER )
        {
            s5_pkt->packet_flags |= PKT_FROM_SERVER;
            s5_pkt->ptrs.ip_api.set(flow->server_ip, flow->client_ip);
            s5_pkt->ptrs.sp = flow->server_port;
            s5_pkt->ptrs.dp = flow->client_port;
        }
        else
        {
            s5_pkt->packet_flags |= PKT_FROM_CLIENT;
            s5_pkt->ptrs.ip_api.set(flow->client_ip, flow->server_ip);
            s5_pkt->ptrs.sp = flow->client_port;
            s5_pkt->ptrs.dp = flow->server_port;
        }
    }
    else if ( !p->packet_flags || (pkt_flags & p->packet_flags) )
    {
        // forward
        s5_pkt->packet_flags |= (p->packet_flags & (PKT_FROM_CLIENT|PKT_FROM_SERVER));
        s5_pkt->ptrs.ip_api.set(*p->ptrs.ip_api.get_src(), *p->ptrs.ip_api.get_dst());
        s5_pkt->ptrs.sp = p->ptrs.sp;
        s5_pkt->ptrs.dp = p->ptrs.dp;
    }
    else
    {
        // reverse
        if ( p->packet_flags & PKT_FROM_CLIENT )
            s5_pkt->packet_flags |= PKT_FROM_SERVER;
        else
            s5_pkt->packet_flags |= PKT_FROM_CLIENT;

        s5_pkt->ptrs.ip_api.set(*p->ptrs.ip_api.get_dst(), *p->ptrs.ip_api.get_src());
        s5_pkt->ptrs.dp = p->ptrs.sp;
        s5_pkt->ptrs.sp = p->ptrs.dp;
    }
}

static inline int _flush_to_seq(
    TcpSession *tcpssn, TcpTracker *st, uint32_t bytes, Packet *p, uint32_t pkt_flags)
{
    uint32_t stop_seq;
    uint32_t footprint;
    uint32_t bytes_processed = 0;
    int32_t flushed_bytes;
    EncodeFlags enc_flags = 0;
    PROFILE_VARS;

    MODULE_PROFILE_START(s5TcpFlushPerfStats);

#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
    DAQ_PktHdr_t pkth;
    GetPacketHeaderFoo(tcpssn, &pkth, pkt_flags);
    PacketManager::format_tcp(enc_flags, p, s5_pkt, PSEUDO_PKT_TCP, &pkth, pkth.opaque);
#else
    PacketManager::format_tcp(enc_flags, p, s5_pkt, PSEUDO_PKT_TCP);
#endif

    prep_s5_pkt(tcpssn->flow, p, pkt_flags);

    // if not specified, set bytes to flush to what was acked
    if ( !bytes && SEQ_GT(st->r_win_base, st->seglist_base_seq) )
        bytes = st->r_win_base - st->seglist_base_seq;

    // FIXIT-L this should not be necessary here
    st->seglist_base_seq = st->seglist_next->seq;
    stop_seq = st->seglist_base_seq + bytes;

    do
    {
        footprint = stop_seq - st->seglist_base_seq;

        if (footprint == 0)
        {
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Negative footprint, bailing %d (0x%X - 0x%X)\n",
                footprint, stop_seq, st->seglist_base_seq); );
            MODULE_PROFILE_END(s5TcpFlushPerfStats);

            return bytes_processed;
        }

#ifdef DEBUG_STREAM_EX
        if (footprint < st->seg_bytes_logical)
        {
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Footprint less than queued bytes, "
                "win_base: 0x%X base_seq: 0x%X\n",
                stop_seq, st->seglist_base_seq); );
        }
#endif

        if (footprint > s5_pkt->max_dsize)
        {
            /* this is as much as we can pack into a stream buffer */
            footprint = s5_pkt->max_dsize;
            stop_seq = st->seglist_base_seq + footprint;
        }

        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Attempting to flush %lu bytes\n", footprint); );

        ((DAQ_PktHdr_t*)s5_pkt->pkth)->ts.tv_sec = st->seglist_next->tv.tv_sec;
        ((DAQ_PktHdr_t*)s5_pkt->pkth)->ts.tv_usec = st->seglist_next->tv.tv_usec;

        /* setup the pseudopacket payload */
        s5_pkt->dsize = 0;
        const uint8_t* s5_pkt_end = s5_pkt->data + s5_pkt->max_dsize;
        flushed_bytes = FlushStream(p, st, stop_seq, (uint8_t*)s5_pkt->data, s5_pkt_end);

        if ( !flushed_bytes )
            break; /* No more data... bail */

        else if ( !s5_pkt->dsize )
        {
            tcpStats.rebuilt_buffers++;
            bytes_processed += flushed_bytes;
        }
        else
        {
            s5_pkt->packet_flags |= (PKT_REBUILT_STREAM|PKT_STREAM_EST);

            if ((p->packet_flags & PKT_PDU_TAIL))
                s5_pkt->packet_flags |= PKT_PDU_TAIL;

            sfBase.iStreamFlushes++;
            bytes_processed += flushed_bytes;

            s5_pkt->application_protocol_ordinal = p->application_protocol_ordinal;

            ShowRebuiltPacket(tcpssn, s5_pkt);
            tcpStats.rebuilt_packets++;
            UpdateStreamReassStats(&sfBase, flushed_bytes);

            MODULE_PROFILE_TMPEND(s5TcpFlushPerfStats);
            {
                PROFILE_VARS;
                MODULE_PROFILE_START(s5TcpProcessRebuiltPerfStats);

                Snort::detect_rebuilt_packet(s5_pkt);

                MODULE_PROFILE_END(s5TcpProcessRebuiltPerfStats);
            }
            MODULE_PROFILE_TMPSTART(s5TcpFlushPerfStats);
        }

        st->seglist_base_seq += flushed_bytes;

        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "setting st->seglist_base_seq to 0x%X\n", st->seglist_base_seq); );

        if ( st->splitter )
            st->splitter->update();

        // TBD abort should be by PAF callback only since
        // recovery may be possible in some cases
        if ( st->flags & TF_MISSING_PKT )
        {
            st->flags |= TF_MISSING_PREV_PKT;
            st->flags |= TF_PKT_MISSED;
            st->flags &= ~TF_MISSING_PKT;
            tcpStats.gaps++;
        }
        else
        {
            st->flags &= ~TF_MISSING_PREV_PKT;
        }
    }
    while ( st->seglist_next and DataToFlush(st) );

    /* tell them how many bytes we processed */
    MODULE_PROFILE_END(s5TcpFlushPerfStats);
    return bytes_processed;
}

/*
 * flush a seglist up to the given point, generate a pseudopacket,
 * and fire it thru the system.
 */
static inline int flush_to_seq(
    TcpSession *tcpssn, TcpTracker *st, uint32_t bytes, Packet *p, uint32_t pkt_flags)
{
    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "In flush_to_seq()\n"); );

    if ( !bytes )
    {
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "bailing, no data\n"); );
        return 0;
    }

    if ( !st->seglist_next )
    {
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "bailing, bad seglist ptr\n"); );
        return 0;
    }

    if (!DataToFlush(st) && !(st->flags & TF_FORCE_FLUSH))
    {
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "only 1 packet in seglist no need to flush\n"); );
        return 0;
    }

    st->flags &= ~TF_MISSING_PKT;
    st->flags &= ~TF_MISSING_PREV_PKT;

    /* This will set this flag on the first reassembly
     * if reassembly for this direction was set midstream */
    if ( SEQ_LT(st->seglist_base_seq, st->seglist_next->seq) &&
        !(st->flags & TF_FIRST_PKT_MISSING) )
    {
        uint32_t missed = st->seglist_next->seq - st->seglist_base_seq;

        if ( missed <= bytes )
            bytes -= missed;

        st->flags |= TF_MISSING_PREV_PKT;
        st->flags |= TF_PKT_MISSED;

        tcpStats.gaps++;
        st->seglist_base_seq = st->seglist_next->seq;

        if ( !bytes )
            return 0;
    }
    st->flags &= ~TF_FIRST_PKT_MISSING;

    return _flush_to_seq(tcpssn, st, bytes, p, pkt_flags);
}

/*
 * get the footprint for the current seglist, the difference
 * between our base sequence and the last ack'd sequence we
 * received
 */
static inline uint32_t get_q_footprint(TcpTracker *st)
{
    uint32_t fp;

    if (st == NULL)
    {
        return 0;
    }

    fp = st->r_win_base - st->seglist_base_seq;

    if (fp <= 0)
        return 0;

    st->seglist_next = st->seglist;
    return fp;
}

// FIXIT-L get_q_sequenced() performance could possibly be
// boosted by tracking sequenced bytes as seglist is updated
// to avoid the while loop, etc. below.
static inline uint32_t get_q_sequenced(TcpTracker *st)
{
    uint32_t len;
    TcpSegment* seg = st ? st->seglist : NULL;
    TcpSegment* base = NULL;

    if ( !seg )
        return 0;

    if ( SEQ_LT(st->r_win_base, seg->seq) )
        return 0;

    while ( seg->next && (seg->next->seq == seg->seq + seg->size) )
    {
        if ( !seg->buffered && !base )
            base = seg;
        seg = seg->next;
    }
    if ( !seg->buffered && !base )
        base = seg;

    if ( !base )
        return 0;

    st->seglist_next = base;
    st->seglist_base_seq = base->seq;
    len = seg->seq + seg->size - base->seq;

    return ( len > 0 ) ? len : 0;
}

// FIXIT-L flush_stream() calls should be replaced with calls to
// CheckFlushPolicyOn*() with the exception that for the *OnAck() case,
// any available ackd data must be flushed in both directions.
static inline int flush_stream(
    TcpSession *tcpssn, TcpTracker *st, Packet *p, uint32_t dir)
{
    // this is not always redundant; stream_reassemble rule option causes trouble
    if ( !st->flush_policy )
        return 0;

    uint32_t bytes;

    if ( Normalize_IsEnabled(NORM_TCP_IPS) )
        bytes = get_q_sequenced(st);
    else
        bytes = get_q_footprint(st);

    return flush_to_seq(tcpssn, st, bytes, p, dir);
}

static void TcpSessionClear (Flow* lwssn, TcpSession* tcpssn, int freeApplicationData)
{
    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "In TcpSessionClear, %lu bytes in use\n", tcp_memcap->used()); );
    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "client has %d segs queued\n", tcpssn->client.seg_count); );
    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "server has %d segs queued\n", tcpssn->server.seg_count); );

    // update stats
    if ( tcpssn->tcp_init )
        tcpStats.trackers_released++;
    else if ( tcpssn->lws_init )
        tcpStats.no_pickups++;
    else
        return;

    StreamUpdatePerfBaseState(&sfBase, tcpssn->flow, TCP_STATE_CLOSED);
    RemoveStreamSession(&sfBase);

    if (lwssn->ssn_state.session_flags & SSNFLAG_PRUNED)
    {
        CloseStreamSession(&sfBase, SESSION_CLOSED_PRUNED);
    }
    else if (lwssn->ssn_state.session_flags & SSNFLAG_TIMEDOUT)
    {
        CloseStreamSession(&sfBase, SESSION_CLOSED_TIMEDOUT);
    }
    else
    {
        CloseStreamSession(&sfBase, SESSION_CLOSED_NORMALLY);
    }

    delete tcpssn->client.splitter;
    delete tcpssn->server.splitter;

    tcpssn->client.splitter = nullptr;
    tcpssn->server.splitter = nullptr;

    // release internal protocol specific state
    purge_all(&tcpssn->client);
    purge_all(&tcpssn->server);

    paf_clear(&tcpssn->client.paf_state);
    paf_clear(&tcpssn->server.paf_state);

    // update light-weight state
    if ( freeApplicationData == 2 )
        lwssn->restart(true);
    else
        lwssn->clear(freeApplicationData);

    // generate event for rate filtering
    EventInternal(INTERNAL_EVENT_SESSION_DEL);

    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "After cleaning, %lu bytes in use\n", tcp_memcap->used()); );

    tcpssn->lws_init = tcpssn->tcp_init = false;
}

static void final_flush(
    TcpSession* tcpssn, TcpTracker& trk, Packet* p,
    PegCount& peg, uint32_t dir)
{
    if ( !p )
    {
        p = s5_pkt;

        DAQ_PktHdr_t* const tmp_pcap_hdr = const_cast<DAQ_PktHdr_t*>(p->pkth);
        peg++;

        /* Do each field individually because of size differences on 64bit OS */
        tmp_pcap_hdr->ts.tv_sec = trk.seglist->tv.tv_sec;
        tmp_pcap_hdr->ts.tv_usec = trk.seglist->tv.tv_usec;
    }

    trk.flags |= TF_FORCE_FLUSH;

    if ( flush_stream(tcpssn, &trk, p, dir) )
        purge_flushed_ackd(tcpssn, &trk);

    trk.flags &= ~TF_FORCE_FLUSH;
}

// flush data on both sides as necessary
static void FlushQueuedSegs(Flow* lwssn, TcpSession* tcpssn, bool clear, Packet* p = nullptr)
{
    // flush the client (data from server)
    bool pending = clear and (!tcpssn->client.splitter or tcpssn->client.splitter->finish(lwssn));

    if ( (pending and (p or tcpssn->client.seglist) and
        !(lwssn->ssn_state.ignore_direction & SSN_DIR_FROM_SERVER)) )
    {
        final_flush(tcpssn, tcpssn->client, p, tcpStats.s5tcp1, PKT_FROM_SERVER);
    }

    // flush the server (data from client)
    pending = clear and (!tcpssn->server.splitter or tcpssn->server.splitter->finish(lwssn));

    if ( (pending and (p or tcpssn->server.seglist) and
        !(lwssn->ssn_state.ignore_direction & SSN_DIR_FROM_CLIENT)) )
    {
        final_flush(tcpssn, tcpssn->server, p, tcpStats.s5tcp2, PKT_FROM_CLIENT);
    }
}

static void TcpSessionCleanup(Flow* lwssn, int freeApplicationData, Packet* p = nullptr)
{
    TcpSession* tcpssn = (TcpSession*)lwssn->session;
    FlushQueuedSegs(lwssn, tcpssn, true, p);
    TcpSessionClear(lwssn, tcpssn, freeApplicationData);
}

#ifdef SEG_TEST
static void CheckSegments (const TcpTracker* a)
{
    TcpSegment* ss = a->seglist;
    uint32_t sx = ss ? ss->seq : 0;

    while ( ss )
    {
        if ( SEQ_GT(sx, ss->seq) )
        {
            const int SEGBORK = 0;
            assert(SEGBORK);
        }
        sx = ss->seq + ss->size;
        ss = ss->next;
    }
}

#endif

#ifndef REG_TEST
#define S5TraceTCP(pkt, flow, tdb, evt)
#else
#define LCL(p, x)    (p->x - p->isn)
#define RMT(p, x, q) (p->x - (q ? q->isn : 0))

// FIXIT-L this should not be thread specific
static THREAD_LOCAL int s5_trace_enabled = -1;

static void TraceEvent(
    const Packet* p, TcpDataBlock*, uint32_t txd, uint32_t rxd
    )
{
    int i;
    char flags[7] = "UAPRSF";
    const TCPHdr* h = p->ptrs.tcph;
    const char* order = "";

    if ( !h )
        return;

    for ( i = 0; i < 6; i++)
        if ( !((1<<(5-i)) & h->th_flags) )
            flags[i] = '-';

    // force relative ack to zero if not conveyed
    if ( flags[1] != 'A' )
        rxd = ntohl(h->th_ack);

    if ( p->packet_flags & PKT_STREAM_ORDER_OK )
        order = " (ins)";

    else if ( p->packet_flags & PKT_STREAM_ORDER_BAD )
        order = " (oos)";

    fprintf(stdout,
        "\n" FMTu64("-3") " %s=0x%02x Seq=%-4u Ack=%-4u Win=%-4u Len=%-4u%s\n",
        //"\n" FMTu64("-3") " %s=0x%02x Seq=%-4u Ack=%-4u Win=%-4u Len=%-4u End=%-4u%s\n",
        pc.total_from_daq, flags, h->th_flags,
        ntohl(h->th_seq)-txd, ntohl(h->th_ack)-rxd,
        ntohs(h->th_win), p->dsize, order
        );
}

static void TraceSession(const Flow* lws)
{
    fprintf(stdout, "    LWS: ST=0x%x SF=0x%x CP=%u SP=%u\n",
        (unsigned)lws->session_state, lws->ssn_state.session_flags,
        lws->client_port, lws->server_port
        );
}

static const char* const statext[] =
{
    "NON", "LST", "SYR", "SYS", "EST", "CLW",
    "LAK", "FW1", "CLG", "FW2", "TWT", "CLD"
};

static const char* const flushxt[] =
{
    "IGN", "FPR", "PRE", "PRO", "PAF"
};

static void TraceSegments (const TcpTracker* a)
{
    TcpSegment* ss = a->seglist;
    uint32_t sx = a->r_win_base;
    unsigned segs = 0, bytes = 0;

    while ( ss )
    {
        if ( SEQ_LT(sx, ss->seq) )
            fprintf(stdout, " +%u", ss->seq-sx);
        else if ( SEQ_GT(sx, ss->seq) )
            fprintf(stdout, " -%u", sx-ss->seq);

        fprintf(stdout, " %u", ss->size);

        segs++;
        bytes += ss->size;

        sx = ss->seq + ss->size;
        ss = ss->next;
    }
    assert(a->seg_count == segs);
    assert(a->seg_bytes_logical == bytes);
}

static void TraceState(
    const TcpTracker* a, const TcpTracker* b, const char* s)
{
    uint32_t why = a->l_nxt_seq ? LCL(a, l_nxt_seq) : 0;

    fprintf(stdout,
        "    %s ST=%s:%02x   UA=%-4u NS=%-4u LW=%-5u RN=%-4u RW=%-4u ",
        s, statext[a->s_mgr.state], a->s_mgr.sub_state,
        LCL(a, l_unackd), why, a->l_window,
        RMT(a, r_nxt_ack, b), RMT(a, r_win_base, b)
        );
    if ( a->s_mgr.state_queue )
        fprintf(stdout,
            "QS=%s QC=0x%02x QA=%-4u",
            statext[a->s_mgr.state_queue], a->s_mgr.expected_flags,
            RMT(a, s_mgr.transition_seq, b)
            );
    fprintf(stdout, "\n");
    unsigned paf = a->splitter->is_paf() ? 2 : 0;
    unsigned fpt = a->flush_policy ? 192 : 0;

    fprintf(stdout,
        "         FP=%s:%-4u SC=%-4u FL=%-4u SL=%-5u BS=%-4u",
        flushxt[a->flush_policy+paf], fpt,
        a->seg_count, a->flush_count, a->seg_bytes_logical,
        a->seglist_base_seq - b->isn
        );
    if ( s5_trace_enabled == 2 )
        TraceSegments(a);

    fprintf(stdout, "\n");
}

static void TraceTCP(
    const Packet* p, const Flow* lws, TcpDataBlock* tdb, int event
    )
{
    const TcpSession* ssn = (TcpSession*)lws->session;
    const TcpTracker* srv = ssn ? &ssn->server : NULL;
    const TcpTracker* cli = ssn ? &ssn->client : NULL;

    const char* cdir = "?", * sdir = "?";
    uint32_t txd = 0, rxd = 0;

    if ( p->packet_flags & PKT_FROM_SERVER )
    {
        sdir = "SRV>";
        cdir = "CLI<";

        if ( ssn->tcp_init )
        {
            txd = srv->isn;
            rxd = cli->isn;
        }
    }
    else if ( p->packet_flags & PKT_FROM_CLIENT )
    {
        sdir = "SRV<";
        cdir = "CLI>";

        if ( ssn->tcp_init )
        {
            txd = cli->isn;
            rxd = srv->isn;
        }
    }
    TraceEvent(p, tdb, txd, rxd);

    if ( !ssn->tcp_init )
        return;

    if ( lws && ssn->lws_init )
        TraceSession(lws);

    if ( lws && !event )
    {
        TraceState(cli, srv, cdir);
        TraceState(srv, cli, sdir);
    }
}

static inline void S5TraceTCP(
    const Packet* p, const Flow* lws, TcpDataBlock* tdb, int event
    )
{
    if ( !s5_trace_enabled )
        return;

    if ( s5_trace_enabled < 0 )
    {
        const char* s5t = getenv("S5_TRACE");

        if ( !s5t )
        {
            s5_trace_enabled = 0;
            return;
        }
        // no error checking required - atoi() is sufficient
        s5_trace_enabled = atoi(s5t);
    }
    TraceTCP(p, lws, tdb, event);
}
#endif 

static uint32_t StreamGetTcpTimestamp(Packet* p, uint32_t* ts, int strip)
{
    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "Getting timestamp...\n"); );

    const NormMode mode = Normalize_GetMode(NORM_TCP_OPT);
    TcpOptIterator iter(p->ptrs.tcph, p);

    // using const because non-const is not supported
    for (const TcpOption& opt : iter)
    {
        if (opt.code == TcpOptCode::TIMESTAMP)
        {
            if ( strip )
            {
                NormalStripTimeStamp(p, &opt, mode);
            }
            else if ( !strip || !NormalStripTimeStamp(p, &opt, mode) )
            {
                *ts = EXTRACT_32BITS(opt.data);
                STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Found timestamp %lu\n", *ts); );

                return TF_TSTAMP;
            }
        }
    }
    *ts = 0;

    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "No timestamp...\n"); );

    return TF_NONE;
}

static uint32_t StreamGetMss(Packet* p, uint16_t* value)
{
    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "Getting MSS...\n"); );

    TcpOptIterator iter(p->ptrs.tcph, p);
    for (const TcpOption& opt : iter)
    {
        if (opt.code == TcpOptCode::MAXSEG)
        {
            *value = EXTRACT_16BITS(opt.data);
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Found MSS %u\n", *value); );
            return TF_MSS;
        }
    }

    *value = 0;

    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "No MSS...\n"); );
    return TF_NONE;
}

static uint32_t StreamGetWscale(Packet* p, uint16_t* value)
{
    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "Getting wscale...\n"); );

    TcpOptIterator iter(p->ptrs.tcph, p);

    // using const because non-const is not supported
    for (const TcpOption& opt : iter)
    {
        if (opt.code == TcpOptCode::WSCALE)
        {
            *value = (uint16_t)opt.data[0];
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Found wscale %d\n", *value); );

            /* If scale specified in option is larger than 14,
             * use 14 because of limitation in the math of
             * shifting a 32bit value (max scaled window is 2^30th).
             *
             * See RFC 1323 for details.
             */
            if (*value > 14)
            {
                *value = 14;
            }

            return TF_WSCALE;
        }
    }

    *value = 0;
    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "No wscale...\n"); );
    return TF_NONE;
}

static uint32_t StreamPacketHasWscale(Packet* p)
{
    uint16_t wscale;

    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "Checking for wscale...\n"); );
    return StreamGetWscale(p, &wscale);
}

#if 0
static inline int IsWellFormed(Packet *p, TcpTracker *ts)
{
    return ( !ts->mss || (p->dsize <= ts->mss) );
}

#endif

static void FinishServerInit(Packet* p, TcpDataBlock* tdb, TcpSession* ssn)
{
    TcpTracker *server;
    TcpTracker *client;

    if (!ssn)
    {
        return;
    }

    server = &ssn->server;
    client = &ssn->client;

    server->l_window = tdb->win;              /* set initial server window */
    server->l_unackd = tdb->seq + 1;
    server->l_nxt_seq = server->l_unackd;
    server->isn = tdb->seq;

    client->r_nxt_ack = tdb->end_seq;

    if ( p->ptrs.tcph->th_flags & TH_FIN )
        server->l_nxt_seq--;

    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "seglist_base_seq = %X\n", client->seglist_base_seq); );

    if (!(ssn->flow->session_state & STREAM_STATE_MIDSTREAM))
    {
        server->s_mgr.state = TCP_STATE_SYN_RCVD;
        client->seglist_base_seq = server->l_unackd;
        client->r_win_base = tdb->end_seq;
    }
    else
    {
        client->seglist_base_seq = tdb->seq;
        client->r_win_base = tdb->seq;
    }
    server->flags |= StreamGetTcpTimestamp(p, &server->ts_last, 0);
    if (server->ts_last == 0)
        server->flags |= TF_TSTAMP_ZERO;
    else
        server->ts_last_pkt = p->pkth->ts.tv_sec;
    server->flags |= StreamGetMss(p, &server->mss);
    server->flags |= StreamGetWscale(p, &server->wscale);

#ifdef DEBUG_STREAM_EX
    PrintTcpSession(ssn);
#endif
}

static inline int SegmentFastTrack(TcpSegment *tail, TcpDataBlock *tdb)
{
    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "Checking seq for fast track: %X > %X\n", tdb->seq,
        tail->seq + tail->size); );

    if (SEQ_EQ(tdb->seq, tail->seq + tail->size))
        return 1;

    return 0;
}

static int AddStreamNode(
    TcpTracker *st, Packet *p,
    TcpDataBlock* tdb,
    int16_t len,
    uint32_t slide,
    uint32_t trunc,
    uint32_t seq,
    TcpSegment *left)
{
    TcpSegment *ss = NULL;
    int32_t newSize = len - slide - trunc;

    if (newSize <= 0)
    {
        /*
         * zero size data because of trimming.  Don't
         * insert it
         */
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "zero size TCP data after left & right trimming "
            "(len: %d slide: %d trunc: %d)\n",
            len, slide, trunc); );
        Discard();
        NormalTrimPayloadIfWin(p, 0, tdb);

#ifdef DEBUG_STREAM_EX
        {
            TcpSegment *idx = st->seglist;
            unsigned long i = 0;
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Dumping seglist, %d segments\n", st->seg_count); );
            while (idx)
            {
                i++;
                STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "%d  ptr: %p  seq: 0x%X  size: %d nxt: %p prv: %p\n",
                    i, idx, idx->seq, idx->size, idx->next, idx->prev); );

                if (st->seg_count < i)
                    FatalError("Circular list\n");

                idx = idx->next;
            }
        }
#endif
        return STREAM_INSERT_ANOMALY;
    }

    // FIXIT-L don't allocate overlapped part
    ss = TcpSegment::init(p, p->pkth->ts, p->data, p->dsize);

    if ( !ss )
        return STREAM_INSERT_FAILED;

    ss->payload = ss->data + slide;
    ss->size = (uint16_t)newSize;
    ss->seq = seq;
    ss->ts = tdb->ts;

    /* handle the urg ptr */
    if (p->ptrs.tcph->th_flags & TH_URG)
    {
        if (p->ptrs.tcph->urp() < p->dsize)
        {
            switch (st->os_policy)
            {
            case STREAM_POLICY_LINUX:
            case STREAM_POLICY_OLD_LINUX:
                /* Linux, Old linux discard data from urgent pointer
                   If urg pointer is 0, it's treated as a 1 */
                ss->urg_offset = p->ptrs.tcph->urp();
                if (ss->urg_offset == 0)
                {
                    ss->urg_offset = 1;
                }
                break;
            case STREAM_POLICY_FIRST:
            case STREAM_POLICY_LAST:
            case STREAM_POLICY_BSD:
            case STREAM_POLICY_MACOS:
            case STREAM_POLICY_SOLARIS:
            case STREAM_POLICY_WINDOWS:
            case STREAM_POLICY_WINDOWS2K3:
            case STREAM_POLICY_VISTA:
            case STREAM_POLICY_HPUX11:
            case STREAM_POLICY_HPUX10:
            case STREAM_POLICY_IRIX:
                /* Others discard data from urgent pointer
                   If urg pointer is beyond this packet, it's treated as a 0 */
                ss->urg_offset = p->ptrs.tcph->urp();
                if (ss->urg_offset > p->dsize)
                {
                    ss->urg_offset = 0;
                }
                break;
            }
        }
    }

    StreamSeglistAddNode(st, left, ss);
    st->seg_bytes_logical += ss->size;
    st->total_bytes_queued += ss->size;

    p->packet_flags |= PKT_STREAM_INSERT;

    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "added %d bytes on segment list @ seq: 0x%X, total %lu, "
        "%d segments queued\n", ss->size, ss->seq,
        st->seg_bytes_logical, SegsToFlush(st, 0)); );

#ifdef SEG_TEST
    CheckSegments(st);
#endif
    return STREAM_INSERT_OK;
}

static int DupStreamNode(
    Packet *p, TcpTracker *st, TcpSegment *left, TcpSegment **retSeg)
{
    TcpSegment* ss = TcpSegment::init(p, left->tv, left->payload, left->size);

    if ( !ss )
        return STREAM_INSERT_FAILED;

    tcpStats.segs_split++;

    /* twiddle the values for overlaps */
    ss->payload = ss->data;
    ss->size = left->size;
    ss->seq = left->seq;

    StreamSeglistAddNode(st, left, ss);
    //st->total_bytes_queued += ss->size;

    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "added %d bytes on segment list @ seq: 0x%X, total %lu, "
        "%d segments queued\n", ss->size, ss->seq,
        st->seg_bytes_logical, SegsToFlush(st, 0)); );

    *retSeg = ss;
    return STREAM_INSERT_OK;
}

static inline void RetransmitProcess(Packet* p, TcpSession*)
{
    // Data has already been analyzed so don't bother looking at it again.
    DisableDetect( p );
}

static inline void RetransmitHandle(Packet* p, TcpSession* tcpssn)
{
    tcpssn->flow->call_handlers(p, false);
}

static inline void EndOfFileHandle(Packet* p, TcpSession* tcpssn)
{
    tcpssn->flow->call_handlers(p, true);
}

static inline NormMode get_norm_ips(TcpTracker* st)
{
    if ( st->config->policy == STREAM_POLICY_PROXY )
        return NORM_MODE_OFF;

    return Normalize_GetMode(NORM_TCP_IPS);
}

static void NewQueue(
    TcpTracker *st, Packet *p, TcpDataBlock *tdb)
{
    PROFILE_VARS;
    MODULE_PROFILE_START(s5TcpInsertPerfStats);

    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, "In NewQueue\n"); );

    uint32_t overlap = 0;
    uint32_t seq = tdb->seq;

    if ( p->ptrs.tcph->th_flags & TH_SYN )
        seq++;

    /* new packet seq is below the last ack... */
    if ( SEQ_GT(st->r_win_base, seq) )
    {
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "segment overlaps ack'd data...\n"); );
        overlap = st->r_win_base - tdb->seq;

        if (overlap >= p->dsize)
        {
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "full overlap on ack'd data, dropping segment\n"); );
            MODULE_PROFILE_END(s5TcpInsertPerfStats);
            return;
        }
    }

    // BLOCK add new block to seglist containing data
    AddStreamNode(st, p, tdb, p->dsize, overlap, 0, tdb->seq+overlap, NULL);

    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "Attached new queue to seglist, %d bytes queued, "
        "base_seq 0x%X\n",
        p->dsize-overlap, st->seglist_base_seq); );

    MODULE_PROFILE_END(s5TcpInsertPerfStats);
}

static int StreamQueue(TcpTracker *st, Packet *p, TcpDataBlock *tdb,
        TcpSession *tcpssn)
{
    TcpSegment *left = NULL;
    TcpSegment *right = NULL;
    TcpSegment *dump_me = NULL;
    uint32_t seq = tdb->seq;
    uint32_t seq_end = tdb->end_seq;
    uint16_t len = p->dsize;
    int trunc = 0;
    int overlap = 0;
    int slide = 0;
    int ret = STREAM_INSERT_OK;
    char done = 0;
    char addthis = 1;
    int32_t dist_head;
    int32_t dist_tail;
    uint16_t reassembly_policy;
    // To check for retransmitted data
    const uint8_t* rdata = p->data;
    uint16_t rsize = p->dsize;
    uint32_t rseq = tdb->seq;
    PROFILE_VARS;
    STREAM_DEBUG_WRAP(
        TcpSegment *lastptr = NULL;
        uint32_t base_seq = st->seglist_base_seq;
        int last = 0;
        );

    const NormMode ips_data = get_norm_ips(st);

    if ( ips_data == NORM_MODE_ON )
        reassembly_policy = REASSEMBLY_POLICY_FIRST;
    else
        reassembly_policy = st->reassembly_policy;

    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "Queuing %d bytes on stream!\n"
        "base_seq: %X seq: %X  seq_end: %X\n",
        seq_end - seq, base_seq, seq, seq_end); );

    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "%d segments on seglist\n", SegsToFlush(st, 0)); );
    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+\n"); );
    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+\n"); );

    MODULE_PROFILE_START(s5TcpInsertPerfStats);

    // NORM fast tracks are in sequence - no norms
    if (st->seglist_tail && SegmentFastTrack(st->seglist_tail, tdb))
    {
        /* segment fit cleanly at the end of the segment list */
        left = st->seglist_tail;
        right = NULL;

        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Fast tracking segment! (tail_seq %X size %d)\n",
            st->seglist_tail->seq, st->seglist_tail->size); );

        // BLOCK add to existing block and/or allocate new block
        ret = AddStreamNode(st, p, tdb, len,
            slide /* 0 */, trunc /* 0 */, seq, left /* tail */);

        MODULE_PROFILE_END(s5TcpInsertPerfStats);
        return ret;
    }

    if (st->seglist && st->seglist_tail)
    {
        if (SEQ_GT(tdb->seq, st->seglist->seq))
        {
            dist_head = tdb->seq - st->seglist->seq;
        }
        else
        {
            dist_head = st->seglist->seq - tdb->seq;
        }

        if (SEQ_GT(tdb->seq, st->seglist_tail->seq))
        {
            dist_tail = tdb->seq - st->seglist_tail->seq;
        }
        else
        {
            dist_tail = st->seglist_tail->seq - tdb->seq;
        }
    }
    else
    {
        dist_head = dist_tail = 0;
    }

    if (SEQ_LEQ(dist_head, dist_tail))
    {
        TcpSegment* ss;

        /* Start iterating at the head (left) */
        for (ss = st->seglist; ss; ss = ss->next)
        {
            STREAM_DEBUG_WRAP(
                DebugMessage(DEBUG_STREAM_STATE,
                "ss: %p  seq: 0x%X  size: %lu delta: %d\n",
                ss, ss->seq, ss->size, (ss->seq-base_seq) - last);
                last = ss->seq-base_seq;
                lastptr = ss;

                DebugMessage(DEBUG_STREAM_STATE,
                "   lastptr: %p ss->next: %p ss->prev: %p\n",
                lastptr, ss->next, ss->prev);
                );

            right = ss;

            if (SEQ_GEQ(right->seq, seq))
                break;

            left = right;
        }

        if (ss == NULL)
            right = NULL;
    }
    else
    {
        TcpSegment* ss;

        /* Start iterating at the tail (right) */
        for (ss = st->seglist_tail; ss; ss = ss->prev)
        {
            STREAM_DEBUG_WRAP(
                DebugMessage(DEBUG_STREAM_STATE,
                "ss: %p  seq: 0x%X  size: %lu delta: %d\n",
                ss, ss->seq, ss->size, (ss->seq-base_seq) - last);
                last = ss->seq-base_seq;
                lastptr = ss;

                DebugMessage(DEBUG_STREAM_STATE,
                "   lastptr: %p ss->next: %p ss->prev: %p\n",
                lastptr, ss->next, ss->prev);
                );

            left = ss;

            if (SEQ_LT(left->seq, seq))
                break;

            right = left;
        }

        if (ss == NULL)
            left = NULL;
    }

    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+\n"); );
    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+\n"); );

    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "left: %p:0x%X  right: %p:0x%X\n", left,
        left ? left->seq : 0, right, right ? right->seq : 0); );
    /*
     * handle left overlaps
     */
    if (left)
    {
        // NOTE that left->seq is always less than seq, otherwise it would
        // be a right based on the above determination of left and right

        /* check if the new segment overlaps on the left side */
        overlap = left->seq + left->size - seq;

        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "left overlap %d\n", overlap); );

        if (overlap > 0)
        {
            // NOTE that overlap will always be less than left->size since
            // seq is always greater than left->seq
            tcpStats.overlaps++;
            st->overlap_count++;

            switch (reassembly_policy)
            {
            case REASSEMBLY_POLICY_FIRST:
            case REASSEMBLY_POLICY_LINUX:
            case REASSEMBLY_POLICY_BSD:
            case REASSEMBLY_POLICY_WINDOWS:
            case REASSEMBLY_POLICY_WINDOWS2K3:
            case REASSEMBLY_POLICY_VISTA:
            case REASSEMBLY_POLICY_HPUX10:
            case REASSEMBLY_POLICY_IRIX:
            case REASSEMBLY_POLICY_OLD_LINUX:
            case REASSEMBLY_POLICY_MACOS:
                STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "left overlap, honoring old data\n"); );
                if (SEQ_LT(left->seq,tdb->seq) && SEQ_GT(left->seq + left->size, tdb->seq +
                    p->dsize))
                {
                    if ( ips_data == NORM_MODE_ON )
                    {
                        unsigned offset = tdb->seq - left->seq;
                        memcpy((uint8_t*)p->data, left->payload+offset, p->dsize);
                        p->packet_flags |= PKT_MODIFIED;
                    }
                    normStats[PC_TCP_IPS_DATA][ips_data]++;
                    sfBase.iPegs[PERF_COUNT_TCP_IPS_DATA][ips_data]++;
                }
                else if (SEQ_LT(left->seq, tdb->seq))
                {
                    if ( ips_data == NORM_MODE_ON )
                    {
                        unsigned offset = tdb->seq - left->seq;
                        unsigned length = left->seq + left->size - tdb->seq;
                        memcpy((uint8_t*)p->data, left->payload+offset, length);
                        p->packet_flags |= PKT_MODIFIED;
                    }
                    normStats[PC_TCP_IPS_DATA][ips_data]++;
                    sfBase.iPegs[PERF_COUNT_TCP_IPS_DATA][ips_data]++;
                }
                seq += overlap;
                //slide = overlap;
                if (SEQ_LEQ(seq_end, seq))
                {
                    /*
                     * houston, we have a problem
                     */
                    /* flag an anomaly */
                    EventBadSegment();
                    Discard();
                    MODULE_PROFILE_END(s5TcpInsertPerfStats);
                    return STREAM_INSERT_ANOMALY;
                }
                break;

            case REASSEMBLY_POLICY_SOLARIS:
            case REASSEMBLY_POLICY_HPUX11:
                if (SEQ_LT(left->seq, seq) && SEQ_GEQ(left->seq + left->size, seq + len))
                {
                    /* New packet is entirely overlapped by an
                     * existing packet on both sides.  Drop the
                     * new data. */
                    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "left overlap, honoring old data\n"); );
                    seq += overlap;
                    //slide = overlap;
                    if (SEQ_LEQ(seq_end, seq))
                    {
                        /*
                         * houston, we have a problem
                         */
                        /* flag an anomaly */
                        EventBadSegment();
                        Discard();
                        MODULE_PROFILE_END(s5TcpInsertPerfStats);
                        return STREAM_INSERT_ANOMALY;
                    }
                }

                /* Otherwise, trim the old data accordingly */
                left->size -= (int16_t)overlap;
                st->seg_bytes_logical -= overlap;
                STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "left overlap, honoring new data\n"); );
                break;
            case REASSEMBLY_POLICY_LAST:
                /* True "Last" policy" */
                if (SEQ_LT(left->seq, seq) && SEQ_GT(left->seq + left->size, seq + len))
                {
                    /* New data is overlapped on both sides by
                     * existing data.  Existing data needs to be
                     * split and the new data inserted in the
                     * middle.
                     *
                     * Need to duplicate left.  Adjust that
                     * seq by + (seq + len) and
                     * size by - (seq + len - left->seq).
                     */
                    ret = DupStreamNode(p, st, left, &right);
                    if (ret != STREAM_INSERT_OK)
                    {
                        /* No warning, its done in StreamSeglistAddNode */
                        MODULE_PROFILE_END(s5TcpInsertPerfStats);
                        return ret;
                    }
                    left->size -= (int16_t)overlap;
                    st->seg_bytes_logical -= overlap;

                    right->seq = seq + len;
                    uint16_t delta = (int16_t)(right->seq - left->seq);
                    right->size -= delta;
                    right->payload += delta;
                    st->seg_bytes_logical -= delta;
                }
                else
                {
                    left->size -= (int16_t)overlap;
                    st->seg_bytes_logical -= overlap;
                }

                STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "left overlap, honoring new data\n"); );
                break;
            }

            if (SEQ_LEQ(seq_end, seq))
            {
                STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "seq_end < seq"); );
                /*
                 * houston, we have a problem
                 */
                /* flag an anomaly */
                EventBadSegment();
                Discard();
                MODULE_PROFILE_END(s5TcpInsertPerfStats);
                return STREAM_INSERT_ANOMALY;
            }
        }
        else
        {
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "No left overlap\n"); );
        }
    }

    //(seq_end > right->seq) && (seq_end <= (right->seq+right->size))))
    while (right && !done && SEQ_LT(right->seq, seq_end))
    {
        trunc = 0;
        overlap = (int)(seq_end - right->seq);
        //overlap = right->size - (right->seq - seq);
        //right->seq + right->size - seq_end;

        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "right overlap(%d): len: %d right->seq: 0x%X seq: 0x%X\n",
            overlap, len, right->seq, seq); );
        /* Treat sequence number overlap as a retransmission
         * Only check right side since left side happens rarely
         */
        RetransmitHandle(p, tcpssn);

        if (overlap < right->size)
        {
            if ( right->is_retransmit(rdata, rsize, rseq) )
            {
                // All data was retransmitted
                RetransmitProcess(p, tcpssn);
                addthis = 0;
                break;
            }

            tcpStats.overlaps++;
            st->overlap_count++;

            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Got partial right overlap\n"); );

            switch (reassembly_policy)
            {
            /* truncate existing data */
            case REASSEMBLY_POLICY_LAST:
            case REASSEMBLY_POLICY_LINUX:
            case REASSEMBLY_POLICY_OLD_LINUX:
            case REASSEMBLY_POLICY_BSD:
            case REASSEMBLY_POLICY_WINDOWS:
            case REASSEMBLY_POLICY_WINDOWS2K3:
            case REASSEMBLY_POLICY_IRIX:
            case REASSEMBLY_POLICY_HPUX10:
            case REASSEMBLY_POLICY_MACOS:
                if (SEQ_EQ(right->seq, seq) &&
                    (reassembly_policy != REASSEMBLY_POLICY_LAST))
                {
                    slide = (right->seq + right->size - seq);
                    seq += slide;
                }
                else
                {
                    /* partial overlap */
                    right->seq += overlap;
                    right->payload += overlap;
                    right->size -= (int16_t)overlap;
                    st->seg_bytes_logical -= overlap;
                    st->total_bytes_queued -= overlap;
                }

                // right->size always > 0 since overlap < right->size

                break;

            case REASSEMBLY_POLICY_FIRST:
            case REASSEMBLY_POLICY_VISTA:
            case REASSEMBLY_POLICY_SOLARIS:
            case REASSEMBLY_POLICY_HPUX11:
                if ( ips_data == NORM_MODE_ON )
                {
                    unsigned offset = right->seq - tdb->seq;
                    unsigned length = tdb->seq + p->dsize - right->seq;
                    memcpy((uint8_t*)p->data+offset, right->payload, length);
                    p->packet_flags |= PKT_MODIFIED;
                }
                normStats[PC_TCP_IPS_DATA][ips_data]++;
                sfBase.iPegs[PERF_COUNT_TCP_IPS_DATA][ips_data]++;
                trunc = overlap;
                break;
            }

            /* all done, keep me out of the loop */
            done = 1;
        }
        else  // Full overlap
        {
            // Don't want to count retransmits as overlaps or do anything
            // else with them.  Account for retransmits of multiple PDUs
            // in one segment.
            if ( right->is_retransmit(rdata, rsize, rseq) )
            {
                rdata += right->size;
                rsize -= right->size;
                rseq += right->size;

                seq += right->size;
                left = right;
                right = right->next;

                if (rsize == 0)
                {
                    // All data was retransmitted
                    RetransmitProcess(p, tcpssn);
                    addthis = 0;
                }
                continue;
            }

            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Got full right overlap\n"); );

            tcpStats.overlaps++;
            st->overlap_count++;

            switch (reassembly_policy)
            {
            case REASSEMBLY_POLICY_BSD:
            case REASSEMBLY_POLICY_LINUX:
            case REASSEMBLY_POLICY_WINDOWS:
            case REASSEMBLY_POLICY_WINDOWS2K3:
            case REASSEMBLY_POLICY_HPUX10:
            case REASSEMBLY_POLICY_IRIX:
            case REASSEMBLY_POLICY_MACOS:
                if (SEQ_GEQ(seq_end, right->seq + right->size) &&
                    SEQ_LT(seq, right->seq))
                {
                    dump_me = right;

                    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "retrans, dropping old data at seq %d, size %d\n",
                        right->seq, right->size); );
                    right = right->next;
                    StreamSeglistDeleteNode(st, dump_me);
                    break;
                }
                else
                {
                    switch (reassembly_policy)
                    {
                    case REASSEMBLY_POLICY_WINDOWS:
                    case REASSEMBLY_POLICY_WINDOWS2K3:
                    case REASSEMBLY_POLICY_BSD:
                    case REASSEMBLY_POLICY_MACOS:
                        /* BSD/MacOS & Windows follow a FIRST policy in the
                         * case below... */
                        break;
                    default:
                        /* All others follow a LAST policy */
                        if (SEQ_GT(seq_end, right->seq + right->size) &&
                            SEQ_EQ(seq, right->seq))
                        {
                            /* When existing data is fully overlapped by new
                             * and sequence numbers are the same, most OSs
                             * follow a LAST policy.
                             */
                            goto right_overlap_last;
                        }
                        break;
                    }
                }
            /* Fall through */
            case REASSEMBLY_POLICY_FIRST:
            case REASSEMBLY_POLICY_VISTA:
                STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Got full right overlap, truncating new\n"); );
                if ( ips_data == NORM_MODE_ON )
                {
                    unsigned offset = right->seq - tdb->seq;
                    memcpy((uint8_t*)p->data+offset, right->payload, right->size);
                    p->packet_flags |= PKT_MODIFIED;
                }
                normStats[PC_TCP_IPS_DATA][ips_data]++;
                sfBase.iPegs[PERF_COUNT_TCP_IPS_DATA][ips_data]++;

                if (SEQ_EQ(right->seq, seq))
                {
                    /* Overlap is greater than or equal to right->size
                     * slide gets set before insertion */
                    seq += right->size;
                    left = right;
                    right = right->next;

                    /* Adjusted seq is fully overlapped */
                    if (SEQ_EQ(seq, seq_end))
                    {
                        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "StreamQueue got full right overlap with "
                            "resulting seq too high, bad segment "
                            "(seq: %X  seq_end: %X overlap: %lu\n",
                            seq, seq_end, overlap); );
                        EventBadSegment();
                        Discard();
                        MODULE_PROFILE_END(s5TcpInsertPerfStats);
                        return STREAM_INSERT_ANOMALY;
                    }

                    /* No data to add on the left of right, so continue
                     * since some of the other non-first targets may have
                     * fallen into this case */
                    continue;
                }

                /* seq is less than right->seq */

                /* trunc is reset to 0 at beginning of loop */
                trunc = overlap;

                /* insert this one, and see if we need to chunk it up
                   Adjust slide so that is correct relative to orig seq */
                slide = seq - tdb->seq;
                ret = AddStreamNode(st, p, tdb, len, slide, trunc, seq, left);
                if (ret != STREAM_INSERT_OK)
                {
                    /* no warning, already done above */
                    MODULE_PROFILE_END(s5TcpInsertPerfStats);
                    return ret;
                }

                /* Set seq to end of right since overlap was greater than
                 * or equal to right->size and inserted seq has been
                 * truncated to beginning of right
                 * And reset trunc to 0 since we may fall out of loop if
                 * next right is NULL */
                seq = right->seq + right->size;
                left = right;
                right = right->next;
                trunc = 0;

                /* Keep looping since in IPS we may need to copy old
                 * data into packet */
                break;

            case REASSEMBLY_POLICY_HPUX11:
            case REASSEMBLY_POLICY_SOLARIS:
                /* If this packet is wholly overlapping and the same size
                 * as a previous one and we have not received the one
                 * immediately preceeding, we take the FIRST. */
                if (SEQ_EQ(right->seq, seq) && (right->size == len) &&
                    (left && !SEQ_EQ(left->seq + left->size, seq)))
                {
                    trunc += overlap;
                    if (SEQ_LEQ((int)(seq_end - trunc), seq))
                    {
                        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "StreamQueue got full right overlap with "
                            "resulting seq too high, bad segment "
                            "(seq: %X  seq_end: %X overlap: %lu\n",
                            seq, seq_end, overlap); );
                        EventBadSegment();
                        Discard();
                        MODULE_PROFILE_END(s5TcpInsertPerfStats);
                        return STREAM_INSERT_ANOMALY;
                    }
                    break;
                }
            /* Fall through */
            case REASSEMBLY_POLICY_OLD_LINUX:
            case REASSEMBLY_POLICY_LAST:
right_overlap_last:
                STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Got full right overlap of old, dropping old\n"); );
                dump_me = right;
                right = right->next;
                StreamSeglistDeleteNode(st, dump_me);
                break;
            }
        }
    }

    if (addthis)
    {
        /* Adjust slide so that is correct relative to orig seq */
        slide = seq - tdb->seq;
        ret = AddStreamNode(
            st, p, tdb, len, slide, trunc, seq, left);
    }
    else
    {
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Fully truncated right overlap\n"); );
    }

    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "StreamQueue returning normally\n"); );

    MODULE_PROFILE_END(s5TcpInsertPerfStats);
    return ret;
}

static void ProcessTcpStream(
    TcpTracker *rcv, TcpSession *tcpssn,
    Packet *p, TcpDataBlock *tdb,
    StreamTcpConfig* config)
{
    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "In ProcessTcpStream(), %d bytes to queue\n", p->dsize); );

    if ( p->packet_flags & PKT_IGNORE )
        return;

#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
    SetPacketHeaderFoo(tcpssn, p);
#endif

    if (rcv->flush_policy == STREAM_FLPOLICY_IGNORE)
    {
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Ignoring segment due to IGNORE flush_policy\n"); );
        return;
    }

    if ((config->flags & STREAM_CONFIG_NO_ASYNC_REASSEMBLY) &&
        !tcpssn->flow->two_way_traffic())
    {
        return;
    }

    if (config->max_consec_small_segs)
    {
        if (p->dsize < config->max_consec_small_seg_size)
        {
            /* check ignore_ports */
            if ( !config->small_seg_ignore[p->ptrs.dp] )
            {
                rcv->small_seg_count++;

                if (rcv->small_seg_count > config->max_consec_small_segs)
                {
                    /* Above threshold, log it...  in this TCP policy,
                     * action controlled by preprocessor rule. */
                    EventMaxSmallSegsExceeded();

                    /* Reset counter, so we're not too noisy */
                    rcv->small_seg_count = 0;
                }
            }
        }
    }

    if (config->max_queued_bytes &&
        (rcv->seg_bytes_total > config->max_queued_bytes))
    {
        tcpStats.max_bytes++;
        return;
    }

    if (config->max_queued_segs &&
        (rcv->seg_count+1 > config->max_queued_segs))
    {
        tcpStats.max_segs++;
        return;
    }

    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "queuing segment\n"); );

    if ( !rcv->seg_count )
    {
        NewQueue(rcv, p, tdb);
        return;
    }
    if ( SEQ_GT(rcv->r_win_base, tdb->seq) )
    {
        uint32_t offset = rcv->r_win_base - tdb->seq;

        if ( offset < p->dsize )
        {
            tdb->seq += offset;
            p->data += offset;
            p->dsize -= (uint16_t)offset;

            StreamQueue(rcv, p, tdb, tcpssn);

            p->dsize += (uint16_t)offset;
            p->data -= offset;
            tdb->seq -= offset;
        }
    }
    else
        StreamQueue(rcv, p, tdb, tcpssn);

    if ((rcv->config->overlap_limit) &&
        (rcv->overlap_count > rcv->config->overlap_limit))
    {
        /* Alert on overlap limit and reset counter */
        EventExcessiveOverlap();
        rcv->overlap_count = 0;
    }
}

static int ProcessTcpData(
    Packet *p, TcpTracker *listener, TcpSession *tcpssn,
    TcpDataBlock *tdb, StreamTcpConfig *config)
{
    PROFILE_VARS;
    MODULE_PROFILE_START(s5TcpDataPerfStats);

    uint32_t seq = tdb->seq;

    if ( p->ptrs.tcph->th_flags & TH_SYN )
    {
        if ( listener->os_policy == STREAM_POLICY_MACOS )
            seq++;

        else
        {
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Bailing, data on SYN, not MAC Policy!\n"); );
            NormalTrimPayloadIfSyn(p, 0, tdb);
            MODULE_PROFILE_END(s5TcpDataPerfStats);
            return STREAM_UNALIGNED;
        }
    }

    /* we're aligned, so that's nice anyway */
    if ( seq == listener->r_nxt_ack )
    {
        /* check if we're in the window */
        if ( listener->config->policy != STREAM_POLICY_PROXY and
            StreamGetWindow(tcpssn->flow, listener, tdb) == 0 )
        {
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Bailing, we're out of the window!\n"); );
            NormalTrimPayloadIfWin(p, 0, tdb);
            MODULE_PROFILE_END(s5TcpDataPerfStats);
            return STREAM_UNALIGNED;
        }

        /* move the ack boundry up, this is the only way we'll accept data */
        // FIXIT-L for ips, must move all the way to first hole or right end
        if (listener->s_mgr.state_queue == TCP_STATE_NONE)
            listener->r_nxt_ack = tdb->end_seq;

        if (p->dsize != 0)
        {
            if ( !(tcpssn->flow->ssn_state.session_flags & SSNFLAG_STREAM_ORDER_BAD) )
                p->packet_flags |= PKT_STREAM_ORDER_OK;

            ProcessTcpStream(listener, tcpssn, p, tdb, config);
            /* set flags to session flags */

            MODULE_PROFILE_END(s5TcpDataPerfStats);
            return STREAM_ALIGNED;
        }
    }
    else
    {
        /* pkt is out of order, do some target-based shizzle here */

        /* NO, we don't want to simply bail.  Some platforms
         * favor unack'd dup data over the original data.
         * Let the reassembly policy decide how to handle
         * the overlapping data.
         *
         * See HP, Solaris, et al. for those that favor
         * duplicate data over the original in some cases.
         */
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "out of order segment (tdb->seq: 0x%X "
            "l->r_nxt_ack: 0x%X!\n", tdb->seq, listener->r_nxt_ack); );

        if (listener->s_mgr.state_queue == TCP_STATE_NONE)
        {
            /* check if we're in the window */
            if ( listener->config->policy != STREAM_POLICY_PROXY and
                StreamGetWindow(tcpssn->flow, listener, tdb) == 0 )
            {
                STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Bailing, we're out of the window!\n"); );
                NormalTrimPayloadIfWin(p, 0, tdb);
                MODULE_PROFILE_END(s5TcpDataPerfStats);
                return STREAM_UNALIGNED;
            }

            if ((listener->s_mgr.state == TCP_STATE_ESTABLISHED) &&
                (listener->flush_policy == STREAM_FLPOLICY_IGNORE))
            {
                if ( SEQ_GT(tdb->end_seq, listener->r_nxt_ack))
                {
                    /* set next ack so we are within the window going forward on
                    * this side. */
                    // FIXIT-L for ips, must move all the way to first hole or right end
                    listener->r_nxt_ack = tdb->end_seq;
                }
            }
        }

        if (p->dsize != 0)
        {
            if ( !(tcpssn->flow->ssn_state.session_flags & SSNFLAG_STREAM_ORDER_BAD) )
            {
                if ( !SEQ_LEQ((tdb->seq + p->dsize), listener->r_nxt_ack) )
                    tcpssn->flow->ssn_state.session_flags |= SSNFLAG_STREAM_ORDER_BAD;
            }
            ProcessTcpStream(listener, tcpssn, p, tdb, config);
        }
    }

    MODULE_PROFILE_END(s5TcpDataPerfStats);
    return STREAM_UNALIGNED;
}

void SetTcpReassemblyPolicy(TcpTracker *st)
{
    st->reassembly_policy = GetTcpReassemblyPolicy(st->os_policy);
}

static void SetOSPolicy(Flow* flow, TcpSession* tcpssn)
{
    if ( !tcpssn->client.os_policy )
    {
        tcpssn->client.os_policy = flow->ssn_policy ? flow->ssn_policy :
            tcpssn->client.config->policy;
        SetTcpReassemblyPolicy(&tcpssn->client);
    }

    if ( !tcpssn->server.os_policy )
    {
        tcpssn->server.os_policy = flow->ssn_policy ? flow->ssn_policy :
            tcpssn->server.config->policy;
        SetTcpReassemblyPolicy(&tcpssn->server);
    }
}

/* Use a for loop and byte comparison, which has proven to be
 * faster on pipelined architectures compared to a memcmp (setup
 * for memcmp is slow).  Not using a 4 byte and 2 byte long because
 * there is no guarantee of memory alignment (and thus performance
 * issues similar to memcmp). */
static inline int ValidMacAddress(
    TcpTracker *talker, TcpTracker *listener, Packet *p)
{
    int i, j, ret = 0;

    if (!(p->proto_bits & PROTO_BIT__ETH))
        return 0;

    // if flag is set, gauranteed to have an eth layer
    const eth::EtherHdr* eh = layer::get_eth_layer(p);

    for ( i = 0; i < 6; ++i )
    {
        if ((talker->mac_addr[i] != eh->ether_src[i]))
            break;
    }
    for ( j = 0; j < 6; ++j )
    {
        if (listener->mac_addr[j] != eh->ether_dst[j])
            break;
    }

    // FIXIT-L make this swap check configurable
    if ( i < 6 && j < 6 )
    {
        if (
            !memcmp(talker->mac_addr, eh->ether_dst, 6) &&
            !memcmp(listener->mac_addr, eh->ether_src, 6)
            )
            // this is prolly a tap
            return 0;
    }

    if ( i < 6 )
    {
        if (p->packet_flags & PKT_FROM_CLIENT)
            ret |= EVENT_SESSION_HIJACK_CLIENT;
        else
            ret |= EVENT_SESSION_HIJACK_SERVER;
    }
    if ( j < 6 )
    {
        if (p->packet_flags & PKT_FROM_CLIENT)
            ret |= EVENT_SESSION_HIJACK_SERVER;
        else
            ret |= EVENT_SESSION_HIJACK_CLIENT;
    }
    return ret;
}

static inline void CopyMacAddr(
    Packet* p, TcpSession* tcpssn, int dir)
{
    int i;

    /* Not ethernet based, nothing to do */
    if (!(p->proto_bits & PROTO_BIT__ETH))
        return;

    // if flag is set, gauranteed to have an eth layer
    const eth::EtherHdr* eh = layer::get_eth_layer(p);

    if (dir == FROM_CLIENT)
    {
        /* Client is SRC */
        for (i=0; i<6; i++)
        {
            tcpssn->client.mac_addr[i] = eh->ether_src[i];
            tcpssn->server.mac_addr[i] = eh->ether_dst[i];
        }
    }
    else
    {
        /* Server is SRC */
        for (i=0; i<6; i++)
        {
            tcpssn->server.mac_addr[i] = eh->ether_src[i];
            tcpssn->client.mac_addr[i] = eh->ether_dst[i];
        }
    }
}

static void NewTcpSession(
    Packet* p, Flow* lwssn, StreamTcpConfig* dstPolicy, TcpSession* tmp)
{
    Inspector* ins = lwssn->gadget;

    if ( !ins )
        ins = lwssn->clouseau;

    if ( ins )
    {
        stream.set_splitter(lwssn, true, ins->get_splitter(true));
        stream.set_splitter(lwssn, false, ins->get_splitter(false));
    }
    else
    {
        stream.set_splitter(lwssn, true, new AtomSplitter(true));
        stream.set_splitter(lwssn, false, new AtomSplitter(false));
    }

    {
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "adding TcpSession to lightweight session\n"); );
        lwssn->protocol = p->type();
        tmp->flow = lwssn;

        /* New session, previous was marked as reset.  Clear the
         * reset flag. */
        if (lwssn->ssn_state.session_flags & SSNFLAG_RESET)
            lwssn->ssn_state.session_flags &= ~SSNFLAG_RESET;

        SetOSPolicy(lwssn, tmp);

        if ( (lwssn->ssn_state.session_flags & SSNFLAG_CLIENT_SWAP) &&
            !(lwssn->ssn_state.session_flags & SSNFLAG_CLIENT_SWAPPED) )
        {
            TcpTracker trk = tmp->client;
            sfip_t ip = lwssn->client_ip;
            uint16_t port = lwssn->client_port;

            tmp->client = tmp->server;
            tmp->server = trk;

            lwssn->client_ip = lwssn->server_ip;
            lwssn->server_ip = ip;

            lwssn->client_port = lwssn->server_port;
            lwssn->server_port = port;

            if ( !lwssn->two_way_traffic() )
            {
                if ( lwssn->ssn_state.session_flags & SSNFLAG_SEEN_CLIENT )
                {
                    lwssn->ssn_state.session_flags ^= SSNFLAG_SEEN_CLIENT;
                    lwssn->ssn_state.session_flags |= SSNFLAG_SEEN_SERVER;
                }
                else if ( lwssn->ssn_state.session_flags & SSNFLAG_SEEN_SERVER )
                {
                    lwssn->ssn_state.session_flags ^= SSNFLAG_SEEN_SERVER;
                    lwssn->ssn_state.session_flags |= SSNFLAG_SEEN_CLIENT;
                }
            }
            lwssn->ssn_state.session_flags |= SSNFLAG_CLIENT_SWAPPED;
        }
        init_flush_policy(lwssn, &tmp->server);
        init_flush_policy(lwssn, &tmp->client);

#ifdef DEBUG_STREAM_EX
        PrintTcpSession(tmp);
#endif
        lwssn->set_expire(p, dstPolicy->session_timeout);

        AddStreamSession(
            &sfBase, lwssn->session_state & STREAM_STATE_MIDSTREAM ? SSNFLAG_MIDSTREAM : 0);

        StreamUpdatePerfBaseState(&sfBase, tmp->flow, TCP_STATE_SYN_SENT);

        EventInternal(INTERNAL_EVENT_SESSION_ADD);

        tmp->ecn = 0;
        assert(!tmp->tcp_init);
        tmp->tcp_init = true;

        tcpStats.trackers_created++;
    }
}

static void NewTcpSessionOnSyn(
    Packet* p, Flow* lwssn,
    TcpDataBlock* tdb, StreamTcpConfig* dstPolicy)
{
    PROFILE_VARS;
    MODULE_PROFILE_START(s5TcpNewSessPerfStats);
    TcpSession* tmp;
    {
        /******************************************************************
         * start new sessions on proper SYN packets
         *****************************************************************/
        tmp = (TcpSession*)lwssn->session;
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Creating new session tracker on SYN!\n"); );

        lwssn->ssn_state.session_flags |= SSNFLAG_SEEN_CLIENT;

        if (p->ptrs.tcph->are_flags_set(TH_CWR|TH_ECE))
        {
            lwssn->ssn_state.session_flags |= SSNFLAG_ECN_CLIENT_QUERY;
        }

        /* setup the stream trackers */
        tmp->client.s_mgr.state = TCP_STATE_SYN_SENT;
        tmp->client.isn = tdb->seq;
        tmp->client.l_unackd = tdb->seq + 1;
        tmp->client.l_nxt_seq = tmp->client.l_unackd;

        if ( tdb->seq != tdb->end_seq )
            tmp->client.l_nxt_seq += (tdb->end_seq - tdb->seq - 1);

        tmp->client.l_window = tdb->win;
        tmp->client.ts_last_pkt = p->pkth->ts.tv_sec;

        tmp->server.seglist_base_seq = tmp->client.l_unackd;
        tmp->server.r_nxt_ack = tmp->client.l_unackd;
        tmp->server.r_win_base = tdb->seq+1;

        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "seglist_base_seq = %X\n", tmp->server.seglist_base_seq); );
        tmp->server.s_mgr.state = TCP_STATE_LISTEN;

        tmp->client.flags |= StreamGetTcpTimestamp(p, &tmp->client.ts_last, 0);
        if (tmp->client.ts_last == 0)
            tmp->client.flags |= TF_TSTAMP_ZERO;
        tmp->client.flags |= StreamGetMss(p, &tmp->client.mss);
        tmp->client.flags |= StreamGetWscale(p, &tmp->client.wscale);

        /* Set the StreamTcpConfig for each direction (pkt from client) */
        tmp->client.config = dstPolicy;  // FIXIT-M use external binding for both dirs
        tmp->server.config = dstPolicy;  // (applies to all the blocks in this funk)

        CopyMacAddr(p, tmp, FROM_CLIENT);
    }
    tcpStats.sessions_on_syn++;
    NewTcpSession(p, lwssn, dstPolicy, tmp);
    MODULE_PROFILE_END(s5TcpNewSessPerfStats);
}

static void NewTcpSessionOnSynAck(
    Packet* p, Flow* lwssn,
    TcpDataBlock* tdb, StreamTcpConfig* dstPolicy)
{
    PROFILE_VARS;
    MODULE_PROFILE_START(s5TcpNewSessPerfStats);
    TcpSession* tmp;
    {
        tmp = (TcpSession*)lwssn->session;
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Creating new session tracker on SYN_ACK!\n"); );

        lwssn->ssn_state.session_flags |= SSNFLAG_SEEN_SERVER;

        if (p->ptrs.tcph->are_flags_set(TH_CWR|TH_ECE))
        {
            lwssn->ssn_state.session_flags |= SSNFLAG_ECN_SERVER_REPLY;
        }

        /* setup the stream trackers */
        tmp->server.s_mgr.state = TCP_STATE_SYN_RCVD;
        tmp->server.isn = tdb->seq;
        tmp->server.l_unackd = tdb->seq + 1;
        tmp->server.l_nxt_seq = tmp->server.l_unackd;
        tmp->server.l_window = tdb->win;

        tmp->server.seglist_base_seq = tdb->ack;
        tmp->server.r_win_base = tdb->ack;
        tmp->server.r_nxt_ack = tdb->ack;
        tmp->server.ts_last_pkt = p->pkth->ts.tv_sec;

        tmp->client.seglist_base_seq = tmp->server.l_unackd;
        tmp->client.r_nxt_ack = tmp->server.l_unackd;
        tmp->client.r_win_base = tdb->seq+1;
        tmp->client.l_nxt_seq = tdb->ack;
        tmp->client.isn = tdb->ack-1;

        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "seglist_base_seq = %X\n", tmp->client.seglist_base_seq); );
        tmp->client.s_mgr.state = TCP_STATE_SYN_SENT;

        tmp->server.flags |= StreamGetTcpTimestamp(p, &tmp->server.ts_last, 0);
        if (tmp->server.ts_last == 0)
            tmp->server.flags |= TF_TSTAMP_ZERO;
        tmp->server.flags |= StreamGetMss(p, &tmp->server.mss);
        tmp->server.flags |= StreamGetWscale(p, &tmp->server.wscale);

        /* Set the config for each direction (pkt from server) */
        tmp->server.config = dstPolicy;
        tmp->client.config = dstPolicy;

        CopyMacAddr(p, tmp, FROM_SERVER);
    }
    tcpStats.sessions_on_syn_ack++;
    NewTcpSession(p, lwssn, dstPolicy, tmp);
    MODULE_PROFILE_END(s5TcpNewSessPerfStats);
}

static void NewTcpSessionOn3Way(
    Packet* p, Flow* lwssn,
    TcpDataBlock* tdb, StreamTcpConfig* dstPolicy)
{
    PROFILE_VARS;
    MODULE_PROFILE_START(s5TcpNewSessPerfStats);
    TcpSession* tmp;
    {
        /******************************************************************
         * start new sessions on completion of 3-way (ACK only, no data)
         *****************************************************************/
        tmp = (TcpSession*)lwssn->session;
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Creating new session tracker on ACK!\n"); );

        lwssn->ssn_state.session_flags |= SSNFLAG_SEEN_CLIENT;

        if (p->ptrs.tcph->are_flags_set(TH_CWR|TH_ECE))
        {
            lwssn->ssn_state.session_flags |= SSNFLAG_ECN_CLIENT_QUERY;
        }

        /* setup the stream trackers */
        tmp->client.s_mgr.state = TCP_STATE_ESTABLISHED;
        tmp->client.isn = tdb->seq;
        tmp->client.l_unackd = tdb->seq + 1;
        tmp->client.l_nxt_seq = tmp->client.l_unackd;
        tmp->client.l_window = tdb->win;

        tmp->client.ts_last_pkt = p->pkth->ts.tv_sec;

        tmp->server.seglist_base_seq = tmp->client.l_unackd;
        tmp->server.r_nxt_ack = tmp->client.l_unackd;
        tmp->server.r_win_base = tdb->seq+1;

        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "seglist_base_seq = %X\n", tmp->server.seglist_base_seq); );
        tmp->server.s_mgr.state = TCP_STATE_ESTABLISHED;

        tmp->client.flags |= StreamGetTcpTimestamp(p, &tmp->client.ts_last, 0);
        if (tmp->client.ts_last == 0)
            tmp->client.flags |= TF_TSTAMP_ZERO;
        tmp->client.flags |= StreamGetMss(p, &tmp->client.mss);
        tmp->client.flags |= StreamGetWscale(p, &tmp->client.wscale);

        /* Set the config for each direction (pkt from client) */
        tmp->client.config = dstPolicy;
        tmp->server.config = dstPolicy;

        CopyMacAddr(p, tmp, FROM_CLIENT);
    }
    tcpStats.sessions_on_3way++;
    NewTcpSession(p, lwssn, dstPolicy, tmp);
    MODULE_PROFILE_END(s5TcpNewSessPerfStats);
}

static void NewTcpSessionOnData(
    Packet* p, Flow* lwssn,
    TcpDataBlock* tdb, StreamTcpConfig* dstPolicy)
{
    PROFILE_VARS;
    MODULE_PROFILE_START(s5TcpNewSessPerfStats);
    TcpSession* tmp;
    {
        tmp = (TcpSession*)lwssn->session;
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Creating new session tracker on data packet (ACK|PSH)!\n"); );

        if (lwssn->ssn_state.direction == FROM_CLIENT)
        {
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Session direction is FROM_CLIENT\n"); );

            /* Sender is client (src port is higher) */
            lwssn->ssn_state.session_flags |= SSNFLAG_SEEN_CLIENT;

            if (p->ptrs.tcph->are_flags_set(TH_CWR|TH_ECE))
            {
                lwssn->ssn_state.session_flags |= SSNFLAG_ECN_CLIENT_QUERY;
            }

            /* setup the stream trackers */
            tmp->client.s_mgr.state = TCP_STATE_ESTABLISHED;
            tmp->client.isn = tdb->seq;
            tmp->client.l_unackd = tdb->seq;
            tmp->client.l_nxt_seq = tmp->client.l_unackd;
            tmp->client.l_window = tdb->win;

            tmp->client.ts_last_pkt = p->pkth->ts.tv_sec;

            tmp->server.seglist_base_seq = tmp->client.l_unackd;
            tmp->server.r_nxt_ack = tmp->client.l_unackd;
            tmp->server.r_win_base = tdb->seq;
            tmp->server.l_window = 0; /* reset later */

            /* Next server packet is what was ACKd */
            //tmp->server.l_nxt_seq = tdb->ack + 1;
            tmp->server.l_unackd = tdb->ack - 1;

            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "seglist_base_seq = %X\n", tmp->server.seglist_base_seq); );
            tmp->server.s_mgr.state = TCP_STATE_ESTABLISHED;

            tmp->client.flags |= StreamGetTcpTimestamp(p, &tmp->client.ts_last, 0);
            if (tmp->client.ts_last == 0)
                tmp->client.flags |= TF_TSTAMP_ZERO;
            tmp->client.flags |= StreamGetMss(p, &tmp->client.mss);
            tmp->client.flags |= StreamGetWscale(p, &tmp->client.wscale);

            /* Set the config for each direction (pkt from client) */
            tmp->client.config = dstPolicy;
            tmp->server.config = dstPolicy;

            CopyMacAddr(p, tmp, FROM_CLIENT);
        }
        else
        {
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Session direction is FROM_SERVER\n"); );

            /* Sender is server (src port is lower) */
            lwssn->ssn_state.session_flags |= SSNFLAG_SEEN_SERVER;

            /* setup the stream trackers */
            tmp->server.s_mgr.state = TCP_STATE_ESTABLISHED;
            tmp->server.isn = tdb->seq;
            tmp->server.l_unackd = tdb->seq;
            tmp->server.l_nxt_seq = tmp->server.l_unackd;
            tmp->server.l_window = tdb->win;

            tmp->server.seglist_base_seq = tdb->ack;
            tmp->server.r_win_base = tdb->ack;
            tmp->server.r_nxt_ack = tdb->ack;
            tmp->server.ts_last_pkt = p->pkth->ts.tv_sec;

            tmp->client.seglist_base_seq = tmp->server.l_unackd;
            tmp->client.r_nxt_ack = tmp->server.l_unackd;
            tmp->client.r_win_base = tdb->seq;
            tmp->client.l_window = 0; /* reset later */
            tmp->client.isn = tdb->ack-1;

            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "seglist_base_seq = %X\n", tmp->client.seglist_base_seq); );
            tmp->client.s_mgr.state = TCP_STATE_ESTABLISHED;

            tmp->server.flags |= StreamGetTcpTimestamp(p, &tmp->server.ts_last, 0);
            if (tmp->server.ts_last == 0)
                tmp->server.flags |= TF_TSTAMP_ZERO;
            tmp->server.flags |= StreamGetMss(p, &tmp->server.mss);
            tmp->server.flags |= StreamGetWscale(p, &tmp->server.wscale);

            /* Set the config for each direction (pkt from server) */
            tmp->server.config = dstPolicy;
            tmp->client.config = dstPolicy;

            CopyMacAddr(p, tmp, FROM_SERVER);
        }
    }
    tcpStats.sessions_on_data++;
    NewTcpSession(p, lwssn, dstPolicy, tmp);
    MODULE_PROFILE_END(s5TcpNewSessPerfStats);
}

static int RepeatedSyn(
    TcpTracker *listener, TcpTracker *talker,
    TcpDataBlock *tdb, TcpSession *tcpssn)
{
    switch (listener->os_policy)
    {
    case STREAM_POLICY_WINDOWS:
    case STREAM_POLICY_WINDOWS2K3:
    case STREAM_POLICY_VISTA:
        /* Windows has some strange behaviour here.  If the
         * sequence of the reset is the next expected sequence,
         * it Resets.  Otherwise it ignores the 2nd SYN.
         */
        if (SEQ_EQ(tdb->seq, listener->r_nxt_ack))
        {
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Got syn on established windows ssn, which causes Reset,"
                "bailing\n"); );
            tcpssn->flow->ssn_state.session_flags |= SSNFLAG_RESET;
            talker->s_mgr.state = TCP_STATE_CLOSED;
            return ACTION_RST;
        }
        else
        {
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Got syn on established windows ssn, not causing Reset,"
                "bailing\n"); );
            Discard();
            return ACTION_NOTHING;
        }
        break;
    case STREAM_POLICY_MACOS:
        /* MACOS ignores a 2nd SYN, regardless of the sequence number. */
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Got syn on established macos ssn, not causing Reset,"
            "bailing\n"); );
        Discard();
        return ACTION_NOTHING;
        break;
    case STREAM_POLICY_FIRST:
    case STREAM_POLICY_LAST:
    case STREAM_POLICY_LINUX:
    case STREAM_POLICY_OLD_LINUX:
    case STREAM_POLICY_BSD:
    case STREAM_POLICY_SOLARIS:
    case STREAM_POLICY_HPUX11:
    case STREAM_POLICY_HPUX10:
    case STREAM_POLICY_IRIX:
        /* If its not a retransmission of the actual SYN... RESET */
        if (!SEQ_EQ(tdb->seq,talker->isn))
        {
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Got syn on established ssn, which causes Reset, bailing\n"); );
            tcpssn->flow->ssn_state.session_flags |= SSNFLAG_RESET;
            talker->s_mgr.state = TCP_STATE_CLOSED;
            return ACTION_RST;
        }
        else
        {
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Got syn on established ssn, not causing Reset,"
                "bailing\n"); );
            Discard();
            return ACTION_NOTHING;
        }
        break;
    }
    return ACTION_NOTHING;
}

static void LogTcpEvents(int eventcode)
{
    if ( !eventcode )
        return;

    if (eventcode & EVENT_SYN_ON_EST)
        EventSynOnEst();

    if (eventcode & EVENT_DATA_ON_SYN)
        EventDataOnSyn();

    if (eventcode & EVENT_DATA_ON_CLOSED)
        EventDataOnClosed();

    if (eventcode & EVENT_BAD_TIMESTAMP)
        EventBadTimestamp();

    if (eventcode & EVENT_WINDOW_TOO_LARGE)
        EventWindowTooLarge();

    if (eventcode & EVENT_DATA_AFTER_RESET)
        EventDataAfterReset();

    if (eventcode & EVENT_SESSION_HIJACK_CLIENT)
        EventSessionHijackedClient();

    if (eventcode & EVENT_SESSION_HIJACK_SERVER)
        EventSessionHijackedServer();

    if (eventcode & EVENT_DATA_WITHOUT_FLAGS)
        EventDataWithoutFlags();

    if (eventcode & EVENT_4WHS)
        Event4whs();

    if (eventcode & EVENT_NO_TIMESTAMP)
        EventNoTimestamp();

    if (eventcode & EVENT_BAD_RST)
        EventBadReset();

    if (eventcode & EVENT_BAD_FIN)
        EventBadFin();

    if (eventcode & EVENT_BAD_ACK)
        EventBadAck();

    if (eventcode & EVENT_DATA_AFTER_RST_RCVD)
        EventDataAfterRstRcvd();

    if (eventcode & EVENT_WINDOW_SLAM)
        EventWindowSlam();
}

static int ProcessTcp(
    Flow* lwssn, Packet* p, TcpDataBlock* tdb,
    StreamTcpConfig* config)
{
    int retcode = ACTION_NOTHING;
    int eventcode = 0;
    int got_ts = 0;
    int new_ssn = 0;
    int ts_action = ACTION_NOTHING;
    TcpSession *tcpssn = NULL;
    TcpTracker *talker = NULL;
    TcpTracker *listener = NULL;
    STREAM_DEBUG_WRAP(char *t = NULL; char *l = NULL;)
    PROFILE_VARS;

    if (lwssn->protocol != PktType::TCP)
    {
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Lightweight session not TCP on TCP packet\n"); );
        return retcode;
    }

    tcpssn = (TcpSession*)lwssn->session;

    MODULE_PROFILE_START(s5TcpStatePerfStats);

    if ( !tcpssn->tcp_init )
    {
        {
            // FIXIT-L expected flow should be checked by flow_con before we
            // get here
            char ignore = flow_con->expected_flow(lwssn, p);

            if ( ignore )
            {
                tcpssn->server.flush_policy = STREAM_FLPOLICY_IGNORE;
                tcpssn->client.flush_policy = STREAM_FLPOLICY_IGNORE;
                return retcode;
            }
        }
        bool require3Way = config->require_3whs();
        bool allow_midstream = config->midstream_allowed(p);

        if ( p->ptrs.tcph->is_syn_only() )
        {
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Stream SYN PACKET, establishing lightweight"
                "session direction.\n"); );
            /* SYN packet from client */
            lwssn->ssn_state.direction = FROM_CLIENT;
            lwssn->session_state |= STREAM_STATE_SYN;

            if ( require3Way || (StreamPacketHasWscale(p) & TF_WSCALE) ||
                (p->dsize > 0) )
            {
                /* Create TCP session if we
                 * 1) require 3-WAY HS, OR
                 * 2) client sent wscale option, OR
                 * 3) have data
                 */
                NewTcpSessionOnSyn(p, lwssn, tdb, config);
                new_ssn = 1;
                NormalTrackECN(tcpssn, (TCPHdr*)p->ptrs.tcph, require3Way);
            }

            /* Nothing left todo here */
        }
        else if ( p->ptrs.tcph->is_syn_ack() )
        {
            /* SYN-ACK from server */
            if ((lwssn->session_state == STREAM_STATE_NONE) ||
                (lwssn->ssn_state.session_flags & SSNFLAG_RESET))
            {
                STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Stream SYN|ACK PACKET, establishing lightweight"
                    "session direction.\n"); );
                lwssn->ssn_state.direction = FROM_SERVER;
            }
            lwssn->session_state |= STREAM_STATE_SYN_ACK;

            if ( !require3Way || allow_midstream )
            {
                NewTcpSessionOnSynAck(p, lwssn, tdb, config);
                new_ssn = 1;
            }
            NormalTrackECN(tcpssn, (TCPHdr*)p->ptrs.tcph, require3Way);
        }
        else if (
            p->ptrs.tcph->is_ack() && !p->ptrs.tcph->is_rst() &&
            (lwssn->session_state & STREAM_STATE_SYN_ACK) )
        {
            /* TODO: do we need to verify the ACK field is >= the seq of the SYN-ACK?
               3-way Handshake complete, create TCP session */
            lwssn->session_state |= STREAM_STATE_ACK | STREAM_STATE_ESTABLISHED;
            NewTcpSessionOn3Way(p, lwssn, tdb, config);
            new_ssn = 1;
            NormalTrackECN(tcpssn, (TCPHdr*)p->ptrs.tcph, require3Way);
            StreamUpdatePerfBaseState(&sfBase, lwssn, TCP_STATE_ESTABLISHED);
        }
        else if ( p->dsize && (!require3Way || allow_midstream) )
        {
            /* create session on data, need to figure out direction, etc
               Assume from client, can update later */
            if (p->ptrs.sp > p->ptrs.dp)
                lwssn->ssn_state.direction = FROM_CLIENT;
            else
                lwssn->ssn_state.direction = FROM_SERVER;

            lwssn->session_state |= STREAM_STATE_MIDSTREAM;
            lwssn->ssn_state.session_flags |= SSNFLAG_MIDSTREAM;

            NewTcpSessionOnData(p, lwssn, tdb, config);
            new_ssn = 1;
            NormalTrackECN(tcpssn, (TCPHdr*)p->ptrs.tcph, require3Way);

            if (lwssn->session_state & STREAM_STATE_ESTABLISHED)
                StreamUpdatePerfBaseState(&sfBase, lwssn, TCP_STATE_ESTABLISHED);
        }
        else if ( !p->dsize )
        {
            /* Do nothing. */
            MODULE_PROFILE_END(s5TcpStatePerfStats);
            return retcode;
        }
    }
    else
    {
        /* If session is already marked as established */
        if ( !(lwssn->session_state & STREAM_STATE_ESTABLISHED) &&
            (!config->require_3whs() || config->midstream_allowed(p)) )
        {
            /* If not requiring 3-way Handshake... */

            /* TCP session created on TH_SYN above,
             * or maybe on SYN-ACK, or anything else */

            /* Need to update Lightweight session state */
            if ( p->ptrs.tcph->is_syn_ack() )
            {
                /* SYN-ACK from server */
                if (lwssn->session_state != STREAM_STATE_NONE)
                {
                    lwssn->session_state |= STREAM_STATE_SYN_ACK;
                }
            }
            else if ( p->ptrs.tcph->is_ack() &&
                (lwssn->session_state & STREAM_STATE_SYN_ACK) )
            {
                lwssn->session_state |= STREAM_STATE_ACK | STREAM_STATE_ESTABLISHED;
                StreamUpdatePerfBaseState(&sfBase, lwssn, TCP_STATE_ESTABLISHED);
            }
        }
        if ( p->ptrs.tcph->is_syn() )
            NormalTrackECN(tcpssn, (TCPHdr*)p->ptrs.tcph, config->require_3whs());
    }

    if (p->packet_flags & PKT_FROM_SERVER)
    {
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Stream: Updating on packet from server\n"); );
        lwssn->ssn_state.session_flags |= SSNFLAG_SEEN_SERVER;

        if (tcpssn->tcp_init)
        {
            talker = &tcpssn->server;
            listener = &tcpssn->client;
        }

        STREAM_DEBUG_WRAP(
            t = "Server";
            l = "Client");

        if ( talker && talker->s_mgr.state == TCP_STATE_LISTEN &&
            ((p->ptrs.tcph->th_flags & (TH_SYN|TH_ACK)) == TH_SYN) )
        {
            eventcode |= EVENT_4WHS;
        }
        /* If we picked this guy up midstream, finish the initialization */
        if ((lwssn->session_state & STREAM_STATE_MIDSTREAM) &&
            !(lwssn->session_state & STREAM_STATE_ESTABLISHED))
        {
            FinishServerInit(p, tdb, tcpssn);
            if ((p->ptrs.tcph->th_flags & TH_ECE) &&
                lwssn->ssn_state.session_flags & SSNFLAG_ECN_CLIENT_QUERY)
            {
                lwssn->ssn_state.session_flags |= SSNFLAG_ECN_SERVER_REPLY;
            }

            if (lwssn->ssn_state.session_flags & SSNFLAG_SEEN_CLIENT)
            {
                // should TCP state go to established too?
                lwssn->session_state |= STREAM_STATE_ESTABLISHED;
                lwssn->ssn_state.session_flags |= SSNFLAG_ESTABLISHED;
                StreamUpdatePerfBaseState(&sfBase, lwssn, TCP_STATE_ESTABLISHED);
            }
        }
        if ( !lwssn->inner_server_ttl )
            lwssn->set_ttl(p, false);
    }
    else
    {
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Stream: Updating on packet from client\n"); );
        /* if we got here we had to see the SYN already... */
        lwssn->ssn_state.session_flags |= SSNFLAG_SEEN_CLIENT;
        if (tcpssn->tcp_init)
        {
            talker = &tcpssn->client;
            listener = &tcpssn->server;
        }

        STREAM_DEBUG_WRAP(
            t = "Client";
            l = "Server"; );

        if ((lwssn->session_state & STREAM_STATE_MIDSTREAM) &&
            !(lwssn->session_state & STREAM_STATE_ESTABLISHED))
        {
            /* Midstream and seen server. */
            if (lwssn->ssn_state.session_flags & SSNFLAG_SEEN_SERVER)
            {
                lwssn->session_state |= STREAM_STATE_ESTABLISHED;
                lwssn->ssn_state.session_flags |= SSNFLAG_ESTABLISHED;
            }
        }
        if ( !lwssn->inner_client_ttl )
            lwssn->set_ttl(p, true);
    }

    /*
     * check for SYN on reset session
     */
    if ((lwssn->ssn_state.session_flags & SSNFLAG_RESET) &&
        (p->ptrs.tcph->th_flags & TH_SYN))
    {
        if ( !tcpssn->tcp_init ||
            (listener->s_mgr.state == TCP_STATE_CLOSED) ||
            (talker->s_mgr.state == TCP_STATE_CLOSED) )
        {
            /* Listener previously issued a reset
               Talker is re-SYN-ing */
            // FIXIT-L this leads to bogus 129:20
            TcpSessionCleanup(lwssn, 1);

            if (p->ptrs.tcph->th_flags & TH_RST)
            {
                /* FIXIT-M  In inline mode, only one of the normalizations
                *           can occur.  If the first normalization
                *           fires, there is nothing for the second normalization
                *           to do.  However, in inline-test mode, since
                *           nothing is actually normalized, both of the
                *           following functions report that they 'would'
                *           normalize. i.e., both functions increment their
                *           count even though only one function can ever
                *           perform a normalization.
                */

                /* Got SYN/RST.  We're done. */
                NormalTrimPayloadIfSyn(p, 0, tdb);
                NormalTrimPayloadIfRst(p, 0, tdb);
                MODULE_PROFILE_END(s5TcpStatePerfStats);
                return retcode | ACTION_RST;
            }
            else if ( p->ptrs.tcph->is_syn_only() )
            {
                lwssn->ssn_state.direction = FROM_CLIENT;
                lwssn->session_state = STREAM_STATE_SYN;
                lwssn->set_ttl(p, true);
                NewTcpSessionOnSyn(p, lwssn, tdb, config);
                tcpStats.resyns++;
                new_ssn = 1;

                bool require3Way = config->require_3whs();
                NormalTrackECN(tcpssn, (TCPHdr*)p->ptrs.tcph, require3Way);

                {
                    listener = &tcpssn->server;
                    talker = &tcpssn->client;
                }
                lwssn->ssn_state.session_flags = SSNFLAG_SEEN_CLIENT;
            }
            else if ( p->ptrs.tcph->is_syn_ack() )
            {
                lwssn->ssn_state.direction = FROM_SERVER;
                lwssn->session_state = STREAM_STATE_SYN_ACK;
                lwssn->set_ttl(p, false);
                NewTcpSessionOnSynAck(p, lwssn, tdb, config);
                tcpStats.resyns++;
                tcpssn = (TcpSession*)lwssn->session;
                new_ssn = 1;

                bool require3Way = config->require_3whs();
                NormalTrackECN(tcpssn, (TCPHdr*)p->ptrs.tcph, require3Way);

                {
                    listener = &tcpssn->client;
                    talker = &tcpssn->server;
                }
                lwssn->ssn_state.session_flags = SSNFLAG_SEEN_SERVER;
            }
        }
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Got SYN pkt on reset ssn, re-SYN-ing\n"); );
    }

    // FIXIT-L why flush here instead of just purge?
    // s5_ignored_session() may be disabling detection too soon if we really want to flush
    if ( stream.ignored_session(lwssn, p) )
    {
        if ( talker && (talker->flags & TF_FORCE_FLUSH) )
        {
            tcpssn->flush_talker(p);
            talker->flags &= ~TF_FORCE_FLUSH;
        }
        if ( listener && (listener->flags & TF_FORCE_FLUSH) )
        {
            tcpssn->flush_listener(p);
            listener->flags &= ~TF_FORCE_FLUSH;
        }
        p->packet_flags |= PKT_IGNORE;
        retcode |= ACTION_DISABLE_INSPECTION;
    }

    /* Handle data on SYN */
    if ((p->dsize) && p->ptrs.tcph->is_syn())
    {
        /* MacOS accepts data on SYN, so don't alert if policy is MACOS */
        if ( talker->os_policy != STREAM_POLICY_MACOS)
        {
            // remove data on SYN
            NormalTrimPayloadIfSyn(p, 0, tdb);

            if ( Normalize_GetMode(NORM_TCP_TRIM_SYN) == NORM_MODE_OFF )
            {
                STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Got data on SYN packet, not processing it\n"); );
                //EventDataOnSyn(config);
                eventcode |= EVENT_DATA_ON_SYN;
                retcode |= ACTION_BAD_PKT;
            }
        }
    }

    if (!tcpssn->tcp_init)
    {
        LogTcpEvents(eventcode);
        MODULE_PROFILE_END(s5TcpStatePerfStats);
        return retcode;
    }

    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "   %s [talker] state: %s\n", t,
        state_names[talker->s_mgr.state]); );
    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "   %s state: %s(%d)\n", l,
        state_names[listener->s_mgr.state],
        listener->s_mgr.state); );

    // may find better placement to eliminate redundant flag checks
    if (p->ptrs.tcph->th_flags & TH_SYN)
        talker->s_mgr.sub_state |= SUB_SYN_SENT;
    if (p->ptrs.tcph->th_flags & TH_ACK)
        talker->s_mgr.sub_state |= SUB_ACK_SENT;

    /*
     * process SYN ACK on unestablished sessions
     */
    if ( (TCP_STATE_SYN_SENT == listener->s_mgr.state) &&
        (TCP_STATE_LISTEN == talker->s_mgr.state) )
    {
        if (p->ptrs.tcph->th_flags & TH_ACK)
        {
            /*
             * make sure we've got a valid segment
             */
            if (!IsBetween(listener->l_unackd, listener->l_nxt_seq, tdb->ack))
            {
                STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Pkt ack is out of bounds, bailing!\n"); );
                Discard();
                NormalTrimPayloadIfWin(p, 0, tdb);
                LogTcpEvents(eventcode);
                MODULE_PROFILE_END(s5TcpStatePerfStats);
                return retcode | ACTION_BAD_PKT;
            }
        }

        talker->flags |= StreamGetTcpTimestamp(p, &tdb->ts, 0);
        if (tdb->ts == 0)
            talker->flags |= TF_TSTAMP_ZERO;

        /*
         * catch resets sent by server
         */
        if (p->ptrs.tcph->th_flags & TH_RST)
        {
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "got RST\n"); );

            NormalTrimPayloadIfRst(p, 0, tdb);

            /* Reset is valid when in SYN_SENT if the
             * ack field ACKs the SYN.
             */
            if (ValidRstSynSent(listener, tdb))
            {
                STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "got RST, closing talker\n"); );
                /* Reset is valid */
                /* Mark session as reset... Leave it around so that any
                 * additional data sent from one side or the other isn't
                 * processed (and is dropped in inline mode).
                 */
                lwssn->ssn_state.session_flags |= SSNFLAG_RESET;
                talker->s_mgr.state = TCP_STATE_CLOSED;
                StreamUpdatePerfBaseState(&sfBase, lwssn, TCP_STATE_CLOSING);
                /* Leave listener open, data may be in transit */
                LogTcpEvents(eventcode);
                MODULE_PROFILE_END(s5TcpStatePerfStats);
                return retcode | ACTION_RST;
            }
            /* Reset not valid. */
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "bad sequence number, bailing\n"); );
            Discard();
            eventcode |= EVENT_BAD_RST;
            NormalDropPacketIf(p, NORM_TCP_BLOCK);
            LogTcpEvents(eventcode);
            MODULE_PROFILE_END(s5TcpStatePerfStats);
            return retcode;
        }

        /*
         * finish up server init
         */
        if (p->ptrs.tcph->th_flags & TH_SYN)
        {
            FinishServerInit(p, tdb, tcpssn);
            if (talker->flags & TF_TSTAMP)
            {
                talker->ts_last_pkt = p->pkth->ts.tv_sec;
                talker->ts_last = tdb->ts;
            }
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Finish server init got called!\n"); );
        }
        else
        {
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Finish server init didn't get called!\n"); );
        }

        if ((p->ptrs.tcph->th_flags & TH_ECE) &&
            lwssn->ssn_state.session_flags & SSNFLAG_ECN_CLIENT_QUERY)
        {
            lwssn->ssn_state.session_flags |= SSNFLAG_ECN_SERVER_REPLY;
        }

        /*
         * explicitly set the state
         */
        listener->s_mgr.state = TCP_STATE_SYN_SENT;
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Accepted SYN ACK\n"); );
        LogTcpEvents(eventcode);
        MODULE_PROFILE_END(s5TcpStatePerfStats);
        return retcode;
    }

    /*
     * scale the window.  Only if BOTH client and server specified
     * wscale option as part of 3-way handshake.
     * This is per RFC 1323.
     */
    if ((talker->flags & TF_WSCALE) && (listener->flags & TF_WSCALE))
    {
        tdb->win <<= talker->wscale;
    }

    /* Check for session hijacking -- compare mac address to the ones
     * that were recorded at session startup.
     */
#ifdef DAQ_PKT_FLAG_PRE_ROUTING
    if ( !(p->pkth->flags & DAQ_PKT_FLAG_PRE_ROUTING) )
#endif
    {
        eventcode |= ValidMacAddress(talker, listener, p);
    }

    /* Check timestamps */
    ts_action = ValidTimestamp(talker, listener, tdb, p, &eventcode, &got_ts);

    /*
     * check RST validity
     */
    if (p->ptrs.tcph->th_flags & TH_RST)
    {
        NormalTrimPayloadIfRst(p, 0, tdb);

        if (ValidRst(lwssn, listener, tdb))
        {
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Got RST, bailing\n"); );

            if (
                listener->s_mgr.state == TCP_STATE_FIN_WAIT_1 ||
                listener->s_mgr.state == TCP_STATE_FIN_WAIT_2 ||
                listener->s_mgr.state == TCP_STATE_CLOSE_WAIT ||
                listener->s_mgr.state == TCP_STATE_CLOSING
            ) {
                tcpssn->flush_talker(p);
                tcpssn->flush_listener(p);
                lwssn->free_application_data();
            }
            lwssn->ssn_state.session_flags |= SSNFLAG_RESET;
            talker->s_mgr.state = TCP_STATE_CLOSED;
            talker->s_mgr.sub_state |= SUB_RST_SENT;
            StreamUpdatePerfBaseState(&sfBase, lwssn, TCP_STATE_CLOSING);

            if ( Normalize_IsEnabled(NORM_TCP_IPS) )
                listener->s_mgr.state = TCP_STATE_CLOSED;
            /* else for ids:
                leave listener open, data may be in transit */

            LogTcpEvents(eventcode);
            MODULE_PROFILE_END(s5TcpStatePerfStats);
            return retcode | ACTION_RST;
        }
        /* Reset not valid. */
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "bad sequence number, bailing\n"); );
        Discard();
        eventcode |= EVENT_BAD_RST;
        NormalDropPacketIf(p, NORM_TCP_BLOCK);
        LogTcpEvents(eventcode);
        MODULE_PROFILE_END(s5TcpStatePerfStats);
        return retcode | ts_action;
    }
    else
    {
        /* check for valid seqeuence/retrans */
        if ( listener->config->policy != STREAM_POLICY_PROXY and
                (listener->s_mgr.state >= TCP_STATE_ESTABLISHED) and
            !ValidSeq(p, lwssn, listener, tdb) )
        {
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "bad sequence number, bailing\n"); );
            Discard();
            NormalTrimPayloadIfWin(p, 0, tdb);
            LogTcpEvents(eventcode);
            MODULE_PROFILE_END(s5TcpStatePerfStats);
            return retcode | ts_action;
        }
    }

    if (ts_action != ACTION_NOTHING)
    {
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "bad timestamp, bailing\n"); );
        Discard();
        // this packet was normalized elsewhere
        LogTcpEvents(eventcode);
        MODULE_PROFILE_END(s5TcpStatePerfStats);
        return retcode | ts_action;
    }

    /*
     * update PAWS timestamps
     */
    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "PAWS update tdb->seq %lu > listener->r_win_base %lu\n",
        tdb->seq, listener->r_win_base); );
    if (got_ts && SEQ_EQ(listener->r_win_base, tdb->seq))
    {
        if ((int32_t)(tdb->ts - talker->ts_last) >= 0 ||
            (uint32_t)p->pkth->ts.tv_sec >= talker->ts_last_pkt+PAWS_24DAYS)
        {
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "updating timestamps...\n"); );
            talker->ts_last = tdb->ts;
            talker->ts_last_pkt = p->pkth->ts.tv_sec;
        }
    }
    else
    {
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "not updating timestamps...\n"); );
    }

    /*
     * check for repeat SYNs
     */
    if ( !new_ssn &&
        ((p->ptrs.tcph->th_flags & (TH_SYN|TH_ACK)) == TH_SYN) )
    {
        int action;
        if ( !SEQ_EQ(tdb->seq, talker->isn) &&
            NormalDropPacketIf(p, NORM_TCP_BLOCK) )
            action = ACTION_BAD_PKT;
        else if ( talker->s_mgr.state >= TCP_STATE_ESTABLISHED )
            action = RepeatedSyn(listener, talker, tdb, tcpssn);
        else
            action = ACTION_NOTHING;

        if (action != ACTION_NOTHING)
        {
            /* got a bad SYN on the session, alert! */
            eventcode |= EVENT_SYN_ON_EST;
            LogTcpEvents(eventcode);
            MODULE_PROFILE_END(s5TcpStatePerfStats);
            return retcode | action;
        }
    }

    /*
     * Check that the window is within the limits
     */
    if ( listener->config->policy != STREAM_POLICY_PROXY )
    {
        if (listener->config->max_window && (tdb->win > listener->config->max_window))
        {
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Got window that was beyond the allowed policy value, bailing\n"); );
            /* got a window too large, alert! */
            eventcode |= EVENT_WINDOW_TOO_LARGE;
            Discard();
            NormalDropPacketIf(p, NORM_TCP_BLOCK);
            LogTcpEvents(eventcode);
            MODULE_PROFILE_END(s5TcpStatePerfStats);
            return retcode | ACTION_BAD_PKT;
        }
        else if ((p->packet_flags & PKT_FROM_CLIENT)
            && (tdb->win <= SLAM_MAX) && (tdb->ack == listener->isn + 1)
            && !(p->ptrs.tcph->th_flags & (TH_FIN|TH_RST))
            && !(lwssn->ssn_state.session_flags & SSNFLAG_MIDSTREAM))
        {
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Window slammed shut!\n"); );
            /* got a window slam alert! */
            eventcode |= EVENT_WINDOW_SLAM;
            Discard();

            if ( NormalDropPacketIf(p, NORM_TCP_BLOCK) )
            {
                LogTcpEvents(eventcode);
                MODULE_PROFILE_END(s5TcpStatePerfStats);
                return retcode | ACTION_BAD_PKT;
            }
        }
    }

    if (talker->s_mgr.state_queue != TCP_STATE_NONE)
    {
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Found queued state transition on ack 0x%X, "
            "current 0x%X!\n", talker->s_mgr.transition_seq,
            tdb->ack); );
        if (tdb->ack == talker->s_mgr.transition_seq)
        {
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "accepting transition!\n"); );
            talker->s_mgr.state = talker->s_mgr.state_queue;
            talker->s_mgr.state_queue = TCP_STATE_NONE;
        }
    }

    /*
     * process ACK flags
     */
    if (p->ptrs.tcph->th_flags & TH_ACK)
    {
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Got an ACK...\n"); );
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "   %s [listener] state: %s\n", l,
            state_names[listener->s_mgr.state]); );

        switch (listener->s_mgr.state)
        {
        case TCP_STATE_SYN_SENT:
            break;
        case TCP_STATE_SYN_RCVD:
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "listener state is SYN_SENT...\n"); );
            if ( IsBetween(listener->l_unackd, listener->l_nxt_seq, tdb->ack) )
            {
                UpdateSsn(p, listener, talker, tdb);
                lwssn->ssn_state.session_flags |= SSNFLAG_ESTABLISHED;
                lwssn->session_state |= STREAM_STATE_ESTABLISHED;
                listener->s_mgr.state = TCP_STATE_ESTABLISHED;
                talker->s_mgr.state = TCP_STATE_ESTABLISHED;
                StreamUpdatePerfBaseState(&sfBase, lwssn, TCP_STATE_ESTABLISHED);
                /* Indicate this packet completes 3-way handshake */
                p->packet_flags |= PKT_STREAM_TWH;
            }

            talker->flags |= got_ts;
            if (got_ts && SEQ_EQ(listener->r_nxt_ack, tdb->seq))
            {
                talker->ts_last_pkt = p->pkth->ts.tv_sec;
                talker->ts_last = tdb->ts;
            }

            break;

        case TCP_STATE_ESTABLISHED:
        case TCP_STATE_CLOSE_WAIT:
            UpdateSsn(p, listener, talker, tdb);
            break;

        case TCP_STATE_FIN_WAIT_1:
            UpdateSsn(p, listener, talker, tdb);

            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "tdb->ack %X >= talker->r_nxt_ack %X\n",
                tdb->ack, talker->r_nxt_ack); );

            if ( SEQ_EQ(tdb->ack, listener->l_nxt_seq) )
            {
                if ( (listener->os_policy == STREAM_POLICY_WINDOWS) && (tdb->win == 0) )
                {
                    eventcode |= EVENT_WINDOW_SLAM;
                    Discard();

                    if ( NormalDropPacketIf(p, NORM_TCP_BLOCK) )
                    {
                        LogTcpEvents(eventcode);
                        MODULE_PROFILE_END(s5TcpStatePerfStats);
                        return retcode | ACTION_BAD_PKT;
                    }
                }

                listener->s_mgr.state = TCP_STATE_FIN_WAIT_2;

                if ( (p->ptrs.tcph->th_flags & TH_FIN) )
                {
                    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "seq ok, setting state!\n"); );

                    if (talker->s_mgr.state_queue == TCP_STATE_NONE)
                    {
                        talker->s_mgr.state = TCP_STATE_LAST_ACK;
                        EndOfFileHandle(p, tcpssn);
                    }
                    if ( lwssn->ssn_state.session_flags & SSNFLAG_MIDSTREAM )
                    {
                        // FIXIT-L this should be handled below in fin section
                        // but midstream sessions fail the seq test
                        listener->s_mgr.state_queue = TCP_STATE_TIME_WAIT;
                        listener->s_mgr.transition_seq = tdb->end_seq;
                        listener->s_mgr.expected_flags = TH_ACK;
                    }
                }
                else if (listener->s_mgr.state_queue == TCP_STATE_CLOSING)
                {
                    listener->s_mgr.state_queue = TCP_STATE_TIME_WAIT;
                    listener->s_mgr.transition_seq = tdb->end_seq;
                    listener->s_mgr.expected_flags = TH_ACK;
                }
            }
            else
            {
                STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "bad ack!\n"); );
            }
            break;

        case TCP_STATE_FIN_WAIT_2:
            UpdateSsn(p, listener, talker, tdb);
            if ( SEQ_GT(tdb->ack, listener->l_nxt_seq) )
            {
                eventcode |= EVENT_BAD_ACK;
                LogTcpEvents(eventcode);
                NormalDropPacketIf(p, NORM_TCP_BLOCK);
                MODULE_PROFILE_END(s5TcpStatePerfStats);
                return retcode | ACTION_BAD_PKT;
            }
            break;

        case TCP_STATE_CLOSING:
            UpdateSsn(p, listener, talker, tdb);
            if (SEQ_GEQ(tdb->end_seq, listener->r_nxt_ack))
            {
                listener->s_mgr.state = TCP_STATE_TIME_WAIT;
            }
            break;

        case TCP_STATE_LAST_ACK:
            UpdateSsn(p, listener, talker, tdb);

            if ( SEQ_EQ(tdb->ack, listener->l_nxt_seq) )
            {
                listener->s_mgr.state = TCP_STATE_CLOSED;
            }
            break;

        default:
            // FIXIT-L safe to ignore when inline?
            break;
        }
    }

    /*
     * handle data in the segment
     */
    if (p->dsize)
    {
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "   %s state: %s(%d) getting data\n", l,
            state_names[listener->s_mgr.state],
            listener->s_mgr.state); );

        // FIN means only that sender is done talking,
        // other side may continue yapping.
        if (TCP_STATE_FIN_WAIT_2 == talker->s_mgr.state ||
            TCP_STATE_TIME_WAIT == talker->s_mgr.state)
        {
            /* data on a segment when we're not accepting data any more
               alert! */
            //EventDataOnClosed(talker->config);
            eventcode |= EVENT_DATA_ON_CLOSED;
            retcode |= ACTION_BAD_PKT;
            NormalDropPacketIf(p, NORM_TCP_BLOCK);
        }
        else if (TCP_STATE_CLOSED == talker->s_mgr.state)
        {
            /* data on a segment when we're not accepting data any more
               alert! */
            if (lwssn->ssn_state.session_flags & SSNFLAG_RESET)
            {
                //EventDataAfterReset(listener->config);
                if ( talker->s_mgr.sub_state & SUB_RST_SENT )
                    eventcode |= EVENT_DATA_AFTER_RESET;
                else
                    eventcode |= EVENT_DATA_AFTER_RST_RCVD;
            }
            else
            {
                //EventDataOnClosed(listener->config);
                eventcode |= EVENT_DATA_ON_CLOSED;
            }
            retcode |= ACTION_BAD_PKT;
            NormalDropPacketIf(p, NORM_TCP_BLOCK);
        }
        else
        {
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Queuing data on listener, t %s, l %s...\n",
                flush_policy_names[talker->flush_policy],
                flush_policy_names[listener->flush_policy]); );

            if ( config->policy != STREAM_POLICY_PROXY )
            {
                // these normalizations can't be done if we missed setup. and
                // window is zero in one direction until we've seen both sides.
                if ( !(lwssn->ssn_state.session_flags & SSNFLAG_MIDSTREAM) )
                {
                    // sender of syn w/mss limits payloads from peer
                    // since we store mss on sender side, use listener mss
                    // same reasoning for window size
                    TcpTracker* st = listener;

                    // trim to fit in window and mss as needed
                    NormalTrimPayloadIfWin(
                        p, (st->r_win_base + st->l_window) - st->r_nxt_ack, tdb);

                    if ( st->mss )
                        NormalTrimPayloadIfMss(p, st->mss, tdb);

                    NormalCheckECN(tcpssn, p);
                }
            }
            /*
             * dunno if this is RFC but fragroute testing expects it
             * for the record, I've seen FTP data sessions that send
             * data packets with no tcp flags set
             */
            if ( (p->ptrs.tcph->th_flags != 0)or
                    (config->policy == STREAM_POLICY_LINUX) or
                    (config->policy == STREAM_POLICY_PROXY) )
            {
                ProcessTcpData(p, listener, tcpssn, tdb, config);
            }
            else
            {
                eventcode |= EVENT_DATA_WITHOUT_FLAGS;
                NormalDropPacketIf(p, NORM_TCP_BLOCK);
            }
        }
    }

    if (p->ptrs.tcph->th_flags & TH_FIN)
    {
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Got a FIN...\n"); );
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "   %s state: %s(%d)\n", l,
            state_names[talker->s_mgr.state],
            talker->s_mgr.state); );

        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "checking ack (0x%X) vs nxt_ack (0x%X)\n",
            tdb->end_seq, listener->r_win_base); );
        if (SEQ_LT(tdb->end_seq,listener->r_win_base))
        {
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "FIN inside r_win_base, bailing\n"); );
            goto dupfin;
        }
        else
        {
            // need substate since we don't change state immediately
            if ( (talker->s_mgr.state >= TCP_STATE_ESTABLISHED) &&
                !(talker->s_mgr.sub_state & SUB_FIN_SENT) )
            {
                talker->l_nxt_seq++;

                //--------------------------------------------------
                // FIXIT-L don't bump r_nxt_ack unless FIN is in seq
                // because it causes bogus 129:5 cases
                // but doing so causes extra gaps
                //if ( SEQ_EQ(tdb->end_seq, listener->r_nxt_ack) )
                listener->r_nxt_ack++;
                //--------------------------------------------------

                talker->s_mgr.sub_state |= SUB_FIN_SENT;

                if ((listener->flush_policy != STREAM_FLPOLICY_ON_ACK) &&
                    (listener->flush_policy != STREAM_FLPOLICY_ON_DATA) &&
                    Normalize_IsEnabled(NORM_TCP_IPS))
                {
                    p->packet_flags |= PKT_PDU_TAIL;
                }
            }
            switch (talker->s_mgr.state)
            {
            case TCP_STATE_SYN_RCVD:
            case TCP_STATE_ESTABLISHED:
                if (talker->s_mgr.state_queue == TCP_STATE_CLOSE_WAIT)
                {
                    talker->s_mgr.state_queue = TCP_STATE_CLOSING;
                }
                talker->s_mgr.state = TCP_STATE_FIN_WAIT_1;
                EndOfFileHandle(p, tcpssn);

                if ( !p->dsize )
                    CheckFlushPolicyOnData(tcpssn, talker, listener, p);

                StreamUpdatePerfBaseState(&sfBase, tcpssn->flow, TCP_STATE_CLOSING);
                break;

            case TCP_STATE_CLOSE_WAIT:
                talker->s_mgr.state = TCP_STATE_LAST_ACK;
                break;

            case TCP_STATE_FIN_WAIT_1:
                if (!p->dsize)
                    RetransmitHandle(p, tcpssn);
                break;

            default:
                /* all other states stay where they are */
                break;
            }

            if ( (talker->s_mgr.state == TCP_STATE_FIN_WAIT_1) ||
                (talker->s_mgr.state == TCP_STATE_LAST_ACK) )
            {
                uint32_t end_seq = ( lwssn->ssn_state.session_flags & SSNFLAG_MIDSTREAM ) ?
                    tdb->end_seq-1 : tdb->end_seq;

                if ( (listener->s_mgr.expected_flags == TH_ACK) &&
                    SEQ_GEQ(end_seq, listener->s_mgr.transition_seq) )
                {
                    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "FIN beyond previous, ignoring\n"); );
                    eventcode |= EVENT_BAD_FIN;
                    LogTcpEvents(eventcode);
                    NormalDropPacketIf(p, NORM_TCP_BLOCK);
                    MODULE_PROFILE_END(s5TcpStatePerfStats);
                    return retcode | ACTION_BAD_PKT;
                }
            }
            switch ( listener->s_mgr.state )
            {
            case TCP_STATE_ESTABLISHED:
                listener->s_mgr.state_queue = TCP_STATE_CLOSE_WAIT;
                listener->s_mgr.transition_seq = tdb->end_seq + 1;
                listener->s_mgr.expected_flags = TH_ACK;
                break;

            case TCP_STATE_FIN_WAIT_1:
                listener->s_mgr.state_queue = TCP_STATE_CLOSING;
                listener->s_mgr.transition_seq = tdb->end_seq + 1;
                listener->s_mgr.expected_flags = TH_ACK;
                break;

            case TCP_STATE_FIN_WAIT_2:
                listener->s_mgr.state_queue = TCP_STATE_TIME_WAIT;
                listener->s_mgr.transition_seq = tdb->end_seq + 1;
                listener->s_mgr.expected_flags = TH_ACK;
                break;
            }
        }
    }

dupfin:

    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "   %s [talker] state: %s\n", t,
        state_names[talker->s_mgr.state]); );
    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "   %s state: %s(%d)\n", l,
        state_names[listener->s_mgr.state],
        listener->s_mgr.state); );

    /*
     * handle TIME_WAIT timer stuff
     */
    if ((talker->s_mgr.state == TCP_STATE_TIME_WAIT && listener->s_mgr.state ==
        TCP_STATE_CLOSED) ||
        (listener->s_mgr.state == TCP_STATE_TIME_WAIT && talker->s_mgr.state ==
        TCP_STATE_CLOSED) ||
        (listener->s_mgr.state == TCP_STATE_TIME_WAIT && talker->s_mgr.state ==
        TCP_STATE_TIME_WAIT))
    {
        // The last ACK is a part of the session.
        // Delete the session after processing is complete.
        LogTcpEvents(eventcode);
        TcpSessionCleanup(lwssn, 0, p);
        lwssn->session_state |= STREAM_STATE_CLOSED;
        MODULE_PROFILE_END(s5TcpStatePerfStats);
        return retcode | ACTION_LWSSN_CLOSED;
    }
    else if (listener->s_mgr.state == TCP_STATE_CLOSED && talker->s_mgr.state ==
        TCP_STATE_SYN_SENT)
    {
        if (p->ptrs.tcph->th_flags & TH_SYN &&
            !(p->ptrs.tcph->th_flags & TH_ACK) &&
            !(p->ptrs.tcph->th_flags & TH_RST))
        {
            lwssn->set_expire(p, config->session_timeout);
        }
    }

    if ( p->dsize > 0 )
        CheckFlushPolicyOnData(tcpssn, talker, listener, p);

    if ( p->ptrs.tcph->th_flags & TH_ACK )
        CheckFlushPolicyOnAck(tcpssn, talker, listener, p);

    LogTcpEvents(eventcode);
    MODULE_PROFILE_END(s5TcpStatePerfStats);
    return retcode;
}

// this is for post-ack flushing
static inline uint32_t GetReverseDir(const Packet* p)
{
    /* Remember, one side's packets are stored in the
     * other side's queue.  So when talker ACKs data,
     * we need to check if we're ready to flush.
     *
     * If we do decide to flush, the flush IP & port info
     * is the opposite of the packet -- again because this
     * is the ACK from the talker and we're flushing packets
     * that actually came from the listener.
     */
    if ( p->packet_flags & PKT_FROM_SERVER )
        return PKT_FROM_CLIENT;

    else if ( p->packet_flags & PKT_FROM_CLIENT )
        return PKT_FROM_SERVER;

    return 0;
}

static inline uint32_t GetForwardDir(const Packet* p)
{
    if ( p->packet_flags & PKT_FROM_SERVER )
        return PKT_FROM_SERVER;

    else if ( p->packet_flags & PKT_FROM_CLIENT )
        return PKT_FROM_CLIENT;

    return 0;
}

// see flush_pdu_ackd() for details
// the key difference is that we operate on forward moving data
// because we don't wait until it is acknowledged
static inline uint32_t flush_pdu_ips(
    TcpSession* ssn, TcpTracker* trk, uint32_t* flags)
{
    uint32_t total = 0, avail;
    TcpSegment* seg;
    PROFILE_VARS;

    MODULE_PROFILE_START(s5TcpPAFPerfStats);
    avail = get_q_sequenced(trk);
    seg = trk->seglist_next;

    // * must stop if gap (checked in paf_check)
    while ( seg && *flags && (total < avail) )
    {
        int32_t flush_pt;
        uint32_t size = seg->size;
        uint32_t end = seg->seq + seg->size;
        uint32_t pos = paf_position(&trk->paf_state);

        total += size;

        if ( paf_initialized(&trk->paf_state) && SEQ_LEQ(end, pos) )
        {
            seg = seg->next;
            continue;
        }

        flush_pt = paf_check(
            trk->splitter, &trk->paf_state, ssn->flow,
            seg->payload, size, total, seg->seq, flags);

        if ( flush_pt >= 0 )
        {
            MODULE_PROFILE_END(s5TcpPAFPerfStats);

            // see flush_pdu_ackd()
            if ( !trk->splitter->is_paf() && avail > (unsigned)flush_pt )
            {
                paf_jump(&trk->paf_state, avail - (unsigned)flush_pt);
                return avail;
            }
            return flush_pt;
        }
        seg = seg->next;
    }

    MODULE_PROFILE_END(s5TcpPAFPerfStats);
    return -1;
}

static inline void fallback(TcpTracker* a)
{
    bool c2s = a->splitter->to_server();

    delete a->splitter;
    a->splitter = new AtomSplitter(c2s, a->config->paf_max);
    a->paf_state.paf = StreamSplitter::SEARCH;
}

static inline int CheckFlushPolicyOnData(
    TcpSession *tcpssn, TcpTracker *talker,
    TcpTracker *listener, Packet *p)
{
    uint32_t flushed = 0;

    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "In CheckFlushPolicyOnData\n"); );
    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "Talker flush policy: %s\n",
        flush_policy_names[talker->flush_policy]); );
    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "Listener flush policy: %s\n",
        flush_policy_names[listener->flush_policy]); );

    switch (listener->flush_policy)
    {
    case STREAM_FLPOLICY_IGNORE:
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "STREAM_FLPOLICY_IGNORE\n"); );
        return 0;

    case STREAM_FLPOLICY_ON_ACK:
        break;

    case STREAM_FLPOLICY_ON_DATA:
    {
        uint32_t flags = GetForwardDir(p);
        int32_t flush_amt = flush_pdu_ips(tcpssn, listener, &flags);
        uint32_t this_flush;

        while ( flush_amt >= 0 )
        {
            if ( !flush_amt )
                flush_amt = listener->seglist_next->seq - listener->seglist_base_seq;
#if 0
            // FIXIT-P can't do this with new HI - copy is inevitable
            // if this payload is exactly one pdu, don't
            // actually flush, just use the raw packet
            if ( listener->seglist_next &&
                (tdb->seq == listener->seglist_next->seq) &&
                (flush_amt == listener->seglist_next->size) &&
                (flush_amt == p->dsize) )
            {
                this_flush = flush_amt;
                listener->seglist_next->buffered = SL_BUF_FLUSHED;
                listener->flush_count++;
                p->packet_flags |= PKT_PDU_FULL;
                ShowRebuiltPacket(tcpssn, p);
            }
            else
#endif
            {
                this_flush = flush_to_seq(
                    tcpssn, listener, flush_amt, p, flags);
            }
            // if we didn't flush as expected, bail
            // (we can flush less than max dsize)
            if ( !this_flush )
                break;

            flushed += this_flush;
            flags = GetForwardDir(p);
            flush_amt = flush_pdu_ips(tcpssn, listener, &flags);
        }
        if ( !flags && listener->splitter->is_paf() )
        {
            fallback(listener);
            return CheckFlushPolicyOnData(tcpssn, talker, listener, p);
        }
    }
    break;
    }
    return flushed;
}

// iterate over seglist and scan all new acked bytes
// - new means not yet scanned
// - must use seglist data (not packet) since this packet may plug a
//   hole and enable paf scanning of following segments
// - if we reach a flush point
//   - return bytes to flush if data available (must be acked)
//   - return zero if not yet received or received but not acked
// - if we reach a skip point
//   - jump ahead and resume scanning any available data
// - must stop if we reach a gap
// - one segment may lead to multiple checks since
//   it may contain multiple encapsulated PDUs
// - if we partially scan a segment we must save state so we
//   know where we left off and can resume scanning the remainder

static inline uint32_t flush_pdu_ackd(
    TcpSession* ssn, TcpTracker* trk, uint32_t* flags)
{
    uint32_t total = 0;
    TcpSegment* seg;
    PROFILE_VARS;

    MODULE_PROFILE_START(s5TcpPAFPerfStats);
    seg = SEQ_LT(trk->seglist_base_seq, trk->r_win_base) ? trk->seglist : NULL;

    // * must stop if not acked
    // * must use adjusted size of seg if not fully acked
    // * must stop if gap (checked in paf_check)
    while ( seg && *flags && SEQ_LT(seg->seq, trk->r_win_base) )
    {
        int32_t flush_pt;
        uint32_t size = seg->size;
        uint32_t end = seg->seq + seg->size;
        uint32_t pos = paf_position(&trk->paf_state);

        if ( paf_initialized(&trk->paf_state) && SEQ_LEQ(end, pos) )
        {
            total += size;
            seg = seg->next;
            continue;
        }
        if ( SEQ_GT(end, trk->r_win_base) )
            size = trk->r_win_base - seg->seq;

        total += size;

        flush_pt = paf_check(
            trk->splitter, &trk->paf_state, ssn->flow,
            seg->payload, size, total, seg->seq, flags);

        if ( flush_pt >= 0 )
        {
            MODULE_PROFILE_END(s5TcpPAFPerfStats);

            // for non-paf splitters, flush_pt > 0 means we reached
            // the minimum required, but we flush what is available
            // instead of creating more, but smaller, packets
            // FIXIT-L just flush to end of segment to avoid splitting
            // instead of all avail?
            if ( !trk->splitter->is_paf() )
            {
                // get_q_footprint() w/o side effects
                int32_t avail = (trk->r_win_base - trk->seglist_base_seq);
                if ( avail > flush_pt )
                {
                    paf_jump(&trk->paf_state, avail - flush_pt);
                    return avail;
                }
            }
            return flush_pt;
        }
        seg = seg->next;
    }

    MODULE_PROFILE_END(s5TcpPAFPerfStats);
    return -1;
}

int CheckFlushPolicyOnAck(
    TcpSession *tcpssn, TcpTracker *talker,
    TcpTracker *listener, Packet *p)
{
    uint32_t flushed = 0;

    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "In CheckFlushPolicyOnAck\n"); );
    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "Talker flush policy: %s\n",
        flush_policy_names[talker->flush_policy]); );
    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "Listener flush policy: %s\n",
        flush_policy_names[listener->flush_policy]); );

    switch (talker->flush_policy)
    {
    case STREAM_FLPOLICY_IGNORE:
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "STREAM_FLPOLICY_IGNORE\n"); );
        return 0;

    case STREAM_FLPOLICY_ON_ACK:
    {
        uint32_t flags = GetReverseDir(p);
        int32_t flush_amt = flush_pdu_ackd(tcpssn, talker, &flags);

        while ( flush_amt >= 0 )
        {
            if ( !flush_amt )
                flush_amt = talker->seglist_next->seq - talker->seglist_base_seq;

            talker->seglist_next = talker->seglist;
            talker->seglist_base_seq = talker->seglist->seq;

            // for consistency with other cases, should return total
            // but that breaks flushing pipelined pdus
            flushed = flush_to_seq(
                tcpssn, talker, flush_amt, p, flags);

            // ideally we would purge just once after this loop
            // but that throws off base
            purge_to_seq(tcpssn, talker, talker->seglist->seq + flushed);

            // if we didn't flush as expected, bail
            // (we can flush less than max dsize)
            if ( !flushed )
                break;

            flags = GetReverseDir(p);
            flush_amt = flush_pdu_ackd(tcpssn, talker, &flags);
        }
        if ( !flags && talker->splitter->is_paf() )
        {
            fallback(talker);
            return CheckFlushPolicyOnAck(tcpssn, talker, listener, p);
        }
    }
    break;

    case STREAM_FLPOLICY_ON_DATA:
        purge_flushed_ackd(tcpssn, talker);
        break;
    }

    return flushed;
}

static void StreamSeglistAddNode(
    TcpTracker *st, TcpSegment *prev, TcpSegment *ss)
{
    if (prev)
    {
        ss->next = prev->next;
        ss->prev = prev;
        prev->next = ss;
        if (ss->next)
            ss->next->prev = ss;
        else
            st->seglist_tail = ss;
    }
    else
    {
        ss->next = st->seglist;
        if (ss->next)
            ss->next->prev = ss;
        else
            st->seglist_tail = ss;
        st->seglist = ss;
    }
    st->seg_count++;
    st->seg_bytes_total += ss->orig_dsize;
    st->total_segs_queued++;
    tcpStats.segs_queued++;
}

static int StreamSeglistDeleteNode (TcpTracker* st, TcpSegment* seg)
{
    int ret;
    assert(st && seg);

    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "Dropping segment at seq %X, len %d\n",
        seg->seq, seg->size); );

    if (seg->prev)
        seg->prev->next = seg->next;
    else
        st->seglist = seg->next;

    if (seg->next)
        seg->next->prev = seg->prev;
    else
        st->seglist_tail = seg->prev;

    st->seg_bytes_logical -= seg->size;
    st->seg_bytes_total -= seg->orig_dsize;

    ret = seg->orig_dsize;

    if (seg->buffered)
    {
        tcpStats.segs_used++;
        st->flush_count--;
    }

    if ( st->seglist_next == seg )
        st->seglist_next = NULL;

    TcpSegment::term(seg);
    st->seg_count--;

    return ret;
}

static int StreamSeglistDeleteNodeTrim(
    TcpTracker* st, TcpSegment* seg, uint32_t flush_seq)
{
    assert(st && seg);

    if ( paf_active(&st->paf_state) &&
        ((seg->seq + seg->size) > flush_seq) )
    {
        uint32_t delta = flush_seq - seg->seq;

        if ( delta < seg->size )
        {
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Left-Trimming segment at seq %X, len %d, delta %u\n",
                seg->seq, seg->size, delta); );

            seg->seq = flush_seq;
            seg->size -= (uint16_t)delta;

            st->seg_bytes_logical -= delta;
            return 0;
        }
    }
    return StreamSeglistDeleteNode(st, seg);
}

bool StreamGetReassemblyFlushPolicyTcp(Flow *lwssn, char dir)
{
    TcpSession *tcpssn = NULL;

    if (!lwssn)
        return false;

    tcpssn = (TcpSession*)lwssn->session;

    if (dir & SSN_DIR_FROM_CLIENT)
    {
        return (char)tcpssn->client.flush_policy != STREAM_FLPOLICY_IGNORE;
    }

    if (dir & SSN_DIR_FROM_SERVER)
    {
        return (char)tcpssn->server.flush_policy != STREAM_FLPOLICY_IGNORE;
    }
    return false;
}

//-------------------------------------------------------------------------
// TcpSession methods
//-------------------------------------------------------------------------

TcpSession::TcpSession(Flow* flow) : Session(flow)
{
    lws_init = tcp_init = false;
}

TcpSession::~TcpSession()
{
    if ( tcp_init )
        TcpSessionClear(flow, (TcpSession*)flow->session, 1);
}

void TcpSession::reset()
{
    if ( tcp_init )
        TcpSessionClear(flow, (TcpSession*)flow->session, 2);
}

bool TcpSession::setup (Packet*)
{
    // FIXIT-L this it should not be necessary to reset here
    reset();

    lws_init = tcp_init = false;
    event_mask = 0;
    ecn = 0;

    memset(&client, 0, offsetof(TcpTracker, alerts));
    memset(&server, 0, offsetof(TcpTracker, alerts));

#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
    ingress_index = egress_index = 0;
    ingress_group = egress_group = 0;
    daq_flags = address_space_id = 0;
#endif

    tcpStats.sessions++;
    return true;
}

void TcpSession::cleanup()
{
    // this flushes data and then calls TcpSessionClear()
    TcpSessionCleanup(flow, 1);
}

// FIXIT-L this was originally called by Stream::drop_packet()
// which is now calling Session::clear()
void TcpSession::clear()
{
    if ( tcp_init )
        // this does NOT flush data
        TcpSessionClear(flow, this, 1);
}

void TcpSession::restart(Packet* p)
{
    TcpTracker* talker, * listener;

    if ( p->packet_flags & PKT_FROM_SERVER )
    {
        talker = &server;
        listener = &client;
    }
    else
    {
        talker = &client;
        listener = &server;
    }

    // FIXIT-H on data / on ack must be based on flush policy
    if ( p->dsize > 0 )
        CheckFlushPolicyOnData(this, talker, listener, p);

    if ( p->ptrs.tcph->is_ack() )
        CheckFlushPolicyOnAck(this, talker, listener, p);
}

void TcpSession::set_splitter(bool c2s, StreamSplitter* ss)
{
    TcpTracker* trk;

    if ( c2s )
        trk = &server;
    else
        trk = &client;

    if ( trk->splitter && tcp_init )
        delete trk->splitter;

    trk->splitter = ss;

    if ( ss )
        paf_setup(&trk->paf_state);
}

StreamSplitter* TcpSession::get_splitter(bool c2s)
{
    if ( c2s )
        return server.splitter;

    return client.splitter;
}

void TcpSession::flush_server(Packet *p)
{
    int flushed;
    TcpTracker *flushTracker = &server;

    flushTracker->flags |= TF_FORCE_FLUSH;

    /* If this is a rebuilt packet, don't flush now because we'll
     * overwrite the packet being processed.
     */
    if (p->packet_flags & PKT_REBUILT_STREAM)
    {
        /* We'll check & clear the TF_FORCE_FLUSH next time through */
        return;
    }

    /* Need to convert the addresses to network order */
    flushed = flush_stream(this, flushTracker, p, PKT_FROM_SERVER);

    if (flushed)
        purge_flushed_ackd(this, flushTracker);

    flushTracker->flags &= ~TF_FORCE_FLUSH;
}

void TcpSession::flush_client(Packet* p)
{
    int flushed;
    TcpTracker *flushTracker = &client;

    flushTracker->flags |= TF_FORCE_FLUSH;

    /* If this is a rebuilt packet, don't flush now because we'll
     * overwrite the packet being processed.
     */
    if (p->packet_flags & PKT_REBUILT_STREAM)
    {
        /* We'll check & clear the TF_FORCE_FLUSH next time through */
        return;
    }

    /* Need to convert the addresses to network order */
    flushed = flush_stream(this, flushTracker, p, PKT_FROM_CLIENT);

    if (flushed)
        purge_flushed_ackd(this, flushTracker);

    flushTracker->flags &= ~TF_FORCE_FLUSH;
}

void TcpSession::flush_listener(Packet* p)
{
    TcpTracker *listener = NULL;
    uint32_t dir = 0;
    int flushed = 0;

    /* figure out direction of this packet -- we should've already
     * looked at it, so the packet_flags are already set. */
    if(p->packet_flags & PKT_FROM_SERVER)
    {
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Flushing listener on packet from server\n"););
        listener = &client;
        /* dir of flush is the data from the opposite side */
        dir = PKT_FROM_SERVER;
    }
    else if (p->packet_flags & PKT_FROM_CLIENT)
    {
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Flushing listener on packet from client\n"););
        listener = &server;
        /* dir of flush is the data from the opposite side */
        dir = PKT_FROM_CLIENT;
    }

    if (dir != 0)
    {
        listener->flags |= TF_FORCE_FLUSH;
        flushed = flush_stream(this, listener, p, dir);

        if (flushed)
            purge_flushed_ackd(this, listener);

        listener->flags &= ~TF_FORCE_FLUSH;
    }
}

void TcpSession::flush_talker(Packet* p)
{
    TcpTracker *talker = NULL;
    uint32_t dir = 0;
    int flushed = 0;

    /* figure out direction of this packet -- we should've already
     * looked at it, so the packet_flags are already set. */
    if(p->packet_flags & PKT_FROM_SERVER)
    {
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Flushing talker on packet from server\n"););
        talker = &server;
        /* dir of flush is the data from the opposite side */
        dir = PKT_FROM_CLIENT;
    }
    else if (p->packet_flags & PKT_FROM_CLIENT)
    {
        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Flushing talker on packet from client\n"););
        talker = &client;
        /* dir of flush is the data from the opposite side */
        dir = PKT_FROM_SERVER;
    }

    if (dir != 0)
    {
        talker->flags |= TF_FORCE_FLUSH;
        flushed = flush_stream(this, talker, p, dir);

        if (flushed)
            purge_flushed_ackd(this, talker);

        talker->flags &= ~TF_FORCE_FLUSH;
    }
}

// FIXIT add alert and check alerted go away when we finish
// packet / PDU split because PDU rules won't run on raw packets
bool TcpSession::add_alert(Packet* p, uint32_t gid, uint32_t sid)
{
    TcpTracker *st;
    StreamAlertInfo* ai;

    if (sfip_equals(p->ptrs.ip_api.get_src(),&flow->client_ip))
        st = &server;
    else
        st = &client;

    if (st->alert_count >= MAX_SESSION_ALERTS)
        return false;

    ai = st->alerts + st->alert_count;
    ai->gid = gid;
    ai->sid = sid;
    ai->seq = 0;

    st->alert_count++;

    return true;
}

bool TcpSession::check_alerted(Packet* p, uint32_t gid, uint32_t sid)
{
    /* If this is not a rebuilt packet, no need to check further */
    if ( !(p->packet_flags & PKT_REBUILT_STREAM) )
        return false;

    TcpTracker *st;

    if (sfip_equals(p->ptrs.ip_api.get_src(), &flow->client_ip))
        st = &server;
    else
        st = &client;

    for ( int i = 0; i < st->alert_count; i++ )
    {
        /*  This is a rebuilt packet and if we've seen this alert before,
         *  return that we have previously alerted on original packet.
         */
        if ( st->alerts[i].gid == gid &&
             st->alerts[i].sid == sid )
        {
            return true;
        }
    }

    return false;
}

int TcpSession::update_alert(
    Packet *p, uint32_t gid, uint32_t sid, uint32_t event_id, uint32_t event_second)
{
    TcpTracker *st;
    int i;
    uint32_t seq_num;

    if (sfip_equals(p->ptrs.ip_api.get_src(), &flow->client_ip))
        st = &server;
    else
        st = &client;

    seq_num = 0;

    for (i=0; i<st->alert_count; i++)
    {
        StreamAlertInfo* ai = st->alerts + i;

        if ( ai->gid == gid &&
            ai->sid == sid && SEQ_EQ(ai->seq, seq_num))
        {
            ai->event_id = event_id;
            ai->event_second = event_second;
            return 0;
        }
    }

    return -1;
}

void TcpSession::set_extra_data(Packet* p, uint32_t xid)
{
    TcpTracker *st;

    if (sfip_equals(p->ptrs.ip_api.get_src(),&flow->client_ip))
        st = &server;
    else
        st = &client;

    st->xtradata_mask |= BIT(xid);
}

void TcpSession::clear_extra_data(Packet* p, uint32_t xid)
{
    TcpTracker *st;

    if (sfip_equals(p->ptrs.ip_api.get_src(),&flow->client_ip))
        st = &server;
    else
        st = &client;

    if ( xid )
        st->xtradata_mask &= ~BIT(xid);
    else
        st->xtradata_mask = 0;
}

uint8_t TcpSession::get_reassembly_direction()
{
    uint8_t dir = SSN_DIR_NONE;

    if ( server.flush_policy != STREAM_FLPOLICY_IGNORE )
    {
        dir |= SSN_DIR_FROM_CLIENT;
    }

    if ( client.flush_policy != STREAM_FLPOLICY_IGNORE )
    {
        dir |= SSN_DIR_FROM_SERVER;
    }

    return dir;
}

bool TcpSession::is_sequenced(uint8_t dir)
{
    if (dir & SSN_DIR_FROM_CLIENT)
    {
        if ( server.flags & (TF_MISSING_PREV_PKT|TF_MISSING_PKT) )
            return false;
    }

    if (dir & SSN_DIR_FROM_SERVER)
    {
        if ( client.flags & (TF_MISSING_PREV_PKT|TF_MISSING_PKT) )
            return false;
    }

    return true;
}

/* This will falsely return SSN_MISSING_BEFORE on the first reassembed
 * packet if reassembly for this direction was set mid-session */
uint8_t TcpSession::missing_in_reassembled(uint8_t dir)
{
    if (dir & SSN_DIR_FROM_CLIENT)
    {
        if ((server.flags & TF_MISSING_PKT) &&
            (server.flags & TF_MISSING_PREV_PKT))
            return SSN_MISSING_BOTH;
        else if (server.flags & TF_MISSING_PREV_PKT)
            return SSN_MISSING_BEFORE;
        else if (server.flags & TF_MISSING_PKT)
            return SSN_MISSING_AFTER;
    }
    else if (dir & SSN_DIR_FROM_SERVER)
    {
        if ((client.flags & TF_MISSING_PKT) &&
            (client.flags & TF_MISSING_PREV_PKT))
            return SSN_MISSING_BOTH;
        else if (client.flags & TF_MISSING_PREV_PKT)
            return SSN_MISSING_BEFORE;
        else if (client.flags & TF_MISSING_PKT)
            return SSN_MISSING_AFTER;
    }

    return SSN_MISSING_NONE;
}

bool TcpSession::are_packets_missing(uint8_t dir)
{
    if (dir & SSN_DIR_FROM_CLIENT)
    {
        if (server.flags & TF_PKT_MISSED)
            return true;
    }

    if (dir & SSN_DIR_FROM_SERVER)
    {
        if (client.flags & TF_PKT_MISSED)
            return true;
    }

    return false;
}

void TcpSession::update_direction(
    char dir, const sfip_t* ip, uint16_t port)
{
    sfip_t tmpIp;
    uint16_t tmpPort;
    TcpTracker tmpTracker;

    if (sfip_equals(&flow->client_ip, ip) && (flow->client_port == port))
    {
        if ((dir == SSN_DIR_FROM_CLIENT) && (flow->ssn_state.direction == SSN_DIR_FROM_CLIENT))
        {
            /* Direction already set as client */
            return;
        }
    }
    else if (sfip_equals(&flow->server_ip, ip) && (flow->server_port == port))
    {
        if ((dir == SSN_DIR_FROM_SERVER) && (flow->ssn_state.direction == SSN_DIR_FROM_SERVER))
        {
            /* Direction already set as server */
            return;
        }
    }

    /* Swap them -- leave flow->ssn_state.direction the same */

    /* XXX: Gotta be a more efficient way to do this without the memcpy */
    tmpIp = flow->client_ip;
    tmpPort = flow->client_port;
    flow->client_ip = flow->server_ip;
    flow->client_port = flow->server_port;
    flow->server_ip = tmpIp;
    flow->server_port = tmpPort;

#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
    SwapPacketHeaderFoo(this);
#endif
    memcpy(&tmpTracker, &client, sizeof(TcpTracker));
    memcpy(&client, &server, sizeof(TcpTracker));
    memcpy(&server, &tmpTracker, sizeof(TcpTracker));
}

/*
 * Main entry point for TCP
 */
int TcpSession::process(Packet* p)
{
    TcpDataBlock tdb;
    int status;
    PROFILE_VARS;

    STREAM_DEBUG_WRAP(
        char flagbuf[9];
        CreateTCPFlagString(p->ptrs.tcph, flagbuf);
        DebugMessage((DEBUG_STREAM|DEBUG_STREAM_STATE),
        "Got TCP Packet 0x%X:%d ->  0x%X:%d %s\nseq: 0x%X   ack:0x%X  dsize: %u\n",
        p->ptrs.ip_api.get_src(), p->ptrs.sp, p->ptrs.ip_api.get_dst(), p->ptrs.dp, flagbuf,
        ntohl(p->ptrs.tcph->th_seq), ntohl(p->ptrs.tcph->th_ack), p->dsize); );

    MODULE_PROFILE_START(s5TcpPerfStats);

    if ( stream.blocked_session(flow, p) ||
        (flow->session_state & STREAM_STATE_IGNORE) )
    {
        MODULE_PROFILE_END(s5TcpPerfStats);
        return ACTION_NOTHING;
    }
    SetupTcpDataBlock(&tdb, p);

    StreamTcpConfig* config = get_tcp_cfg(flow->ssn_server);

    if ( !lws_init )
    {
        // FIXIT most of this now looks out of place or redundant
        if ( config->require_3whs() )
        {
            if ( p->ptrs.tcph->is_syn_only() )
            {
                /* SYN only */
                flow->session_state = STREAM_STATE_SYN;
            }
            else
            {
                // If we're within the "startup" window, try to handle
                // this packet as midstream pickup -- allows for
                // connections that already existed before snort started.
                if ( config->midstream_allowed(p) )
                    goto midstream_pickup_allowed;

                // Do nothing with this packet since we require a 3-way ;)
                DEBUG_WRAP(
                    DebugMessage(DEBUG_STREAM_STATE, "Stream: Requiring 3-way "
                    "Handshake, but failed to retrieve session object "
                    "for non SYN packet.\n"); );

                if ( !p->ptrs.tcph->is_rst() && !(event_mask & EVENT_NO_3WHS) )
                {
                    EventNo3whs();
                    event_mask |= EVENT_NO_3WHS;
                }

                MODULE_PROFILE_END(s5TcpPerfStats);
#ifdef REG_TEST
                S5TraceTCP(p, flow, &tdb, 1);
#endif
                return 0;
            }
        }
        else
        {
midstream_pickup_allowed:
            if (
                !p->ptrs.tcph->is_syn_ack() &&
                !p->dsize &&
                !(StreamPacketHasWscale(p) & TF_WSCALE) )
            {
                MODULE_PROFILE_END(s5TcpPerfStats);
#ifdef REG_TEST
                S5TraceTCP(p, flow, &tdb, 1);
#endif
                return 0;
            }
        }
        lws_init = true;
    }
    /*
     * Check if the session is expired.
     * Should be done before we do something with the packet...
     * ie, Insert a packet, or handle state change SYN, FIN, RST, etc.
     */
    if ( stream.expired_session(flow, p) )
    {
        /* Session is timed out */
        if (flow->ssn_state.session_flags & SSNFLAG_RESET)
        {
            /* If this one has been reset, delete the TCP
             * portion, and start a new. */
            TcpSessionCleanup(flow, 1);
        }
        else
        {
            STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Stream TCP session timedout!\n"); );

            /* Not reset, simply time'd out.  Clean it up */
            TcpSessionCleanup(flow, 1);
        }
        tcpStats.timeouts++;
    }
    status = ProcessTcp(flow, p, &tdb, config);

    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "Finished Stream TCP cleanly!\n"
        "---------------------------------------------------\n"); );

    if ( !(status & ACTION_LWSSN_CLOSED) )
    {
        flow->markup_packet_flags(p);
        flow->set_expire(p, config->session_timeout);
    }
    if ( status & ACTION_DISABLE_INSPECTION )
    {
        DisableInspection(p);

        STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Stream Ignoring packet from %d. Session marked as ignore\n",
            p->packet_flags & PKT_FROM_SERVER ? "server" : "client"); );
    }

    MODULE_PROFILE_END(s5TcpPerfStats);
    S5TraceTCP(p, flow, &tdb, 0);
    return 0;
}

void TcpSession::flush()
{
    if ( (SegsToFlush(&server, 1) > 0) || (SegsToFlush(&client, 1) > 0) )
        FlushQueuedSegs(flow, this, false);
}

void TcpSession::start_proxy()
{
    client.config->policy = STREAM_POLICY_PROXY;
    server.config->policy = STREAM_POLICY_PROXY;
}

//-------------------------------------------------------------------------
// tcp module stuff
//-------------------------------------------------------------------------

void tcp_show(StreamTcpConfig* tcp_config)
{
    StreamPrintTcpConfig(tcp_config);
}


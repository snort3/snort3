/****************************************************************************
 *
 * Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2005-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

/**
 * @file    stream_tcp.c
 * @author  Martin Roesch <roesch@sourcefire.com>
 * @author  Steven Sturges <ssturges@sourcefire.com>
 *
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

#include "stream_tcp.h"
#include "tcp_config.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <assert.h>

#include "analyzer.h"
#include "perf_monitor/perf.h"
#include "snort_types.h"
#include "snort_debug.h"
#include "detect.h"
#include "mstring.h"
#include "sfxhash.h"
#include "util.h"
#include "sflsq.h"
#include "snort_bounds.h"
#include "generators.h"
#include "snort.h"
#include "parser/ip_addr_set.h"
#include "time/packet_time.h"
#include "decode.h"
#include "encode.h"
#include "log_text.h"
#include "packet_io/active.h"
#include "normalize/normalize.h"
#include "stream_common.h"
#include "flow/flow_control.h"
#include "flow/session.h"
#include "stream_paf.h"
#include "stream_ha.h"
#include "target_based/sftarget_protocol_reference.h"
#include "target_based/sftarget_hostentry.h"
#include "profiler.h"
#include "ipv6_port.h"
#include "sf_iph.h"
#include "fpdetect.h"
#include "detection_util.h"
#include "file_api/file_api.h"
#include "stream_module.h"

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats s5TcpPerfStats;
static THREAD_LOCAL PreprocStats s5TcpNewSessPerfStats;
static THREAD_LOCAL PreprocStats s5TcpStatePerfStats;
static THREAD_LOCAL PreprocStats s5TcpDataPerfStats;
static THREAD_LOCAL PreprocStats s5TcpInsertPerfStats;
static THREAD_LOCAL PreprocStats s5TcpPAFPerfStats;
static THREAD_LOCAL PreprocStats s5TcpFlushPerfStats;
static THREAD_LOCAL PreprocStats s5TcpBuildPacketPerfStats;
static THREAD_LOCAL PreprocStats s5TcpProcessRebuiltPerfStats;
static THREAD_LOCAL PreprocStats streamSizePerfStats;
static THREAD_LOCAL PreprocStats streamReassembleRuleOptionPerfStats;

static PreprocStats* tcp_get_profile(const char* key)
{
    if ( !strcmp(key, "tcp") )
        return &s5TcpPerfStats;

    if ( !strcmp(key, "tcpNewSess") )
        return &s5TcpNewSessPerfStats;

    if ( !strcmp(key, "tcpState") )
        return &s5TcpStatePerfStats;

    if ( !strcmp(key, "tcpData") )
        return &s5TcpDataPerfStats;

    if ( !strcmp(key, "tcpPktInsert") )
        return &s5TcpInsertPerfStats;

    if ( !strcmp(key, "tcpPAF") )
        return &s5TcpPAFPerfStats;

    if ( !strcmp(key, "tcpFlush") )
        return &s5TcpFlushPerfStats;

    if ( !strcmp(key, "tcpBuildPacket") )
        return &s5TcpBuildPacketPerfStats;

    if ( !strcmp(key, "tcpProcessRebuilt") )
        return &s5TcpProcessRebuiltPerfStats;

    if ( !strcmp(key, "stream_size") )
        return &streamSizePerfStats;

    if ( !strcmp(key, "reassemble") )
        return &streamReassembleRuleOptionPerfStats;

    return nullptr;
}
#endif

struct TcpStats
{
    PegCount streamtrackers_created;
    PegCount streamtrackers_released;
    PegCount streamsegs_created;
    PegCount streamsegs_released;
    PegCount rebuilt_packets;
    PegCount rebuilt_seqs_used;
    PegCount overlaps;
    PegCount gaps;
    PegCount internalEvents;
    PegCount s5tcp1;
    PegCount s5tcp2;
};

static const char* tcp_pegs[] =
{
    "trackers created",
    "trackers released",
    "segs created",
    "segs released",
    "rebuilt packets",
    "rebuilt seqs used",
    "overlaps",
    "gaps",
    "internal events",
    "client cleanup flushes",
    "server cleanup flushes"
};

static SessionStats gssnStats;
static TcpStats gtcpStats;

static THREAD_LOCAL SessionStats ssnStats;
static THREAD_LOCAL TcpStats tcpStats;

#define S5_DEFAULT_MEMCAP 8388608  /* 8MB */
THREAD_LOCAL Memcap* tcp_memcap = nullptr;

/*  M A C R O S  **************************************************/

/* TCP flags */
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_NORESERVED (TH_FIN|TH_SYN|TH_RST|TH_PUSH|TH_ACK|TH_URG)

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
# define MIN(a,b)  (((a)<(b)) ? (a):(b))
#endif
#ifndef MAX
# define MAX(a,b)  (((a)>(b)) ? (a):(b))
#endif

#define PAWS_WINDOW         60
#define PAWS_24DAYS         2073600         /* 24 days in seconds */

/* for state transition queuing */
#define CHK_SEQ         0
#define NO_CHK_SEQ      1

#define S5_UNALIGNED       0
#define S5_ALIGNED         1

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
#define EVENT_BAD_SEGMENT               0x00000010
#define EVENT_WINDOW_TOO_LARGE          0x00000020
#define EVENT_EXCESSIVE_TCP_OVERLAPS    0x00000040
#define EVENT_DATA_AFTER_RESET          0x00000080
#define EVENT_SESSION_HIJACK_CLIENT     0x00000100
#define EVENT_SESSION_HIJACK_SERVER     0x00000200
#define EVENT_DATA_WITHOUT_FLAGS        0x00000400
#define EVENT_4WHS                      0x00000800
#define EVENT_NO_TIMESTAMP              0x00001000
#define EVENT_BAD_RST                   0x00002000
#define EVENT_BAD_FIN                   0x00004000
#define EVENT_BAD_ACK                   0x00008000
#define EVENT_DATA_AFTER_RST_RCVD       0x00010000
#define EVENT_WINDOW_SLAM               0x00020000

#define TF_NONE                     0x00
#define TF_WSCALE                   0x01
#define TF_TSTAMP                   0x02
#define TF_TSTAMP_ZERO              0x04
#define TF_MSS                      0x08
#define TF_FORCE_FLUSH              0x10
#define TF_MISSING_PKT              0x20
#define TF_PKT_MISSED               0x40
#define TF_MISSING_PREV_PKT         0x80
#define TF_ALL                      0xFF

#define STREAM_INSERT_OK            0
#define STREAM_INSERT_ANOMALY       1
#define STREAM_INSERT_TIMEOUT       2
#define STREAM_INSERT_FAILED        3

#define S5_DEFAULT_TCP_PACKET_MEMCAP  8388608  /* 8MB */
#define S5_MIN_OVERLAP_LIMIT 0
#define S5_MAX_OVERLAP_LIMIT 255
#define S5_MAX_FLUSH_FACTOR 2048

/* target-based policy types */
#define STREAM_POLICY_FIRST     1
#define STREAM_POLICY_LINUX     2
#define STREAM_POLICY_BSD       3
#define STREAM_POLICY_OLD_LINUX 4
#define STREAM_POLICY_LAST      5
#define STREAM_POLICY_WINDOWS   6
#define STREAM_POLICY_SOLARIS   7
#define STREAM_POLICY_HPUX11    8
#define STREAM_POLICY_IRIX      9
#define STREAM_POLICY_MACOS     10
#define STREAM_POLICY_HPUX10    11
#define STREAM_POLICY_VISTA     12
#define STREAM_POLICY_WINDOWS2K3 13
#define STREAM_POLICY_IPS       14
#define STREAM_POLICY_DEFAULT   STREAM_POLICY_BSD

#define REASSEMBLY_POLICY_FIRST     1
#define REASSEMBLY_POLICY_LINUX     2
#define REASSEMBLY_POLICY_BSD       3
#define REASSEMBLY_POLICY_OLD_LINUX 4
#define REASSEMBLY_POLICY_LAST      5
#define REASSEMBLY_POLICY_WINDOWS   6
#define REASSEMBLY_POLICY_SOLARIS   7
#define REASSEMBLY_POLICY_HPUX11    8
#define REASSEMBLY_POLICY_IRIX      9
#define REASSEMBLY_POLICY_MACOS     10
#define REASSEMBLY_POLICY_HPUX10    11
#define REASSEMBLY_POLICY_VISTA     12
#define REASSEMBLY_POLICY_WINDOWS2K3 13
#define REASSEMBLY_POLICY_DEFAULT   REASSEMBLY_POLICY_BSD

#define S5_MAX_MAX_WINDOW       0x3FFFc000 /* max window allowed by TCP */
                                           /* 65535 << 14 (max wscale) */
#define S5_MIN_MAX_WINDOW       0

#define MAX_PORTS_TO_PRINT      20

#define S5_DEFAULT_MAX_QUEUED_BYTES 1048576 /* 1 MB */
#define S5_MIN_MAX_QUEUED_BYTES 1024       /* Don't let this go below 1024 */
#define S5_MAX_MAX_QUEUED_BYTES 0x40000000 /* 1 GB, most we could reach within
                                            * largest window scale */
#define AVG_PKT_SIZE            400
#define S5_DEFAULT_MAX_QUEUED_SEGS (S5_DEFAULT_MAX_QUEUED_BYTES/AVG_PKT_SIZE)
#define S5_MIN_MAX_QUEUED_SEGS  2          /* Don't let this go below 2 */
#define S5_MAX_MAX_QUEUED_SEGS  0x40000000 /* 1 GB worth of one-byte segments */

#define S5_DEFAULT_MAX_SMALL_SEG_SIZE 0    /* disabled */
#define S5_MAX_MAX_SMALL_SEG_SIZE 2048     /* 2048 bytes in single packet, uh, not small */
#define S5_MIN_MAX_SMALL_SEG_SIZE 0        /* 0 means disabled */

#define S5_DEFAULT_CONSEC_SMALL_SEGS 0     /* disabled */
#define S5_MAX_CONSEC_SMALL_SEGS 2048      /* 2048 single byte packets without acks is alot */
#define S5_MIN_CONSEC_SMALL_SEGS 0         /* 0 means disabled */

#define SUB_SYN_SENT  0x01
#define SUB_ACK_SENT  0x02
#define SUB_SETUP_OK  0x03
#define SUB_RST_SENT  0x04
#define SUB_FIN_SENT  0x08

// flush types
#define S5_FT_INTERNAL  0  // normal s5 "footprint"
#define S5_FT_EXTERNAL  1  // set by other preprocessor
#define S5_FT_PAF_MAX   2  // paf_max + footprint fp

#define SLAM_MAX 4

#define S5_MIN_ALT_HS_TIMEOUT   0         /* min timeout (0 seconds) */

/* Only track a maximum number of alerts per session */
#define MAX_SESSION_ALERTS 8

//#define DEBUG_STREAM5
#ifdef DEBUG_STREAM5
#define STREAM5_DEBUG_WRAP(x) DEBUG_WRAP(x)
#else
#define STREAM5_DEBUG_WRAP(x)
#endif

/* client/server ip/port dereference */
#define tcp_client_ip flow->client_ip
#define tcp_client_port flow->client_port
#define tcp_server_ip flow->server_ip
#define tcp_server_port flow->server_port

/*  D A T A  S T R U C T U R E S  ***********************************/

typedef struct _TcpDataBlock
{
    uint32_t   seq;
    uint32_t   ack;
    uint32_t   win;
    uint32_t   end_seq;
    uint32_t   ts;
} TcpDataBlock;

typedef struct _StateMgr
{
    uint8_t    state;
    uint8_t    sub_state;
    uint8_t    state_queue;
    uint8_t    expected_flags;
    uint32_t   transition_seq;
    uint32_t   stq_get_seq;
} StateMgr;

void* get_paf_config(Stream5TcpConfig* tcp_config)
{
    return tcp_config->paf_config;
}

#define RAND_FLUSH_POINTS 64

//-------------------------------------------------------------------------
// extra, extra - read all about it!
// -- u2 is the only output plugin that currently supports extra data
// -- extra data may be captured before or after alerts
// -- extra data may be per packet or persistent (saved on session)
//
// -- per packet extra data is logged iff we alert on the packet
//    containing the extra data - u2 drives this
// -- an extra data mask is added to Packet to indicate when per packet
//    extra data is available
//
// -- persistent extra data must be logged exactly once for each alert
//    regardless of capture/alert ordering - s5 purge_alerts drives this
// -- an extra data mask is added to the session trackers to indicate that
//    persistent extra data is available
//
// -- event id and second are added to the session alert trackers so that
//    the extra data can be correlated with events
// -- event id and second are not available when Stream5AddSessionAlertTcp
//    is called; u2 calls Stream5UpdateSessionAlertTcp as events are logged
//    to set these fields
//-------------------------------------------------------------------------

typedef struct _Stream5AlertInfo
{
    /* For storing alerts that have already been seen on the session */
    uint32_t sid;
    uint32_t gid;
    uint32_t seq;
    // if we log extra data, event_* is used to correlate with alert
    uint32_t event_id;
    uint32_t event_second;
} Stream5AlertInfo;

//-----------------------------------------------------------------
// we make a lot of StreamSegments, StreamTrackers, and TcpSessions
// so they are organized by member size/alignment requirements to
// minimize unused space in the structs.
// ... however, use of padding below is critical, adjust if needed
//-----------------------------------------------------------------

typedef struct _StreamSegment
{
    uint8_t    *data;
    uint8_t    *payload;

    struct _StreamSegment *prev;
    struct _StreamSegment *next;

#ifdef DEBUG
    int ordinal;
#endif
    struct timeval tv;
    uint32_t caplen;
    uint32_t pktlen;

    uint32_t   ts;
    uint32_t   seq;

    uint16_t   orig_dsize;
    uint16_t   size;

    uint16_t   urg_offset;
    uint8_t    buffered;

    // this sequence ensures 4-byte alignment of iph in pkt
    // (only significant if we call the grinder)
    uint8_t    pad1;
    uint16_t   pad2;
    uint8_t    pkt[1];  // variable length

} StreamSegment;

typedef struct _StreamTracker
{
    StateMgr  s_mgr;        /* state tracking goodies */
    FlushMgr  flush_mgr;    /* please flush twice, it's a long way to
                             * the bitbucket... */

    // this is intended to be private to s5_paf but is included
    // directly to avoid the need for allocation; do not directly
    // manipulate within this module.
    PAF_State paf_state;    // for tracking protocol aware flushing

    Stream5AlertInfo alerts[MAX_SESSION_ALERTS]; /* history of alerts */

    Stream5TcpPolicy *tcp_policy;
    StreamSegment *seglist;       /* first queued segment */
    StreamSegment *seglist_tail;  /* last queued segment */

    // TBD move out of here since only used per packet?
    StreamSegment* seglist_next;  /* next queued segment to flush */

#ifdef DEBUG
    int segment_ordinal;
#endif

    /* Local for these variables means the local part of the connection.  For
     * example, if this particular StreamTracker was tracking the client side
     * of a connection, the l_unackd value would represent the client side of
     * the connection's last unacked sequence number
     */
    uint32_t l_unackd;     /* local unack'd seq number */
    uint32_t l_nxt_seq;    /* local next expected sequence */
    uint32_t l_window;     /* local receive window */

    uint32_t r_nxt_ack;    /* next expected ack from remote side */
    uint32_t r_win_base;   /* remote side window base sequence number
                            * (i.e. the last ack we got) */
    uint32_t isn;          /* initial sequence number */
    uint32_t ts_last;      /* last timestamp (for PAWS) */
    uint32_t ts_last_pkt;  /* last packet timestamp we got */

    uint32_t seglist_base_seq;   /* seq of first queued segment */
    uint32_t seg_count;          /* number of current queued segments */
    uint32_t seg_bytes_total;    /* total bytes currently queued */
    uint32_t seg_bytes_logical;  /* logical bytes queued (total - overlaps) */
    uint32_t total_bytes_queued; /* total bytes queued (life of session) */
    uint32_t total_segs_queued;  /* number of segments queued (life) */
    uint32_t overlap_count;      /* overlaps encountered */
    uint32_t small_seg_count;
    uint32_t flush_count;        /* number of flushed queued segments */
    uint32_t xtradata_mask;      /* extra data available to log */

    uint16_t os_policy;
    uint16_t reassembly_policy;

    uint16_t wscale;       /* window scale setting */
    uint16_t mss;          /* max segment size */

    uint8_t  mac_addr[6];
    uint8_t  flags;        /* bitmap flags (TF_xxx) */

    uint8_t  alert_count;  /* number alerts stored (up to MAX_SESSION_ALERTS) */

} StreamTracker;

class TcpSession : public Session
{
public:
    TcpSession(Flow*);

    void* get_policy (void*, Packet*);
    bool setup (Packet*);
    void update_direction(char dir, snort_ip*, uint16_t port);
    int process(Packet*);

    void reset();
    void clear();
    void cleanup();

public:
    StreamTracker client;
    StreamTracker server;

#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
    int32_t ingress_index;  /* Index of the inbound interface. */
    int32_t egress_index;   /* Index of the outbound interface. */
    int32_t ingress_group;  /* Index of the inbound group. */
    int32_t egress_group;   /* Index of the outbound group. */
    uint32_t daq_flags;     /* Flags for the packet (DAQ_PKT_FLAG_*) */
    uint16_t address_space_id;
#endif

    uint8_t ecn;
    bool lws_init;
    bool tcp_init;
};

Session* get_tcp_session(Flow* lwssn)
{
    return new TcpSession(lwssn);
}

#define SL_BUF_FLUSHED 1

static inline int SetupOK (const StreamTracker* st)
{
    return ( (st->s_mgr.sub_state & SUB_SETUP_OK) == SUB_SETUP_OK );
}

static inline uint32_t SegsToFlush (const StreamTracker* st, unsigned max)
{
    uint32_t n = st->seg_count - st->flush_count;
    StreamSegment* s;

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

static inline bool DataToFlush (const StreamTracker* st)
{
    if ( st->flush_mgr.flush_policy == STREAM_FLPOLICY_PROTOCOL
      || st->flush_mgr.flush_policy == STREAM_FLPOLICY_PROTOCOL_IPS
    )
        return ( SegsToFlush(st, 1) > 0 );

    if ( st->flush_mgr.flush_policy == STREAM_FLPOLICY_FOOTPRINT_IPS )
        return ( SegsToFlush(st, 1) > 1 );

    return ( SegsToFlush(st, 2) > 1 );
}

int default_ports[] =
{
    21, 23, 25, 42, 53, 80, 110, 111, 135, 136, 137, 139, 143, 445,
    513, 514, 1433, 1521, 2401, 3306
};

static const char *default_protocols[] =
{
    "ftp", "telnet", "smtp", "nameserver", "dns", "http", "pop3", "sunrpc",
    "dcerpc", "netbios-ssn", "imap", "login", "shell", "mssql", "oracle", "cvs",
    "mysql"
};

static THREAD_LOCAL FlushConfig ignore_flush_policy[MAX_PORTS];
static THREAD_LOCAL FlushConfig ignore_flush_policy_protocol[MAX_PROTOCOL_ORDINAL];

/*  P R O T O T Y P E S  ********************************************/
static void Stream5ParseTcpArgs(SnortConfig*, Stream5TcpConfig *, char *, Stream5TcpPolicy *);static void Stream5PrintTcpConfig(Stream5TcpPolicy *);

static inline void SetupTcpDataBlock(TcpDataBlock *, Packet *);
static int ProcessTcp(Flow *, Packet *, TcpDataBlock *,
        Stream5TcpPolicy *);
static inline int CheckFlushPolicyOnData(
    TcpSession *, StreamTracker *, StreamTracker *,
    TcpDataBlock *, Packet *);
static inline int CheckFlushPolicyOnAck(
    TcpSession *, StreamTracker *, StreamTracker *,
    TcpDataBlock *, Packet *);
static void Stream5SeglistAddNode(StreamTracker *, StreamSegment *,
                StreamSegment *);
static int Stream5SeglistDeleteNode(StreamTracker*, StreamSegment*);
static int Stream5SeglistDeleteNodeTrim(StreamTracker*, StreamSegment*, uint32_t flush_seq);
static int AddStreamNode(
    StreamTracker*, Packet*, TcpDataBlock*,
    int16_t len, uint32_t slide, uint32_t trunc,
    uint32_t seq, StreamSegment *left, StreamSegment **retSeg);
static int DupStreamNode(
    Packet*,
    StreamTracker*,
    StreamSegment* left,
    StreamSegment** retSeg);

static uint32_t Stream5GetWscale(Packet *, uint16_t *);
static uint32_t Stream5PacketHasWscale(Packet *);
static uint32_t Stream5GetMss(Packet *, uint16_t *);
static uint32_t Stream5GetTcpTimestamp(Packet *, uint32_t *, int strip);
static int FlushStream(
    Packet*, StreamTracker *st, uint32_t toSeq, uint8_t *flushbuf,
    const uint8_t *flushbuf_end);
static void TcpSessionCleanup(Flow *ssn, int freeApplicationData);

int s5TcpStreamSizeInit(SnortConfig* sc, char *name, char *parameters, void **dataPtr);
int s5TcpStreamSizeEval(Packet*, const uint8_t **cursor, void *dataPtr);
void s5TcpStreamSizeCleanup(void *dataPtr);
int s5TcpStreamReassembleRuleOptionInit(
    SnortConfig* sc, char *name, char *parameters, void **dataPtr);
int s5TcpStreamReassembleRuleOptionEval(Packet*, const uint8_t **cursor, void *dataPtr);
void s5TcpStreamReassembleRuleOptionCleanup(void *dataPtr);
#if 0
static void targetPolicyIterate(void (*callback)(int));
#endif

/*  G L O B A L S  **************************************************/
// FIXIT eliminate these globals
static THREAD_LOCAL Packet *s5_pkt = NULL;

/* enum for policy names */
static const char *reassembly_policy_names[] = {
    "no policy!",
    "FIRST",
    "LINUX",
    "BSD",
    "OLD LINUX",
    "LAST",
    "WINDOWS",
    "SOLARIS",
    "HPUX11",
    "IRIX",
    "MACOS",
    "HPUX10",
    "WINDOWS VISTA",
    "WINDOWS 2003"
    "IPS"
};

#ifdef DEBUG_STREAM5
static const char *state_names[] = {
    "NONE",
    "LISTEN",
    "SYN_RCVD",
    "SYN_SENT",
    "ESTABLISHED",
    "CLOSE_WAIT",
    "LAST_ACK",
    "FIN_WAIT_1",
    "CLOSING",
    "FIN_WAIT_2",
    "TIME_WAIT",
    "CLOSED"
};
#endif

static const char *flush_policy_names[] = {
    "None",
    "Footprint",
    "Logical",
    "Response",
    "Sliding Window",
#if 0
    "Consumed",
#endif
    "Ignore",
    "Protocol",
    "Footprint-IPS",
    "Protocol-IPS"
};

static THREAD_LOCAL int s5_tcp_cleanup = 0;

static const uint32_t g_static_points[RAND_FLUSH_POINTS] =
                         { 128, 217, 189, 130, 240, 221, 134, 129,
                           250, 232, 141, 131, 144, 177, 201, 130,
                           230, 190, 177, 142, 130, 200, 173, 129,
                           250, 244, 174, 151, 201, 190, 180, 198,
                           220, 201, 142, 185, 219, 129, 194, 140,
                           145, 191, 197, 183, 199, 220, 231, 245,
                           233, 135, 143, 158, 174, 194, 200, 180,
                           201, 142, 153, 187, 173, 199, 143, 201 };

/*  F U N C T I O N S  **********************************************/
static inline uint32_t GenerateFlushPoint(FlushPointList *flush_point_list)
{
    return (rand() % flush_point_list->flush_range) + flush_point_list->flush_base;
}

static inline void InitFlushPointList(FlushPointList *flush_point_list, uint32_t value, uint32_t range, int use_static)
{
    uint32_t i;
    uint32_t flush_range = range;
    uint32_t flush_base = value - range/2;

    if (!flush_point_list)
        return;

    if (!flush_point_list->initialized)
    {
#ifdef REG_TEST
        const char* sfp = getenv("S5_FPT");
        // no error checking required - atoi() is sufficient
        uint32_t cfp = sfp ? atoi(sfp) : 0;
        if ( cfp < 128 || cfp > 255 ) cfp = 192;
#else
        const uint32_t cfp = 192;
#endif

        flush_point_list->flush_range = flush_range;
        flush_point_list->flush_base = flush_base;
#ifndef DYNAMIC_RANDOM_FLUSH_POINTS
        flush_point_list->current = 0;

        flush_point_list->flush_points = (uint32_t*)SnortAlloc(sizeof(uint32_t) * RAND_FLUSH_POINTS);
        for (i=0;i<RAND_FLUSH_POINTS;i++)
        {
            if (snort_conf->run_flags & RUN_FLAG__STATIC_HASH)
            {
                if ( i == 0 )
                    LogMessage("WARNING:  using constant flush point = %u!\n", cfp);
                flush_point_list->flush_points[i] = cfp;

            }
            else if (use_static)
            {
                if ( i == 0 )
                    LogMessage("WARNING: using static flush points.\n");
                flush_point_list->flush_points[i] = g_static_points[i];
            }
            else
            {
                flush_point_list->flush_points[i] = GenerateFlushPoint(flush_point_list);
            }
        }
#endif
        flush_point_list->initialized = 1;
    }
}

static inline void UpdateFlushMgr(
    FlushMgr *mgr, FlushPointList *flush_point_list, uint32_t flags)
{
    if ( mgr->flush_type == S5_FT_EXTERNAL )
        return;

    switch (mgr->flush_policy)
    {
        case STREAM_FLPOLICY_FOOTPRINT:
        case STREAM_FLPOLICY_LOGICAL:
            break;

        case STREAM_FLPOLICY_PROTOCOL:
            if ( flags & TF_PKT_MISSED )
            {
                mgr->flush_policy = STREAM_FLPOLICY_FOOTPRINT;
                mgr->flush_type = S5_FT_PAF_MAX;
            }
            break;

        case STREAM_FLPOLICY_FOOTPRINT_IPS:
            break;

        case STREAM_FLPOLICY_PROTOCOL_IPS:
            if ( flags & TF_PKT_MISSED )
            {
                mgr->flush_policy = STREAM_FLPOLICY_FOOTPRINT_IPS;
                mgr->flush_type = S5_FT_PAF_MAX;
            }
            break;

        default:
            return;
    }
    /* Ideally, we would call rand() each time, but that
     * is a performance headache waiting to happen. */
#ifdef DYNAMIC_RANDOM_FLUSH_POINTS
    mgr->flush_pt = GenerateFlushPoint();
#else
    if (flush_point_list)
    {
        /* Handle case where it wasn't initialized... */
        if (flush_point_list->initialized == 0)
        {
            InitFlushPointList(flush_point_list, 192, 128, 0);
        }
        mgr->flush_pt = flush_point_list->flush_points[flush_point_list->current];
        flush_point_list->current = (flush_point_list->current+1) % RAND_FLUSH_POINTS;
    }
#endif
    mgr->last_size = 0;
    mgr->last_count = 0;

    if ( mgr->flush_type == S5_FT_PAF_MAX )
        mgr->flush_pt += ScPafMax();
}

static inline void InitFlushMgr(
    FlushMgr *mgr, FlushPointList *flush_point_list,
    uint8_t policy, uint8_t auto_disable)
{
    mgr->flush_policy = policy;
    mgr->flush_type = S5_FT_INTERNAL;
    mgr->auto_disable = auto_disable;

    UpdateFlushMgr(mgr, flush_point_list, 0);

    if ( Normalize_IsEnabled(snort_conf, NORM_TCP_IPS) )
    {
        if ( policy == STREAM_FLPOLICY_FOOTPRINT )
            mgr->flush_policy = STREAM_FLPOLICY_FOOTPRINT_IPS;

        else if ( policy == STREAM_FLPOLICY_PROTOCOL )
            mgr->flush_policy = STREAM_FLPOLICY_PROTOCOL_IPS;
    }
}

static inline void InitFlushMgrByPort (
    Flow* lwssn, StreamTracker* pst,
    uint16_t port, bool c2s, uint8_t flush_policy)
{
    uint8_t registration, auto_disable = 0;
    bool flush = (flush_policy != STREAM_FLPOLICY_IGNORE);

#if 0
    // this check required if PAF doesn't abort
    if ( lwssn->session_state & STREAM5_STATE_MIDSTREAM )
        registration = 0;
    else
#endif
        registration = s5_paf_port_registration(
            lwssn->s5_config->tcp_config->paf_config, port, c2s, flush);
    
    if ( registration )
    {   
        flush_policy = STREAM_FLPOLICY_PROTOCOL;
        s5_paf_setup(&pst->paf_state, registration);
        auto_disable = !flush;
    }   
    InitFlushMgr(&pst->flush_mgr,
        &pst->tcp_policy->flush_point_list, flush_policy, auto_disable);
}

static inline void InitFlushMgrByService (
    Flow* lwssn, StreamTracker* pst,
    int16_t service, bool c2s, uint8_t flush_policy)
{
    uint8_t registration, auto_disable = 0;
    bool flush = (flush_policy != STREAM_FLPOLICY_IGNORE);
    
#if 0
    // this check required if PAF doesn't abort
    if ( lwssn->session_state & STREAM5_STATE_MIDSTREAM )
        registration = 0;
    else
#endif
        registration = s5_paf_service_registration(
            lwssn->s5_config->tcp_config->paf_config, service, c2s, flush);
    
    if ( registration )
    {   
        flush_policy = STREAM_FLPOLICY_PROTOCOL;
        s5_paf_setup(&pst->paf_state, registration);
        auto_disable = !flush;
    }   
    InitFlushMgr(&pst->flush_mgr,
        &pst->tcp_policy->flush_point_list, flush_policy, auto_disable);
}

static int ResetFlushMgrsPolicy(Stream5TcpConfig* tcp_config)
{
    if (tcp_config == NULL)
        return 0;

    {
        int j;
        Stream5TcpPolicy *policy = tcp_config->policy;
        FlushPointList *fpl = &policy->flush_point_list;
        FlushMgr *client, *server;
        uint8_t flush_policy;

        fpl->current = 0;

        for (j = 0; j < MAX_PORTS; j++)
        {
            client = &policy->flush_config[j].client;
            flush_policy = policy->flush_config[j].client.flush_policy;
            InitFlushMgr(client, fpl, flush_policy, 0);

            server = &policy->flush_config[j].server;
            flush_policy = policy->flush_config[j].server.flush_policy;
            InitFlushMgr(server, fpl, flush_policy, 0);
        }
        /* protocol 0 is the unknown case. skip it */
        for (j = 1; j < MAX_PROTOCOL_ORDINAL; j++)
        {
            client = &policy->flush_config_protocol[j].client;
            flush_policy = policy->flush_config_protocol[j].client.flush_policy;
            InitFlushMgr(client, fpl, flush_policy, 0);

            server = &policy->flush_config_protocol[j].server;
            flush_policy = policy->flush_config_protocol[j].server.flush_policy;
            InitFlushMgr(server, fpl, flush_policy, 0);
        }
    }

    return 0;
}

void** Stream5GetPAFUserDataTcp (Flow* lwssn, bool to_server)
{
    TcpSession* tcpssn = (TcpSession*)lwssn->session;

    return to_server ? &tcpssn->server.paf_state.user
                     : &tcpssn->client.paf_state.user;
}

bool Stream5IsPafActiveTcp (Flow* lwssn, bool to_server)
{
    TcpSession* tcpssn = (TcpSession*)lwssn->session;
    FlushMgr* fm;

    fm = to_server ? &tcpssn->server.flush_mgr : &tcpssn->client.flush_mgr;

    return ( (fm->flush_policy == STREAM_FLPOLICY_PROTOCOL)
          || (fm->flush_policy == STREAM_FLPOLICY_PROTOCOL_IPS)
    );
}

bool Stream5ActivatePafTcp (Flow* lwssn, bool to_server)
{
    TcpSession* tcpssn = (TcpSession*)lwssn->session;
    StreamTracker* trk;
    FlushMgr* fm;

    if ( to_server )
    {
        trk = &tcpssn->server;
        fm = &tcpssn->server.flush_mgr;
    }
    else
    {
        trk = &tcpssn->client;
        fm = &tcpssn->client.flush_mgr;
    }

    switch ( fm->flush_policy)
    {
    case STREAM_FLPOLICY_IGNORE:
        InitFlushMgr(fm, &trk->tcp_policy->flush_point_list, STREAM_FLPOLICY_PROTOCOL, 0);
        break;

    case STREAM_FLPOLICY_FOOTPRINT:
        fm->flush_policy = STREAM_FLPOLICY_PROTOCOL;
        break;

    case STREAM_FLPOLICY_FOOTPRINT_IPS:
        fm->flush_policy = STREAM_FLPOLICY_PROTOCOL_IPS;
        break;

    default:
        return false;
    }
    s5_paf_setup(&trk->paf_state, trk->paf_state.cb_mask);
    return true;
}

void Stream5UpdatePerfBaseState(SFBASE *sf_base,
                                Flow *lwssn,
                                char newState)
{
    if (!lwssn)
    {
        return;
    }

    switch (newState)
    {
    case TCP_STATE_SYN_SENT:
        if (!(lwssn->s5_state.session_flags & SSNFLAG_COUNTED_INITIALIZE))
        {
            sf_base->iSessionsInitializing++;
            lwssn->s5_state.session_flags |= SSNFLAG_COUNTED_INITIALIZE;
        }
        break;
    case TCP_STATE_ESTABLISHED:
        if (!(lwssn->s5_state.session_flags & SSNFLAG_COUNTED_ESTABLISH))
        {
            sf_base->iSessionsEstablished++;

            if (perfmon_config && (perfmon_config->perf_flags & SFPERF_FLOWIP))
                UpdateFlowIPState(&sfFlow, IP_ARG(lwssn->client_ip), IP_ARG(lwssn->server_ip), SFS_STATE_TCP_ESTABLISHED);

            lwssn->s5_state.session_flags |= SSNFLAG_COUNTED_ESTABLISH;

            if ((lwssn->s5_state.session_flags & SSNFLAG_COUNTED_INITIALIZE) && 
                !(lwssn->s5_state.session_flags & SSNFLAG_COUNTED_CLOSING))
            {
                assert(sf_base->iSessionsInitializing);
                sf_base->iSessionsInitializing--;
            }
        }
        break;
    case TCP_STATE_CLOSING:
        if (!(lwssn->s5_state.session_flags & SSNFLAG_COUNTED_CLOSING))
        {
            sf_base->iSessionsClosing++;
            lwssn->s5_state.session_flags |= SSNFLAG_COUNTED_CLOSING;
            if (lwssn->s5_state.session_flags & SSNFLAG_COUNTED_ESTABLISH)
            {
                assert(sf_base->iSessionsEstablished);
                sf_base->iSessionsEstablished--;

                if (perfmon_config && (perfmon_config->perf_flags & SFPERF_FLOWIP))
                    UpdateFlowIPState(&sfFlow, IP_ARG(lwssn->client_ip), IP_ARG(lwssn->server_ip), SFS_STATE_TCP_CLOSED);
            }
            else if (lwssn->s5_state.session_flags & SSNFLAG_COUNTED_INITIALIZE)
            {
                assert(sf_base->iSessionsInitializing);
                sf_base->iSessionsInitializing--;
            }
        }
        break;
    case TCP_STATE_CLOSED:
        if (lwssn->s5_state.session_flags & SSNFLAG_COUNTED_CLOSING)
        {
            assert(sf_base->iSessionsClosing);
            sf_base->iSessionsClosing--;
        }
        else if (lwssn->s5_state.session_flags & SSNFLAG_COUNTED_ESTABLISH)
        {
            assert(sf_base->iSessionsEstablished);
            sf_base->iSessionsEstablished--;

            if (perfmon_config && (perfmon_config->perf_flags & SFPERF_FLOWIP))
                UpdateFlowIPState(&sfFlow, IP_ARG(lwssn->client_ip), IP_ARG(lwssn->server_ip), SFS_STATE_TCP_CLOSED);
        }
        else if (lwssn->s5_state.session_flags & SSNFLAG_COUNTED_INITIALIZE)
        {
            assert(sf_base->iSessionsInitializing);
            sf_base->iSessionsInitializing--;
        }
        break;
    default:
        break;
    }
    sf_base->stream5_mem_in_use = tcp_memcap->used();
}

static void Stream5TcpRegisterPreprocProfiles(void)
{
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile(
        "tcp", &s5TcpPerfStats, 0, &totalPerfStats, tcp_get_profile);
    RegisterPreprocessorProfile(
        "tcpNewSess", &s5TcpNewSessPerfStats, 1, &s5TcpPerfStats, tcp_get_profile);
    RegisterPreprocessorProfile(
        "tcpState", &s5TcpStatePerfStats, 1, &s5TcpPerfStats, tcp_get_profile);
    RegisterPreprocessorProfile(
        "tcpData", &s5TcpDataPerfStats, 2, &s5TcpStatePerfStats, tcp_get_profile);
    RegisterPreprocessorProfile(
        "tcpPktInsert", &s5TcpInsertPerfStats, 3, &s5TcpDataPerfStats, tcp_get_profile);
    RegisterPreprocessorProfile(
        "tcpPAF", &s5TcpPAFPerfStats, 2, &s5TcpStatePerfStats, tcp_get_profile);
    RegisterPreprocessorProfile(
        "tcpFlush", &s5TcpFlushPerfStats, 2, &s5TcpStatePerfStats, tcp_get_profile);
    RegisterPreprocessorProfile(
        "tcpBuildPacket", &s5TcpBuildPacketPerfStats, 3, &s5TcpFlushPerfStats,
        tcp_get_profile);
    RegisterPreprocessorProfile(
        "tcpProcessRebuilt", &s5TcpProcessRebuiltPerfStats, 3,
        &s5TcpFlushPerfStats, tcp_get_profile);
#endif
}

static void Stream5TcpRegisterRuleOptions(SnortConfig*)
{
#if 0
    // FIXIT implement preproc rule option as any other rule option
    /* Register the 'stream_size' rule option */
    RegisterPreprocessorRuleOption(sc, "stream_size", &s5TcpStreamSizeInit,
                                   &s5TcpStreamSizeEval, &s5TcpStreamSizeCleanup,
                                   NULL, NULL, NULL, NULL);

    RegisterPreprocessorRuleOption(sc, "stream_reassemble", &s5TcpStreamReassembleRuleOptionInit,
                                   &s5TcpStreamReassembleRuleOptionEval, &s5TcpStreamReassembleRuleOptionCleanup,
                                   NULL, NULL, NULL, NULL);
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile(
        "stream_size", &streamSizePerfStats, 4, &preprocRuleOptionPerfStats,
        tcp_get_profile);
    RegisterPreprocessorProfile(
        "reassemble", &streamReassembleRuleOptionPerfStats, 4,
        &preprocRuleOptionPerfStats, tcp_get_profile);
#endif
#endif
}

static void Stream5TcpInitFlushPoints(void)
{
    int i;

    /* Seed the flushpoint random generator */
    srand( (unsigned int) sizeof(default_ports) + (unsigned int) time(NULL) );

    /* Default is to ignore, for all ports */
    for(i=0;i<MAX_PORTS;i++)
    {
        ignore_flush_policy[i].client.flush_policy = STREAM_FLPOLICY_IGNORE;
        ignore_flush_policy[i].server.flush_policy = STREAM_FLPOLICY_IGNORE;
    }
    for(i=0;i<MAX_PROTOCOL_ORDINAL;i++)
    {
        ignore_flush_policy_protocol[i].client.flush_policy = STREAM_FLPOLICY_IGNORE;
        ignore_flush_policy_protocol[i].server.flush_policy = STREAM_FLPOLICY_IGNORE;
    }
}

static inline uint16_t StreamPolicyIdFromName(char *name)
{
    if (!name)
    {
        return STREAM_POLICY_DEFAULT;
    }

    if(!strcasecmp(name, "bsd"))
    {
        return STREAM_POLICY_BSD;
    }
    else if(!strcasecmp(name, "old-linux"))
    {
        return STREAM_POLICY_OLD_LINUX;
    }
    else if(!strcasecmp(name, "linux"))
    {
        return STREAM_POLICY_LINUX;
    }
    else if(!strcasecmp(name, "first"))
    {
        return STREAM_POLICY_FIRST;
    }
    else if(!strcasecmp(name, "last"))
    {
        return STREAM_POLICY_LAST;
    }
    else if(!strcasecmp(name, "windows"))
    {
        return STREAM_POLICY_WINDOWS;
    }
    else if(!strcasecmp(name, "solaris"))
    {
        return STREAM_POLICY_SOLARIS;
    }
    else if(!strcasecmp(name, "win2003") ||
            !strcasecmp(name, "win2k3"))
    {
        return STREAM_POLICY_WINDOWS2K3;
    }
    else if(!strcasecmp(name, "vista"))
    {
        return STREAM_POLICY_VISTA;
    }
    else if(!strcasecmp(name, "hpux") ||
            !strcasecmp(name, "hpux11"))
    {
        return STREAM_POLICY_HPUX11;
    }
    else if(!strcasecmp(name, "hpux10"))
    {
        return STREAM_POLICY_HPUX10;
    }
    else if(!strcasecmp(name, "irix"))
    {
        return STREAM_POLICY_IRIX;
    }
    else if(!strcasecmp(name, "macos") ||
            !strcasecmp(name, "grannysmith"))
    {
        return STREAM_POLICY_MACOS;
    }
    return STREAM_POLICY_DEFAULT; /* BSD is the default */
}

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
        default:
            return REASSEMBLY_POLICY_DEFAULT;
    }
}

#define STATIC_FP ((s5TcpPolicy->flags & STREAM5_CONFIG_STATIC_FLUSHPOINTS)?1:0)

static void Stream5ParseTcpArgs(
    SnortConfig*, Stream5TcpConfig *config, char *args,
    Stream5TcpPolicy *s5TcpPolicy)
{
    char **toks;
    int num_toks;
    int i;
    char **stoks = NULL;
    int s_toks;
    char *endPtr = NULL;
    char set_flush_policy = 0;
    char set_target_flush_policy = 0;
    int reassembly_direction = SSN_DIR_CLIENT;
    int32_t long_val = 0;

    s5TcpPolicy->policy = STREAM_POLICY_DEFAULT;
    s5TcpPolicy->reassembly_policy = REASSEMBLY_POLICY_DEFAULT;
    s5TcpPolicy->session_timeout = S5_DEFAULT_SSN_TIMEOUT;
    s5TcpPolicy->max_window = 0;
    s5TcpPolicy->flags = 0;
    s5TcpPolicy->max_queued_bytes = S5_DEFAULT_MAX_QUEUED_BYTES;
    s5TcpPolicy->max_queued_segs = S5_DEFAULT_MAX_QUEUED_SEGS;

    s5TcpPolicy->max_consec_small_segs = S5_DEFAULT_CONSEC_SMALL_SEGS;
    s5TcpPolicy->max_consec_small_seg_size = S5_DEFAULT_MAX_SMALL_SEG_SIZE;

    if(args != NULL && strlen(args) != 0)
    {
        toks = mSplit(args, ",", 0, &num_toks, 0);

        for (i = 0; i < num_toks; i++)
        {
            if(!strcasecmp(toks[i], "use_static_footprint_sizes"))
                s5TcpPolicy->flags |= STREAM5_CONFIG_STATIC_FLUSHPOINTS;
        }

        for (i = 0; i < num_toks; i++)
        {
            int max_s_toks = 1;  // set to 0 to disable check
            stoks = mSplit(toks[i], " ", 3, &s_toks, 0);

            if (s_toks == 0)
            {
                ParseError("Missing parameter in Stream5 TCP config.");
            }

            if(!strcasecmp(stoks[0], "timeout"))
            {
                if(stoks[1])
                {
                    s5TcpPolicy->session_timeout = strtoul(stoks[1], &endPtr, 10);
                }

                if (!stoks[1] || (endPtr == &stoks[1][0]))
                {
                    ParseError("Invalid timeout in config file.  "
                        "Integer parameter required.");
                }

                if ((s5TcpPolicy->session_timeout > S5_MAX_SSN_TIMEOUT) ||
                    (s5TcpPolicy->session_timeout < S5_MIN_SSN_TIMEOUT))
                {
                    ParseError("Invalid timeout in config file.  "
                        "Must be between %d and %d",
                        S5_MIN_SSN_TIMEOUT, S5_MAX_SSN_TIMEOUT);
                }
                max_s_toks = 2;
            }
            else if(!strcasecmp(stoks[0], "overlap_limit"))
            {
                if(stoks[1])
                {
                    long_val = SnortStrtol(stoks[1], &endPtr, 10);
                    if (errno == ERANGE)
                    {
                        errno = 0;
                        long_val = -1;
                    }
                    s5TcpPolicy->overlap_limit = (uint8_t)long_val;
                }

                if (!stoks[1] || (endPtr == &stoks[1][0]))
                {
                    ParseError("Invalid overlap limit in config file."
                            "Integer parameter required");
                }

                if ((long_val > S5_MAX_OVERLAP_LIMIT) ||
                    (long_val < S5_MIN_OVERLAP_LIMIT))
                {
                    ParseError("Invalid overlap limit in config file."
                        "  Must be between %d and %d",
                        S5_MIN_OVERLAP_LIMIT, S5_MAX_OVERLAP_LIMIT);
                }
                max_s_toks = 2;
            }
            else if(!strcasecmp(stoks[0], "policy"))
            {
                s5TcpPolicy->policy = StreamPolicyIdFromName(stoks[1]);

                if ((s5TcpPolicy->policy == STREAM_POLICY_DEFAULT) &&
                    (strcasecmp(stoks[1], "bsd")))
                {
                    /* Default is BSD.  If we don't have "bsd", its
                     * the default and invalid.
                     */
                    ParseError("Bad policy name '%s'", stoks[1]);
                }
                s5TcpPolicy->reassembly_policy =
                    GetTcpReassemblyPolicy(s5TcpPolicy->policy);

                max_s_toks = 2;
            }
            else if(!strcasecmp(stoks[0], "require_3whs"))
            {
                s5TcpPolicy->flags |= STREAM5_CONFIG_REQUIRE_3WHS;

                if (s_toks > 1)
                {
                    s5TcpPolicy->hs_timeout = SnortStrtoul(stoks[1], &endPtr, 10);

                    if ((endPtr == &stoks[1][0]) || (*endPtr != '\0') || (errno == ERANGE))
                    {
                        ParseError(
                            "Invalid 3Way Handshake allowable.  Integer parameter required.");
                    }

                    if (s5TcpPolicy->hs_timeout > S5_MAX_SSN_TIMEOUT)
                    {
                        ParseError("Invalid handshake timeout in "
                                   "config file.  Must be between %d and %d",
                                   S5_MIN_ALT_HS_TIMEOUT, S5_MAX_SSN_TIMEOUT);
                    }
                }

                max_s_toks = 2;
            }
            else if(!strcasecmp(stoks[0], "max_window"))
            {
                if(stoks[1])
                {
                    long_val = SnortStrtol(stoks[1], &endPtr, 10);
                    if (errno == ERANGE)
                    {
                        errno = 0;
                        ParseError("Invalid Max Window size.  Integer parameter required.");
                    }
                    s5TcpPolicy->max_window = (uint32_t)long_val;
                }

                if (!stoks[1] || (endPtr == &stoks[1][0]))
                {
                    ParseError("Invalid Max Window size.  Integer parameter required.");
                }

                if ((long_val > S5_MAX_MAX_WINDOW) ||
                    (long_val < S5_MIN_MAX_WINDOW))
                {
                    ParseError("Invalid Max Window size."
                        "  Must be between %d and %d",
                        S5_MIN_MAX_WINDOW, S5_MAX_MAX_WINDOW);
                }
                max_s_toks = 2;
            }
            else if(!strcasecmp(stoks[0], "use_static_footprint_sizes"))
            {
                // we already handled this one above
            }
            else if(!strcasecmp(stoks[0], "flush_factor"))
            {
                if (stoks[1])
                {
                    s5TcpPolicy->flush_factor = (uint16_t)SnortStrtoulRange(
                        stoks[1], &endPtr, 10, 0, S5_MAX_FLUSH_FACTOR);
                }
                if (
                    (!stoks[1] || (endPtr == &stoks[1][0])) ||
                    (s5TcpPolicy->flush_factor > S5_MAX_FLUSH_FACTOR))
                {
                    ParseError("'flush_factor %d' invalid: "
                        "value must be between 0 and %d segments.",
                        s5TcpPolicy->flush_factor, S5_MAX_FLUSH_FACTOR);
                }
                max_s_toks = 2;
            }
            else if(!strcasecmp(stoks[0], "ignore_any_rules"))
            {
                s5TcpPolicy->flags |= STREAM5_CONFIG_IGNORE_ANY;
            }
            else if(!strcasecmp(stoks[0], "dont_reassemble_async"))
            {
                s5TcpPolicy->flags |= STREAM5_CONFIG_NO_ASYNC_REASSEMBLY;
            }
            else if(!strcasecmp(stoks[0], "max_queued_bytes"))
            {
                if(stoks[1])
                {
                    long_val = SnortStrtol(stoks[1], &endPtr, 10);
                    if (errno == ERANGE)
                    {
                        errno = 0;
                        ParseError("Invalid Max Queued Bytes.  Integer parameter required.");
                    }
                    s5TcpPolicy->max_queued_bytes = (uint32_t)long_val;
                }

                if (!stoks[1] || (endPtr == &stoks[1][0]))
                {
                    ParseError("Invalid Max Queued Bytes.  Integer parameter required.");
                }
                if (((long_val > S5_MAX_MAX_QUEUED_BYTES) ||
                     (long_val < S5_MIN_MAX_QUEUED_BYTES)) &&
                    (long_val != 0))
                {
                    ParseError("Invalid Max Queued Bytes."
                        "  Must be 0 (disabled) or between %d and %d",
                        S5_MIN_MAX_QUEUED_BYTES, S5_MAX_MAX_QUEUED_BYTES);
                }
                max_s_toks = 2;
            }
            else if(!strcasecmp(stoks[0], "max_queued_segs"))
            {
                if(stoks[1])
                {
                    long_val = SnortStrtol(stoks[1], &endPtr, 10);
                    if (errno == ERANGE)
                    {
                        errno = 0;
                        ParseError("Invalid Max Queued Bytes.  Integer parameter required.");
                    }
                    s5TcpPolicy->max_queued_segs = (uint32_t)long_val;
                }

                if (!stoks[1] || (endPtr == &stoks[1][0]))
                {
                    ParseError("Invalid Max Queued Bytes.  Integer parameter required.");
                }

                if (((long_val > S5_MAX_MAX_QUEUED_SEGS) ||
                     (long_val < S5_MIN_MAX_QUEUED_SEGS)) &&
                    (long_val != 0))
                {
                    ParseError("Invalid Max Queued Bytes."
                        "  Must be 0 (disabled) or between %d and %d",
                        S5_MIN_MAX_QUEUED_SEGS, S5_MAX_MAX_QUEUED_SEGS);
                }
                max_s_toks = 2;
            }
            else if (!strcasecmp(stoks[0], "small_segments"))
            {
                char **ptoks;
                int num_ptoks;

                /* Small segments takes at least 3 parameters... */
                if (s_toks < 3)
                {
                    ParseError("Insufficient parameters to small "
                        "segments configuration.  Syntax is: "
                        "<number> bytes <number> ignore_ports p1 p2, "
                        "with ignore_ports being an optional parameter");
                }

                /* first the number of consecutive segments */
                long_val = SnortStrtol(stoks[1], &endPtr, 10);
                if (errno == ERANGE)
                {
                    errno = 0;
                    ParseError("Invalid Small Segment number.  Integer parameter required.");
                }
                s5TcpPolicy->max_consec_small_segs = (uint32_t)long_val;

                if ((long_val > S5_MAX_CONSEC_SMALL_SEGS) ||
                    (long_val < S5_MIN_CONSEC_SMALL_SEGS))
                {
                    ParseError("Invalid Small Segments."
                        "  Must be integer between %d and %d, inclusive",
                        S5_MIN_CONSEC_SMALL_SEGS, S5_MAX_CONSEC_SMALL_SEGS);
                }

                ptoks = mSplit(stoks[2], " ", MAX_PORTS + 3, &num_ptoks, 0);

                /* the bytes keyword */
                if (strcasecmp(ptoks[0], "bytes") || (num_ptoks < 2))
                {
                    ParseError("Insufficient parameters to small "
                        "segments configuration.  Syntax is: "
                        "<number> bytes <number> ignore_ports p1 p2, "
                        "with ignore_ports being an optional parameter");
                }

                /* the minimum bytes for a segment to be considered "small" */
                long_val = SnortStrtol(ptoks[1], &endPtr, 10);
                if (errno == ERANGE)
                {
                    errno = 0;
                    ParseError("Invalid Small Segment bytes.  Integer parameter required.");
                }
                s5TcpPolicy->max_consec_small_seg_size = (uint32_t)long_val;

                if ((long_val > S5_MAX_MAX_SMALL_SEG_SIZE) ||
                    (long_val < S5_MIN_MAX_SMALL_SEG_SIZE))
                {
                    ParseError("Invalid Small Segments bytes."
                        "  Must be integer between %d and %d, inclusive",
                        S5_MIN_MAX_SMALL_SEG_SIZE, S5_MAX_MAX_SMALL_SEG_SIZE);
                }

                /* and the optional ignore_ports */
                if (num_ptoks > 2)
                {
                    int j;
                    unsigned short port = 0;
                    long long_port = 0;
                    if (strcasecmp(ptoks[2], "ignore_ports") || (num_ptoks < 4))
                    {
                        ParseError("Insufficient parameters to small "
                            "segments configuration.  Syntax is: "
                            "<number> bytes <number> ignore_ports p1 p2, "
                            "with ignore_ports being an optional parameter");
                    }

                    for (j=3; j<num_ptoks;j++)
                    {
                        if (ptoks[j])
                        {
                            long_port = strtol(ptoks[j], &endPtr, 10);
                        }
                        if (!ptoks[j] || (endPtr == &ptoks[j][0]))
                        {
                            ParseError(
                                "Invalid Port for small segments ignore_ports parameter.  "
                                "Integer parameter required.");
                        }

                        if ((long_port < 0) || (long_port > MAX_PORTS-1))
                        {
                            ParseError(
                                "Invalid port %ld for small segments ignore_ports "
                                "parameter, must be between 0 and %d, inclusive",
                                long_port, MAX_PORTS-1);
                        }
                        port = (unsigned short)long_port;

                        s5TcpPolicy->small_seg_ignore[port/8] |= (1 << (port %8));
                    }
                }
                max_s_toks = 0; // we already checked all tokens
                mSplitFree(&ptoks, num_ptoks);
            }
            else if (!strcasecmp(stoks[0], "ports"))
            {
                if (s_toks > 1)
                {
                    if(!strcasecmp(stoks[1], "client"))
                    {
                        reassembly_direction = SSN_DIR_CLIENT;
                    }
                    else if(!strcasecmp(stoks[1], "server"))
                    {
                        reassembly_direction = SSN_DIR_SERVER;
                    }
                    else
                    {
                        reassembly_direction = SSN_DIR_BOTH;
                    }
                }

                if (s_toks > 2)
                {
                    char **ptoks;
                    int num_ptoks;
                    int j;
                    unsigned short port = 0;
                    long long_port = 0;

                    /* Initialize it if not already... */
                    InitFlushPointList(&s5TcpPolicy->flush_point_list, 192, 128, STATIC_FP);

                    if (!strcasecmp(stoks[2], "all"))
                    {
                        for (j=0; j<MAX_PORTS; j++)
                        {
                            if (reassembly_direction & SSN_DIR_CLIENT)
                            {
                                FlushMgr *flush_mgr = &s5TcpPolicy->flush_config[j].client;
                                FlushPointList *flush_point_list = &s5TcpPolicy->flush_point_list;
                                InitFlushMgr(flush_mgr, flush_point_list, STREAM_FLPOLICY_FOOTPRINT, 0);
                            }
                            if (reassembly_direction & SSN_DIR_SERVER)
                            {
                                FlushMgr *flush_mgr = &s5TcpPolicy->flush_config[j].server;
                                FlushPointList *flush_point_list = &s5TcpPolicy->flush_point_list;
                                InitFlushMgr(flush_mgr, flush_point_list, STREAM_FLPOLICY_FOOTPRINT, 0);
                            }
                        }
                    }
                    else if (!strcasecmp(stoks[2], "none"))
                    {
                        for (j=0; j<MAX_PORTS; j++)
                        {
                            if (reassembly_direction & SSN_DIR_CLIENT)
                            {
                                FlushMgr *flush_mgr = &s5TcpPolicy->flush_config[j].client;
                                flush_mgr->flush_policy = STREAM_FLPOLICY_IGNORE;
                            }
                            if (reassembly_direction & SSN_DIR_SERVER)
                            {
                                FlushMgr *flush_mgr = &s5TcpPolicy->flush_config[j].server;
                                flush_mgr->flush_policy = STREAM_FLPOLICY_IGNORE;
                            }
                        }
                    }
                    else
                    {
                        ptoks = mSplit(stoks[2], " ", MAX_PORTS, &num_ptoks, 0);

                        for (j=0;j<num_ptoks;j++)
                        {
                            if (ptoks[j])
                            {
                                long_port = strtol(ptoks[j], &endPtr, 10);
                            }
                            if (!ptoks[j] || (endPtr == &ptoks[j][0]))
                            {
                                ParseError("Invalid Port list.  Integer parameter required.");
                            }

                            if ((long_port < 0) || (long_port > MAX_PORTS-1))
                            {
                                ParseError(
                                    "Invalid port %ld, must be between 0 and %d, "
                                    "inclusive", long_port, MAX_PORTS-1);
                            }
                            port = (unsigned short)long_port;

                            if (reassembly_direction & SSN_DIR_CLIENT)
                            {
                                FlushMgr *flush_mgr = &s5TcpPolicy->flush_config[port].client;
                                FlushPointList *flush_point_list = &s5TcpPolicy->flush_point_list;
                                InitFlushMgr(flush_mgr, flush_point_list, STREAM_FLPOLICY_FOOTPRINT, 0);
                            }
                            if (reassembly_direction & SSN_DIR_SERVER)
                            {
                                FlushMgr *flush_mgr = &s5TcpPolicy->flush_config[port].server;
                                FlushPointList *flush_point_list = &s5TcpPolicy->flush_point_list;
                                InitFlushMgr(flush_mgr, flush_point_list, STREAM_FLPOLICY_FOOTPRINT, 0);
                            }
                        }
                        mSplitFree(&ptoks, num_ptoks);
                    }
                    set_flush_policy = 1;
                }
                max_s_toks = 0;  // we already checked all tokens
            }
            else if (!strcasecmp(stoks[0], "protocol"))
            {
                if (s_toks > 1)
                {
                    if(!strcasecmp(stoks[1], "client"))
                    {
                        reassembly_direction = SSN_DIR_CLIENT;
                    }
                    else if(!strcasecmp(stoks[1], "server"))
                    {
                        reassembly_direction = SSN_DIR_SERVER;
                    }
                    else
                    {
                        reassembly_direction = SSN_DIR_BOTH;
                    }
                }

                if (s_toks > 2)
                {
                    char **ptoks;
                    int num_ptoks;
                    int j;

                    /* Initialize it if not already... */
                    InitFlushPointList(&s5TcpPolicy->flush_point_list, 192, 128, STATIC_FP);

                    if (!strcasecmp(stoks[2], "all"))
                    {
                        for (j=1; j<MAX_PROTOCOL_ORDINAL; j++)
                        {
                            if (reassembly_direction & SSN_DIR_CLIENT)
                            {
                                FlushMgr *flush_mgr = &s5TcpPolicy->flush_config_protocol[j].client;
                                FlushPointList *flush_point_list = &s5TcpPolicy->flush_point_list;
                                InitFlushMgr(flush_mgr, flush_point_list, STREAM_FLPOLICY_FOOTPRINT, 0);
                            }
                            if (reassembly_direction & SSN_DIR_SERVER)
                            {
                                FlushMgr *flush_mgr = &s5TcpPolicy->flush_config_protocol[j].server;
                                FlushPointList *flush_point_list = &s5TcpPolicy->flush_point_list;
                                InitFlushMgr(flush_mgr, flush_point_list, STREAM_FLPOLICY_FOOTPRINT, 0);
                            }
                            s5TcpPolicy->flush_config_protocol[j].configured = 1;
                        }
                    }
                    else if (!strcasecmp(stoks[2], "none"))
                    {
                        for (j=1; j<MAX_PROTOCOL_ORDINAL; j++)
                        {
                            if (reassembly_direction & SSN_DIR_CLIENT)
                            {
                                FlushMgr *flush_mgr = &s5TcpPolicy->flush_config_protocol[j].client;
                                flush_mgr->flush_policy = STREAM_FLPOLICY_IGNORE;
                            }
                            if (reassembly_direction & SSN_DIR_SERVER)
                            {
                                FlushMgr *flush_mgr = &s5TcpPolicy->flush_config_protocol[j].server;
                                flush_mgr->flush_policy = STREAM_FLPOLICY_IGNORE;
                            }
                            s5TcpPolicy->flush_config_protocol[j].configured = 1;
                        }
                    }
                    else
                    {
                        ptoks = mSplit(stoks[2], " ", MAX_PROTOCOL_ORDINAL, &num_ptoks, 0);

                        for (j=0;j<num_ptoks;j++)
                        {
                            int16_t proto_ordinal;
                            if (!ptoks[j])
                            {
                                ParseError(
                                    "Invalid Protocol Name.  Protocol name must be specified.");
                            }
                            /* First look it up */
                            proto_ordinal = FindProtocolReference(ptoks[j]);
                            if (proto_ordinal == SFTARGET_UNKNOWN_PROTOCOL)
                            {
                                /* Not known -- add it */
                                proto_ordinal = AddProtocolReference(ptoks[j]);
                                if (proto_ordinal == SFTARGET_UNKNOWN_PROTOCOL)
                                {
                                    ParseError("Failed to find protocol reference for '%s'",
                                        ptoks[j]);
                                }
                            }

                            if (reassembly_direction & SSN_DIR_CLIENT)
                            {
                                FlushMgr *flush_mgr = &s5TcpPolicy->flush_config_protocol[proto_ordinal].client;
                                FlushPointList *flush_point_list = &s5TcpPolicy->flush_point_list;
                                InitFlushMgr(flush_mgr, flush_point_list, STREAM_FLPOLICY_FOOTPRINT, 0);
                            }
                            if (reassembly_direction & SSN_DIR_SERVER)
                            {
                                FlushMgr *flush_mgr = &s5TcpPolicy->flush_config_protocol[proto_ordinal].server;
                                FlushPointList *flush_point_list = &s5TcpPolicy->flush_point_list;
                                InitFlushMgr(flush_mgr, flush_point_list, STREAM_FLPOLICY_FOOTPRINT, 0);
                            }
                            s5TcpPolicy->flush_config_protocol[proto_ordinal].configured = 1;
                        }
                        mSplitFree(&ptoks, num_ptoks);
                    }
                    set_target_flush_policy = 1;
                }
                max_s_toks = 0;  // we already checked all tokens
            }
            else
            {
                ParseError("Invalid Stream5 TCP policy option");
            }

            if ( max_s_toks && (s_toks > max_s_toks) )
            {
                ParseError("Invalid Stream5 TCP Policy option.  Missing comma?");
            }
            mSplitFree(&stoks, s_toks);
        }

        mSplitFree(&toks, num_toks);
    }

    config->policy = s5TcpPolicy;

    {
        if (s5TcpPolicy->flags & STREAM5_CONFIG_IGNORE_ANY)
        {
            ParseError("'ignore_any_rules' option can be used only"
                   " with Default Stream5 TCP Policy");
        }
    }

    if (!set_flush_policy)
    {
        /* Initialize it if not already... */
        InitFlushPointList(&s5TcpPolicy->flush_point_list, 192, 128, STATIC_FP);
        for (i=0;i<(int)(sizeof(default_ports)/sizeof(int)); i++)
        {
            if (reassembly_direction & SSN_DIR_CLIENT)
            {
                FlushMgr *flush_mgr = &s5TcpPolicy->flush_config[default_ports[i]].client;
                FlushPointList *flush_point_list = &s5TcpPolicy->flush_point_list;
                InitFlushMgr(flush_mgr, flush_point_list, STREAM_FLPOLICY_FOOTPRINT, 0);
            }
            if (reassembly_direction & SSN_DIR_SERVER)
            {
                FlushMgr *flush_mgr = &s5TcpPolicy->flush_config[default_ports[i]].server;
                FlushPointList *flush_point_list = &s5TcpPolicy->flush_point_list;
                InitFlushMgr(flush_mgr, flush_point_list, STREAM_FLPOLICY_FOOTPRINT, 0);
            }
        }
    }

    if (!set_target_flush_policy)
    {
        int app_id;
        /* Initialize it if not already... */
        InitFlushPointList(&s5TcpPolicy->flush_point_list, 192, 128, STATIC_FP);
        for (i=0; i<(int)(sizeof(default_protocols)/sizeof(char *)); i++)
        {
            /* Look up the protocol by name. Add it if it doesn't exist. */
            app_id = FindProtocolReference(default_protocols[i]);
            if (app_id == SFTARGET_UNKNOWN_PROTOCOL)
            {
                app_id = AddProtocolReference(default_protocols[i]);
            }

            /* While this should never happen, I don't feel guilty adding this
             * logic as it executes at parse time. */
            if (app_id == SFTARGET_UNKNOWN_PROTOCOL)
                continue;

            /* Set flush managers. */
            if (reassembly_direction & SSN_DIR_CLIENT)
            {
                FlushMgr *flush_mgr = &s5TcpPolicy->flush_config_protocol[app_id].client;
                FlushPointList *flush_point_list = &s5TcpPolicy->flush_point_list;
                InitFlushMgr(flush_mgr, flush_point_list, STREAM_FLPOLICY_FOOTPRINT, 0);
            }
            if (reassembly_direction & SSN_DIR_SERVER)
            {
                FlushMgr *flush_mgr = &s5TcpPolicy->flush_config_protocol[app_id].server;
                FlushPointList *flush_point_list = &s5TcpPolicy->flush_point_list;
                InitFlushMgr(flush_mgr, flush_point_list, STREAM_FLPOLICY_FOOTPRINT, 0);
            }
            s5TcpPolicy->flush_config_protocol[app_id].configured = 1;
        }
    }
}

static void Stream5PrintTcpConfig(Stream5TcpPolicy *s5TcpPolicy)
{
    int i=0, j=0;
    LogMessage("Stream5 TCP Policy config:\n");
    LogMessage("    Reassembly Policy: %s\n",
        reassembly_policy_names[s5TcpPolicy->reassembly_policy]);
    LogMessage("    Timeout: %d seconds\n", s5TcpPolicy->session_timeout);
    if (s5TcpPolicy->max_window != 0)
        LogMessage("    Max TCP Window: %u\n", s5TcpPolicy->max_window);
    if (s5TcpPolicy->overlap_limit)
        LogMessage("    Limit on TCP Overlaps: %d\n", s5TcpPolicy->overlap_limit);
    if (s5TcpPolicy->max_queued_bytes != 0)
    {
        LogMessage("    Maximum number of bytes to queue per session: %d\n",
            s5TcpPolicy->max_queued_bytes);
    }
    if (s5TcpPolicy->max_queued_segs != 0)
    {
        LogMessage("    Maximum number of segs to queue per session: %d\n",
            s5TcpPolicy->max_queued_segs);
    }
    if (s5TcpPolicy->flags)
    {
        LogMessage("    Options:\n");
        if (s5TcpPolicy->flags & STREAM5_CONFIG_REQUIRE_3WHS)
        {
            LogMessage("        Require 3-Way Handshake: YES\n");
            if (s5TcpPolicy->hs_timeout != 0)
            {
                LogMessage("        3-Way Handshake Timeout: %d\n",
                    s5TcpPolicy->hs_timeout);
            }
        }
        if (s5TcpPolicy->flags & STREAM5_CONFIG_STATIC_FLUSHPOINTS)
        {
            LogMessage("        Static Flushpoint Sizes: YES\n");
        }
        if (s5TcpPolicy->flags & STREAM5_CONFIG_IGNORE_ANY)
        {
            LogMessage("        Ignore Any -> Any Rules: YES\n");
        }
        if (s5TcpPolicy->flags & STREAM5_CONFIG_NO_ASYNC_REASSEMBLY)
        {
            LogMessage("        Don't queue packets on one-sided sessions: YES\n");
        }
    }
    LogMessage("    Reassembly Ports:\n");
    for (i=0; i<MAX_PORTS; i++)
    {
        int direction = 0;
        int client_flushpolicy = s5TcpPolicy->flush_config[i].client.flush_policy;
        int server_flushpolicy = s5TcpPolicy->flush_config[i].server.flush_policy;
        char client_policy_str[STD_BUF];
        char server_policy_str[STD_BUF];
        client_policy_str[0] = server_policy_str[0] = '\0';

        if (client_flushpolicy != STREAM_FLPOLICY_IGNORE)
        {
            direction |= SSN_DIR_CLIENT;

            if (client_flushpolicy < STREAM_FLPOLICY_MAX)
                SnortSnprintf(client_policy_str, STD_BUF, "client (%s)",
                              flush_policy_names[client_flushpolicy]);
        }
        if (server_flushpolicy != STREAM_FLPOLICY_IGNORE)
        {
            direction |= SSN_DIR_SERVER;

            if (server_flushpolicy < STREAM_FLPOLICY_MAX)
                SnortSnprintf(server_policy_str, STD_BUF, "server (%s)",
                              flush_policy_names[server_flushpolicy]);
        }
        if (direction)
        {
            if (j<MAX_PORTS_TO_PRINT)
            {
                LogMessage("      %d %s %s\n", i,
                    client_policy_str, server_policy_str);
            }
            j++;
        }
    }

    if (j > MAX_PORTS_TO_PRINT)
    {
        LogMessage("      additional ports configured but not printed.\n");
    }

#ifdef REG_TEST
    LogMessage("    TCP Session Size: %lu\n",sizeof(TcpSession));
#endif
}

int StreamPolicyIdFromHostAttributeEntry(HostAttributeEntry *host_entry)
{
    if (!host_entry)
        return 0;

    host_entry->hostInfo.streamPolicy = StreamPolicyIdFromName(host_entry->hostInfo.streamPolicyName);
    host_entry->hostInfo.streamPolicySet = 1;

    STREAM5_DEBUG_WRAP(
        DebugMessage(DEBUG_STREAM_STATE,
            "STREAM5 INIT: %s(%d) for Entry %s\n",
            reassembly_policy_names[host_entry->hostInfo.streamPolicy],
            host_entry->hostInfo.streamPolicy,
            host_entry->hostInfo.streamPolicyName););
    return 0;
}

/**
 * Stream5VerifyTcpConfig is is called after all preprocs (static & dynamic)
 * are inited.
 */
int Stream5VerifyTcpConfig(SnortConfig*, Stream5TcpConfig *config)
{
    if (config == NULL)
        return -1;

    if ( !config->policy )
    {
        LogMessage("WARNING: Stream5 TCP default policy not specified in configuration.\n");
        return -1;
    }

    SFAT_SetPolicyIds(StreamPolicyIdFromHostAttributeEntry);

    return 0;
}

void Stream5ResetTcpInstance(Stream5TcpConfig* pc)
{
    ResetFlushMgrsPolicy(pc);
}

void Stream5TcpConfigFree(Stream5TcpConfig *config)
{
    if (config == NULL)
        return;

    {
        Stream5TcpPolicy *policy = config->policy;

        free(policy->flush_point_list.flush_points);
        free(policy);
    }

    if ( config->paf_config )
        s5_paf_delete(config->paf_config);

    free(config);
}

#ifdef DEBUG_STREAM5
static void PrintStateMgr(StateMgr *s)
{
    LogMessage("StateMgr:\n");
    LogMessage("    state:          %s\n", state_names[s->state]);
    LogMessage("    state_queue:    %s\n", state_names[s->state_queue]);
    LogMessage("    expected_flags: 0x%X\n", s->expected_flags);
    LogMessage("    transition_seq: 0x%X\n", s->transition_seq);
    LogMessage("    stq_get_seq:    %d\n", s->stq_get_seq);
}

static void PrintStreamTracker(StreamTracker *s)
{
    LogMessage(" + StreamTracker +\n");
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

static void PrintTcpSession(TcpSession *ts)
{
    char buf[64];

    LogMessage("TcpSession:\n");
    sfip_ntop(&ts->tcp_server_ip, buf, sizeof(buf));
    LogMessage("    server IP:          %s\n", buf);
    sfip_ntop(&ts->tcp_client_ip, buf, sizeof(buf));
    LogMessage("    client IP:          %s\n", buf);

    LogMessage("    server port:        %d\n", ts->tcp_server_port);
    LogMessage("    client port:        %d\n", ts->tcp_client_port);

    LogMessage("    flags:              0x%X\n", ts->flow->s5_state.session_flags);

    LogMessage("Client Tracker:\n");
    PrintStreamTracker(&ts->client);
    LogMessage("Server Tracker:\n");
    PrintStreamTracker(&ts->server);
}

static void PrintTcpDataBlock(TcpDataBlock *tdb)
{
    LogMessage("TcpDataBlock:\n");
    LogMessage("    seq:    0x%08X\n", tdb->seq);
    LogMessage("    ack:    0x%08X\n", tdb->ack);
    LogMessage("    win:    %d\n", tdb->win);
    LogMessage("    end:    0x%08X\n", tdb->end_seq);
}

#ifdef DEBUG_STREAM5
static void PrintFlushMgr(FlushMgr *fm)
{
    if(fm == NULL)
        return;

    switch(fm->flush_policy)
    {
        case STREAM_FLPOLICY_NONE:
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "    NONE\n"););
            break;
        case STREAM_FLPOLICY_FOOTPRINT:
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "    FOOTPRINT %d\n", fm->flush_pt););
            break;
        case STREAM_FLPOLICY_LOGICAL:
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "    LOGICAL %d\n", fm->flush_pt););
            break;
        case STREAM_FLPOLICY_RESPONSE:
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "    RESPONSE\n"););
            break;
        case STREAM_FLPOLICY_SLIDING_WINDOW:
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "    SLIDING_WINDOW %d\n", fm->flush_pt););
            break;
#if 0
        case STREAM_FLPOLICY_CONSUMED:
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "          CONSUMED %d\n", fm->flush_pt););
            break;
#endif
        case STREAM_FLPOLICY_IGNORE:
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "    IGNORE\n"););
            break;

        case STREAM_FLPOLICY_PROTOCOL:
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "    PROTOCOL\n"););
            break;
    }
}
#endif  // DEBUG
#endif  // DEBUG_STREAM5

static inline void Discard ()
{
    ssnStats.discards++;
}

static inline void EventSynOnEst(Stream5TcpPolicy*)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_SYN_ON_EST);
    ssnStats.events++;
}

static inline void EventExcessiveOverlap(Stream5TcpPolicy*)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_EXCESSIVE_TCP_OVERLAPS);
    ssnStats.events++;
}

static inline void EventBadTimestamp(Stream5TcpPolicy*)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_BAD_TIMESTAMP);
    ssnStats.events++;
}

static inline void EventWindowTooLarge(Stream5TcpPolicy*)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_WINDOW_TOO_LARGE);
    ssnStats.events++;
}

static inline void EventDataOnSyn(Stream5TcpPolicy*)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_DATA_ON_SYN);
    ssnStats.events++;
}

static inline void EventDataOnClosed(Stream5TcpPolicy*)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_DATA_ON_CLOSED);
    ssnStats.events++;
}

static inline void EventDataAfterReset(Stream5TcpPolicy*)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_DATA_AFTER_RESET);
    ssnStats.events++;
}

static inline void EventBadSegment(Stream5TcpPolicy*)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_BAD_SEGMENT);
    ssnStats.events++;
}

static inline void EventSessionHijackedClient(Stream5TcpPolicy*)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_SESSION_HIJACKED_CLIENT);
    ssnStats.events++;
}
static inline void EventSessionHijackedServer(Stream5TcpPolicy*)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_SESSION_HIJACKED_SERVER);
    ssnStats.events++;
}

static inline void EventDataWithoutFlags(Stream5TcpPolicy*)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_DATA_WITHOUT_FLAGS);
    ssnStats.events++;
}

static inline void EventMaxSmallSegsExceeded(Stream5TcpPolicy*)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_SMALL_SEGMENT);
    ssnStats.events++;
}

static inline void Event4whs(Stream5TcpPolicy*)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_4WAY_HANDSHAKE);
    ssnStats.events++;
}

static inline void EventNoTimestamp(Stream5TcpPolicy*)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_NO_TIMESTAMP);
    ssnStats.events++;
}

static inline void EventBadReset(Stream5TcpPolicy*)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_BAD_RST);
    ssnStats.events++;
}

static inline void EventBadFin(Stream5TcpPolicy*)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_BAD_FIN);
    ssnStats.events++;
}

static inline void EventBadAck(Stream5TcpPolicy*)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_BAD_ACK);
    ssnStats.events++;
}

static inline void EventDataAfterRstRcvd(Stream5TcpPolicy*)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_DATA_AFTER_RST_RCVD);
    ssnStats.events++;
}

static inline void EventInternal (uint32_t eventSid)
{
    if ( !InternalEventIsEnabled(snort_conf->rate_filter_config, eventSid) )
        return;

    tcpStats.internalEvents++;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "Stream5 raised internal event %d\n", eventSid););

    SnortEventqAdd(GENERATOR_INTERNAL, eventSid);
}

static inline void EventWindowSlam (Stream5TcpPolicy*)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_WINDOW_SLAM);
    ssnStats.events++;
}

static inline void EventNo3whs (Stream5TcpPolicy*)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_NO_3WHS);
    ssnStats.events++;
}

/*
 *  Utility functions for TCP stuff
 */
typedef enum {
    PC_TCP_TRIM,
    PC_TCP_ECN_SSN,
    PC_TCP_TS_NOP,
    PC_TCP_IPS_DATA,
    PC_TCP_BLOCK,
    PC_MAX
} PegCounts;

static PegCount gnormStats[PC_MAX];
static THREAD_LOCAL PegCount normStats[PC_MAX];

static const char* pegName[PC_MAX] = {
    "tcp::trim",
    "tcp::ecn_ssn",
    "tcp::ts_nop",
    "tcp::ips_data",
    "tcp::block",
};

void Stream_SumNormalizationStats()
{
    sum_stats((PegCount*)&gnormStats, (PegCount*)&normStats, array_size(pegName));
}

void Stream_PrintNormalizationStats (void)
{
    show_stats((PegCount*)&gnormStats, pegName, PC_MAX);
}

void Stream_ResetNormalizationStats (void)
{
    memset(gnormStats, 0, sizeof(gnormStats));
}

//-----------------------------------------------------------------------
// instead of centralizing all these normalizations so that
// Normalize_IsEnabled() is called only once, the checks and
// normalizations are localized.  this should lead to many
// fewer total checks.  however, it is best to minimize
// configuration checks on a per packet basis so there is
// still room for improvement.
static inline void NormalDropPacket (Packet*)
{
    Active_DropPacket();
}

static inline int NormalDropPacketIf (Packet* p, NormFlags f)
{
    if ( Normalize_IsEnabled(snort_conf, f) )
    {
        NormalDropPacket(p);
        normStats[PC_TCP_BLOCK]++;
        sfBase.iPegs[PERF_COUNT_TCP_BLOCK]++;
        return 1;
    }
    return 0;
}

static inline void NormalStripTimeStamp (Packet* p, int i)
{
    uint8_t* opt;

    if ( i < 0 )
    {
        for ( i = 0; i < p->tcp_option_count; i++ )
        {
            if ( p->tcp_options[i].code == TCPOPT_TIMESTAMP )
                break;
        }
        if ( i == p->tcp_option_count )
            return;
    }
    // first set raw option bytes to nops
    opt = (uint8_t*)p->tcp_options[i].data - 2;
    memset(opt, TCPOPT_NOP, TCPOLEN_TIMESTAMP);

    // then nop decoded option code only
    p->tcp_options[i].code = TCPOPT_NOP;

    p->packet_flags |= PKT_MODIFIED;
    normStats[PC_TCP_TS_NOP]++;
    sfBase.iPegs[PERF_COUNT_TCP_TS_NOP]++;
}

static inline void NormalTrimPayload (
    Packet* p, uint16_t max, TcpDataBlock* tdb
) {
    if ( p->dsize > max )
    {
        uint16_t fat = p->dsize - max;
        p->dsize = max;
        p->packet_flags |= (PKT_MODIFIED|PKT_RESIZED);
        tdb->end_seq -= fat;
        normStats[PC_TCP_TRIM]++;
        sfBase.iPegs[PERF_COUNT_TCP_TRIM]++;
    }
}

static inline int NormalTrimPayloadIf (
    Packet* p, NormFlags f, uint16_t max, TcpDataBlock* tdb
) {
    if (
        Normalize_IsEnabled(snort_conf, f) &&
        p->dsize > max )
    {
        NormalTrimPayload(p, max, tdb);
        return 1;
    }
    return 0;
}

static inline void NormalTrackECN (TcpSession* s, TCPHdr* tcph, int req3way)
{
    if ( !s )
        return;

    if ( TCP_ISFLAGSET(tcph, TH_SYN|TH_ACK) )
    {
        if ( !req3way || s->ecn )
            s->ecn = ((tcph->th_flags & (TH_ECE|TH_CWR)) == TH_ECE);
    }
    else if ( TCP_ISFLAGSET(tcph, TH_SYN) )
        s->ecn = TCP_ISFLAGSET(tcph, (TH_ECE|TH_CWR));
}

static inline void NormalCheckECN (TcpSession* s, Packet* p)
{
    if ( !s->ecn && (p->tcph->th_flags & (TH_ECE|TH_CWR)) )
    {
        ((TCPHdr*)p->tcph)->th_flags &= ~(TH_ECE|TH_CWR);
        p->packet_flags |= PKT_MODIFIED;
        normStats[PC_TCP_ECN_SSN]++;
        sfBase.iPegs[PERF_COUNT_TCP_ECN_SSN]++;
    }
}

//-------------------------------------------------------------------------
// ssn ingress is client; ssn egress is server

#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
static inline void SetPacketHeaderFoo (TcpSession* tcpssn, const Packet* p)
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

static inline void GetPacketHeaderFoo (
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
    pkth->flags = tcpssn->daq_flags;
    pkth->address_space_id = tcpssn->address_space_id;
}

static inline void SwapPacketHeaderFoo (TcpSession* tcpssn)
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
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "(%X, %X, %X) = (low, high, cur)\n", low,high,cur););

    /* If we haven't seen anything, ie, low & high are 0, return true */
    if ((low == 0) && (low == high))
        return 1;

    return (SEQ_GEQ(cur, low) && SEQ_LEQ(cur, high));
}

#define SSNFLAG_SEEN_BOTH (SSNFLAG_SEEN_SERVER | SSNFLAG_SEEN_CLIENT)
static inline bool TwoWayTraffic (Flow* lwssn)
{
    return ( (lwssn->s5_state.session_flags & SSNFLAG_SEEN_BOTH) == SSNFLAG_SEEN_BOTH );
}

static inline uint32_t Stream5GetWindow(
    Flow* lwssn, StreamTracker* st, TcpDataBlock* tdb)
{
    int32_t window;

    if ( st->l_window )
    {
        // don't use the window if we may have missed scaling
        if ( !(lwssn->session_state & STREAM5_STATE_MIDSTREAM) )
            return st->l_window;
    }
    // one way zero window is unitialized
    // two way zero window is actually closed (regardless of scaling)
    else if ( TwoWayTraffic(lwssn) )
        return st->l_window;

    // ensure the data is in the window
    window = tdb->end_seq - st->r_win_base;

    if ( window <  0 )
        window = 0;

    return (uint32_t)window;
}

// ack number must ack syn
static inline int ValidRstSynSent(StreamTracker *st, TcpDataBlock *tdb)
{
    return tdb->ack == st->l_unackd;
}

// per rfc 793 a rst is valid if the seq number is in window
// for all states but syn-sent (handled above).  however, we
// validate here based on how various implementations actually
// handle a rst.
static inline int ValidRst(
    Flow* lwssn, StreamTracker *st, TcpDataBlock *tdb)
{
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Checking end_seq (%X) > r_win_base (%X) && "
                "seq (%X) < r_nxt_ack(%X)\n",
                tdb->end_seq, st->r_win_base, tdb->seq,
                st->r_nxt_ack+Stream5GetWindow(lwssn, st, tdb)););

    switch (st->os_policy)
    {
        case STREAM_POLICY_HPUX11:
            if (SEQ_GEQ(tdb->seq, st->r_nxt_ack))
            {
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "rst is valid seq (>= next seq)!\n"););
                return 1;
            }
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "rst is not valid seq (>= next seq)!\n"););
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
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "rst is valid seq (next seq)!\n"););
                return 1;
            }
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "rst is not valid seq (next seq)!\n"););
            return 0;
            break;
        case STREAM_POLICY_BSD:
        case STREAM_POLICY_LINUX:
        case STREAM_POLICY_OLD_LINUX:
        case STREAM_POLICY_SOLARIS:
            if(SEQ_GEQ(tdb->end_seq, st->r_win_base))
            {
                // reset must be admitted when window closed
                if ( SEQ_LEQ(tdb->seq, st->r_win_base+Stream5GetWindow(lwssn, st, tdb)) )
                {
                    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "rst is valid seq (within window)!\n"););
                    return 1;
                }
            }

            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "rst is not valid seq (within window)!\n"););
            return 0;
            break;
    }

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "rst is not valid!\n"););
    return 0;
}

static inline int ValidTimestamp(StreamTracker *talker,
                                 StreamTracker *listener,
                                 TcpDataBlock *tdb,
                                 Packet *p,
                                 int *eventcode,
                                 int *got_ts)
{
    if(p->tcph->th_flags & TH_RST)
        return ACTION_NOTHING;

#if 0
    if ( p->tcph->th_flags & TH_ACK &&
        Normalize_IsEnabled(snort_conf, NORM_TCP_OPT) )
    {
        // FIXTHIS validate tsecr here (check that it was previously sent)
        // checking for the most recent ts is easy enough must check if
        // ts are up to date in retransmitted packets
    }
#endif
    /*
     * check PAWS
     */
    if((talker->flags & TF_TSTAMP) && (listener->flags & TF_TSTAMP))
    {
        char validate_timestamp = 1;
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Checking timestamps for PAWS\n"););

        *got_ts = Stream5GetTcpTimestamp(p, &tdb->ts, 0);

        if (*got_ts)
        {
            if (listener->tcp_policy->policy == STREAM_POLICY_HPUX11)
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
                if ((listener->tcp_policy->policy == STREAM_POLICY_LINUX) ||
                    (listener->tcp_policy->policy == STREAM_POLICY_WINDOWS2K3))
                {
                    /* Linux, Win2k3 et al.  do not support timestamps if
                     * the 3whs used a 0 timestamp. */
                    talker->flags &= ~TF_TSTAMP;
                    listener->flags &= ~TF_TSTAMP;
                    validate_timestamp = 0;
                }
                else if ((listener->tcp_policy->policy == STREAM_POLICY_OLD_LINUX) ||
                         (listener->tcp_policy->policy == STREAM_POLICY_WINDOWS) ||
                         (listener->tcp_policy->policy == STREAM_POLICY_VISTA))
                {
                    /* Older Linux (2.2 kernel & earlier), Win32 (non 2K3)
                     * allow the 3whs to use a 0 timestamp. */
                    talker->flags &= ~TF_TSTAMP_ZERO;
                    if(SEQ_EQ(listener->r_nxt_ack, tdb->seq))
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
                if (listener->tcp_policy->policy == STREAM_POLICY_LINUX)
                {
                    /* Linux 2.6 accepts timestamp values that are off
                     * by one. */
                    result = (int)((tdb->ts - talker->ts_last) + 1);
                }
                else
                {
                    result = (int)(tdb->ts - talker->ts_last);
                }

                if(result < 0)
                {
                    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                                "Packet outside PAWS window, dropping\n"););
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
                    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                                "packet PAWS timestamp way too far ahead of"
                                "last packet %d %d...\n", p->pkth->ts.tv_sec,
                                talker->ts_last_pkt););
                    //Discard();
                    *eventcode |= EVENT_BAD_TIMESTAMP;
                    NormalDropPacketIf(p, NORM_TCP_OPT);
                    return ACTION_BAD_PKT;
                }
                else
                {
                    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                                "packet PAWS ok...\n"););
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
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "packet no timestamp, had one earlier from this side...ok for now...\n"););

            if (listener->tcp_policy->policy == STREAM_POLICY_SOLARIS)
            {
                /* Solaris stops using timestamps if it receives a packet
                 * without a timestamp and there were timestamps in use.
                 */
                listener->flags &= ~TF_TSTAMP;
            }
            NormalDropPacketIf(p, NORM_TCP_OPT);
        }
    }
    else if ( TCP_ISFLAGSET(p->tcph, TH_SYN) &&
             !TCP_ISFLAGSET(p->tcph, TH_ACK) )
    {
        *got_ts = Stream5GetTcpTimestamp(p, &tdb->ts, 0);
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
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "listener not doing timestamps...\n"););
        *got_ts = Stream5GetTcpTimestamp(p, &tdb->ts, strip);

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
                    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                                "Packet with 0 timestamp, dropping\n"););
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
    const Packet* p, Flow* lwssn, StreamTracker *st, TcpDataBlock *tdb)
{
    uint32_t win = Stream5GetWindow(lwssn, st, tdb);

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
    const Packet* p, Flow* lwssn, StreamTracker *st, TcpDataBlock *tdb)
{
    int right_ok;
    uint32_t left_seq;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Checking end_seq (%X) > r_win_base (%X) && "
                "seq (%X) < r_nxt_ack(%X)\n",
                tdb->end_seq, st->r_win_base, tdb->seq,
                st->r_nxt_ack+Stream5GetWindow(lwssn, st, tdb)););

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
        uint32_t win = Stream5GetWindow(lwssn, st, tdb);

        if( SEQ_LEQ(tdb->seq, st->r_win_base+win) )
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "seq is within window!\n"););
            return 1;
        }
        else
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "seq is past the end of the window!\n"););
        }
    }
    else
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "end_seq is before win_base\n"););
    }
    return 0;
}
#endif

static inline void UpdateSsn(
    Packet*, StreamTracker *rcv, StreamTracker *snd, TcpDataBlock *tdb)
{
#if 0
    if (
         // FIXTHIS these checks are a hack to avoid off by one normalization
         // due to FIN ... if last segment filled a hole, r_nxt_ack is not at
         // end of data, FIN is ignored so sequence isn't bumped, and this
         // forces seq-- on ACK of FIN.  :(
         rcv->s_mgr.state == TCP_STATE_ESTABLISHED &&
         rcv->s_mgr.state_queue == TCP_STATE_NONE &&
         Normalize_IsEnabled(snort_conf, NORM_TCP_IPS) )
    {
        // walk the seglist until a gap or tdb->ack whichever is first
        // if a gap exists prior to ack, move ack back to start of gap
        StreamSegment* seg = snd->seglist;

        // FIXTHIS must check ack oob with empty seglist
        // FIXTHIS add lower gap bound to tracker for efficiency?
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
                ((TCPHdr*)p->tcph)->th_ack = htonl(seq);
                p->packet_flags |= PKT_MODIFIED;
                break;
            }
        }
    }
#endif
    // ** if we don't see a segment, we can't track seq at ** below
    // so we update the seq by the ack if it is beyond next expected
    if(SEQ_GT(tdb->ack, rcv->l_unackd))
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

void tcp_sinit(Stream5Config* s5)
{
    s5_pkt = Encode_New();

    if ( !s5->global_config->tcp_mem_cap )
        s5->global_config->tcp_mem_cap = S5_DEFAULT_MEMCAP;

    tcp_memcap = new Memcap(s5->global_config->tcp_mem_cap);
}

void tcp_sterm()
{
    if (s5_pkt)
    {
        Encode_Delete(s5_pkt);
        s5_pkt = NULL;
    }
    delete tcp_memcap;
    tcp_memcap = nullptr;
}

static inline void SetupTcpDataBlock(TcpDataBlock *tdb, Packet *p)
{
    tdb->seq = ntohl(p->tcph->th_seq);
    tdb->ack = ntohl(p->tcph->th_ack);
    tdb->win = ntohs(p->tcph->th_win);
    tdb->end_seq = tdb->seq + (uint32_t) p->dsize;
    tdb->ts = 0;

    if(p->tcph->th_flags & TH_SYN)
    {
        tdb->end_seq++;
        if(!(p->tcph->th_flags & TH_ACK))
            EventInternal(INTERNAL_EVENT_SYN_RECEIVED);
    }
    // don't bump end_seq for fin here
    // we will bump if/when fin is processed


#ifdef DEBUG_STREAM5
    PrintTcpDataBlock(&tdb);
#endif
}

static void SegmentFree (StreamSegment *seg)
{
    unsigned dropped = sizeof(StreamSegment);

    STREAM5_DEBUG_WRAP( DebugMessage(DEBUG_STREAM_STATE,
        "Dumping segment at seq %X, size %d, caplen %d\n",
        seg->seq, seg->size, seg->caplen););

    if ( seg->caplen > 0 )
        dropped += seg->caplen - 1;  // seg contains 1st byte

    tcp_memcap->dealloc(dropped);
    free(seg);
    tcpStats.streamsegs_released++;

    STREAM5_DEBUG_WRAP( DebugMessage(DEBUG_STREAM_STATE,
        "SegmentFree dropped %d bytes\n", dropped););
}

static void DeleteSeglist(StreamSegment *listhead)
{
    StreamSegment *idx = listhead;
    StreamSegment *dump_me;
    int i = 0;

    STREAM5_DEBUG_WRAP( DebugMessage(DEBUG_STREAM_STATE,
                "In DeleteSeglist\n"););
    while(idx)
    {
        i++;
        dump_me = idx;
        idx = idx->next;
        SegmentFree(dump_me);
    }

    STREAM5_DEBUG_WRAP( DebugMessage(DEBUG_STREAM_STATE,
                "Dropped %d segments\n", i););
}

static inline int purge_alerts(
    StreamTracker *st, uint32_t flush_seq, Flow* flow)
{
    int i;
    int new_count = 0;

    for (i=0;i<st->alert_count;i++)
    {
        Stream5AlertInfo* ai = st->alerts + i;

        if (SEQ_LT(ai->seq, flush_seq) )
        {
            stream.log_extra_data(
                flow, st->xtradata_mask, ai->event_id, ai->event_second);

            memset(ai, 0, sizeof(*ai));
        }
        else
        {
            if (new_count != i)
            {
                st->alerts[new_count] = st->alerts[i];
            }
            new_count++;
        }
    }
    st->alert_count = new_count;

    return new_count;
}

static inline int purge_to_seq(TcpSession *tcpssn, StreamTracker *st, uint32_t flush_seq)
{
    StreamSegment *ss = NULL;
    StreamSegment *dump_me = NULL;
    int purged_bytes = 0;
    uint32_t last_ts = 0;

    if(st->seglist == NULL)
    {
        if ( SEQ_LT(st->seglist_base_seq, flush_seq) )
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "setting st->seglist_base_seq to 0x%X\n", flush_seq););
            st->seglist_base_seq = flush_seq;
        }
        return 0;
    }

    ss = st->seglist;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "In purge_to_seq, start seq = 0x%X end seq = 0x%X delta %d\n",
                ss->seq, flush_seq, flush_seq-ss->seq););
    while(ss)
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "s: %X  sz: %d\n", ss->seq, ss->size););
        dump_me = ss;

        ss = ss->next;
        if(SEQ_LT(dump_me->seq, flush_seq))
        {
            if (dump_me->ts > last_ts)
            {
                last_ts = dump_me->ts;
            }
            purged_bytes += Stream5SeglistDeleteNodeTrim(st, dump_me, flush_seq);
        }
        else
            break;
    }

    if ( SEQ_LT(st->seglist_base_seq, flush_seq) )
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "setting st->seglist_base_seq to 0x%X\n", flush_seq););
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

static inline void purge_all (StreamTracker *st)
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
// * FIXTHIS need flag to mark any reassembled packets that have a gap
//   (if we reassemble such)
static inline int purge_flushed_ackd (TcpSession *tcpssn, StreamTracker *st)
{
    StreamSegment* seg = st->seglist;
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

static void ShowRebuiltPacket (TcpSession* ssn, Packet* pkt)
{
    if ( ssn->flow->s5_config->global_config->flags & STREAM5_CONFIG_SHOW_PACKETS )
        LogIPPkt(IPPROTO_TCP, pkt);
}

static inline int _flush_to_seq (

    TcpSession *tcpssn, StreamTracker *st, uint32_t bytes, Packet *p,
    snort_ip_p sip, snort_ip_p, uint16_t, uint16_t, uint32_t dir)
{
    uint32_t stop_seq;
    uint32_t footprint = 0;
    uint32_t bytes_processed = 0;
    int32_t flushed_bytes;
#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
    DAQ_PktHdr_t pkth;
#endif
    EncodeFlags enc_flags = 0;
    PROFILE_VARS;

    PREPROC_PROFILE_START(s5TcpFlushPerfStats);

    if ( !p->packet_flags || (dir & p->packet_flags) )
        enc_flags = ENC_FLAG_FWD;

#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
    GetPacketHeaderFoo(tcpssn, &pkth, dir);
    Encode_Format_With_DAQ_Info(enc_flags, p, s5_pkt, PSEUDO_PKT_TCP, &pkth, 0);
#elif defined(HAVE_DAQ_ACQUIRE_WITH_META)
    Encode_Format_With_DAQ_Info(enc_flags, p, s5_pkt, PSEUDO_PKT_TCP, 0);
#else
    Encode_Format(enc_flags, p, s5_pkt, PSEUDO_PKT_TCP);
#endif

    // TBD in ips mode, these should be coming from current packet (tdb)
    ((TCPHdr *)s5_pkt->tcph)->th_ack = htonl(st->l_unackd);
    ((TCPHdr *)s5_pkt->tcph)->th_win = htons((uint16_t)st->l_window);

    // if not specified, set bytes to flush to what was acked
    if ( !bytes && SEQ_GT(st->r_win_base, st->seglist_base_seq) )
        bytes = st->r_win_base - st->seglist_base_seq;

    stop_seq = st->seglist_base_seq + bytes;

    do
    {
        footprint = stop_seq - st->seglist_base_seq;

        if(footprint == 0)
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "Negative footprint, bailing %d (0x%X - 0x%X)\n",
                        footprint, stop_seq, st->seglist_base_seq););
            PREPROC_PROFILE_END(s5TcpFlushPerfStats);

            return bytes_processed;
        }

#ifdef DEBUG_STREAM5
        if(footprint < st->seg_bytes_logical)
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "Footprint less than queued bytes, "
                        "win_base: 0x%X base_seq: 0x%X\n",
                        stop_seq, st->seglist_base_seq););
        }
#endif

        if(footprint > s5_pkt->max_dsize)
        {
            /* this is as much as we can pack into a stream buffer */
            footprint = s5_pkt->max_dsize;
            stop_seq = st->seglist_base_seq + footprint;
        }

        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Attempting to flush %lu bytes\n", footprint););

        /* setup the pseudopacket payload */
        const uint8_t* s5_pkt_end = s5_pkt->data + s5_pkt->max_dsize;
        flushed_bytes = FlushStream(p, st, stop_seq, (uint8_t *)s5_pkt->data, s5_pkt_end);

        if(flushed_bytes == -1)
        {
            /* couldn't put a stream together for whatever reason
             * should probably clean the seglist and bail...
             */
            if(st->seglist)
            {
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "dumping entire seglist!\n"););
                purge_all(st);
            }

            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "setting st->seglist_base_seq to 0x%X\n", stop_seq););
            st->seglist_base_seq = stop_seq;

            PREPROC_PROFILE_END(s5TcpFlushPerfStats);
            return bytes_processed;
        }

        if (flushed_bytes == 0)
        {
            /* No more ACK'd data... bail */
            break;
        }

        ((TCPHdr *)s5_pkt->tcph)->th_seq = htonl(st->seglist_next->seq);
        s5_pkt->packet_flags |= (PKT_REBUILT_STREAM|PKT_STREAM_EST);
        s5_pkt->dsize = (uint16_t)flushed_bytes;

        if ((p->packet_flags & PKT_PDU_TAIL))
            s5_pkt->packet_flags |= PKT_PDU_TAIL;

        Encode_Update(s5_pkt);

        if(sfip_family(sip) == AF_INET)
        {
            s5_pkt->inner_ip4h.ip_len = s5_pkt->iph->ip_len;
        }
        else
        {
            IP6RawHdr* ip6h = (IP6RawHdr*)s5_pkt->raw_ip6h;
            if ( ip6h ) s5_pkt->inner_ip6h.len = ip6h->ip6plen;
        }

        ((DAQ_PktHdr_t*)s5_pkt->pkth)->ts.tv_sec = st->seglist_next->tv.tv_sec;
        ((DAQ_PktHdr_t*)s5_pkt->pkth)->ts.tv_usec = st->seglist_next->tv.tv_usec;

        sfBase.iStreamFlushes++;
        bytes_processed += s5_pkt->dsize;

        s5_pkt->packet_flags |= dir;
        s5_pkt->flow = tcpssn->flow;
        s5_pkt->application_protocol_ordinal = p->application_protocol_ordinal;

        ShowRebuiltPacket(tcpssn, s5_pkt);
        tcpStats.rebuilt_packets++;
        UpdateStreamReassStats(&sfBase, flushed_bytes);

        PREPROC_PROFILE_TMPEND(s5TcpFlushPerfStats);
        {
            PROFILE_VARS;
            PREPROC_PROFILE_START(s5TcpProcessRebuiltPerfStats);

            DetectRebuiltPacket(s5_pkt);

            PREPROC_PROFILE_END(s5TcpProcessRebuiltPerfStats);
        }
        PREPROC_PROFILE_TMPSTART(s5TcpFlushPerfStats);

        // TBD abort should be by PAF callback only since
        // recovery may be possible in some cases
    } while ( !(st->flags & TF_MISSING_PKT) && DataToFlush(st) );

    if ( st->tcp_policy )
        UpdateFlushMgr(&st->flush_mgr, &st->tcp_policy->flush_point_list, st->flags);

    /* tell them how many bytes we processed */
    PREPROC_PROFILE_END(s5TcpFlushPerfStats);
    return bytes_processed;
}

/*
 * flush a seglist up to the given point, generate a pseudopacket,
 * and fire it thru the system.
 */
static inline int flush_to_seq(
    TcpSession *tcpssn, StreamTracker *st, uint32_t bytes, Packet *p,
    snort_ip_p sip, snort_ip_p dip, uint16_t sp, uint16_t dp, uint32_t dir)
{
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "In flush_to_seq()\n"););

    if ( !bytes )
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "bailing, no data\n"););
        return 0;
    }

    if ( !st->seglist_next )
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "bailing, bad seglist ptr\n"););
        return 0;
    }

    if (!DataToFlush(st) && !(st->flags & TF_FORCE_FLUSH))
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "only 1 packet in seglist no need to flush\n"););
        return 0;
    }

    st->flags &= ~TF_MISSING_PKT;
    st->flags &= ~TF_MISSING_PREV_PKT;

    /* This will set this flag on the first reassembly
     * if reassembly for this direction was set midstream */
    if ( SEQ_LT(st->seglist_base_seq, st->seglist_next->seq) )
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

    return _flush_to_seq(tcpssn, st, bytes, p, sip, dip, sp, dp, dir);

}

/*
 * get the footprint for the current seglist, the difference
 * between our base sequence and the last ack'd sequence we
 * received
 */
static inline uint32_t get_q_footprint(StreamTracker *st)
{
    uint32_t fp;

    if (st == NULL)
    {
        return 0;
    }

    fp = st->r_win_base - st->seglist_base_seq;

    if(fp <= 0)
        return 0;

    st->seglist_next = st->seglist;
    return fp;
}

// FIXTHIS get_q_sequenced() performance could possibly be
// boosted by tracking sequenced bytes as seglist is updated
// to avoid the while loop, etc. below.
static inline uint32_t get_q_sequenced(StreamTracker *st)
{
    uint32_t len;
    StreamSegment* seg = st ? st->seglist : NULL;
    StreamSegment* base = NULL;

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

static inline int flush_ackd(
    TcpSession *tcpssn, StreamTracker *st, Packet *p,
    snort_ip_p sip, snort_ip_p dip, uint16_t sp, uint16_t dp, uint32_t dir)
{
    uint32_t bytes = get_q_footprint(st);
    return flush_to_seq(tcpssn, st, bytes, p, sip, dip, sp, dp, dir);
}

// FIXTHIS flush_stream() calls should be replaced with calls to
// CheckFlushPolicyOn*() with the exception that for the *OnAck() case,
// any available ackd data must be flushed in both directions.
static inline int flush_stream(
    TcpSession *tcpssn, StreamTracker *st, Packet *p,
    snort_ip_p sip, snort_ip_p dip, uint16_t sp, uint16_t dp, uint32_t dir)
{
    if ( Normalize_IsEnabled(snort_conf, NORM_TCP_IPS) )
    {
        uint32_t bytes = get_q_sequenced(st);
        return flush_to_seq(tcpssn, st, bytes, p, sip, dip, sp, dp, dir);
    }
    return flush_ackd(tcpssn, st, p, sip, dip, sp, dp, dir);
}

static inline unsigned int getSegmentFlushSize(
        StreamTracker* st,
        StreamSegment *ss,
        uint32_t to_seq,
        unsigned int flushBufSize
        )
{
    unsigned int flushSize = ss->size;

    //copy only till flush buffer gets full
    if ( flushSize > flushBufSize )
        flushSize = flushBufSize;

    // copy only to flush point
    if ( s5_paf_active(&st->paf_state) && SEQ_GT(ss->seq + flushSize, to_seq) )
        flushSize = to_seq - ss->seq;

    return flushSize;
}

/*
 * flush the client seglist up to the most recently acked segment
 */
static int FlushStream(
    Packet*, StreamTracker *st, uint32_t toSeq, uint8_t *flushbuf,
    const uint8_t *flushbuf_end)
{
    StreamSegment *ss = NULL, *seglist, *sr;
    uint16_t bytes_flushed = 0;
    uint16_t bytes_skipped = 0;
    uint32_t bytes_queued = st->seg_bytes_logical;
    uint32_t segs = 0;
    int ret;
    PROFILE_VARS;

    if ( st->seglist == NULL || st->seglist_tail == NULL )
        return -1;

    PREPROC_PROFILE_START(s5TcpBuildPacketPerfStats);

    // skip over previously flushed segments
    seglist = st->seglist_next;

    for(ss = seglist; ss && SEQ_LT(ss->seq,  toSeq); ss = ss->next)
    {
        unsigned int flushbuf_size = flushbuf_end - flushbuf;
        unsigned int bytes_to_copy = getSegmentFlushSize(st, ss, toSeq, flushbuf_size);

        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Flushing %u bytes from %X\n", bytes_to_copy, ss->seq));

        if(ss->urg_offset == 1)
        {
            /* if urg_offset is set, seq + urg_offset is seq # of octet
             * in stream following the last urgent octet.  all preceding
             * octets in segment are considered urgent.  this code will
             * skip over the urgent data when flushing.
             */

            unsigned int non_urgent_bytes =
                ss->urg_offset < bytes_to_copy ? (bytes_to_copy - ss->urg_offset) : 0;

            if ( non_urgent_bytes )
            {
                ret = SafeMemcpy(flushbuf, ss->payload+ss->urg_offset,
                          non_urgent_bytes, flushbuf, flushbuf_end);

                if (ret == SAFEMEM_ERROR)
                {
                    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                                "ERROR writing flushbuf attempting to "
                                "write flushbuf out of range!\n"););
                }
                else
                    flushbuf += non_urgent_bytes;

                bytes_skipped += ss->urg_offset;
            }
        }
        else
        {
            ret = SafeMemcpy(flushbuf, ss->payload,
                      bytes_to_copy, flushbuf, flushbuf_end);

            if (ret == SAFEMEM_ERROR)
            {
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "ERROR writing flushbuf attempting to "
                            "write flushbuf out of range!\n"););
            }
            else
                flushbuf += bytes_to_copy;
        }

        if ( bytes_to_copy < ss->size &&
             DupStreamNode(NULL, st, ss, &sr) == STREAM_INSERT_OK )
        {
            ss->size = bytes_to_copy;
            sr->seq += bytes_to_copy;
            sr->size -= bytes_to_copy;
            sr->payload += bytes_to_copy + (ss->payload - ss->data);
        }
        bytes_flushed += bytes_to_copy;
        ss->buffered = SL_BUF_FLUSHED;
        st->flush_count++;
        segs++;

        if ( flushbuf >= flushbuf_end )
            break;

        if ( SEQ_EQ(ss->seq + bytes_to_copy,  toSeq) )
            break;

        /* Check for a gap/missing packet */
        // FIXTHIS PAF should account for missing data and resume
        // scanning at the start of next PDU instead of aborting.
        // FIXTHIS FIN may be in toSeq causing bogus gap counts.
        if ( (ss->next && (ss->seq + ss->size != ss->next->seq)) ||
            (!ss->next && (ss->seq + ss->size < toSeq)))
        {
            st->flags |= TF_MISSING_PKT;
            st->flags |= TF_PKT_MISSED;
            tcpStats.gaps++;
        }
    }

    st->seglist_base_seq = toSeq;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "setting st->seglist_base_seq to 0x%X\n", st->seglist_base_seq););

    bytes_queued -= bytes_flushed;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "flushed %d bytes / %d segs on stream, "
        "skipped %d bytes, %d still queued\n",
        bytes_flushed, segs, bytes_skipped, bytes_queued););

    assert(st->seglist);
    PREPROC_PROFILE_END(s5TcpBuildPacketPerfStats);
    return bytes_flushed - bytes_skipped;
}

int Stream5FlushServer(Packet *p, Flow *lwssn)
{
    int flushed;
    TcpSession* tcpssn = (TcpSession*)lwssn->session;
    StreamTracker *flushTracker = &tcpssn->server;

    flushTracker->flags |= TF_FORCE_FLUSH;

    /* If this is a rebuilt packet, don't flush now because we'll
     * overwrite the packet being processed.
     */
    if (p->packet_flags & PKT_REBUILT_STREAM)
    {
        /* We'll check & clear the TF_FORCE_FLUSH next time through */
        return 0;
    }

    /* Need to convert the addresses to network order */
    flushed = flush_stream(tcpssn, flushTracker, p,
                            &tcpssn->tcp_server_ip,
                            &tcpssn->tcp_client_ip,
                            tcpssn->tcp_server_port,
                            tcpssn->tcp_client_port,
                            PKT_FROM_SERVER);
    if (flushed)
        purge_flushed_ackd(tcpssn, flushTracker);

    flushTracker->flags &= ~TF_FORCE_FLUSH;

    return flushed;
}

int Stream5FlushClient(Packet *p, Flow *lwssn)
{
    int flushed;
    TcpSession* tcpssn = (TcpSession*)lwssn->session;
    StreamTracker *flushTracker = &tcpssn->client;

    flushTracker->flags |= TF_FORCE_FLUSH;

    /* If this is a rebuilt packet, don't flush now because we'll
     * overwrite the packet being processed.
     */
    if (p->packet_flags & PKT_REBUILT_STREAM)
    {
        /* We'll check & clear the TF_FORCE_FLUSH next time through */
        return 0;
    }

    /* Need to convert the addresses to network order */
    flushed = flush_stream(tcpssn, flushTracker, p,
                            &tcpssn->tcp_client_ip,
                            &tcpssn->tcp_server_ip,
                            tcpssn->tcp_client_port,
                            tcpssn->tcp_server_port,
                            PKT_FROM_CLIENT);
    if (flushed)
        purge_flushed_ackd(tcpssn, flushTracker);

    flushTracker->flags &= ~TF_FORCE_FLUSH;

    return flushed;
}

int Stream5FlushListener(Packet *p, Flow *lwssn)
{
    StreamTracker *listener = NULL;
    int dir = 0;
    int flushed = 0;

    TcpSession* tcpssn = (TcpSession*)lwssn->session;

    /* figure out direction of this packet -- we should've already
     * looked at it, so the packet_flags are already set. */
    if(p->packet_flags & PKT_FROM_SERVER)
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Flushing listener on packet from server\n"););
        listener = &tcpssn->client;
        /* dir of flush is the data from the opposite side */
        dir = PKT_FROM_SERVER;
    }
    else if (p->packet_flags & PKT_FROM_CLIENT)
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Flushing listener on packet from client\n"););
        listener = &tcpssn->server;
        /* dir of flush is the data from the opposite side */
        dir = PKT_FROM_CLIENT;
    }

    if (dir != 0)
    {
        listener->flags |= TF_FORCE_FLUSH;
        flushed = flush_stream(tcpssn, listener, p,
                            GET_SRC_IP(p), GET_DST_IP(p),
                            p->tcph->th_sport, p->tcph->th_dport, dir);
        if (flushed)
            purge_flushed_ackd(tcpssn, listener);

        listener->flags &= ~TF_FORCE_FLUSH;
    }

    return flushed;
}

int Stream5FlushTalker(Packet *p, Flow *lwssn)
{
    StreamTracker *talker = NULL;
    int dir = 0;
    int flushed = 0;

    TcpSession* tcpssn = (TcpSession*)lwssn->session;

    /* figure out direction of this packet -- we should've already
     * looked at it, so the packet_flags are already set. */
    if(p->packet_flags & PKT_FROM_SERVER)
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Flushing talker on packet from server\n"););
        talker = &tcpssn->server;
        /* dir of flush is the data from the opposite side */
        dir = PKT_FROM_CLIENT;
    }
    else if (p->packet_flags & PKT_FROM_CLIENT)
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Flushing talker on packet from client\n"););
        talker = &tcpssn->client;
        /* dir of flush is the data from the opposite side */
        dir = PKT_FROM_SERVER;
    }

    if (dir != 0)
    {
        talker->flags |= TF_FORCE_FLUSH;
        flushed = flush_stream(tcpssn, talker, p,
                            GET_DST_IP(p), GET_SRC_IP(p),
                            p->tcph->th_dport, p->tcph->th_sport, dir);
        if (flushed)
            purge_flushed_ackd(tcpssn, talker);

        talker->flags &= ~TF_FORCE_FLUSH;
    }

    return flushed;
}

static void TcpSessionClear (Flow* lwssn, TcpSession* tcpssn, int freeApplicationData)
{
    STREAM5_DEBUG_WRAP( DebugMessage(DEBUG_STREAM_STATE,
                "In TcpSessionClear, %lu bytes in use\n", tcp_memcap->used()););
    STREAM5_DEBUG_WRAP( DebugMessage(DEBUG_STREAM_STATE,
                "client has %d segs queued\n", tcpssn->client.seg_count););
    STREAM5_DEBUG_WRAP( DebugMessage(DEBUG_STREAM_STATE,
                "server has %d segs queued\n", tcpssn->server.seg_count););

    // update stats
    tcpStats.streamtrackers_released++;
    Stream5UpdatePerfBaseState(&sfBase, tcpssn->flow, TCP_STATE_CLOSED);
    RemoveStreamSession(&sfBase);

    if (lwssn->s5_state.session_flags & SSNFLAG_PRUNED)
    {
        CloseStreamSession(&sfBase, SESSION_CLOSED_PRUNED);
    }
    else if (lwssn->s5_state.session_flags & SSNFLAG_TIMEDOUT)
    {
        CloseStreamSession(&sfBase, SESSION_CLOSED_TIMEDOUT);
    }
    else
    {
        CloseStreamSession(&sfBase, SESSION_CLOSED_NORMALLY);
    }

    // release internal protocol specific state
    purge_all(&tcpssn->client);
    purge_all(&tcpssn->server);

    s5_paf_clear(&tcpssn->client.paf_state);
    s5_paf_clear(&tcpssn->server.paf_state);

    // update light-weight state
    lwssn->clear(freeApplicationData);

    // generate event for rate filtering
    EventInternal(INTERNAL_EVENT_SESSION_DEL);

    STREAM5_DEBUG_WRAP( DebugMessage(DEBUG_STREAM_STATE,
                "After cleaning, %lu bytes in use\n", tcp_memcap->used()););
}

static void TcpSessionCleanup(Flow *lwssn, int freeApplicationData)
{
    DAQ_PktHdr_t tmp_pcap_hdr;
    TcpSession* tcpssn = (TcpSession*)lwssn->session;

    /* Flush ack'd data on both sides as necessary */
    {
        Packet p;
        int flushed;

        /* Flush the client */
        if (tcpssn->client.seglist && !(lwssn->s5_state.ignore_direction & SSN_DIR_SERVER) )
        {
            tcpStats.s5tcp1++;
            /* Do each field individually because of size differences on 64bit OS */
            tmp_pcap_hdr.ts.tv_sec = tcpssn->client.seglist->tv.tv_sec;
            tmp_pcap_hdr.ts.tv_usec = tcpssn->client.seglist->tv.tv_usec;
            tmp_pcap_hdr.caplen = tcpssn->client.seglist->caplen;
            tmp_pcap_hdr.pktlen = tcpssn->client.seglist->pktlen;

            DecodeRebuiltPacket(&p, &tmp_pcap_hdr, tcpssn->client.seglist->pkt, lwssn);

            if ( !p.tcph )
            {
                flushed = 0;
            }
            else
            {
                tcpssn->client.flags |= TF_FORCE_FLUSH;
                flushed = flush_stream(tcpssn, &tcpssn->client, &p,
                            p.iph_api->iph_ret_src(&p), p.iph_api->iph_ret_dst(&p),
                            p.tcph->th_sport, p.tcph->th_dport,
                            PKT_FROM_SERVER);
            }
            if (flushed)
                purge_flushed_ackd(tcpssn, &tcpssn->client);
            else
                LogRebuiltPacket(&p);

            tcpssn->client.flags &= ~TF_FORCE_FLUSH;
        }

        /* Flush the server */
        if (tcpssn->server.seglist && !(lwssn->s5_state.ignore_direction & SSN_DIR_CLIENT) )
        {
            tcpStats.s5tcp2++;
            /* Do each field individually because of size differences on 64bit OS */
            tmp_pcap_hdr.ts.tv_sec = tcpssn->server.seglist->tv.tv_sec;
            tmp_pcap_hdr.ts.tv_usec = tcpssn->server.seglist->tv.tv_usec;
            tmp_pcap_hdr.caplen = tcpssn->server.seglist->caplen;
            tmp_pcap_hdr.pktlen = tcpssn->server.seglist->pktlen;

            DecodeRebuiltPacket(&p, &tmp_pcap_hdr, tcpssn->server.seglist->pkt, lwssn);

            if ( !p.tcph )
            {
                flushed = 0;
            }
            else
            {
                tcpssn->server.flags |= TF_FORCE_FLUSH;
                flushed = flush_stream(tcpssn, &tcpssn->server, &p,
                            p.iph_api->iph_ret_src(&p), p.iph_api->iph_ret_dst(&p),
                            p.tcph->th_sport, p.tcph->th_dport,
                            PKT_FROM_CLIENT);
            }
            if (flushed)
                purge_flushed_ackd(tcpssn, &tcpssn->server);
            else
                LogRebuiltPacket(&p);

            tcpssn->server.flags &= ~TF_FORCE_FLUSH;
        }
    }

    TcpSessionClear(lwssn, tcpssn, freeApplicationData);
}

#ifdef SEG_TEST
static void CheckSegments (const StreamTracker* a)
{
    StreamSegment* ss = a->seglist;
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

#ifdef REG_TEST
#define LCL(p, x)    (p->x - p->isn)
#define RMT(p, x, q) (p->x - (q ? q->isn : 0))

// FIXIT this should not be thread specific
static THREAD_LOCAL int s5_trace_enabled = -1;

static void TraceEvent (
    const Packet* p, TcpDataBlock*, uint32_t txd, uint32_t rxd
) {
    int i;
    char flags[7] = "UAPRSF";
    const TCPHdr* h = p->tcph;
    const char* order = "";

    if ( !h )
       return;

    for ( i = 0; i < 6; i++)
        if ( !((1<<(5-i)) & h->th_flags) ) flags[i] = '-';

    // force relative ack to zero if not conveyed
    if ( flags[1] != 'A' ) rxd = ntohl(h->th_ack);

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

static void TraceSession (const Flow* lws)
{
    fprintf(stdout, "    LWS: ST=0x%x SF=0x%x CP=%u SP=%u\n",
        (unsigned)lws->session_state, lws->s5_state.session_flags,
        (unsigned)ntohs(lws->client_port), (unsigned)ntohs(lws->server_port)
    );
}

static const char* statext[] = {
    "NON", "LST", "SYR", "SYS", "EST", "CLW",
    "LAK", "FW1", "CLG", "FW2", "TWT", "CLD"
};

static const char* flushxt[] = {
    "NON", "FPR", "LOG", "RSP", "SLW",
#if 0
    "CON",
#endif
    "IGN", "PRO",
    "PRE", "PAF"
};

static void TraceSegments (const StreamTracker* a)
{
    StreamSegment* ss = a->seglist;
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

static void TraceState (
    const StreamTracker* a, const StreamTracker* b, const char* s)
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
    fprintf(stdout,
        "         FP=%s:%-4u SC=%-4u FL=%-4u SL=%-5u BS=%-4u",
        flushxt[a->flush_mgr.flush_policy], a->flush_mgr.flush_pt,
        a->seg_count, a->flush_count, a->seg_bytes_logical,
        a->seglist_base_seq - b->isn
    );
    if ( s5_trace_enabled == 2 )
        TraceSegments(a);

    fprintf(stdout, "\n");
}

static void TraceTCP (
    const Packet* p, const Flow* lws, TcpDataBlock* tdb, int event
) {
    const TcpSession* ssn = (TcpSession*)lws->session;
    const StreamTracker* srv = ssn ? &ssn->server : NULL;
    const StreamTracker* cli = ssn ? &ssn->client : NULL;

    const char* cdir = "?", *sdir = "?";
    uint32_t txd = 0, rxd = 0;

    if ( p->packet_flags & PKT_FROM_SERVER )
    {
        sdir = "SRV>";
        cdir = "CLI<";
        if ( srv ) txd = srv->isn;
        if ( cli ) rxd = cli->isn;
    }
    else if ( p->packet_flags & PKT_FROM_CLIENT )
    {
        sdir = "SRV<";
        cdir = "CLI>";
        if ( cli ) txd = cli->isn;
        if ( srv ) rxd = srv->isn;
    }
    TraceEvent(p, tdb, txd, rxd);

    if ( lws ) TraceSession(lws);

    if ( !event )
    {
        if ( cli ) TraceState(cli, srv, cdir);
        if ( srv ) TraceState(srv, cli, sdir);
    }
}

static inline void S5TraceTCP (
    const Packet* p, const Flow* lws, TcpDataBlock* tdb, int event
) {
    if ( !s5_trace_enabled )
        return;

    if ( s5_trace_enabled < 0 )
    {
        const char* s5t = getenv("S5_TRACE");

        if ( !s5t ) {
            s5_trace_enabled = 0;
            return;
        }
        // no error checking required - atoi() is sufficient
        s5_trace_enabled = atoi(s5t);
    }
    TraceTCP(p, lws, tdb, event);
}
#else
#define S5TraceTCP(pkt, flow, tdb, evt)
#endif  // REG_TEST

static uint32_t Stream5GetTcpTimestamp(Packet *p, uint32_t *ts, int strip)
{
    unsigned int i = 0;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Getting timestamp...\n"););
    while(i < p->tcp_option_count && i < TCP_OPTLENMAX)
    {
        if(p->tcp_options[i].code == TCPOPT_TIMESTAMP)
        {
            if ( strip && Normalize_IsEnabled(snort_conf, NORM_TCP_OPT) )
            {
                NormalStripTimeStamp(p, i);
            }
            else
            {
                *ts = EXTRACT_32BITS(p->tcp_options[i].data);
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                                "Found timestamp %lu\n", *ts););

                return TF_TSTAMP;
            }
        }
        i++;
    }
    *ts = 0;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "No timestamp...\n"););

    return TF_NONE;
}

static uint32_t Stream5GetMss(Packet *p, uint16_t *value)
{
    unsigned int i = 0;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Getting MSS...\n"););
    while(i < p->tcp_option_count && i < TCP_OPTLENMAX)
    {
        if(p->tcp_options[i].code == TCPOPT_MAXSEG)
        {
            *value = EXTRACT_16BITS(p->tcp_options[i].data);
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "Found MSS %u\n", *value););
            return TF_MSS;
        }

        i++;
    }

    *value = 0;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "No MSS...\n"););
    return TF_NONE;
}

static uint32_t Stream5GetWscale(Packet *p, uint16_t *value)
{
    unsigned int i = 0;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Getting wscale...\n"););
    while(i < p->tcp_option_count && i < TCP_OPTLENMAX)
    {
        if(p->tcp_options[i].code == TCPOPT_WSCALE)
        {
            *value = (uint16_t) p->tcp_options[i].data[0];
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "Found wscale %d\n", *value););

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

        i++;
    }

    *value = 0;
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "No wscale...\n"););
    return TF_NONE;
}

static uint32_t Stream5PacketHasWscale(Packet *p)
{
    uint16_t wscale;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Checking for wscale...\n"););
    return Stream5GetWscale(p, &wscale);
}

static inline int IsWellFormed(Packet *p, StreamTracker *ts)
{
    return ( !ts->mss || (p->dsize <= ts->mss) );
}

static void FinishServerInit(Packet *p, TcpDataBlock *tdb, TcpSession *ssn)
{
    StreamTracker *server;
    StreamTracker *client;

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

    if ( p->tcph->th_flags & TH_FIN )
        server->l_nxt_seq--;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
               "seglist_base_seq = %X\n", client->seglist_base_seq););

    if (!(ssn->flow->session_state & STREAM5_STATE_MIDSTREAM))
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
    server->flags |= Stream5GetTcpTimestamp(p, &server->ts_last, 0);
    if (server->ts_last == 0)
        server->flags |= TF_TSTAMP_ZERO;
    else
        server->ts_last_pkt = p->pkth->ts.tv_sec;
    server->flags |= Stream5GetMss(p, &server->mss);
    server->flags |= Stream5GetWscale(p, &server->wscale);

#ifdef DEBUG_STREAM5
    PrintTcpSession(ssn);
#endif
}

static void NewQueue(
    StreamTracker *st, Packet *p, TcpDataBlock *tdb)
{
    StreamSegment *ss = NULL;
    uint32_t overlap = 0;
    PROFILE_VARS;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "In NewQueue\n"););

    PREPROC_PROFILE_START(s5TcpInsertPerfStats);

    if(st->flush_mgr.flush_policy != STREAM_FLPOLICY_IGNORE)
    {
        uint32_t seq = tdb->seq;

        if ( p->tcph->th_flags & TH_SYN )
            seq++;

        /* new packet seq is below the last ack... */
        if ( SEQ_GT(st->r_win_base, seq) )
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "segment overlaps ack'd data...\n"););
            overlap = st->r_win_base - tdb->seq;
            if(overlap >= p->dsize)
            {
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "full overlap on ack'd data, dropping segment\n"););
                PREPROC_PROFILE_END(s5TcpInsertPerfStats);
                return;
            }
        }

        AddStreamNode(st, p, tdb, p->dsize, overlap, 0, tdb->seq+overlap, NULL, &ss);

        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Attached new queue to seglist, %d bytes queued, "
                    "base_seq 0x%X\n",
                    ss->size, st->seglist_base_seq););
    }

    PREPROC_PROFILE_END(s5TcpInsertPerfStats);
    return;
}

static inline StreamSegment *FindSegment(StreamTracker *st, uint32_t pkt_seq)
{
    int32_t dist_head;
    int32_t dist_tail;
    StreamSegment *ss;

    if (!st->seglist)
        return NULL;

    dist_head = pkt_seq - st->seglist->seq;
    dist_tail = pkt_seq - st->seglist_tail->seq;

    if (dist_head <= dist_tail)
    {
        /* Start iterating at the head (left) */
        for (ss = st->seglist; ss; ss = ss->next)
        {
            if (SEQ_EQ(ss->seq, pkt_seq))
                return ss;

            if (SEQ_GEQ(ss->seq, pkt_seq))
                break;
        }
    }
    else
    {
        /* Start iterating at the tail (right) */
        for (ss = st->seglist_tail; ss; ss = ss->prev)
        {
            if (SEQ_EQ(ss->seq, pkt_seq))
                return ss;

            if (SEQ_LT(ss->seq, pkt_seq))
                break;
        }
    }
    return NULL;
}

static inline int SegmentFastTrack(StreamSegment *tail, TcpDataBlock *tdb)
{
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Checking seq for fast track: %X > %X\n", tdb->seq,
                tail->seq + tail->size););

    if(SEQ_EQ(tdb->seq, tail->seq + tail->size))
        return 1;

    return 0;
}

static inline StreamSegment* SegmentAlloc (
    Packet* p, const struct timeval* tv, uint32_t caplen, uint32_t pktlen, const uint8_t* pkt)
{
    StreamSegment* ss;
    unsigned size = sizeof(*ss);

    if ( caplen > 0 )
        size += caplen - 1;  // ss contains 1st byte

    tcp_memcap->alloc(size);

    if ( tcp_memcap->at_max() )
    {
        sfBase.iStreamFaults++;

        if ( !p )
        {
            tcp_memcap->dealloc(size);
            return NULL;
        }
        flow_con->prune_flows(IPPROTO_TCP, p);
    }

    ss = (StreamSegment*)SnortAlloc(size);

    ss->tv.tv_sec = tv->tv_sec;
    ss->tv.tv_usec = tv->tv_usec;
    ss->caplen = caplen;
    ss->pktlen = pktlen;

    memcpy(ss->pkt, pkt, caplen);

    return ss;
}

static int AddStreamNode(
    StreamTracker *st, Packet *p,
    TcpDataBlock* tdb,
    int16_t len,
    uint32_t slide,
    uint32_t trunc,
    uint32_t seq,
    StreamSegment *left,
    StreamSegment **retSeg)
{
    StreamSegment *ss = NULL;
    int32_t newSize = len - slide - trunc;

    if (newSize <= 0)
    {
        /*
         * zero size data because of trimming.  Don't
         * insert it
         */
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "zero size TCP data after left & right trimming "
                    "(len: %d slide: %d trunc: %d)\n",
                    len, slide, trunc););
        Discard();
        NormalTrimPayloadIf(p, NORM_TCP_TRIM, 0, tdb);

#ifdef DEBUG_STREAM5
        {
            StreamSegment *idx = st->seglist;
            unsigned long i = 0;
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Dumping seglist, %d segments\n", st->seg_count););
            while (idx)
            {
                i++;
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "%d  ptr: %p  seq: 0x%X  size: %d nxt: %p prv: %p\n",
                        i, idx, idx->seq, idx->size, idx->next, idx->prev););

                if(st->seg_count < i)
                    FatalError("Circular list, WTF?\n");

                idx = idx->next;
            }
        }
#endif
        return STREAM_INSERT_ANOMALY;
    }

    ss = SegmentAlloc(p, &p->pkth->ts, p->pkth->caplen, p->pkth->pktlen, p->pkt);

    ss->data = ss->pkt + (p->data - p->pkt);
    ss->orig_dsize = p->dsize;

    ss->payload = ss->data + slide;
    ss->size = (uint16_t)newSize;
    ss->seq = seq;
    ss->ts = tdb->ts;

    /* handle the urg ptr */
    if(p->tcph->th_flags & TH_URG)
    {
        if(ntohs(p->tcph->th_urp) < p->dsize)
        {
            switch(st->os_policy)
            {
            case STREAM_POLICY_LINUX:
            case STREAM_POLICY_OLD_LINUX:
                /* Linux, Old linux discard data from urgent pointer */
                /* If urg pointer is 0, it's treated as a 1 */
                ss->urg_offset = ntohs(p->tcph->th_urp);
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
                /* Others discard data from urgent pointer */
                /* If urg pointer is beyond this packet, it's treated as a 0 */
                ss->urg_offset = ntohs(p->tcph->th_urp);
                if (ss->urg_offset > p->dsize)
                {
                    ss->urg_offset = 0;
                }
                break;
            }
        }
    }

    Stream5SeglistAddNode(st, left, ss);
    st->seg_bytes_logical += ss->size;
    st->seg_bytes_total += ss->caplen;  /* Includes protocol headers and payload */
    st->total_segs_queued++;
    st->total_bytes_queued += ss->size;

    p->packet_flags |= PKT_STREAM_INSERT;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "added %d bytes on segment list @ seq: 0x%X, total %lu, "
                "%d segments queued\n", ss->size, ss->seq,
                st->seg_bytes_logical, SegsToFlush(st, 0)););

    *retSeg = ss;
#ifdef SEG_TEST
    CheckSegments(st);
#endif
    return STREAM_INSERT_OK;
}

static int DupStreamNode(Packet *p,
        StreamTracker *st,
        StreamSegment *left,
        StreamSegment **retSeg)
{
    StreamSegment* ss = SegmentAlloc(p, &left->tv, left->caplen, left->pktlen, left->pkt);

    if ( !ss )
        return STREAM_INSERT_FAILED;

    ss->data = ss->pkt + (left->data - left->pkt);
    ss->orig_dsize = left->orig_dsize;

    /* twiddle the values for overlaps */
    ss->payload = ss->data;
    ss->size = left->size;
    ss->seq = left->seq;

    Stream5SeglistAddNode(st, left, ss);
    st->seg_bytes_total += ss->caplen;
    st->total_segs_queued++;
    //st->total_bytes_queued += ss->size;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "added %d bytes on segment list @ seq: 0x%X, total %lu, "
                "%d segments queued\n", ss->size, ss->seq,
                st->seg_bytes_logical, SegsToFlush(st, 0)););

    *retSeg = ss;
    return STREAM_INSERT_OK;

}

static inline bool IsRetransmit(StreamSegment *seg, const uint8_t *rdata,
        uint16_t rsize, uint32_t rseq)
{
    // If seg->orig_size == seg->size, then it's sequence number wasn't adjusted
    // so can just do a straight compare of the sequence numbers.
    // Don't want to count as a retransmit if segment's size/sequence number
    // has been adjusted.
    if (SEQ_EQ(seg->seq, rseq) && (seg->orig_dsize == seg->size))
    {
        if (((seg->size <= rsize) && (memcmp(seg->data, rdata, seg->size) == 0))
                || ((seg->size > rsize) && (memcmp(seg->data, rdata, rsize) == 0)))
            return true;
    }

    return false;
}

static inline void RetransmitHandle(Packet *p, TcpSession *tcpssn)
{
    // Data has already been analyzed so don't bother looking at it again.
    DisableDetect(p);

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Allowing retransmitted data "
                "-- not blocked previously\n"););

    if ( tcpssn->flow->handler[SE_REXMIT] )
        stream.call_handler(p, tcpssn->flow->handler[SE_REXMIT]);
}

static int StreamQueue(StreamTracker *st, Packet *p, TcpDataBlock *tdb,
        TcpSession *tcpssn)
{
    StreamSegment *ss = NULL;
    StreamSegment *left = NULL;
    StreamSegment *right = NULL;
    StreamSegment *dump_me = NULL;
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
    int ips_data;
    // To check for retransmitted data
    const uint8_t *rdata = p->data;
    uint16_t rsize = p->dsize;
    uint32_t rseq = tdb->seq;
    PROFILE_VARS;
    STREAM5_DEBUG_WRAP(
        StreamSegment *lastptr = NULL;
        uint32_t base_seq = st->seglist_base_seq;
        int last = 0;
    );

    ips_data = Normalize_IsEnabled(snort_conf, NORM_TCP_IPS);
    if ( ips_data )
        reassembly_policy = REASSEMBLY_POLICY_FIRST;
    else
        reassembly_policy = st->reassembly_policy;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Queuing %d bytes on stream!\n"
                "base_seq: %X seq: %X  seq_end: %X\n",
                seq_end - seq, base_seq, seq, seq_end););

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "%d segments on seglist\n", SegsToFlush(st, 0)););
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+\n"););
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+\n"););

    PREPROC_PROFILE_START(s5TcpInsertPerfStats);

    // NORM fast tracks are in sequence - no norms
    if(st->seglist_tail && SegmentFastTrack(st->seglist_tail, tdb))
    {
        /* segment fit cleanly at the end of the segment list */
        left = st->seglist_tail;
        right = NULL;

        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Fast tracking segment! (tail_seq %X size %d)\n",
            st->seglist_tail->seq, st->seglist_tail->size););

        ret = AddStreamNode(st, p, tdb, len,
                slide /* 0 */, trunc /* 0 */, seq, left /* tail */,
                &ss);

        PREPROC_PROFILE_END(s5TcpInsertPerfStats);
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
        /* Start iterating at the head (left) */
        for(ss = st->seglist; ss; ss = ss->next)
        {
            STREAM5_DEBUG_WRAP(
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

            if(SEQ_GEQ(right->seq, seq))
                break;

            left = right;
        }

        if(ss == NULL)
            right = NULL;
    }
    else
    {
        /* Start iterating at the tail (right) */
        for(ss = st->seglist_tail; ss; ss = ss->prev)
        {
            STREAM5_DEBUG_WRAP(
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

            if(SEQ_LT(left->seq, seq))
                break;

            right = left;
        }

        if(ss == NULL)
            left = NULL;
    }

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+\n"););
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+\n"););

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "left: %p:0x%X  right: %p:0x%X\n", left,
                left?left->seq:0, right, right?right->seq:0););

    /*
     * handle left overlaps
     */
    if(left)
    {
        // NOTE that left->seq is always less than seq, otherwise it would
        // be a right based on the above determination of left and right

        /* check if the new segment overlaps on the left side */
        overlap = left->seq + left->size - seq;

        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "left overlap %d\n", overlap););

        if(overlap > 0)
        {
            // NOTE that overlap will always be less than left->size since
            // seq is always greater than left->seq
            tcpStats.overlaps++;
            st->overlap_count++;

            switch(reassembly_policy)
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
                    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                                "left overlap, honoring old data\n"););
                    if ( ips_data )
                    {
                        if (SEQ_LT(left->seq,tdb->seq) && SEQ_GT(left->seq + left->size, tdb->seq + p->dsize))
                        {
                            unsigned offset = tdb->seq - left->seq;
                            memcpy((uint8_t*)p->data, left->payload+offset, p->dsize);
                            p->packet_flags |= PKT_MODIFIED;
                            normStats[PC_TCP_IPS_DATA]++;
                            sfBase.iPegs[PERF_COUNT_TCP_IPS_DATA]++;
                        }
                        else if (SEQ_LT(left->seq, tdb->seq))
                        {
                            unsigned offset = tdb->seq - left->seq;
                            unsigned length = left->seq + left->size - tdb->seq;
                            memcpy((uint8_t*)p->data, left->payload+offset, length);
                            p->packet_flags |= PKT_MODIFIED;
                            normStats[PC_TCP_IPS_DATA]++;
                            sfBase.iPegs[PERF_COUNT_TCP_IPS_DATA]++;
                        }
                    }
                    seq += overlap;
                    slide = overlap;
                    if(SEQ_LEQ(seq_end, seq))
                    {
                        /*
                         * houston, we have a problem
                         */
                        /* flag an anomaly */
                        EventBadSegment(st->tcp_policy);
                        Discard();
                        PREPROC_PROFILE_END(s5TcpInsertPerfStats);
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
                        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                                    "left overlap, honoring old data\n"););
                        seq += overlap;
                        slide = overlap;
                        if(SEQ_LEQ(seq_end, seq))
                        {
                            /*
                             * houston, we have a problem
                             */
                            /* flag an anomaly */
                            EventBadSegment(st->tcp_policy);
                            Discard();
                            PREPROC_PROFILE_END(s5TcpInsertPerfStats);
                            return STREAM_INSERT_ANOMALY;
                        }
                    }

                    /* Otherwise, trim the old data accordingly */
                    left->size -= (int16_t)overlap;
                    st->seg_bytes_logical -= overlap;
                    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                                "left overlap, honoring new data\n"););
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
                            /* No warning,
                             * its done in StreamSeglistAddNode */
                            PREPROC_PROFILE_END(s5TcpInsertPerfStats);
                            return ret;
                        }
                        left->size -= (int16_t)overlap;
                        st->seg_bytes_logical -= overlap;

                        right->seq = seq + len;
                        right->size -= (int16_t)(seq + len - left->seq);
                        right->payload += (seq + len - left->seq);
                        st->seg_bytes_logical -= (seq + len - left->seq);
                    }
                    else
                    {
                        left->size -= (int16_t)overlap;
                        st->seg_bytes_logical -= overlap;
                    }

                    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                                "left overlap, honoring new data\n"););
                    break;
            }

            if(SEQ_LEQ(seq_end, seq))
            {
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "seq_end < seq"););
                /*
                 * houston, we have a problem
                 */
                /* flag an anomaly */
                EventBadSegment(st->tcp_policy);
                Discard();
                PREPROC_PROFILE_END(s5TcpInsertPerfStats);
                return STREAM_INSERT_ANOMALY;
            }
        }
        else
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "No left overlap\n"););
        }
    }

    //(seq_end > right->seq) && (seq_end <= (right->seq+right->size))))
    while(right && !done && SEQ_LT(right->seq, seq_end))
    {
        trunc = 0;
        overlap = (int)(seq_end - right->seq);
        //overlap = right->size - (right->seq - seq);
        //right->seq + right->size - seq_end;

        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "right overlap(%d): len: %d right->seq: 0x%X seq: 0x%X\n",
                    overlap, len, right->seq, seq););

        if(overlap < right->size)
        {
            if (IsRetransmit(right, rdata, rsize, rseq))
            {
                // All data was retransmitted
                RetransmitHandle(p, tcpssn);
                addthis = 0;
                break;
            }

            tcpStats.overlaps++;
            st->overlap_count++;

            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "Got partial right overlap\n"););

            switch(reassembly_policy)
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
                    if ( ips_data )
                    {
                        unsigned offset = right->seq - tdb->seq;
                        unsigned length = tdb->seq + p->dsize - right->seq;
                        memcpy((uint8_t*)p->data+offset, right->payload, length);
                        p->packet_flags |= PKT_MODIFIED;
                        normStats[PC_TCP_IPS_DATA]++;
                        sfBase.iPegs[PERF_COUNT_TCP_IPS_DATA]++;
                    }
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
            while (IsRetransmit(right, rdata, rsize, rseq))
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
                    RetransmitHandle(p, tcpssn);
                    addthis = 0;
                    break;
                }
                else if ((right == NULL) || (rsize < right->size))
                {
                    // Need to add new node or some data left to check
                    break;
                }
            }

            if ((rsize == 0) || (right == NULL))
                break;
            else if (rsize < right->size)
                continue;

            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "Got full right overlap\n"););

            tcpStats.overlaps++;
            st->overlap_count++;

            switch(reassembly_policy)
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

                        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                                    "retrans, dropping old data at seq %d, size %d\n",
                                    right->seq, right->size););
                        right = right->next;
                        Stream5SeglistDeleteNode(st, dump_me);
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
                    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                                "Got full right overlap, truncating new\n"););
                    if ( ips_data )
                    {
                        unsigned offset = right->seq - tdb->seq;
                        memcpy((uint8_t*)p->data+offset, right->payload, right->size);
                        p->packet_flags |= PKT_MODIFIED;
                        normStats[PC_TCP_IPS_DATA]++;
                        sfBase.iPegs[PERF_COUNT_TCP_IPS_DATA]++;
                    }
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
                            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                                        "StreamQueue got full right overlap with "
                                        "resulting seq too high, bad segment "
                                        "(seq: %X  seq_end: %X overlap: %lu\n",
                                        seq, seq_end, overlap););
                            EventBadSegment(st->tcp_policy);
                            Discard();
                            PREPROC_PROFILE_END(s5TcpInsertPerfStats);
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

                    /* insert this one, and see if we need to chunk it up */
                    /* Adjust slide so that is correct relative to orig seq */
                    slide = seq - tdb->seq;
                    ret = AddStreamNode(st, p, tdb, len, slide, trunc, seq, left, &ss);
                    if (ret != STREAM_INSERT_OK)
                    {
                        /* no warning, already done above */
                        PREPROC_PROFILE_END(s5TcpInsertPerfStats);
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
                        if(SEQ_LEQ((int)(seq_end - trunc), seq))
                        {
                            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                                "StreamQueue got full right overlap with "
                                "resulting seq too high, bad segment "
                                "(seq: %X  seq_end: %X overlap: %lu\n",
                                seq, seq_end, overlap););
                            EventBadSegment(st->tcp_policy);
                            Discard();
                            PREPROC_PROFILE_END(s5TcpInsertPerfStats);
                            return STREAM_INSERT_ANOMALY;
                        }
                        break;
                    }
                /* Fall through */
                case REASSEMBLY_POLICY_OLD_LINUX:
                case REASSEMBLY_POLICY_LAST:
right_overlap_last:
                    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                                "Got full right overlap of old, dropping old\n"););
                    dump_me = right;
                    right = right->next;
                    Stream5SeglistDeleteNode(st, dump_me);
                    break;
            }
        }
    }

    if (addthis)
    {
        /* Adjust slide so that is correct relative to orig seq */
        slide = seq - tdb->seq;
        ret = AddStreamNode(
            st, p, tdb, len, slide, trunc, seq, left, &ss);
    }
    else
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Fully truncated right overlap\n"););
    }

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "StreamQueue returning normally\n"););

    PREPROC_PROFILE_END(s5TcpInsertPerfStats);
    return ret;
}

static void ProcessTcpStream(StreamTracker *rcv, TcpSession *tcpssn,
                             Packet *p, TcpDataBlock *tdb,
                             Stream5TcpPolicy *s5TcpPolicy)
{

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "In ProcessTcpStream(), %d bytes to queue\n", p->dsize););

    if ( p->packet_flags & PKT_IGNORE )
        return;

#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
    SetPacketHeaderFoo(tcpssn, p);
#endif

    if ((s5TcpPolicy->flags & STREAM5_CONFIG_NO_ASYNC_REASSEMBLY) &&
        !TwoWayTraffic(tcpssn->flow))
    {
        return;
    }

    if (s5TcpPolicy->max_consec_small_segs)
    {
        if (p->dsize < s5TcpPolicy->max_consec_small_seg_size)
        {
            /* check ignore_ports */
            if (!(s5TcpPolicy->small_seg_ignore[p->dp/8] & (1 << (p->dp %8))))
            {
                rcv->small_seg_count++;

                if (rcv->small_seg_count > s5TcpPolicy->max_consec_small_segs)
                {
                    /* Above threshold, log it... requires detect_anomalies be
                    * on in this TCP policy, action controlled by preprocessor
                    * rule. */
                    EventMaxSmallSegsExceeded(s5TcpPolicy);

                    /* Reset counter, so we're not too noisy */
                    rcv->small_seg_count = 0;
                }
            }
        }
    }

    if (s5TcpPolicy->max_queued_bytes &&
        (rcv->seg_bytes_total > s5TcpPolicy->max_queued_bytes))
    {
        if (!(tcpssn->flow->s5_state.session_flags & SSNFLAG_LOGGED_QUEUE_FULL))
        {
            /* only log this one per session */
            tcpssn->flow->s5_state.session_flags |= SSNFLAG_LOGGED_QUEUE_FULL;
        }
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Ignoring segment due to too many bytes queued\n"););
        return;
    }

    if (s5TcpPolicy->max_queued_segs &&
        (rcv->seg_count+1 > s5TcpPolicy->max_queued_segs))
    {
        if (!(tcpssn->flow->s5_state.session_flags & SSNFLAG_LOGGED_QUEUE_FULL))
        {
            /* only log this one per session */
            tcpssn->flow->s5_state.session_flags |= SSNFLAG_LOGGED_QUEUE_FULL;
        }
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Ignoring segment due to too many bytes queued\n"););
        return;
    }

    if(rcv->seg_count != 0)
    {
        if(rcv->flush_mgr.flush_policy == STREAM_FLPOLICY_IGNORE)
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Ignoring segment due to IGNORE flush_policy\n"););
            return;
        }
        else
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "queuing segment\n"););

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

            if ((rcv->tcp_policy->overlap_limit) &&
                (rcv->overlap_count > rcv->tcp_policy->overlap_limit))
            {
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "Reached the overlap limit.  Flush the data "
                        "and kill the session if configured\n"););
                if (p->packet_flags & PKT_FROM_CLIENT)
                {
                    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "Flushing data on packet from the client\n"););
                    flush_stream(tcpssn, rcv, p,
                            GET_SRC_IP(p), GET_DST_IP(p),
                            p->tcph->th_sport, p->tcph->th_dport,
                            PKT_FROM_CLIENT);

                    flush_stream(tcpssn, &tcpssn->server, p,
                            GET_DST_IP(p), GET_SRC_IP(p),
                            p->tcph->th_dport, p->tcph->th_sport,
                            PKT_FROM_SERVER);
                }
                else
                {
                    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "Flushing data on packet from the server\n"););
                    flush_stream(tcpssn, rcv, p,
                            GET_SRC_IP(p), GET_DST_IP(p),
                            p->tcph->th_sport, p->tcph->th_dport,
                            PKT_FROM_SERVER);

                    flush_stream(tcpssn, &tcpssn->client, p,
                            GET_DST_IP(p), GET_SRC_IP(p),
                            p->tcph->th_dport, p->tcph->th_sport,
                            PKT_FROM_CLIENT);
                }
                purge_all(&tcpssn->client);
                purge_all(&tcpssn->server);

                /* Alert on overlap limit and reset counter */
                EventExcessiveOverlap(rcv->tcp_policy);
                rcv->overlap_count = 0;
            }
        }
    }
    else
    {
        if(rcv->flush_mgr.flush_policy == STREAM_FLPOLICY_IGNORE)
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "Ignoring segment due to IGNORE flush_policy\n"););
            return;
        }
        else
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                                "queuing segment\n"););
            NewQueue(rcv, p, tdb);
        }
    }

    return;
}

static int ProcessTcpData(Packet *p, StreamTracker *listener, TcpSession *tcpssn,
        TcpDataBlock *tdb, Stream5TcpPolicy *s5TcpPolicy)
{
    PROFILE_VARS;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "In ProcessTcpData()\n"););

    PREPROC_PROFILE_START(s5TcpDataPerfStats);
    if ((p->tcph->th_flags & TH_SYN) && (listener->os_policy != STREAM_POLICY_MACOS))
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Bailing, data on SYN, not MAC Policy!\n"););
        NormalTrimPayloadIf(p, NORM_TCP_TRIM, 0, tdb);
        PREPROC_PROFILE_END(s5TcpDataPerfStats);
        return S5_UNALIGNED;
    }

    /* we're aligned, so that's nice anyway */
    if(tdb->seq == listener->r_nxt_ack)
    {
        /* check if we're in the window */
        if(Stream5GetWindow(tcpssn->flow, listener, tdb) == 0)
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "Bailing, we're out of the window!\n"););
            NormalTrimPayloadIf(p, NORM_TCP_TRIM, 0, tdb);
            PREPROC_PROFILE_END(s5TcpDataPerfStats);
            return S5_UNALIGNED;
        }

        /* move the ack boundry up, this is the only way we'll accept data */
        // FIXTHIS for ips, must move all the way to first hole or right end
        if (listener->s_mgr.state_queue == TCP_STATE_NONE)
            listener->r_nxt_ack = tdb->end_seq;

        if(p->dsize != 0)
        {
            if ( !(tcpssn->flow->s5_state.session_flags & SSNFLAG_STREAM_ORDER_BAD) )
                p->packet_flags |= PKT_STREAM_ORDER_OK;

            ProcessTcpStream(listener, tcpssn, p, tdb, s5TcpPolicy);
            /* set flags to session flags */

            PREPROC_PROFILE_END(s5TcpDataPerfStats);
            return S5_ALIGNED;
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
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "out of order segment (tdb->seq: 0x%X "
                    "l->r_nxt_ack: 0x%X!\n", tdb->seq, listener->r_nxt_ack););

        if (listener->s_mgr.state_queue == TCP_STATE_NONE)
        {
            /* check if we're in the window */
            if(Stream5GetWindow(tcpssn->flow, listener, tdb) == 0)
            {
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "Bailing, we're out of the window!\n"););
                NormalTrimPayloadIf(p, NORM_TCP_TRIM, 0, tdb);
                PREPROC_PROFILE_END(s5TcpDataPerfStats);
                return S5_UNALIGNED;
            }

            if ((listener->s_mgr.state == TCP_STATE_ESTABLISHED) &&
                (listener->flush_mgr.flush_policy == STREAM_FLPOLICY_IGNORE))
            {
                if ( SEQ_GT(tdb->end_seq, listener->r_nxt_ack))
                {
                    /* set next ack so we are within the window going forward on
                    * this side. */
                    // FIXTHIS for ips, must move all the way to first hole or right end
                    listener->r_nxt_ack = tdb->end_seq;
                }
            }
        }

        if(p->dsize != 0)
        {
            if ( !(tcpssn->flow->s5_state.session_flags & SSNFLAG_STREAM_ORDER_BAD) )
            {
                if ( !SEQ_LEQ((tdb->seq + p->dsize), listener->r_nxt_ack) )
                    tcpssn->flow->s5_state.session_flags |= SSNFLAG_STREAM_ORDER_BAD;
            }
            ProcessTcpStream(listener, tcpssn, p, tdb, s5TcpPolicy);
        }
    }

    PREPROC_PROFILE_END(s5TcpDataPerfStats);
    return S5_UNALIGNED;
}

uint16_t StreamGetPolicy(Flow *lwssn, Stream5TcpPolicy *s5TcpPolicy,
              int direction)
{
    uint16_t policy_id;
    /* Not caching this host_entry in the frag tracker so we can
     * swap the table out after processing this packet if we need
     * to.  */
    HostAttributeEntry *host_entry = NULL;
    int ssn_dir;

    if (!IsAdaptiveConfigured())
        return s5TcpPolicy->policy;

    if (direction == FROM_CLIENT)
    {
        host_entry = SFAT_LookupHostEntryByIP(&lwssn->server_ip);
        ssn_dir = SSN_DIR_SERVER;
    }
    else
    {
        host_entry = SFAT_LookupHostEntryByIP(&lwssn->client_ip);
        ssn_dir = SSN_DIR_CLIENT;
    }
    if (host_entry && (isStreamPolicySet(host_entry) == POLICY_SET))
    {
        policy_id = getStreamPolicy(host_entry);

        if (policy_id != SFAT_UNKNOWN_STREAM_POLICY)
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "StreamGetPolicy: Policy Map Entry: %d(%s)\n",
                policy_id, reassembly_policy_names[policy_id]););

            /* Since we've already done the lookup, try to get the
             * application protocol id with that host_entry. */
            stream.set_application_protocol_id_from_host_entry(lwssn, host_entry, ssn_dir);
            return policy_id;
        }
    }

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "StreamGetPolicy: Using configured default %d(%s)\n",
        s5TcpPolicy->policy, reassembly_policy_names[s5TcpPolicy->policy]););

    return s5TcpPolicy->policy;
}

void SetTcpReassemblyPolicy(StreamTracker *st)
{
    st->reassembly_policy = GetTcpReassemblyPolicy(st->os_policy);
}

static void SetOSPolicy(TcpSession *tcpssn)
{
    if (tcpssn->client.os_policy == 0)
    {
        tcpssn->client.os_policy = StreamGetPolicy(tcpssn->flow, tcpssn->client.tcp_policy, FROM_SERVER);
        SetTcpReassemblyPolicy(&tcpssn->client);
    }

    if (tcpssn->server.os_policy == 0)
    {
        tcpssn->server.os_policy = StreamGetPolicy(tcpssn->flow, tcpssn->server.tcp_policy, FROM_CLIENT);
        SetTcpReassemblyPolicy(&tcpssn->server);
    }
}

/* Use a for loop and byte comparison, which has proven to be
 * faster on pipelined architectures compared to a memcmp (setup
 * for memcmp is slow).  Not using a 4 byte and 2 byte long because
 * there is no guarantee of memory alignment (and thus performance
 * issues similar to memcmp). */
static inline int ValidMacAddress(
    StreamTracker *talker, StreamTracker *listener, Packet *p)
{
    int i, j, ret = 0;

    if (p->eh == NULL)
        return 0;

    for ( i = 0; i < 6; ++i )
    {
        if ((talker->mac_addr[i] != p->eh->ether_src[i]))
            break;
    }
    for ( j = 0; j < 6; ++j )
    {
        if (listener->mac_addr[j] != p->eh->ether_dst[j])
            break;
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
    Packet *p, TcpSession *tcpssn, int dir)
{
    int i;

    /* Not ethernet based, nothing to do */
    if (p->eh == NULL)
        return;

    if (dir == FROM_CLIENT)
    {
        /* Client is SRC */
        for (i=0;i<6;i++)
        {
            tcpssn->client.mac_addr[i] = p->eh->ether_src[i];
            tcpssn->server.mac_addr[i] = p->eh->ether_dst[i];
        }
    }
    else
    {
        /* Server is SRC */
        for (i=0;i<6;i++)
        {
            tcpssn->server.mac_addr[i] = p->eh->ether_src[i];
            tcpssn->client.mac_addr[i] = p->eh->ether_dst[i];
        }
    }
}

static int NewTcpSession(
    Packet *p, Flow *lwssn,
    TcpDataBlock *tdb, Stream5TcpPolicy *dstPolicy)
{
    TcpSession *tmp = NULL;
    uint16_t server_port = 0;
    PROFILE_VARS;

    PREPROC_PROFILE_START(s5TcpNewSessPerfStats);

    if (TCP_ISFLAGSET(p->tcph, TH_SYN) &&
        !TCP_ISFLAGSET(p->tcph, TH_ACK))
    {
        /******************************************************************
         * start new sessions on proper SYN packets
         *****************************************************************/
        tmp = (TcpSession*)lwssn->session;
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Creating new session tracker on SYN!\n"););

        lwssn->s5_state.session_flags |= SSNFLAG_SEEN_CLIENT;

        if((p->tcph->th_flags & (TH_CWR|TH_ECE)) == (TH_CWR|TH_ECE))
        {
            lwssn->s5_state.session_flags |= SSNFLAG_ECN_CLIENT_QUERY;
        }

        /* setup the stream trackers */
        tmp->client.s_mgr.state = TCP_STATE_SYN_SENT;
        tmp->client.isn = tdb->seq;
        tmp->client.l_unackd = tdb->seq + 1;
        tmp->client.l_nxt_seq = tmp->client.l_unackd;
        tmp->client.l_window = tdb->win;

        tmp->client.ts_last_pkt = p->pkth->ts.tv_sec;

        tmp->server.seglist_base_seq = tmp->client.l_unackd;
        tmp->server.r_nxt_ack = tmp->client.l_unackd;
        tmp->server.r_win_base = tdb->seq+1;

        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "seglist_base_seq = %X\n", tmp->server.seglist_base_seq););
        tmp->server.s_mgr.state = TCP_STATE_LISTEN;

        tmp->client.flags |= Stream5GetTcpTimestamp(p, &tmp->client.ts_last, 0);
        if (tmp->client.ts_last == 0)
            tmp->client.flags |= TF_TSTAMP_ZERO;
        tmp->client.flags |= Stream5GetMss(p, &tmp->client.mss);
        tmp->client.flags |= Stream5GetWscale(p, &tmp->client.wscale);


        /* Set the Stream5TcpPolicy for each direction (pkt from client) */
        tmp->client.tcp_policy = dstPolicy;  // FIXIT BINDING use external for both dirs
        tmp->server.tcp_policy = dstPolicy;

        /* Server is destination */
        server_port = p->dp;

        CopyMacAddr(p, tmp, FROM_CLIENT);
    }
    else if (TCP_ISFLAGSET(p->tcph, (TH_SYN|TH_ACK)))
    {
        /******************************************************************
         * start new sessions on SYN/ACK from server
         *****************************************************************/
        tmp = (TcpSession*)lwssn->session;
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Creating new session tracker on SYN_ACK!\n"););

        lwssn->s5_state.session_flags |= SSNFLAG_SEEN_SERVER;

        if((p->tcph->th_flags & (TH_CWR|TH_ECE)) == (TH_CWR|TH_ECE))
        {
            lwssn->s5_state.session_flags |= SSNFLAG_ECN_SERVER_REPLY;
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

        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "seglist_base_seq = %X\n", tmp->client.seglist_base_seq););
        tmp->client.s_mgr.state = TCP_STATE_SYN_SENT;

        tmp->server.flags |= Stream5GetTcpTimestamp(p, &tmp->server.ts_last, 0);
        if (tmp->server.ts_last == 0)
            tmp->server.flags |= TF_TSTAMP_ZERO;
        tmp->server.flags |= Stream5GetMss(p, &tmp->server.mss);
        tmp->server.flags |= Stream5GetWscale(p, &tmp->server.wscale);

        /* Set the Stream5TcpPolicy for each direction (pkt from server) */
        tmp->server.tcp_policy = dstPolicy;  // FIXIT BINDING use external for both dirs
        tmp->client.tcp_policy = dstPolicy;
        lwssn->policy = tmp->server.tcp_policy;

        /* Client is destination */
        server_port = p->sp;

        CopyMacAddr(p, tmp, FROM_SERVER);
    }
    else if ((p->tcph->th_flags & TH_ACK) &&
             !(p->tcph->th_flags & TH_RST) &&
             (lwssn->session_state & STREAM5_STATE_ESTABLISHED))
    {
        /******************************************************************
         * start new sessions on completion of 3-way (ACK only, no data)
         *****************************************************************/
        tmp = (TcpSession*)lwssn->session;
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Creating new session tracker on ACK!\n"););

        lwssn->s5_state.session_flags |= SSNFLAG_SEEN_CLIENT;

        if((p->tcph->th_flags & (TH_CWR|TH_ECE)) == (TH_CWR|TH_ECE))
        {
            lwssn->s5_state.session_flags |= SSNFLAG_ECN_CLIENT_QUERY;
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

        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "seglist_base_seq = %X\n", tmp->server.seglist_base_seq););
        tmp->server.s_mgr.state = TCP_STATE_ESTABLISHED;

        tmp->client.flags |= Stream5GetTcpTimestamp(p, &tmp->client.ts_last, 0);
        if (tmp->client.ts_last == 0)
            tmp->client.flags |= TF_TSTAMP_ZERO;
        tmp->client.flags |= Stream5GetMss(p, &tmp->client.mss);
        tmp->client.flags |= Stream5GetWscale(p, &tmp->client.wscale);

        /* Set the Stream5TcpPolicy for each direction (pkt from client) */
        tmp->client.tcp_policy = dstPolicy;  // FIXIT BINDING use external for both dirs
        tmp->server.tcp_policy = dstPolicy;

        /* Server is destination */
        server_port = p->dp;

        CopyMacAddr(p, tmp, FROM_CLIENT);
    }
    else if (p->dsize != 0)
    {
        /******************************************************************
         * start new sessions on data in packet
         *****************************************************************/
        tmp = (TcpSession*)lwssn->session;
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Creating new session tracker on data packet (ACK|PSH)!\n"););

        if (lwssn->s5_state.direction == FROM_CLIENT)
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "Session direction is FROM_CLIENT\n"););

            /* Sender is client (src port is higher) */
            lwssn->s5_state.session_flags |= SSNFLAG_SEEN_CLIENT;

            if((p->tcph->th_flags & (TH_CWR|TH_ECE)) == (TH_CWR|TH_ECE))
            {
                lwssn->s5_state.session_flags |= SSNFLAG_ECN_CLIENT_QUERY;
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

            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "seglist_base_seq = %X\n", tmp->server.seglist_base_seq););
            tmp->server.s_mgr.state = TCP_STATE_ESTABLISHED;

            tmp->client.flags |= Stream5GetTcpTimestamp(p, &tmp->client.ts_last, 0);
            if (tmp->client.ts_last == 0)
                tmp->client.flags |= TF_TSTAMP_ZERO;
            tmp->client.flags |= Stream5GetMss(p, &tmp->client.mss);
            tmp->client.flags |= Stream5GetWscale(p, &tmp->client.wscale);

            /* Set the Stream5TcpPolicy for each direction (pkt from client) */
            tmp->client.tcp_policy = dstPolicy;  // FIXIT BINDING use external for both dirs
            tmp->server.tcp_policy = dstPolicy;

            /* Server is destination */
            server_port = p->dp;

            CopyMacAddr(p, tmp, FROM_CLIENT);
        }
        else
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "Session direction is FROM_SERVER\n"););

            /* Sender is server (src port is lower) */
            lwssn->s5_state.session_flags |= SSNFLAG_SEEN_SERVER;

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

            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "seglist_base_seq = %X\n", tmp->client.seglist_base_seq););
            tmp->client.s_mgr.state = TCP_STATE_ESTABLISHED;

            tmp->server.flags |= Stream5GetTcpTimestamp(p, &tmp->server.ts_last, 0);
            if (tmp->server.ts_last == 0)
                tmp->server.flags |= TF_TSTAMP_ZERO;
            tmp->server.flags |= Stream5GetMss(p, &tmp->server.mss);
            tmp->server.flags |= Stream5GetWscale(p, &tmp->server.wscale);

            /* Set the Stream5TcpPolicy for each direction (pkt from server) */
            tmp->server.tcp_policy = dstPolicy;  // FIXIT BINDING use external for both dirs
            tmp->client.tcp_policy = dstPolicy;
            lwssn->policy = tmp->server.tcp_policy;

            /* Client is destination */
            server_port = p->sp;

            CopyMacAddr(p, tmp, FROM_SERVER);
        }
    }

    if (tmp)
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "adding TcpSession to lightweight session\n"););
        lwssn->protocol = GET_IPH_PROTO(p);
        tmp->flow = lwssn;

        /* New session, previous was marked as reset.  Clear the
         * reset flag. */
        if (lwssn->s5_state.session_flags & SSNFLAG_RESET)
            lwssn->s5_state.session_flags &= ~SSNFLAG_RESET;

        SetOSPolicy(tmp);

        if ( (lwssn->s5_state.session_flags & SSNFLAG_CLIENT_SWAP) &&
            !(lwssn->s5_state.session_flags & SSNFLAG_CLIENT_SWAPPED) )
        {
            StreamTracker trk = tmp->client;
            snort_ip ip = lwssn->client_ip;
            uint16_t port = lwssn->client_port;

            tmp->client = tmp->server;
            tmp->server = trk;

            lwssn->client_ip = lwssn->server_ip;
            lwssn->server_ip = ip;

            lwssn->client_port = lwssn->server_port;
            lwssn->server_port = port;

            if ( !TwoWayTraffic(lwssn) )
            {
                if ( lwssn->s5_state.session_flags & SSNFLAG_SEEN_CLIENT )
                {
                    lwssn->s5_state.session_flags ^= SSNFLAG_SEEN_CLIENT;
                    lwssn->s5_state.session_flags |= SSNFLAG_SEEN_SERVER;
                }
                else if ( lwssn->s5_state.session_flags & SSNFLAG_SEEN_SERVER )
                {
                    lwssn->s5_state.session_flags ^= SSNFLAG_SEEN_SERVER;
                    lwssn->s5_state.session_flags |= SSNFLAG_SEEN_CLIENT;
                }
            }
            lwssn->s5_state.session_flags |= SSNFLAG_CLIENT_SWAPPED;
        }
        /* Set up the flush behaviour, based on the configured info
         * for the server and client ports.
         */
        /* Yes, the server flush manager gets the info from the
         * policy's server port's the flush policy from the client
         * and visa-versa.
         *
         * For example, when policy said 'ports client 80', that means
         * reassemble packets from the client side (stored in the server's
         * flush buffer in the session) destined for port 80.  Port 80 is
         * the server port and we're reassembling the client side.
         * That should make this almost as clear as opaque mud!
         */
        if (tmp->server.tcp_policy->flush_config_protocol[lwssn->s5_state.application_protocol].configured == 1)
        {
            StreamTracker* pst = &tmp->server;
            uint8_t flush_policy =
                pst->tcp_policy->flush_config_protocol[lwssn->s5_state.application_protocol].client.flush_policy;
            InitFlushMgrByService(lwssn, pst, lwssn->s5_state.application_protocol, true, flush_policy);
        }
        else
        {
            StreamTracker* pst = &tmp->server;
            uint8_t flush_policy =
                pst->tcp_policy->flush_config[server_port].client.flush_policy;
            InitFlushMgrByPort(lwssn, pst, server_port, true, flush_policy);
        }

        if (tmp->client.tcp_policy->flush_config_protocol[lwssn->s5_state.application_protocol].configured == 1)
        {
            StreamTracker* pst = &tmp->client;
            uint8_t flush_policy =
                pst->tcp_policy->flush_config_protocol[lwssn->s5_state.application_protocol].server.flush_policy;
            InitFlushMgrByService(lwssn, pst, lwssn->s5_state.application_protocol, false, flush_policy);
        }
        else
        {
            StreamTracker* pst = &tmp->client;
            uint8_t flush_policy =
                pst->tcp_policy->flush_config[server_port].server.flush_policy;
            InitFlushMgrByPort(lwssn, pst, server_port, false, flush_policy);
        }


#ifdef DEBUG_STREAM5
        PrintTcpSession(tmp);
#endif
        lwssn->set_expire(p, dstPolicy->session_timeout);

        tcpStats.streamtrackers_created++;

        AddStreamSession(&sfBase, lwssn->session_state & STREAM5_STATE_MIDSTREAM ? SSNFLAG_MIDSTREAM : 0);

        Stream5UpdatePerfBaseState(&sfBase, tmp->flow, TCP_STATE_SYN_SENT);

        EventInternal(INTERNAL_EVENT_SESSION_ADD);

        tmp->ecn = 0;
        tmp->tcp_init = true;
        PREPROC_PROFILE_END(s5TcpNewSessPerfStats);
        return 1;
    }

    PREPROC_PROFILE_END(s5TcpNewSessPerfStats);
    return 0;
}

static int RepeatedSyn(
    StreamTracker *listener, StreamTracker *talker,
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
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Got syn on established windows ssn, which causes Reset,"
                "bailing\n"););
            tcpssn->flow->s5_state.session_flags |= SSNFLAG_RESET;
            talker->s_mgr.state = TCP_STATE_CLOSED;
            return ACTION_RST;
        }
        else
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Got syn on established windows ssn, not causing Reset,"
                "bailing\n"););
            Discard();
            return ACTION_NOTHING;
        }
        break;
    case STREAM_POLICY_MACOS:
        /* MACOS ignores a 2nd SYN, regardless of the sequence number. */
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Got syn on established macos ssn, not causing Reset,"
            "bailing\n"););
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
        if(!SEQ_EQ(tdb->seq,talker->isn))
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Got syn on established ssn, which causes Reset, bailing\n"););
            tcpssn->flow->s5_state.session_flags |= SSNFLAG_RESET;
            talker->s_mgr.state = TCP_STATE_CLOSED;
            return ACTION_RST;
        }
        else
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Got syn on established ssn, not causing Reset,"
                "bailing\n"););
            Discard();
            return ACTION_NOTHING;
        }
        break;
    }
    return ACTION_NOTHING;
}

static void LogTcpEvents(Stream5TcpPolicy *s5TcpPolicy, int eventcode)
{
    if ( !eventcode )
        return;

    if (eventcode & EVENT_SYN_ON_EST)
        EventSynOnEst(s5TcpPolicy);

    if (eventcode & EVENT_DATA_ON_SYN)
        EventDataOnSyn(s5TcpPolicy);

    if (eventcode & EVENT_DATA_ON_CLOSED)
        EventDataOnClosed(s5TcpPolicy);

    if (eventcode & EVENT_BAD_TIMESTAMP)
        EventBadTimestamp(s5TcpPolicy);

    if (eventcode & EVENT_BAD_SEGMENT)
        EventBadSegment(s5TcpPolicy);

    if (eventcode & EVENT_WINDOW_TOO_LARGE)
        EventWindowTooLarge(s5TcpPolicy);

    if (eventcode & EVENT_EXCESSIVE_TCP_OVERLAPS)
        EventExcessiveOverlap(s5TcpPolicy);

    if (eventcode & EVENT_DATA_AFTER_RESET)
        EventDataAfterReset(s5TcpPolicy);

    if (eventcode & EVENT_SESSION_HIJACK_CLIENT)
        EventSessionHijackedClient(s5TcpPolicy);

    if (eventcode & EVENT_SESSION_HIJACK_SERVER)
        EventSessionHijackedServer(s5TcpPolicy);

    if (eventcode & EVENT_DATA_WITHOUT_FLAGS)
        EventDataWithoutFlags(s5TcpPolicy);

    if (eventcode & EVENT_4WHS)
        Event4whs(s5TcpPolicy);

    if (eventcode & EVENT_NO_TIMESTAMP)
        EventNoTimestamp(s5TcpPolicy);

    if (eventcode & EVENT_BAD_RST)
        EventBadReset(s5TcpPolicy);

    if (eventcode & EVENT_BAD_FIN)
        EventBadFin(s5TcpPolicy);

    if (eventcode & EVENT_BAD_ACK)
        EventBadAck(s5TcpPolicy);

    if (eventcode & EVENT_DATA_AFTER_RST_RCVD)
        EventDataAfterRstRcvd(s5TcpPolicy);

    if (eventcode & EVENT_WINDOW_SLAM)
        EventWindowSlam(s5TcpPolicy);
}

static int ProcessTcp(Flow *lwssn, Packet *p, TcpDataBlock *tdb,
        Stream5TcpPolicy *s5TcpPolicy)
{
    int retcode = ACTION_NOTHING;
    int eventcode = 0;
    int got_ts = 0;
    int new_ssn = 0;
    int ts_action = ACTION_NOTHING;
    TcpSession *tcpssn = NULL;
    StreamTracker *talker = NULL;
    StreamTracker *listener = NULL;
    uint32_t require3Way = true; // FIXIT (s5TcpPolicy->flags & STREAM5_CONFIG_REQUIRE_3WHS);
    STREAM5_DEBUG_WRAP(char *t = NULL; char *l = NULL;)
    PROFILE_VARS;

    if (lwssn->protocol != IPPROTO_TCP)
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Lightweight session not TCP on TCP packet\n"););
        return retcode;
    }

    tcpssn = (TcpSession*)lwssn->session;

    PREPROC_PROFILE_START(s5TcpStatePerfStats);

    if ( !tcpssn->tcp_init )
    {
        if ( ScPafEnabled() )
        {
            char ignore = flow_con->expected_flow(lwssn, p);

            if ( ignore )
            {
                Stream5SetReassemblyTcp(
                    lwssn, STREAM_FLPOLICY_IGNORE, ignore, STREAM_FLPOLICY_SET_ABSOLUTE);
                PREPROC_PROFILE_END(s5TcpStatePerfStats);
                return retcode;
            }
        }

        if (TCP_ISFLAGSET(p->tcph, TH_SYN) &&
            !TCP_ISFLAGSET(p->tcph, TH_ACK))
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Stream5 SYN PACKET, establishing lightweight"
                    "session direction.\n"););
            /* SYN packet from client */
            lwssn->s5_state.direction = FROM_CLIENT;
            IP_COPY_VALUE(lwssn->client_ip, GET_SRC_IP(p));
            lwssn->client_port = p->tcph->th_sport;
            IP_COPY_VALUE(lwssn->server_ip, GET_DST_IP(p));
            lwssn->server_port = p->tcph->th_dport;
            lwssn->session_state |= STREAM5_STATE_SYN;

            if (require3Way || (Stream5PacketHasWscale(p) & TF_WSCALE) ||
                ((p->dsize > 0) &&
                 (StreamGetPolicy(lwssn, s5TcpPolicy, FROM_CLIENT) ==
                     STREAM_POLICY_MACOS)))
            {
                /* Create TCP session if we
                 * 1) require 3-WAY HS, OR
                 * 2) client sent wscale option, OR
                 * 3) have data and its a MAC OS policy -- MAC
                 *    is the only one that accepts data on SYN
                 *    (and thus requires a TCP session at this point)
                 */
                NewTcpSession(p, lwssn, tdb, s5TcpPolicy);
                new_ssn = 1;
                NormalTrackECN(tcpssn, (TCPHdr*)p->tcph, require3Way);
            }

            /* Nothing left todo here */
        }
        else if (TCP_ISFLAGSET(p->tcph, (TH_SYN|TH_ACK)))
        {
            /* SYN-ACK from server */
            if ((lwssn->session_state == STREAM5_STATE_NONE) ||
                (lwssn->s5_state.session_flags & SSNFLAG_RESET))
            {
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "Stream5 SYN|ACK PACKET, establishing lightweight"
                        "session direction.\n"););
                lwssn->s5_state.direction = FROM_SERVER;
                IP_COPY_VALUE(lwssn->client_ip, GET_DST_IP(p));
                lwssn->client_port = p->tcph->th_dport;
                IP_COPY_VALUE(lwssn->server_ip, GET_SRC_IP(p));
                lwssn->server_port = p->tcph->th_sport;
            }
            lwssn->session_state |= STREAM5_STATE_SYN_ACK;
            NewTcpSession(p, lwssn, tdb, s5TcpPolicy);
            new_ssn = 1;
            NormalTrackECN(tcpssn, (TCPHdr*)p->tcph, require3Way);
            /* Nothing left todo here */
        }
        else if (TCP_ISFLAGSET(p->tcph, TH_ACK) &&
                !TCP_ISFLAGSET(p->tcph, TH_RST) &&
                 (lwssn->session_state & STREAM5_STATE_SYN_ACK))
        {
            /* TODO: do we need to verify the ACK field is >= the seq of the SYN-ACK? */

            /* 3-way Handshake complete, create TCP session */
            lwssn->session_state |= STREAM5_STATE_ACK | STREAM5_STATE_ESTABLISHED;
            NewTcpSession(p, lwssn, tdb, s5TcpPolicy);
            new_ssn = 1;
            NormalTrackECN(tcpssn, (TCPHdr*)p->tcph, require3Way);
            Stream5UpdatePerfBaseState(&sfBase, lwssn, TCP_STATE_ESTABLISHED);
        }
        else
        {
            /* create session on data, need to figure out direction, etc */
            /* Assume from client, can update later */
            if (p->sp > p->dp)
            {
                lwssn->s5_state.direction = FROM_CLIENT;
                IP_COPY_VALUE(lwssn->client_ip, GET_SRC_IP(p));
                lwssn->client_port = p->tcph->th_sport;
                IP_COPY_VALUE(lwssn->server_ip, GET_DST_IP(p));
                lwssn->server_port = p->tcph->th_dport;
            }
            else
            {
                lwssn->s5_state.direction = FROM_SERVER;
                IP_COPY_VALUE(lwssn->client_ip, GET_DST_IP(p));
                lwssn->client_port = p->tcph->th_dport;
                IP_COPY_VALUE(lwssn->server_ip, GET_SRC_IP(p));
                lwssn->server_port = p->tcph->th_sport;
            }
            lwssn->session_state |= STREAM5_STATE_MIDSTREAM;
            lwssn->s5_state.session_flags |= SSNFLAG_MIDSTREAM;

            NewTcpSession(p, lwssn, tdb, s5TcpPolicy);
            new_ssn = 1;
            NormalTrackECN(tcpssn, (TCPHdr*)p->tcph, require3Way);

            if (lwssn->session_state & STREAM5_STATE_ESTABLISHED)
                Stream5UpdatePerfBaseState(&sfBase, lwssn, TCP_STATE_ESTABLISHED);
        }
    }
    else
    {
        /* If session is already marked as established */
        if ( !(lwssn->session_state & STREAM5_STATE_ESTABLISHED) )
        {
            /* If not requiring 3-way Handshake... */

            /* TCP session created on TH_SYN above,
             * or maybe on SYN-ACK, or anything else */

            /* Need to update Lightweight session state */
            if (TCP_ISFLAGSET(p->tcph, (TH_SYN|TH_ACK)))
            {
                /* SYN-ACK from server */
                if (lwssn->session_state != STREAM5_STATE_NONE)
                {
                    lwssn->session_state |= STREAM5_STATE_SYN_ACK;
                }
            }
            else if (TCP_ISFLAGSET(p->tcph, TH_ACK) &&
                     (lwssn->session_state & STREAM5_STATE_SYN_ACK))
            {
                lwssn->session_state |= STREAM5_STATE_ACK | STREAM5_STATE_ESTABLISHED;
                Stream5UpdatePerfBaseState(&sfBase, lwssn, TCP_STATE_ESTABLISHED);
            }
        }
        if (TCP_ISFLAGSET(p->tcph, TH_SYN))
            NormalTrackECN(tcpssn, (TCPHdr*)p->tcph, require3Way);
    }

    /* figure out direction of this packet */
    lwssn->set_direction(p);

    if(p->packet_flags & PKT_FROM_SERVER)
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Stream5: Updating on packet from server\n"););
        lwssn->s5_state.session_flags |= SSNFLAG_SEEN_SERVER;
        if (tcpssn)
        {
            talker = &tcpssn->server;
            listener = &tcpssn->client;
        }

        STREAM5_DEBUG_WRAP(
                t = "Server";
                l = "Client");

        if ( talker && talker->s_mgr.state == TCP_STATE_LISTEN &&
            ((p->tcph->th_flags & (TH_SYN|TH_ACK)) == TH_SYN) )
        {
            eventcode |= EVENT_4WHS;
        }
        /* If we picked this guy up midstream, finish the initialization */
        if ((lwssn->session_state & STREAM5_STATE_MIDSTREAM) &&
            !(lwssn->session_state & STREAM5_STATE_ESTABLISHED))
        {
            FinishServerInit(p, tdb, tcpssn);
            if((p->tcph->th_flags & TH_ECE) &&
                lwssn->s5_state.session_flags & SSNFLAG_ECN_CLIENT_QUERY)
            {
                lwssn->s5_state.session_flags |= SSNFLAG_ECN_SERVER_REPLY;
            }

            if (lwssn->s5_state.session_flags & SSNFLAG_SEEN_CLIENT)
            {
                // should TCP state go to established too?
                lwssn->session_state |= STREAM5_STATE_ESTABLISHED;
                lwssn->s5_state.session_flags |= SSNFLAG_ESTABLISHED;
                Stream5UpdatePerfBaseState(&sfBase, lwssn, TCP_STATE_ESTABLISHED);
            }
        }
        if ( !lwssn->inner_server_ttl )
            lwssn->set_ttl(p, false);
    }
    else
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Stream5: Updating on packet from client\n"););
        /* if we got here we had to see the SYN already... */
        lwssn->s5_state.session_flags |= SSNFLAG_SEEN_CLIENT;
        if (tcpssn)
        {
            talker = &tcpssn->client;
            listener = &tcpssn->server;
        }

        STREAM5_DEBUG_WRAP(
                t = "Client";
                l = "Server";);

        if ((lwssn->session_state & STREAM5_STATE_MIDSTREAM) &&
            !(lwssn->session_state & STREAM5_STATE_ESTABLISHED))
        {
            /* Midstream and seen server. */
            if (lwssn->s5_state.session_flags & SSNFLAG_SEEN_SERVER)
            {
                lwssn->session_state |= STREAM5_STATE_ESTABLISHED;
                lwssn->s5_state.session_flags |= SSNFLAG_ESTABLISHED;
            }
        }
        if ( !lwssn->inner_client_ttl )
            lwssn->set_ttl(p, true);
    }

    /*
     * check for SYN on reset session
     */
    if ((lwssn->s5_state.session_flags & SSNFLAG_RESET) &&
        (p->tcph->th_flags & TH_SYN))
    {
        if ((!tcpssn) ||
            ((listener->s_mgr.state == TCP_STATE_CLOSED) ||
             (talker->s_mgr.state == TCP_STATE_CLOSED)))
        {
            /* Listener previously issued a reset */
            /* Talker is re-SYN-ing */
            TcpSessionCleanup(lwssn, 1);

            if (p->tcph->th_flags & TH_RST)
            {
                /* Got SYN/RST.  We're done. */
                NormalTrimPayloadIf(p, NORM_TCP_TRIM, 0, tdb);
                tcpssn = NULL;
                PREPROC_PROFILE_END(s5TcpStatePerfStats);
                return retcode | ACTION_RST;
            }
            else if (TCP_ISFLAGSET(p->tcph, TH_SYN) &&
                     !TCP_ISFLAGSET(p->tcph, TH_ACK))
            {
                lwssn->s5_state.direction = FROM_CLIENT;
                IP_COPY_VALUE(lwssn->client_ip, GET_SRC_IP(p));
                lwssn->client_port = p->tcph->th_sport;
                IP_COPY_VALUE(lwssn->server_ip, GET_DST_IP(p));
                lwssn->server_port = p->tcph->th_dport;
                lwssn->session_state = STREAM5_STATE_SYN;
                lwssn->set_ttl(p, true);
                NewTcpSession(p, lwssn, tdb, s5TcpPolicy);
                tcpssn = (TcpSession *)lwssn->session;
                new_ssn = 1;
                NormalTrackECN(tcpssn, (TCPHdr*)p->tcph, require3Way);

                if (tcpssn)
                {
                    listener = &tcpssn->server;
                    talker = &tcpssn->client;
                }
                lwssn->s5_state.session_flags = SSNFLAG_SEEN_CLIENT;
            }
            else if (TCP_ISFLAGSET(p->tcph, (TH_SYN|TH_ACK)))
            {
                lwssn->s5_state.direction = FROM_SERVER;
                IP_COPY_VALUE(lwssn->client_ip, GET_DST_IP(p));
                lwssn->client_port = p->tcph->th_dport;
                IP_COPY_VALUE(lwssn->server_ip, GET_SRC_IP(p));
                lwssn->server_port = p->tcph->th_sport;
                lwssn->session_state = STREAM5_STATE_SYN_ACK;
                lwssn->set_ttl(p, false);
                NewTcpSession(p, lwssn, tdb, s5TcpPolicy);
                tcpssn = (TcpSession *)lwssn->session;
                new_ssn = 1;
                NormalTrackECN(tcpssn, (TCPHdr*)p->tcph, require3Way);

                if (tcpssn)
                {
                    listener = &tcpssn->client;
                    talker = &tcpssn->server;
                }
                lwssn->s5_state.session_flags = SSNFLAG_SEEN_SERVER;
            }
        }
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Got SYN pkt on reset ssn, re-SYN-ing\n"););
    }

    // FIXIT why flush here instead of just purge?
    // s5_ignored_session() may be disabling detection too soon if we really want to flush
    if ( stream.ignored_session(lwssn, p) )
    {
        if ( talker && (talker->flags & TF_FORCE_FLUSH) )
        {
            Stream5FlushTalker(p, lwssn);
            talker->flags &= ~TF_FORCE_FLUSH;
        }
        if ( listener && (listener->flags & TF_FORCE_FLUSH) )
        {
            Stream5FlushListener(p, lwssn);
            listener->flags &= ~TF_FORCE_FLUSH;
        }
        p->packet_flags |= PKT_IGNORE;
        retcode |= ACTION_DISABLE_INSPECTION;
    }

    /* Check if the session is to be ignored */
    if ( !ScPafEnabled() )
    {
        char ignore = flow_con->expected_flow(lwssn, p);

        if ( ignore )
        {
            Stream5SetReassemblyTcp(
                lwssn, STREAM_FLPOLICY_IGNORE, ignore, STREAM_FLPOLICY_SET_ABSOLUTE);
            PREPROC_PROFILE_END(s5TcpStatePerfStats);
            return retcode;
        }
    }

    /* Handle data on SYN */
    if ((p->dsize) && TCP_ISFLAGSET(p->tcph, TH_SYN))
    {
        /* MacOS accepts data on SYN, so don't alert if policy is MACOS */
        if (StreamGetPolicy(lwssn, s5TcpPolicy, FROM_CLIENT) !=
            STREAM_POLICY_MACOS)
        {
            if ( Normalize_IsEnabled(snort_conf, NORM_TCP_TRIM) )
            {
                NormalTrimPayload(p, 0, tdb); // remove data on SYN
            }
            else
            {
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Got data on SYN packet, not processing it\n"););
                //EventDataOnSyn(s5TcpPolicy);
                eventcode |= EVENT_DATA_ON_SYN;
                retcode |= ACTION_BAD_PKT;
            }
        }
    }

    if (!tcpssn)
    {
        LogTcpEvents(s5TcpPolicy, eventcode);
        PREPROC_PROFILE_END(s5TcpStatePerfStats);
        return retcode;
    }

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "   %s [talker] state: %s\n", t,
                state_names[talker->s_mgr.state]););
    STREAM5_DEBUG_WRAP(PrintFlushMgr(&talker->flush_mgr););
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "   %s state: %s(%d)\n", l,
                state_names[listener->s_mgr.state],
                listener->s_mgr.state););
    STREAM5_DEBUG_WRAP(PrintFlushMgr(&listener->flush_mgr););

    // may find better placement to eliminate redundant flag checks
    if(p->tcph->th_flags & TH_SYN)
        talker->s_mgr.sub_state |= SUB_SYN_SENT;
    if(p->tcph->th_flags & TH_ACK)
        talker->s_mgr.sub_state |= SUB_ACK_SENT;

    /*
     * process SYN ACK on unestablished sessions
     */
    if( (TCP_STATE_SYN_SENT == listener->s_mgr.state) &&
        (TCP_STATE_LISTEN == talker->s_mgr.state) )
    {
        if(p->tcph->th_flags & TH_ACK)
        {
            /*
             * make sure we've got a valid segment
             */
            if(!IsBetween(listener->l_unackd, listener->l_nxt_seq, tdb->ack))
            {
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "Pkt ack is out of bounds, bailing!\n"););
                Discard();
                NormalTrimPayloadIf(p, NORM_TCP_TRIM, 0, tdb);
                LogTcpEvents(listener->tcp_policy, eventcode);
                PREPROC_PROFILE_END(s5TcpStatePerfStats);
                return retcode | ACTION_BAD_PKT;
            }
        }

        talker->flags |= Stream5GetTcpTimestamp(p, &tdb->ts, 0);
        if (tdb->ts == 0)
            talker->flags |= TF_TSTAMP_ZERO;

        /*
         * catch resets sent by server
         */
        if(p->tcph->th_flags & TH_RST)
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "got RST\n"););

            NormalTrimPayloadIf(p, NORM_TCP_TRIM, 0, tdb);

            /* Reset is valid when in SYN_SENT if the
             * ack field ACKs the SYN.
             */
            if(ValidRstSynSent(listener, tdb))
            {
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "got RST, closing talker\n"););
                /* Reset is valid */
                /* Mark session as reset... Leave it around so that any
                 * additional data sent from one side or the other isn't
                 * processed (and is dropped in inline mode).
                 */
                lwssn->s5_state.session_flags |= SSNFLAG_RESET;
                talker->s_mgr.state = TCP_STATE_CLOSED;
                Stream5UpdatePerfBaseState(&sfBase, lwssn, TCP_STATE_CLOSING);
                /* Leave listener open, data may be in transit */
                LogTcpEvents(listener->tcp_policy, eventcode);
                PREPROC_PROFILE_END(s5TcpStatePerfStats);
                return retcode | ACTION_RST;
            }
            /* Reset not valid. */
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "bad sequence number, bailing\n"););
            Discard();
            eventcode |= EVENT_BAD_RST;
            NormalDropPacketIf(p, NORM_TCP);
            LogTcpEvents(listener->tcp_policy, eventcode);
            PREPROC_PROFILE_END(s5TcpStatePerfStats);
            return retcode;
        }

        /*
         * finish up server init
         */
        if(p->tcph->th_flags & TH_SYN)
        {
            FinishServerInit(p, tdb, tcpssn);
            if (talker->flags & TF_TSTAMP)
            {
                talker->ts_last_pkt = p->pkth->ts.tv_sec;
                talker->ts_last = tdb->ts;
            }
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "Finish server init got called!\n"););
        }
        else
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "Finish server init didn't get called!\n"););
        }

        if((p->tcph->th_flags & TH_ECE) &&
            lwssn->s5_state.session_flags & SSNFLAG_ECN_CLIENT_QUERY)
        {
            lwssn->s5_state.session_flags |= SSNFLAG_ECN_SERVER_REPLY;
        }

        /*
         * explicitly set the state
         */
        listener->s_mgr.state = TCP_STATE_SYN_SENT;
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Accepted SYN ACK\n"););
        LogTcpEvents(listener->tcp_policy, eventcode);
        PREPROC_PROFILE_END(s5TcpStatePerfStats);
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
    if(p->tcph->th_flags & TH_RST)
    {
        NormalTrimPayloadIf(p, NORM_TCP_TRIM, 0, tdb);

        if(ValidRst(lwssn, listener, tdb))
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Got RST, bailing\n"););

            if (
                listener->s_mgr.state == TCP_STATE_FIN_WAIT_1 ||
                listener->s_mgr.state == TCP_STATE_FIN_WAIT_2 ||
                listener->s_mgr.state == TCP_STATE_CLOSE_WAIT ||
                listener->s_mgr.state == TCP_STATE_CLOSING
            ) {
                Stream5FlushTalker(p, lwssn);
                Stream5FlushListener(p, lwssn);
                lwssn->free_application_data();
            }
            lwssn->s5_state.session_flags |= SSNFLAG_RESET;
            talker->s_mgr.state = TCP_STATE_CLOSED;
            talker->s_mgr.sub_state |= SUB_RST_SENT;
            Stream5UpdatePerfBaseState(&sfBase, lwssn, TCP_STATE_CLOSING);

            if ( Normalize_IsEnabled(snort_conf, NORM_TCP_IPS) )
                listener->s_mgr.state = TCP_STATE_CLOSED;
            /* else for ids:
                leave listener open, data may be in transit */

            LogTcpEvents(listener->tcp_policy, eventcode);
            PREPROC_PROFILE_END(s5TcpStatePerfStats);
            return retcode | ACTION_RST;
        }
        /* Reset not valid. */
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "bad sequence number, bailing\n"););
        Discard();
        eventcode |= EVENT_BAD_RST;
        NormalDropPacketIf(p, NORM_TCP);
        LogTcpEvents(listener->tcp_policy, eventcode);
        PREPROC_PROFILE_END(s5TcpStatePerfStats);
        return retcode | ts_action;
    }
    else
    {
        /* check for valid seqeuence/retrans */
        if ( (listener->s_mgr.state >= TCP_STATE_ESTABLISHED) &&
            !ValidSeq(p, lwssn, listener, tdb) )
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "bad sequence number, bailing\n"););
            Discard();
            NormalTrimPayloadIf(p, NORM_TCP_TRIM, 0, tdb);
            LogTcpEvents(listener->tcp_policy, eventcode);
            PREPROC_PROFILE_END(s5TcpStatePerfStats);
            return retcode | ts_action;
        }
    }

    if (ts_action != ACTION_NOTHING)
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "bad timestamp, bailing\n"););
        Discard();
        // this packet was normalized elsewhere
        LogTcpEvents(listener->tcp_policy, eventcode);
        PREPROC_PROFILE_END(s5TcpStatePerfStats);
        return retcode | ts_action;
    }

    /*
     * update PAWS timestamps
     */
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "PAWS update tdb->seq %lu > listener->r_win_base %lu\n",
                tdb->seq, listener->r_win_base););
    if(got_ts && SEQ_EQ(listener->r_win_base, tdb->seq))
    {
        if((int32_t)(tdb->ts - talker->ts_last) >= 0 ||
           (uint32_t)p->pkth->ts.tv_sec >= talker->ts_last_pkt+PAWS_24DAYS)
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "updating timestamps...\n"););
            talker->ts_last = tdb->ts;
            talker->ts_last_pkt = p->pkth->ts.tv_sec;
        }
    }
    else
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "not updating timestamps...\n"););
    }

    /*
     * check for repeat SYNs
     */
    if ( !new_ssn &&
        ((p->tcph->th_flags & (TH_SYN|TH_ACK)) == TH_SYN) )
    {
        int action;
        if ( !SEQ_EQ(tdb->seq, talker->isn) &&
             NormalDropPacketIf(p, NORM_TCP) )
            action = ACTION_BAD_PKT;
        else
        if ( talker->s_mgr.state >= TCP_STATE_ESTABLISHED )
            action = RepeatedSyn(listener, talker, tdb, tcpssn);
        else
            action = ACTION_NOTHING;

        if (action != ACTION_NOTHING)
        {
            /* got a bad SYN on the session, alert! */
            eventcode |= EVENT_SYN_ON_EST;
            LogTcpEvents(listener->tcp_policy, eventcode);
            PREPROC_PROFILE_END(s5TcpStatePerfStats);
            return retcode | action;
        }
    }

    /*
     * Check that the window is within the limits
     */
    if (listener->tcp_policy->max_window && (tdb->win > listener->tcp_policy->max_window))
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Got window that was beyond the allowed policy value, bailing\n"););
        /* got a window too large, alert! */
        eventcode |= EVENT_WINDOW_TOO_LARGE;
        Discard();
        NormalDropPacketIf(p, NORM_TCP);
        LogTcpEvents(listener->tcp_policy, eventcode);
        PREPROC_PROFILE_END(s5TcpStatePerfStats);
        return retcode | ACTION_BAD_PKT;
    }
    else if ((p->packet_flags & PKT_FROM_CLIENT)
            && (tdb->win <= SLAM_MAX) && (tdb->ack == listener->isn + 1)
            && !(p->tcph->th_flags & (TH_FIN|TH_RST))
            && !(lwssn->s5_state.session_flags & SSNFLAG_MIDSTREAM))
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Window slammed shut!\n"););
        /* got a window slam alert! */
        eventcode |= EVENT_WINDOW_SLAM;
        Discard();

        if ( NormalDropPacketIf(p, NORM_TCP) )
        {
            LogTcpEvents(listener->tcp_policy, eventcode);
            PREPROC_PROFILE_END(s5TcpStatePerfStats);
            return retcode | ACTION_BAD_PKT;
        }
    }

    if(talker->s_mgr.state_queue != TCP_STATE_NONE)
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Found queued state transition on ack 0x%X, "
                    "current 0x%X!\n", talker->s_mgr.transition_seq,
                    tdb->ack););
        if(tdb->ack == talker->s_mgr.transition_seq)
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "accepting transition!\n"););
            talker->s_mgr.state = talker->s_mgr.state_queue;
            talker->s_mgr.state_queue = TCP_STATE_NONE;
        }
    }

    /*
     * process ACK flags
     */
    if(p->tcph->th_flags & TH_ACK)
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Got an ACK...\n"););
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "   %s [listener] state: %s\n", l,
                    state_names[listener->s_mgr.state]););

        switch(listener->s_mgr.state)
        {
            case TCP_STATE_SYN_SENT:
                    break;
            case TCP_STATE_SYN_RCVD:
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "listener state is SYN_SENT...\n"););
                if ( IsBetween(listener->l_unackd, listener->l_nxt_seq, tdb->ack) )
                {
                    UpdateSsn(p, listener, talker, tdb);
                    lwssn->s5_state.session_flags |= SSNFLAG_ESTABLISHED;
                    lwssn->session_state |= STREAM5_STATE_ESTABLISHED;
                    listener->s_mgr.state = TCP_STATE_ESTABLISHED;
                    talker->s_mgr.state = TCP_STATE_ESTABLISHED;
                    Stream5UpdatePerfBaseState(&sfBase, lwssn, TCP_STATE_ESTABLISHED);
                    /* Indicate this packet completes 3-way handshake */
                    p->packet_flags |= PKT_STREAM_TWH;
                }

                talker->flags |= got_ts;
                if(got_ts && SEQ_EQ(listener->r_nxt_ack, tdb->seq))
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

                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "tdb->ack %X >= talker->r_nxt_ack %X\n",
                            tdb->ack, talker->r_nxt_ack););

                if ( SEQ_EQ(tdb->ack, listener->l_nxt_seq) )
                {
                    if ( (listener->os_policy == STREAM_POLICY_WINDOWS) && (tdb->win == 0) )
                    {
                        eventcode |= EVENT_WINDOW_SLAM;
                        Discard();

                        if ( NormalDropPacketIf(p, NORM_TCP) )
                        {
                            LogTcpEvents(listener->tcp_policy, eventcode);
                            PREPROC_PROFILE_END(s5TcpStatePerfStats);
                            return retcode | ACTION_BAD_PKT;
                        }
                    }

                    listener->s_mgr.state = TCP_STATE_FIN_WAIT_2;

                    if ( (p->tcph->th_flags & TH_FIN) )
                    {
                        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                                "seq ok, setting state!\n"););

                        if (talker->s_mgr.state_queue == TCP_STATE_NONE)
                        {
                            talker->s_mgr.state = TCP_STATE_LAST_ACK;
                        }
                        if ( lwssn->s5_state.session_flags & SSNFLAG_MIDSTREAM )
                        {
                            // FIXTHIS this should be handled below in fin section
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
                    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                                "bad ack!\n"););
                }
                break;

            case TCP_STATE_FIN_WAIT_2:
                UpdateSsn(p, listener, talker, tdb);
                if ( SEQ_GT(tdb->ack, listener->l_nxt_seq) )
                {
                    eventcode |= EVENT_BAD_ACK;
                    LogTcpEvents(talker->tcp_policy, eventcode);
                    NormalDropPacketIf(p, NORM_TCP);
                    PREPROC_PROFILE_END(s5TcpStatePerfStats);
                    return retcode | ACTION_BAD_PKT;
                }
                break;

            case TCP_STATE_CLOSING:
                UpdateSsn(p, listener, talker, tdb);
                if(SEQ_GEQ(tdb->end_seq, listener->r_nxt_ack))
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
                // FIXTHIS safe to ignore when inline?
                break;
        }
    }

    /*
     * handle data in the segment
     */
    if(p->dsize)
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "   %s state: %s(%d) getting data\n", l,
                    state_names[listener->s_mgr.state],
                    listener->s_mgr.state););

        // FIN means only that sender is done talking,
        // other side may continue yapping.
        if(TCP_STATE_FIN_WAIT_2 == talker->s_mgr.state ||
           TCP_STATE_TIME_WAIT == talker->s_mgr.state)
        {
            /* data on a segment when we're not accepting data any more */
            /* alert! */
            //EventDataOnClosed(talker->tcp_policy);
            eventcode |= EVENT_DATA_ON_CLOSED;
            retcode |= ACTION_BAD_PKT;
            NormalDropPacketIf(p, NORM_TCP);
        }
        else if (TCP_STATE_CLOSED == talker->s_mgr.state)
        {
            /* data on a segment when we're not accepting data any more */
            /* alert! */
            if (lwssn->s5_state.session_flags & SSNFLAG_RESET)
            {
                //EventDataAfterReset(listener->tcp_policy);
                if ( talker->s_mgr.sub_state & SUB_RST_SENT )
                    eventcode |= EVENT_DATA_AFTER_RESET;
                else
                    eventcode |= EVENT_DATA_AFTER_RST_RCVD;
            }
            else
            {
                //EventDataOnClosed(listener->tcp_policy);
                eventcode |= EVENT_DATA_ON_CLOSED;
            }
            retcode |= ACTION_BAD_PKT;
            NormalDropPacketIf(p, NORM_TCP);
        }
        else
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "Queuing data on listener, t %s, l %s...\n",
                        flush_policy_names[talker->flush_mgr.flush_policy],
                        flush_policy_names[listener->flush_mgr.flush_policy]););

            // these normalizations can't be done if we missed setup. and
            // window is zero in one direction until we've seen both sides.
            if ( !(lwssn->s5_state.session_flags & SSNFLAG_MIDSTREAM) )
            {
                if ( Normalize_IsEnabled(snort_conf, NORM_TCP_TRIM) )
                {
                    // sender of syn w/mss limits payloads from peer
                    // since we store mss on sender side, use listener mss
                    // same reasoning for window size
                    StreamTracker* st = listener;

                    // get the current window size
                    uint32_t max = (st->r_win_base + st->l_window) - st->r_nxt_ack;

                    // get lesser of current window or mss but
                    // if mss is zero it is unset so don't use it
                    if ( st->mss && st->mss < max )
                        max = st->mss;

                    NormalTrimPayload(p, max, tdb);
                }
                if ( Normalize_IsEnabled(snort_conf, NORM_TCP_ECN_STR) )
                    NormalCheckECN(tcpssn, p);
            }
            /*
             * dunno if this is RFC but fragroute testing expects it
             * for the record, I've seen FTP data sessions that send
             * data packets with no tcp flags set
             */
            if ((p->tcph->th_flags != 0) || (s5TcpPolicy->policy == STREAM_POLICY_LINUX))
            {
                ProcessTcpData(p, listener, tcpssn, tdb, s5TcpPolicy);
            }
            else
            {
                eventcode |= EVENT_DATA_WITHOUT_FLAGS;
                NormalDropPacketIf(p, NORM_TCP);
            }
        }
    }

    if(p->tcph->th_flags & TH_FIN)
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Got an FIN...\n"););
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "   %s state: %s(%d)\n", l,
                    state_names[talker->s_mgr.state],
                    talker->s_mgr.state););

        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "checking ack (0x%X) vs nxt_ack (0x%X)\n",
                    tdb->end_seq, listener->r_win_base););
        if(SEQ_LT(tdb->end_seq,listener->r_win_base))
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "FIN inside r_win_base, bailing\n"););
            goto dupfin;
        }
        else
        {
            // need substate since we don't change state immediately
            if ( (talker->s_mgr.state >= TCP_STATE_ESTABLISHED) &&
                !(talker->s_mgr.sub_state & SUB_FIN_SENT) )
            {
                talker->l_nxt_seq++;
                listener->r_nxt_ack++;
                talker->s_mgr.sub_state |= SUB_FIN_SENT;

                if ((listener->flush_mgr.flush_policy != STREAM_FLPOLICY_PROTOCOL) &&
                    (listener->flush_mgr.flush_policy != STREAM_FLPOLICY_PROTOCOL_IPS) &&
                    Normalize_IsEnabled(snort_conf, NORM_TCP_IPS))
                {
                    p->packet_flags |= PKT_PDU_TAIL;
                }
            }
            switch(talker->s_mgr.state)
            {
                case TCP_STATE_SYN_RCVD:
                case TCP_STATE_ESTABLISHED:
                    if (talker->s_mgr.state_queue == TCP_STATE_CLOSE_WAIT)
                    {
                        talker->s_mgr.state_queue = TCP_STATE_CLOSING;
                    }
                    talker->s_mgr.state = TCP_STATE_FIN_WAIT_1;
                    if ( !p->dsize )
                        CheckFlushPolicyOnData(tcpssn, talker, listener, tdb, p);

                    Stream5UpdatePerfBaseState(&sfBase, tcpssn->flow, TCP_STATE_CLOSING);
                    break;

                case TCP_STATE_CLOSE_WAIT:
                    talker->s_mgr.state = TCP_STATE_LAST_ACK;
                    break;

                default:
                    /* all other states stay where they are */
                    break;
            }

            if ( (talker->s_mgr.state == TCP_STATE_FIN_WAIT_1) ||
                      (talker->s_mgr.state == TCP_STATE_LAST_ACK) )
            {
                uint32_t end_seq = ( lwssn->s5_state.session_flags & SSNFLAG_MIDSTREAM ) ?
                      tdb->end_seq-1 : tdb->end_seq;

                if ( (listener->s_mgr.expected_flags == TH_ACK) &&
                     SEQ_GEQ(end_seq, listener->s_mgr.transition_seq) )
                {
                    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "FIN beyond previous, ignoring\n"););
                    eventcode |= EVENT_BAD_FIN;
                    LogTcpEvents(talker->tcp_policy, eventcode);
                    NormalDropPacketIf(p, NORM_TCP);
                    PREPROC_PROFILE_END(s5TcpStatePerfStats);
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

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "   %s [talker] state: %s\n", t,
                state_names[talker->s_mgr.state]););
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "   %s state: %s(%d)\n", l,
                state_names[listener->s_mgr.state],
                listener->s_mgr.state););

    /*
     * handle TIME_WAIT timer stuff
     */
    if((talker->s_mgr.state == TCP_STATE_TIME_WAIT && listener->s_mgr.state == TCP_STATE_CLOSED) ||
       (listener->s_mgr.state == TCP_STATE_TIME_WAIT && talker->s_mgr.state == TCP_STATE_CLOSED) ||
       (listener->s_mgr.state == TCP_STATE_TIME_WAIT && talker->s_mgr.state == TCP_STATE_TIME_WAIT))
    {
//dropssn:
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Session terminating, flushing session buffers\n"););

        if(p->packet_flags & PKT_FROM_SERVER)
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "flushing FROM_SERVER\n"););
            if(talker->seg_bytes_logical)
            {
                uint32_t flushed = flush_stream(tcpssn, talker, p,
                        GET_DST_IP(p), GET_SRC_IP(p),
                        p->tcph->th_dport, p->tcph->th_sport,
                        PKT_FROM_CLIENT);

                if(flushed)
                {
                    // FIXTHIS - these calls redundant?
                    purge_alerts(talker, talker->r_win_base, tcpssn->flow);
                    purge_to_seq(tcpssn, talker, talker->seglist->seq + flushed);
                }
            }

            if(listener->seg_bytes_logical)
            {
                uint32_t flushed = flush_stream(tcpssn, listener, p,
                        GET_SRC_IP(p), GET_DST_IP(p),
                        p->tcph->th_sport, p->tcph->th_dport,
                        PKT_FROM_SERVER);

                if(flushed)
                {
                    purge_alerts(listener, listener->r_win_base, tcpssn->flow);
                    purge_to_seq(tcpssn, listener, listener->seglist->seq + flushed);
                }
            }
        }
        else
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "flushing FROM_CLIENT\n"););
            if(listener->seg_bytes_logical)
            {
                uint32_t flushed = flush_stream(tcpssn, listener, p,
                        GET_SRC_IP(p), GET_DST_IP(p),
                        p->tcph->th_sport, p->tcph->th_dport,
                        PKT_FROM_CLIENT);

                if(flushed)
                {
                    purge_alerts(listener, listener->r_win_base, tcpssn->flow);
                    purge_to_seq(tcpssn, listener, listener->seglist->seq + flushed);
                }
            }

            if(talker->seg_bytes_logical)
            {
                uint32_t flushed = flush_stream(tcpssn, talker, p,
                        GET_DST_IP(p), GET_SRC_IP(p),
                        p->tcph->th_dport, p->tcph->th_sport,
                        PKT_FROM_SERVER);

                if(flushed)
                {
                    purge_alerts(talker, talker->r_win_base, tcpssn->flow);
                    purge_to_seq(tcpssn, talker, talker->seglist->seq + flushed);
                }
            }
        }
        LogTcpEvents(listener->tcp_policy, eventcode);
        /* The last ACK is a part of the session.  Delete the session after processing is complete. */
        TcpSessionCleanup(lwssn, 0);
        lwssn->session_state |= STREAM5_STATE_CLOSED;
        PREPROC_PROFILE_END(s5TcpStatePerfStats);
        return retcode | ACTION_LWSSN_CLOSED;
    }
    else if(listener->s_mgr.state == TCP_STATE_CLOSED && talker->s_mgr.state == TCP_STATE_SYN_SENT)
    {
        if(p->tcph->th_flags & TH_SYN &&
           !(p->tcph->th_flags & TH_ACK) &&
           !(p->tcph->th_flags & TH_RST))
        {
            lwssn->set_expire(p, s5TcpPolicy->session_timeout);
        }
    }

    if ( p->dsize > 0 )
        CheckFlushPolicyOnData(tcpssn, talker, listener, tdb, p);

    if ( p->tcph->th_flags & TH_ACK )
        CheckFlushPolicyOnAck(tcpssn, talker, listener, tdb, p);

    LogTcpEvents(listener->tcp_policy, eventcode);
    PREPROC_PROFILE_END(s5TcpStatePerfStats);
    return retcode;
}

// this is for post-ack flushing
static inline uint32_t GetReverseDir (const Packet* p)
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

static inline uint32_t GetForwardDir (const Packet* p)
{
    if ( p->packet_flags & PKT_FROM_SERVER )
        return PKT_FROM_SERVER;

    else if ( p->packet_flags & PKT_FROM_CLIENT )
        return PKT_FROM_CLIENT;

    return 0;
}

static inline int CheckFlushCoercion (
    Packet* p, FlushMgr* fm, uint16_t flush_factor
) {
    if ( !flush_factor )
        return 0;

    if (
        p->dsize &&
        (p->dsize < fm->last_size) &&
        (fm->last_count >= flush_factor) )
    {
        fm->last_size = 0;
        fm->last_count = 0;
        return 1;
    }
    if ( p->dsize > fm->last_size )
        fm->last_size = p->dsize;

    fm->last_count++;
    return 0;
}

static inline bool AutoDisable (StreamTracker* a, StreamTracker* b)
{
    if ( !a->flush_mgr.auto_disable )
        return false;

    a->flush_mgr.flush_policy = STREAM_FLPOLICY_IGNORE;
    purge_all(a);

    if ( b->flush_mgr.auto_disable )
    {
        b->flush_mgr.flush_policy = STREAM_FLPOLICY_IGNORE;
        purge_all(b);
    }
    return true;
}

// see flush_pdu_ackd() for details
// the key difference is that we operate on forward moving data
// because we don't wait until it is acknowledged
static inline uint32_t flush_pdu_ips (
    TcpSession* ssn, StreamTracker* trk, Packet* pkt, uint32_t* flags)
{
    bool to_srv = ( *flags == PKT_FROM_CLIENT );
    uint16_t srv_port = ( to_srv ? pkt->dp : pkt->sp );
    uint32_t total = 0, avail;
    StreamSegment* seg;
    PROFILE_VARS;

    PREPROC_PROFILE_START(s5TcpPAFPerfStats);
    avail = get_q_sequenced(trk);
    seg = trk->seglist_next;

    // * must stop if gap (checked in s5_paf_check)
    while ( seg && *flags && (total < avail) )
    {
        uint32_t flush_pt;
        uint32_t size = seg->size;
        uint32_t end = seg->seq + seg->size;
        uint32_t pos = s5_paf_position(&trk->paf_state);

        total += size;

        if ( s5_paf_initialized(&trk->paf_state) && SEQ_LEQ(end, pos) )
        {
            seg = seg->next;
            continue;
        }

        flush_pt = s5_paf_check(
            ssn->flow->s5_config->tcp_config->paf_config,
	    &trk->paf_state, ssn->flow,
            seg->payload, size, total, seg->seq, srv_port, flags,
            trk->flush_mgr.flush_pt);

        if ( flush_pt > 0 )
        {
            PREPROC_PROFILE_END(s5TcpPAFPerfStats);
            return flush_pt;
        }
        seg = seg->next;
    }

    PREPROC_PROFILE_END(s5TcpPAFPerfStats);
    return 0;
}

static inline int CheckFlushPolicyOnData(
    TcpSession *tcpssn, StreamTracker *talker,
    StreamTracker *listener, TcpDataBlock *tdb, Packet *p)
{
    uint32_t flushed = 0;
    uint32_t avail;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "In CheckFlushPolicyOnData\n"););
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Talker flush policy: %s\n",
                flush_policy_names[talker->flush_mgr.flush_policy]););
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Listener flush policy: %s\n",
                flush_policy_names[listener->flush_mgr.flush_policy]););

    switch(listener->flush_mgr.flush_policy)
    {
        case STREAM_FLPOLICY_IGNORE:
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "STREAM_FLPOLICY_IGNORE\n"););
            return 0;

        case STREAM_FLPOLICY_FOOTPRINT_IPS:
        {
            int coerce;
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "STREAM_FLPOLICY_FOOTPRINT-IPS\n"););

            avail = get_q_sequenced(listener);
            coerce = CheckFlushCoercion(
                p, &listener->flush_mgr, listener->tcp_policy->flush_factor);

            if (
                (avail > 0) &&
                (coerce || (avail >= listener->flush_mgr.flush_pt) ||
                (avail && talker->s_mgr.state == TCP_STATE_FIN_WAIT_1))
            ) {
                uint32_t dir = GetForwardDir(p);

                if ( talker->s_mgr.state == TCP_STATE_FIN_WAIT_1 )
                    listener->flags |= TF_FORCE_FLUSH;

                flushed = flush_to_seq(
                    tcpssn, listener, avail, p,
                    GET_SRC_IP(p), GET_DST_IP(p),
                    p->tcph->th_sport, p->tcph->th_dport, dir);
            }
        }
        break;

        case STREAM_FLPOLICY_PROTOCOL_IPS:
        {
            uint32_t flags = GetForwardDir(p);
            uint32_t flush_amt = flush_pdu_ips(tcpssn, listener, p, &flags);
            uint32_t this_flush;

            while ( flush_amt > 0 )
            {
                // if this payload is exactly one pdu, don't
                // actually flush, just use the raw packet
                if ( (tdb->seq == listener->seglist->seq) &&
                     (flush_amt == listener->seglist->size) &&
                     (flush_amt == p->dsize) )
                {
                    this_flush = flush_amt;
                    listener->seglist->buffered = SL_BUF_FLUSHED;
                    listener->flush_count++;
                    p->packet_flags |= PKT_PDU_FULL;
                    ShowRebuiltPacket(tcpssn, p);
                }
                else
                {
                    this_flush = flush_to_seq(
                        tcpssn, listener, flush_amt, p,
                        GET_SRC_IP(p), GET_DST_IP(p),
                        p->tcph->th_sport, p->tcph->th_dport, flags);
                }
                // if we didn't flush as expected, bail
                // (we can flush less than max dsize)
                if ( !this_flush )
                    break;

                flushed += this_flush;
                flags = GetForwardDir(p);
                flush_amt = flush_pdu_ips(tcpssn, listener, p, &flags);
            }
            if ( !flags )
            {
                if ( AutoDisable(listener, talker) )
                    return 0;

                listener->flush_mgr.flush_policy = STREAM_FLPOLICY_FOOTPRINT_IPS;
                listener->flush_mgr.flush_pt += ScPafMax();
                listener->flush_mgr.flush_type = S5_FT_PAF_MAX;

                return CheckFlushPolicyOnData(tcpssn, talker, listener, tdb, p);
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

static inline uint32_t flush_pdu_ackd (
    TcpSession* ssn, StreamTracker* trk, Packet* pkt, uint32_t* flags)
{
    bool to_srv = ( *flags == PKT_FROM_CLIENT );
    uint16_t srv_port = ( to_srv ? pkt->sp : pkt->dp );
    uint32_t total = 0;
    StreamSegment* seg;
    PROFILE_VARS;

    PREPROC_PROFILE_START(s5TcpPAFPerfStats);
    seg = SEQ_LT(trk->seglist_base_seq, trk->r_win_base) ? trk->seglist : NULL;

    // * must stop if not acked
    // * must use adjusted size of seg if not fully acked
    // * must stop if gap (checked in s5_paf_check)
    while ( seg && *flags && SEQ_LT(seg->seq, trk->r_win_base) )
    {
        uint32_t flush_pt;
        uint32_t size = seg->size;
        uint32_t end = seg->seq + seg->size;
        uint32_t pos = s5_paf_position(&trk->paf_state);

        if ( s5_paf_initialized(&trk->paf_state) && SEQ_LEQ(end, pos) )
        {
            total += size;
            seg = seg->next;
            continue;
        }
        if ( SEQ_GT(end, trk->r_win_base) )
            size = trk->r_win_base - seg->seq;

        total += size;

        flush_pt = s5_paf_check(
            ssn->flow->s5_config->tcp_config->paf_config,
            &trk->paf_state, ssn->flow,
            seg->payload, size, total, seg->seq, srv_port, flags,
            trk->flush_mgr.flush_pt);

        if ( flush_pt > 0 )
        {
            PREPROC_PROFILE_END(s5TcpPAFPerfStats);
            return flush_pt;
        }
        seg = seg->next;
    }

    PREPROC_PROFILE_END(s5TcpPAFPerfStats);
    return 0;
}

int CheckFlushPolicyOnAck(
    TcpSession *tcpssn, StreamTracker *talker,
    StreamTracker *listener, TcpDataBlock *tdb, Packet *p)
{
    uint32_t flushed = 0;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "In CheckFlushPolicyOnAck\n"););
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Talker flush policy: %s\n",
                flush_policy_names[talker->flush_mgr.flush_policy]););
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Listener flush policy: %s\n",
                flush_policy_names[listener->flush_mgr.flush_policy]););

    switch(talker->flush_mgr.flush_policy)
    {
        case STREAM_FLPOLICY_IGNORE:
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "STREAM_FLPOLICY_IGNORE\n"););
            return 0;

        case STREAM_FLPOLICY_FOOTPRINT:
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "STREAM_FLPOLICY_FOOTPRINT\n"););
            {
                if(get_q_footprint(talker) >= talker->flush_mgr.flush_pt)
                {
                    uint32_t dir = GetReverseDir(p);

                    flushed = flush_ackd(tcpssn, talker, p,
                            GET_DST_IP(p), GET_SRC_IP(p),
                            p->tcph->th_dport, p->tcph->th_sport, dir);

                    if(flushed)
                        purge_flushed_ackd(tcpssn, talker);
                }
            }
            break;

        case STREAM_FLPOLICY_LOGICAL:
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "STREAM_FLPOLICY_LOGICAL\n"););
            if(talker->seg_bytes_logical > talker->flush_mgr.flush_pt)
            {
                uint32_t dir = GetReverseDir(p);

                flushed = flush_ackd(tcpssn, talker, p,
                        GET_DST_IP(p), GET_SRC_IP(p),
                        p->tcph->th_dport, p->tcph->th_sport, dir);

                if(flushed)
                    purge_flushed_ackd(tcpssn, talker);
            }
            break;

        case STREAM_FLPOLICY_RESPONSE:
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "Running FLPOLICY_RESPONSE\n"););
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "checking l.r_win_base (0x%X) > "
                        "t.seglist_base_seq (0x%X)\n",
                        talker->r_win_base, talker->seglist_base_seq););

            if(SEQ_GT(talker->r_win_base, talker->seglist_base_seq) &&
                    IsWellFormed(p, talker))
            {
                uint32_t dir = GetReverseDir(p);

                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "flushing talker, t->sbl: %d\n",
                            talker->seg_bytes_logical););
                //PrintStreamTracker(talker);
                //PrintStreamTracker(talker);

                flushed = flush_ackd(tcpssn, talker, p,
                        GET_DST_IP(p), GET_SRC_IP(p),
                        p->tcph->th_dport, p->tcph->th_sport, dir);

                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "bye bye data...\n"););

                if(flushed)
                    purge_flushed_ackd(tcpssn, talker);
            }
            break;

        case STREAM_FLPOLICY_SLIDING_WINDOW:
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "STREAM_FLPOLICY_SLIDING_WINDOW\n"););
            if(get_q_footprint(talker) >= talker->flush_mgr.flush_pt)
            {
                uint32_t dir = GetReverseDir(p);

                flushed = flush_ackd(tcpssn, talker, p,
                        GET_DST_IP(p), GET_SRC_IP(p),
                        p->tcph->th_dport, p->tcph->th_sport, dir);

                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "Deleting head node for sliding window...\n"););

                /* Base sequence for next window'd flush is the end
                 * of the first packet. */
                talker->seglist_base_seq = talker->seglist->seq + talker->seglist->size;
                Stream5SeglistDeleteNode(talker, talker->seglist);

                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "setting talker->seglist_base_seq to 0x%X\n",
                            talker->seglist->seq););

            }
            break;

#if 0
        case STREAM_FLPOLICY_CONSUMED:
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "STREAM_FLPOLICY_CONSUMED\n"););
            if(get_q_footprint(talker) >= talker->flush_mgr.flush_pt)
            {
                uint32_t dir = GetReverseDir(p);

                flushed = flush_ackd(tcpssn, talker, p,
                        p->iph->ip_dst.s_addr, p->iph->ip_src.s_addr,
                        p->tcph->th_dport, p->tcph->th_sport, dir);

                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "Deleting head node for sliding window...\n"););

                talker->seglist_base_seq = talker->seglist->seq + talker->seglist->size;
                /* TODO: Delete up to the consumed bytes */
                Stream5SeglistDeleteNode(talker, talker->seglist);

                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "setting talker->seglist_base_seq to 0x%X\n",
                            talker->seglist->seq););

            }
            break;
#endif
        case STREAM_FLPOLICY_PROTOCOL:
        {
            uint32_t flags = GetReverseDir(p);
            uint32_t flush_amt = flush_pdu_ackd(tcpssn, talker, p, &flags);

            while ( flush_amt > 0 )
            {
                talker->seglist_next = talker->seglist;
                talker->seglist_base_seq = talker->seglist->seq;

                // for consistency with other cases, should return total
                // but that breaks flushing pipelined pdus
                flushed = flush_to_seq(
                    tcpssn, talker, flush_amt, p,
                    GET_DST_IP(p), GET_SRC_IP(p),
                    p->tcph->th_dport, p->tcph->th_sport, flags);

                // ideally we would purge just once after this loop
                // but that throws off base
                purge_to_seq(tcpssn, talker, talker->seglist->seq + flushed);

                // if we didn't flush as expected, bail
                // (we can flush less than max dsize)
                if ( !flushed )
                    break;

                flags = GetReverseDir(p);
                flush_amt = flush_pdu_ackd(tcpssn, talker, p, &flags);
            }
            if ( !flags )
            {
                if ( AutoDisable(talker, listener) )
                    return 0;

                talker->flush_mgr.flush_policy = STREAM_FLPOLICY_FOOTPRINT;
                talker->flush_mgr.flush_pt += ScPafMax();
                talker->flush_mgr.flush_type = S5_FT_PAF_MAX;

                return CheckFlushPolicyOnAck(tcpssn, talker, listener, tdb, p);
            }
        }
        break;

        case STREAM_FLPOLICY_FOOTPRINT_IPS:
        case STREAM_FLPOLICY_PROTOCOL_IPS:
            purge_flushed_ackd(tcpssn, talker);
            break;
    }

    return flushed;
}

static void Stream5SeglistAddNode(StreamTracker *st, StreamSegment *prev,
        StreamSegment *ss)
{
    tcpStats.streamsegs_created++;

    if(prev)
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
        if(ss->next)
            ss->next->prev = ss;
        else
            st->seglist_tail = ss;
        st->seglist = ss;
    }
    st->seg_count++;
#ifdef DEBUG
    ss->ordinal = st->segment_ordinal++;
    if (ss->next && (ss->next->seq == ss->seq))
    {
        LogMessage("Same seq to right, check me\n");
    }
#endif
}

static int Stream5SeglistDeleteNode (StreamTracker* st, StreamSegment* seg)
{
    int ret;
    assert(st && seg);

    STREAM5_DEBUG_WRAP( DebugMessage(DEBUG_STREAM_STATE,
                    "Dropping segment at seq %X, len %d\n",
                    seg->seq, seg->size););

    if(seg->prev)
        seg->prev->next = seg->next;
    else
        st->seglist = seg->next;

    if(seg->next)
        seg->next->prev = seg->prev;
    else
        st->seglist_tail = seg->prev;

    st->seg_bytes_logical -= seg->size;
    st->seg_bytes_total -= seg->caplen;

    ret = seg->caplen;

    if (seg->buffered)
    {
        tcpStats.rebuilt_seqs_used++;
        st->flush_count--;
    }

    if ( st->seglist_next == seg )
        st->seglist_next = NULL;

    SegmentFree(seg);
    st->seg_count--;

    return ret;
}

static int Stream5SeglistDeleteNodeTrim (
    StreamTracker* st, StreamSegment* seg, uint32_t flush_seq)
{
    assert(st && seg);

    if ( s5_paf_active(&st->paf_state) &&
        ((seg->seq + seg->size) > flush_seq) )
    {
        uint32_t delta = flush_seq - seg->seq;

        if ( delta < seg->size )
        {
            STREAM5_DEBUG_WRAP( DebugMessage(DEBUG_STREAM_STATE,
                "Left-Trimming segment at seq %X, len %d, delta %u\n",
                seg->seq, seg->size, delta););

            seg->seq = flush_seq;
            seg->size -= (uint16_t)delta;

            st->seg_bytes_logical -= delta;
            return 0;
        }
    }
    return Stream5SeglistDeleteNode(st, seg);
}

/* Iterates through the packets that were reassembled for
 * logging of tagged packets.
 */
int GetTcpRebuiltPackets(Packet *p, Flow *ssn,
        PacketIterator callback, void *userdata)
{
    int packets = 0;
    TcpSession *tcpssn = (TcpSession *)ssn->session;
    StreamTracker *st;
    StreamSegment *ss;
    uint32_t start_seq = ntohl(p->tcph->th_seq);
    uint32_t end_seq = start_seq + p->dsize;

    /* StreamTracker is the opposite of the ip of the reassembled
     * packet --> it came out the queue for the other side */
    if (IP_EQUALITY(GET_SRC_IP(p), &tcpssn->tcp_client_ip))
    {
        st = &tcpssn->server;
    }
    else
    {
        st = &tcpssn->client;
    }

    // skip over segments not covered by this reassembled packet
    for (ss = st->seglist; ss && SEQ_LT(ss->seq, start_seq); ss = ss->next);

    // return flushed segments only
    for (; ss && ss->buffered == SL_BUF_FLUSHED; ss = ss->next)
    {
        if (SEQ_GEQ(ss->seq,start_seq) && SEQ_LT(ss->seq, end_seq))
        {
            DAQ_PktHdr_t pkth;
            pkth.ts.tv_sec = ss->tv.tv_sec;
            pkth.ts.tv_usec = ss->tv.tv_usec;
            pkth.caplen = ss->caplen;
            pkth.pktlen = ss->pktlen;

            callback(&pkth, ss->pkt, userdata);
            packets++;
        }
        else
            break;
    }

    return packets;
}

/* Iterates through the packets that were reassembled for
 * logging of tagged packets.
 */
int GetTcpStreamSegments(Packet *p, Flow *ssn,
        StreamSegmentIterator callback, void *userdata)
{
    int packets = 0;
    TcpSession *tcpssn = (TcpSession *)ssn->session;
    StreamTracker *st;
    StreamSegment *ss;
    uint32_t start_seq = ntohl(p->tcph->th_seq);
    uint32_t end_seq = start_seq + p->dsize;

    /* StreamTracker is the opposite of the ip of the reassembled
     * packet --> it came out the queue for the other side */
    if (IP_EQUALITY(GET_SRC_IP(p), &tcpssn->tcp_client_ip))
        st = &tcpssn->server;
    else
        st = &tcpssn->client;

    // skip over segments not covered by this reassembled packet
    for (ss = st->seglist; ss && SEQ_LT(ss->seq, start_seq); ss = ss->next);

    // return flushed segments only
    for (; ss && ss->buffered == SL_BUF_FLUSHED; ss = ss->next)
    {
        if (SEQ_GEQ(ss->seq,start_seq) && SEQ_LT(ss->seq, end_seq))
        {
            DAQ_PktHdr_t pkth;
            pkth.ts.tv_sec = ss->tv.tv_sec;
            pkth.ts.tv_usec = ss->tv.tv_usec;
            pkth.caplen = ss->caplen;
            pkth.pktlen = ss->pktlen;

            if (callback(&pkth, ss->pkt, ss->data, ss->seq, userdata) != 0)
                return -1;

            packets++;
        }
        else
            break;
    }

    return packets;
}

int Stream5AddSessionAlertTcp(
    Flow* lwssn, Packet* p,
    uint32_t gid, uint32_t sid)
{
    StreamTracker *st;
    Stream5AlertInfo* ai;
    TcpSession *tcpssn = (TcpSession*)lwssn->session;

    if (IP_EQUALITY(GET_SRC_IP(p),&tcpssn->tcp_client_ip))
    {
        st = &tcpssn->server;
    }
    else
    {
        st = &tcpssn->client;
    }

    if (st->alert_count >= MAX_SESSION_ALERTS)
        return 0;

    ai = st->alerts + st->alert_count;
    ai->gid = gid;
    ai->sid = sid;
    ai->seq = GET_PKT_SEQ(p);

    if ( p->tcph->th_flags & TH_FIN )
        ai->seq--;

    st->alert_count++;

    return 0;
}

int Stream5CheckSessionAlertTcp(Flow *lwssn, Packet *p, uint32_t gid, uint32_t sid)
{
    StreamTracker *st;
    int i;
    int iRet = 0;
    TcpSession *tcpssn = (TcpSession*)lwssn->session;

    /* If this is not a rebuilt packet, no need to check further */
    if (!(p->packet_flags & PKT_REBUILT_STREAM))
    {
        return 0;
    }

    if (IP_EQUALITY(GET_SRC_IP(p), &tcpssn->tcp_client_ip))
    {
        st = &tcpssn->server;
    }
    else
    {
        st = &tcpssn->client;
    }

    for (i=0;i<st->alert_count;i++)
    {
        /*  This is a rebuilt packet and if we've seen this alert before,
         *  return that we have previously alerted on original packet.
         */
        if ( st->alerts[i].gid == gid &&
             st->alerts[i].sid == sid )
        {
            return -1;
        }
    }

    return iRet;
}

int Stream5UpdateSessionAlertTcp (
    Flow *lwssn, Packet *p,
    uint32_t gid, uint32_t sid,
    uint32_t event_id, uint32_t event_second)
{
    StreamTracker *st;
    int i;
    uint32_t seq_num;
    TcpSession *tcpssn = (TcpSession*)lwssn->session;

    if (IP_EQUALITY(GET_SRC_IP(p), &tcpssn->tcp_client_ip))
    {
        st = &tcpssn->server;
    }
    else
    {
        st = &tcpssn->client;
    }

    seq_num = GET_PKT_SEQ(p);

    if ( p->tcph->th_flags & TH_FIN )
        seq_num--;

    for (i=0;i<st->alert_count;i++)
    {
        Stream5AlertInfo* ai = st->alerts + i;

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

void Stream5SetExtraDataTcp (Flow* lwssn, Packet* p, uint32_t xid)
{
    StreamTracker *st;
    TcpSession *tcpssn = (TcpSession*)lwssn->session;

    if (IP_EQUALITY(GET_SRC_IP(p),&tcpssn->tcp_client_ip))
        st = &tcpssn->server;
    else
        st = &tcpssn->client;

    st->xtradata_mask |= BIT(xid);
}

void Stream5ClearExtraDataTcp (Flow* lwssn, Packet* p, uint32_t xid)
{
    StreamTracker *st;
    TcpSession *tcpssn = (TcpSession*)lwssn->session;

    if (IP_EQUALITY(GET_SRC_IP(p),&tcpssn->tcp_client_ip))
        st = &tcpssn->server;
    else
        st = &tcpssn->client;

    if ( xid )
        st->xtradata_mask &= ~BIT(xid);
    else
        st->xtradata_mask = 0;
}

char Stream5GetReassemblyDirectionTcp(Flow *lwssn)
{
    char dir = SSN_DIR_NONE;
    TcpSession *tcpssn = NULL;

    if (!lwssn)
        return SSN_DIR_NONE;

    tcpssn = (TcpSession*)lwssn->session;

    if ((tcpssn->server.flush_mgr.flush_policy != STREAM_FLPOLICY_NONE) &&
        (tcpssn->server.flush_mgr.flush_policy != STREAM_FLPOLICY_IGNORE))
    {
        dir |= SSN_DIR_SERVER;
    }

    if ((tcpssn->client.flush_mgr.flush_policy != STREAM_FLPOLICY_NONE) &&
        (tcpssn->client.flush_mgr.flush_policy != STREAM_FLPOLICY_IGNORE))
    {
        dir |= SSN_DIR_CLIENT;
    }

    return dir;
}

uint32_t Stream5GetFlushPointTcp(Flow *lwssn, char dir)
{
    TcpSession *tcpssn = NULL;

    if (lwssn == NULL)
        return 0;

    tcpssn = (TcpSession*)lwssn->session;

    if (dir & SSN_DIR_CLIENT)
        return tcpssn->client.flush_mgr.flush_pt;
    else if (dir & SSN_DIR_SERVER)
        return tcpssn->server.flush_mgr.flush_pt;

    return 0;
}

void Stream5SetFlushPointTcp(Flow *lwssn,
        char dir, uint32_t flush_point)
{
    TcpSession *tcpssn = NULL;

    if (lwssn == NULL)
        return;

    tcpssn = (TcpSession*)lwssn->session;

    if (flush_point == 0)
        return;

    if (dir & SSN_DIR_CLIENT)
    {
        tcpssn->client.flush_mgr.flush_pt = flush_point;
        tcpssn->client.flush_mgr.last_size = 0;
        tcpssn->client.flush_mgr.last_count = 0;
        tcpssn->client.flush_mgr.flush_type = S5_FT_EXTERNAL;
    }
    else if (dir & SSN_DIR_SERVER)
    {
        tcpssn->server.flush_mgr.flush_pt = flush_point;
        tcpssn->server.flush_mgr.last_size = 0;
        tcpssn->server.flush_mgr.last_count = 0;
        tcpssn->server.flush_mgr.flush_type = S5_FT_EXTERNAL;
    }
}

char Stream5SetReassemblyTcp(
    Flow *lwssn, FlushPolicy flush_policy, char dir, char flags)
{
    TcpSession *tcpssn = NULL;

    if (!lwssn)
        return SSN_DIR_NONE;

    tcpssn = (TcpSession*)lwssn->session;

    if (flags & STREAM_FLPOLICY_SET_APPEND)
    {
        if (dir & SSN_DIR_CLIENT)
        {
            if (tcpssn->client.flush_mgr.flush_policy != STREAM_FLPOLICY_NONE)
            {
                /* Changing policy with APPEND, Bad */
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "Stream: Changing client flush policy using "
                            "append is asking for trouble.  Ignored\n"););
            }
            else
            {
                InitFlushMgr(&tcpssn->client.flush_mgr,
                    &tcpssn->client.tcp_policy->flush_point_list,
                    flush_policy, 0);
            }
        }

        if (dir & SSN_DIR_SERVER)
        {
            if (tcpssn->server.flush_mgr.flush_policy != STREAM_FLPOLICY_NONE)
            {
                /* Changing policy with APPEND, Bad */
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "Stream: Changing server flush policy using "
                            "append is asking for trouble.  Ignored\n"););
            }
            else
            {
                InitFlushMgr(&tcpssn->server.flush_mgr,
                    &tcpssn->server.tcp_policy->flush_point_list,
                    flush_policy, 0);
            }
        }

    }
    else if (flags & STREAM_FLPOLICY_SET_ABSOLUTE)
    {
        if (dir & SSN_DIR_CLIENT)
        {
            InitFlushMgr(&tcpssn->client.flush_mgr,
                &tcpssn->client.tcp_policy->flush_point_list,
                flush_policy, 0);
        }

        if (dir & SSN_DIR_SERVER)
        {
            InitFlushMgr(&tcpssn->server.flush_mgr,
                &tcpssn->server.tcp_policy->flush_point_list,
                flush_policy, 0);
        }
    }

    return Stream5GetReassemblyDirectionTcp(lwssn);
}

char Stream5GetReassemblyFlushPolicyTcp(Flow *lwssn, char dir)
{
    TcpSession *tcpssn = NULL;

    if (!lwssn)
        return STREAM_FLPOLICY_NONE;

    tcpssn = (TcpSession*)lwssn->session;

    if (dir & SSN_DIR_CLIENT)
    {
        return (char)tcpssn->client.flush_mgr.flush_policy;
    }

    if (dir & SSN_DIR_SERVER)
    {
        return (char)tcpssn->server.flush_mgr.flush_policy;
    }
    return STREAM_FLPOLICY_NONE;
}

char Stream5IsStreamSequencedTcp(Flow *lwssn, char dir)
{
    TcpSession *tcpssn = NULL;

    if (!lwssn)
        return 1;

    tcpssn = (TcpSession*)lwssn->session;

    if (dir & SSN_DIR_CLIENT)
    {
        if ( tcpssn->server.flags & (TF_MISSING_PREV_PKT|TF_MISSING_PKT) )
            return 0;
    }

    if (dir & SSN_DIR_SERVER)
    {
        if ( tcpssn->client.flags & (TF_MISSING_PREV_PKT|TF_MISSING_PKT) )
            return 0;
    }

    return 1;
}

/* This will falsly return SSN_MISSING_BEFORE on the first reassembed
 * packet if reassembly for this direction was set mid-session */
int Stream5MissingInReassembledTcp(Flow *lwssn, char dir)
{
    TcpSession *tcpssn = NULL;

    if (!lwssn)
        return SSN_MISSING_NONE;

    tcpssn = (TcpSession *)lwssn->session;

    if (dir & SSN_DIR_CLIENT)
    {
        if ((tcpssn->server.flags & TF_MISSING_PKT) &&
            (tcpssn->server.flags & TF_MISSING_PREV_PKT))
            return SSN_MISSING_BOTH;
        else if (tcpssn->server.flags & TF_MISSING_PREV_PKT)
            return SSN_MISSING_BEFORE;
        else if (tcpssn->server.flags & TF_MISSING_PKT)
            return SSN_MISSING_AFTER;
    }
    else if (dir & SSN_DIR_SERVER)
    {
        if ((tcpssn->client.flags & TF_MISSING_PKT) &&
            (tcpssn->client.flags & TF_MISSING_PREV_PKT))
            return SSN_MISSING_BOTH;
        else if (tcpssn->client.flags & TF_MISSING_PREV_PKT)
            return SSN_MISSING_BEFORE;
        else if (tcpssn->client.flags & TF_MISSING_PKT)
            return SSN_MISSING_AFTER;
    }

    return SSN_MISSING_NONE;
}

char Stream5PacketsMissingTcp(Flow *lwssn, char dir)
{
    TcpSession *tcpssn = NULL;

    if (!lwssn)
        return 0;

    tcpssn = (TcpSession *)lwssn->session;

    if (dir & SSN_DIR_CLIENT)
    {
        if (tcpssn->server.flags & TF_PKT_MISSED)
            return 1;
    }

    if (dir & SSN_DIR_SERVER)
    {
        if (tcpssn->client.flags & TF_PKT_MISSED)
            return 1;
    }

    return 0;
}

#define SSOD_LESS_THAN 1
#define SSOD_GREATER_THAN 2
#define SSOD_EQUALS 3
#define SSOD_LESS_THAN_OR_EQUALS 4
#define SSOD_GREATER_THAN_OR_EQUALS 5
#define SSOD_NOT_EQUALS 6

#define SSOD_MATCH 1
#define SSOD_NOMATCH 0
typedef struct _StreamSizeOptionData
{
    char opcode;
    uint32_t size;
    char direction;
} StreamSizeOptionData;

int s5TcpStreamSizeInit(
    SnortConfig*, char *name, char *parameters, void **dataPtr)
{
    char **toks;
    int num_toks;
    char *endp;
    StreamSizeOptionData *ssod;
    toks = mSplit(parameters, ",", 4, &num_toks, 0);

    if (num_toks != 3)
    {
        ParseError("Invalid parameters for %s option", name);
    }

    ssod = (StreamSizeOptionData*)SnortAlloc(sizeof(*ssod));

    if (!ssod)
    {
        ParseError("Failed to allocate data for %s option",
            name);
    }

    /* Parse the direction.
     * Can be: client, server, both, either
     */
    if (!strcasecmp(toks[0], "client"))
    {
        ssod->direction = SSN_DIR_CLIENT;
    }
    else if (!strcasecmp(toks[0], "server"))
    {
        ssod->direction = SSN_DIR_SERVER;
    }
    else if (!strcasecmp(toks[0], "both"))
    {
        ssod->direction = SSN_DIR_BOTH;
    }
    else if (!strcasecmp(toks[0], "either"))
    {
        ssod->direction = SSN_DIR_NONE;
    }
    else
    {
        ParseError("Invalid direction: %s for option %s",
            toks[0], name);
    }

    /* Parse the opcode.
     * Can be: =, <, > , !=, <=, >=
     */
    if (!strcasecmp(toks[1], "="))
    {
        ssod->opcode = SSOD_EQUALS;
    }
    else if (!strcasecmp(toks[1], "<"))
    {
        ssod->opcode = SSOD_LESS_THAN;
    }
    else if (!strcasecmp(toks[1], ">"))
    {
        ssod->opcode = SSOD_GREATER_THAN;
    }
    else if (!strcasecmp(toks[1], "!="))
    {
        ssod->opcode = SSOD_NOT_EQUALS;
    }
    else if (!strcasecmp(toks[1], "<="))
    {
        ssod->opcode = SSOD_LESS_THAN_OR_EQUALS;
    }
    else if (!strcasecmp(toks[1], ">="))
    {
        ssod->opcode = SSOD_GREATER_THAN_OR_EQUALS;
    }
    else
    {
        ParseError("Invalid opcode: %s for option %s",
            toks[1], name);
    }

    ssod->size = SnortStrtoul(toks[2], &endp, 0);
    if ((endp == toks[2]) || (errno == ERANGE))
    {
        ParseError("Invalid size: %s for option %s",
            toks[2], name);
    }

    *dataPtr = ssod;
    mSplitFree(&toks, num_toks);

    return 1;
}

static inline int s5TcpStreamSizeCompare(uint32_t size1, uint32_t size2, char opcode)
{
    int retval = 0;
    switch (opcode)
    {
        case SSOD_EQUALS:
            if (size1 == size2)
                retval = 1;
            break;
        case SSOD_LESS_THAN:
            if (size1 < size2)
                retval = 1;
            break;
        case SSOD_GREATER_THAN:
            if (size1 > size2)
                retval = 1;
            break;
        case SSOD_NOT_EQUALS:
            if (size1 != size2)
                retval = 1;
            break;
        case SSOD_LESS_THAN_OR_EQUALS:
            if (size1 <= size2)
                retval = 1;
            break;
        case SSOD_GREATER_THAN_OR_EQUALS:
            if (size1 >= size2)
                retval = 1;
            break;
        default:
            break;
    }
    return retval;
}

int s5TcpStreamSizeEval(Packet* pkt, const uint8_t**, void *dataPtr)
{
    Flow *lwssn = NULL;
    TcpSession *tcpssn = NULL;
    StreamSizeOptionData *ssod = (StreamSizeOptionData *)dataPtr;
    uint32_t client_size;
    uint32_t server_size;
    PROFILE_VARS;

    if (!pkt || !pkt->flow || !ssod || !pkt->tcph)
        return DETECTION_OPTION_NO_MATCH;

    lwssn = (Flow*)pkt->flow;

    PREPROC_PROFILE_START(streamSizePerfStats);

    tcpssn = (TcpSession *)lwssn->session;

    if (tcpssn->client.l_nxt_seq > tcpssn->client.isn)
    {
        /* the normal case... */
        client_size = tcpssn->client.l_nxt_seq - tcpssn->client.isn;
    }
    else
    {
        /* the seq num wrapping case... */
        client_size = tcpssn->client.isn - tcpssn->client.l_nxt_seq;
    }
    if (tcpssn->server.l_nxt_seq > tcpssn->server.isn)
    {
        /* the normal case... */
        server_size = tcpssn->server.l_nxt_seq - tcpssn->server.isn;
    }
    else
    {
        /* the seq num wrapping case... */
        server_size = tcpssn->server.isn - tcpssn->server.l_nxt_seq;
    }

    switch (ssod->direction)
    {
        case SSN_DIR_CLIENT:
            if (s5TcpStreamSizeCompare(client_size, ssod->size, ssod->opcode)
                == SSOD_MATCH)
            {
                PREPROC_PROFILE_END(streamSizePerfStats);
                return DETECTION_OPTION_MATCH;
            }
            break;
        case SSN_DIR_SERVER:
            if (s5TcpStreamSizeCompare(server_size, ssod->size, ssod->opcode)
                == SSOD_MATCH)
            {
                PREPROC_PROFILE_END(streamSizePerfStats);
                return DETECTION_OPTION_MATCH;
            }
            break;
        case SSN_DIR_NONE: /* overloaded.  really, its an 'either' */
            if ((s5TcpStreamSizeCompare(client_size, ssod->size, ssod->opcode)
                    == SSOD_MATCH) ||
                (s5TcpStreamSizeCompare(server_size, ssod->size, ssod->opcode)
                    == SSOD_MATCH))
            {
                PREPROC_PROFILE_END(streamSizePerfStats);
                return DETECTION_OPTION_MATCH;
            }
            break;
        case SSN_DIR_BOTH:
            if ((s5TcpStreamSizeCompare(client_size, ssod->size, ssod->opcode)
                    == SSOD_MATCH) &&
                (s5TcpStreamSizeCompare(server_size, ssod->size, ssod->opcode)
                    == SSOD_MATCH))
            {
                PREPROC_PROFILE_END(streamSizePerfStats);
                return DETECTION_OPTION_MATCH;
            }
            break;
        default:
            break;
    }
    PREPROC_PROFILE_END(streamSizePerfStats);
    return DETECTION_OPTION_NO_MATCH;
}

void s5TcpStreamSizeCleanup(void *dataPtr)
{
    StreamSizeOptionData *ssod = (StreamSizeOptionData*)dataPtr;
    if (ssod)
    {
        free(ssod);
    }
}

typedef struct _StreamReassembleRuleOptionData
{
    char enable;
    char alert;
    char direction;
    char fastpath;
} StreamReassembleRuleOptionData;

int s5TcpStreamReassembleRuleOptionInit(
    SnortConfig*, char *name, char *parameters, void **dataPtr)
{
    char **toks;
    int num_toks;
    StreamReassembleRuleOptionData *srod = NULL;
    toks = mSplit(parameters, ",", 4, &num_toks, 0);

    if (num_toks < 2)
    {
        ParseError("Invalid parameters for %s option", name);
    }

    srod = (StreamReassembleRuleOptionData*)SnortAlloc(sizeof(*srod));

    if (!srod)
    {
        ParseError("Failed to allocate data for %s option", name);
    }

    /* Parse the action.
     * Can be: enable or disable
     */
    if (!strcasecmp(toks[0], "enable"))
    {
        srod->enable = 1;
    }
    else if (!strcasecmp(toks[0], "disable"))
    {
        srod->enable = 0;
    }
    else
    {
        ParseError("Invalid action: %s for option %s.  Valid "
            "parameters are 'enable' or 'disable'", toks[0], name);
    }

    /* Parse the direction.
     * Can be: client, server, both
     */
    /* Need to these around, so they match the ones specified via the stream5_tcp ports
     * option, ie, stream5_tcp: ports client enables reassembly on client-sourced traffic. */
    if (!strcasecmp(toks[1], "client"))
    {
        srod->direction = SSN_DIR_SERVER;
    }
    else if (!strcasecmp(toks[1], "server"))
    {
        srod->direction = SSN_DIR_CLIENT;
    }
    else if (!strcasecmp(toks[1], "both"))
    {
        srod->direction = SSN_DIR_BOTH;
    }
    else
    {
        ParseError("Invalid direction: %s for option %s", toks[1], name);
    }

    /* Parse the optional parameters:
     * noalert flag, fastpath flag
     */
    srod->alert = 1;
    if (num_toks > 2)
    {
        int i = 2;
        for (; i< num_toks; i++)
        {
            if (!strcasecmp(toks[i], "noalert"))
            {
                srod->alert = 0;
            }
            else if (!strcasecmp(toks[i], "fastpath"))
            {
                srod->fastpath = 1;
                if (srod->enable)
                {
                    ParseError("Using 'fastpath' with 'enable' is "
                        "not valid for %s", name);
                }
            }
            else
            {
                ParseError("Invalid optional parameter: %s for option %s",
                    toks[i], name);
            }
        }
    }

    *dataPtr = srod;
    mSplitFree(&toks, num_toks);

    return 1;
}

int s5TcpStreamReassembleRuleOptionEval(
    Packet* pkt, const uint8_t**, void *dataPtr)
{
    Flow *lwssn = NULL;
    StreamReassembleRuleOptionData *srod = (StreamReassembleRuleOptionData *)dataPtr;
    PROFILE_VARS;

    if (!pkt || !pkt->flow || !srod || !pkt->tcph)
        return 0;

    PREPROC_PROFILE_START(streamReassembleRuleOptionPerfStats);
    lwssn = (Flow*)pkt->flow;

    if (!srod->enable) /* Turn it off */
        Stream5SetReassemblyTcp(lwssn, STREAM_FLPOLICY_IGNORE, srod->direction, STREAM_FLPOLICY_SET_ABSOLUTE);
    else
        Stream5SetReassemblyTcp(lwssn, STREAM_FLPOLICY_FOOTPRINT, srod->direction, STREAM_FLPOLICY_SET_ABSOLUTE);

    if (srod->fastpath)
    {
        /* Turn off inspection */
        lwssn->s5_state.ignore_direction |= srod->direction;
        DisableInspection(pkt);

        /* TBD: Set TF_FORCE_FLUSH ? */
    }

    if (srod->alert)
    {
        PREPROC_PROFILE_END(streamReassembleRuleOptionPerfStats);
        return DETECTION_OPTION_MATCH;
    }

    PREPROC_PROFILE_END(streamReassembleRuleOptionPerfStats);
    return DETECTION_OPTION_NO_ALERT;
}

void s5TcpStreamReassembleRuleOptionCleanup(void *dataPtr)
{
    StreamReassembleRuleOptionData *srod = (StreamReassembleRuleOptionData*)dataPtr;
    if (srod)
    {
        free(srod);
    }
}

uint16_t* Stream5GetTcpPortList(void* pv, int& ignore_any)
{
    Stream5Config* pc = (Stream5Config*)pv;
    if ( !pc->tcp_config )
        return NULL;
    ignore_any = pc->tcp_config->policy->flags & STREAM5_CONFIG_IGNORE_ANY;
    return pc->tcp_config->port_filter;
}

void s5TcpSetPortFilterStatus(
    Stream5TcpConfig* tcp_config, unsigned short port, uint16_t status)
{
    tcp_config->port_filter[port] |= status;
}

void s5TcpUnsetPortFilterStatus(
    Stream5TcpConfig* tcp_config, unsigned short port, uint16_t status)
{
    tcp_config->port_filter[port] &= ~status;
}

int s5TcpGetPortFilterStatus(
    Stream5TcpConfig* tcp_config, unsigned short port)
{
    return (int)tcp_config->port_filter[port];
}

bool s5TcpIgnoreAny(Stream5TcpConfig* tcp_config)
{
    return ( tcp_config->policy->flags & STREAM5_CONFIG_IGNORE_ANY );
}

void s5TcpSetSynSessionStatus(
    Stream5TcpConfig* tcp_config, uint16_t status)
{
    tcp_config->session_on_syn |= status;
}

void s5TcpUnsetSynSessionStatus(
    Stream5TcpConfig* tcp_config, uint16_t status)
{
    tcp_config->session_on_syn &= ~status;
}

#if 0
static void targetPolicyIterate(void (*callback)(int))
{
    unsigned int i;

    for (i = 0; i < snort_conf->num_policies_allocated; i++)
    {
        if (snort_conf->targeted_policies[i] != NULL)
        {
            callback(i);
        }
    }
}
#endif

//-------------------------------------------------------------------------
// tcp ha stuff

#ifdef ENABLE_HA
static void Stream5TCPDeactivateSession(Flow *lwssn)
{
#if 0
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "Cleaning up the TCP session associated with the session"
        " being put into standby.\n"););
#endif
    TcpSessionCleanup(lwssn, 0);

    lwssn->session_state &= 
        ~(STREAM5_STATE_SYN | STREAM5_STATE_SYN_ACK | 
          STREAM5_STATE_ACK | STREAM5_STATE_ESTABLISHED);

    lwssn->s5_state.session_flags &= ~(SSNFLAG_SEEN_CLIENT | SSNFLAG_SEEN_SERVER);
}

static HA_Api ha_tcp_api = {
    Stream::get_session,
    Stream::new_session,
    Stream5TCPDeactivateSession,
    Stream::delete_session,
};
#endif

void Stream5ResetTcp()
{
    s5_tcp_cleanup = 1;
    flow_con->purge_flows(IPPROTO_TCP);
    s5_tcp_cleanup = 0;
}

void Stream5ConfigTcp(Stream5TcpConfig *config, SnortConfig* sc, char *args)
{
    Stream5TcpPolicy *s5TcpPolicy;

    if (config == NULL)
        return;

    s5TcpPolicy = (Stream5TcpPolicy *) SnortAlloc(sizeof(Stream5TcpPolicy));

    /* Initialize flush policy to Ignore */
    memcpy(&s5TcpPolicy->flush_config, ignore_flush_policy,
            sizeof(FlushConfig) * MAX_PORTS);
    memcpy(&s5TcpPolicy->flush_config_protocol, ignore_flush_policy_protocol,
            sizeof(FlushConfig) * MAX_PROTOCOL_ORDINAL);

    Stream5ParseTcpArgs(sc, config, args, s5TcpPolicy);

    config->policy = s5TcpPolicy;

    if ( ScPafEnabled() && !config->paf_config )
        config->paf_config = s5_paf_new();
}

Stream5TcpConfig* Stream5ConfigTcp(SnortConfig* sc, char *args)
{
    Stream5TcpConfig* tcp_config =
        (Stream5TcpConfig*)SnortAlloc(sizeof(*tcp_config));

    Stream5TcpInitFlushPoints();
    Stream5TcpRegisterPreprocProfiles();
    Stream5TcpRegisterRuleOptions(sc);

#ifdef ENABLE_HA
    ha_set_api(IPPROTO_TCP, &ha_tcp_api);
#endif

    Stream5ConfigTcp(tcp_config, sc, args);

    return tcp_config;
}

//-------------------------------------------------------------------------
// TcpSession methods
//-------------------------------------------------------------------------

TcpSession::TcpSession(Flow* flow) : Session(flow)
{
    reset();
}

void TcpSession::reset()
{
    memset(&client, 0, sizeof(client));
    memset(&server, 0, sizeof(server));

#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
    ingress_index = egress_index = 0;
    ingress_group = egress_group = 0;
    daq_flags = address_space_id = 0;
#endif

    ecn = 0;
    lws_init = tcp_init = false;
}

void* TcpSession::get_policy (void* pv, Packet* p)
{
    Stream5TcpConfig* tcp_config = (Stream5TcpConfig*)pv;
    Stream5TcpPolicy* s5TcpPolicy = tcp_config->policy;

#ifdef REG_TEST
    if ( !s5TcpPolicy )
    {
        // FIXIT should be deleted or moved?
        TcpDataBlock tdb;
        SetupTcpDataBlock(&tdb, p);
        S5TraceTCP(p, NULL, &tdb, 0);
    }
#endif
    return s5TcpPolicy;
}

bool TcpSession::setup (Packet* p)
{
    if ( TCP_ISFLAGSET(p->tcph, TH_SYN) &&
        !TCP_ISFLAGSET(p->tcph, TH_ACK) )
        flow->session_state = STREAM5_STATE_SYN;  // FIXIT same as line 4555

    assert(flow->session == this);
    reset();

    ssnStats.sessions++;
    return true;
}

// FIXIT diff betw TcpSessionCleanup() and TcpSessionClear() ?
// Cleanup() flushes data; Clear() does not flush data
void TcpSession::cleanup()
{
    // this flushes data
    TcpSessionCleanup(flow, 1);
}

// FIXIT this was originally called by Stream::drop_packet()
// which is now calling Session::clear()
void TcpSession::clear()
{
    // this does NOT flush data
    TcpSessionClear(flow, this, 1);
}

void TcpSession::update_direction(
    char dir, snort_ip_p ip, uint16_t port)
{
    snort_ip tmpIp;
    uint16_t tmpPort;
    StreamTracker tmpTracker;

    if (IP_EQUALITY(&tcp_client_ip, ip) && (tcp_client_port == port))
    {
        if ((dir == SSN_DIR_CLIENT) && (flow->s5_state.direction == SSN_DIR_CLIENT))
        {
            /* Direction already set as client */
            return;
        }
    }
    else if (IP_EQUALITY(&tcp_server_ip, ip) && (tcp_server_port == port))
    {
        if ((dir == SSN_DIR_SERVER) && (flow->s5_state.direction == SSN_DIR_SERVER))
        {
            /* Direction already set as server */
            return;
        }
    }

    /* Swap them -- leave flow->s5_state.direction the same */

    /* XXX: Gotta be a more efficient way to do this without the memcpy */
    tmpIp = tcp_client_ip;
    tmpPort = tcp_client_port;
    tcp_client_ip = tcp_server_ip;
    tcp_client_port = tcp_server_port;
    tcp_server_ip = tmpIp;
    tcp_server_port = tmpPort;

#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
    SwapPacketHeaderFoo(this);
#endif
    memcpy(&tmpTracker, &client, sizeof(StreamTracker));
    memcpy(&client, &server, sizeof(StreamTracker));
    memcpy(&server, &tmpTracker, sizeof(StreamTracker));
}

/*
 * Main entry point for TCP
 */
int TcpSession::process(Packet *p)
{
    TcpDataBlock tdb;
    int status;
    PROFILE_VARS;

    STREAM5_DEBUG_WRAP(
        char flagbuf[9];
        CreateTCPFlagString(p, flagbuf);
        DebugMessage((DEBUG_STREAM|DEBUG_STREAM_STATE),
            "Got TCP Packet 0x%X:%d ->  0x%X:%d %s\nseq: 0x%X   ack:0x%X  dsize: %u\n",
            GET_SRC_IP(p), p->sp, GET_DST_IP(p), p->dp, flagbuf,
            ntohl(p->tcph->th_seq), ntohl(p->tcph->th_ack), p->dsize););

    PREPROC_PROFILE_START(s5TcpPerfStats);

    if ( stream.blocked_session(flow, p) )
    {
        PREPROC_PROFILE_END(s5TcpPerfStats);
        return ACTION_NOTHING;
    }
    SetupTcpDataBlock(&tdb, p);

    Stream5TcpPolicy* s5TcpPolicy = (Stream5TcpPolicy*)flow->policy;
    TcpSession* tcpssn = (TcpSession*)flow->session;

    if ( !tcpssn->lws_init )
    {
        if (TCP_ISFLAGSET(p->tcph, TH_SYN) &&
            !TCP_ISFLAGSET(p->tcph, TH_ACK))
        {
            /* SYN only */
            flow->session_state = STREAM5_STATE_SYN;  // FIXIT same as line 4511
            tcpssn->lws_init = true;
        }
        else
        {
            // If we're within the "startup" window, try to handle
            // this packet as midstream pickup -- allows for
            // connections that already existed before snort started.
            if (p->pkth->ts.tv_sec - packet_first_time() >= s5TcpPolicy->hs_timeout)
            {
                 // Do nothing with this packet since we require a 3-way ;)
                DEBUG_WRAP(
                    DebugMessage(DEBUG_STREAM_STATE, "Stream5: Requiring 3-way "
                    "Handshake, but failed to retrieve session object "
                    "for non SYN packet.\n"););

                EventNo3whs(s5TcpPolicy);
                PREPROC_PROFILE_END(s5TcpPerfStats);
                S5TraceTCP(p, flow, &tdb, 1);
                return 0;
            }
            if ( TCP_ISFLAGSET(p->tcph, TH_SYN) || p->dsize )
            {
                tcpssn->lws_init = true;
            }
            else
            {
                // No data, don't bother to track yet
                PREPROC_PROFILE_END(s5TcpPerfStats);
                S5TraceTCP(p, flow, &tdb, 1);
                return 0;
            }
        }
    }
    /*
     * Check if the session is expired.
     * Should be done before we do something with the packet...
     * ie, Insert a packet, or handle state change SYN, FIN, RST, etc.
     */
    if ( stream.expired_session(flow, p) )
    {
        /* Session is timed out */
        if (flow->s5_state.session_flags & SSNFLAG_RESET)
        {
            /* If this one has been reset, delete the TCP
             * portion, and start a new. */
            TcpSessionCleanup(flow, 1);
        }
        else
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Stream5 TCP session timedout!\n"););

            /* Not reset, simply time'd out.  Clean it up */
            TcpSessionCleanup(flow, 1);
        }
        ssnStats.timeouts++;
    }
    status = ProcessTcp(flow, p, &tdb, s5TcpPolicy);

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "Finished Stream5 TCP cleanly!\n"
                    "---------------------------------------------------\n"););

    if ( status & ACTION_LWSSN_CLOSED )
    {
        /* TCP Session closed, so send an HA deletion event for the session. */
        ha_notify_deletion(flow);
    }
    else
    {
        flow->markup_packet_flags(p);
        flow->set_expire(p, s5TcpPolicy->session_timeout);
    }
    if ( status & ACTION_DISABLE_INSPECTION )
    {
        DisableInspection(p);

        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Stream5 Ignoring packet from %d. Session marked as ignore\n",
            p->packet_flags & PKT_FROM_SERVER? "server" : "client"););
    }

    PREPROC_PROFILE_END(s5TcpPerfStats);
    S5TraceTCP(p, flow, &tdb, 0);
    return 0;
}

void tcp_sum()
{
    sum_stats((PegCount*)&gssnStats, (PegCount*)&ssnStats,
        session_peg_count);

    sum_stats((PegCount*)&gtcpStats, (PegCount*)&tcpStats,
        array_size(tcp_pegs));
}

void tcp_stats()
{
    // FIXIT need to get these before delete flow_con
    //flow_con->get_prunes(IPPROTO_TCP, ssnStats.prunes);

    show_stats((PegCount*)&gssnStats, session_pegs, session_peg_count,
        "stream5_tcp");

    show_stats((PegCount*)&gtcpStats, tcp_pegs, array_size(tcp_pegs));
}

void tcp_reset_stats()
{
    memset(&gssnStats, 0, sizeof(gssnStats));
    memset(&gtcpStats, 0, sizeof(gtcpStats));

    flow_con->reset_prunes(IPPROTO_TCP);
}

void tcp_show(Stream5TcpConfig* tcp_config)
{
    Stream5PrintTcpConfig(tcp_config->policy);
}


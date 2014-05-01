/*
 ** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 ** Copyright (C) 2004-2013 Sourcefire, Inc.
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License Version 2 as
 ** published by the Free Software Foundation.  You may not use, modify or
 ** distribute this program under any other version of the GNU General
 ** Public License.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program; if not, write to the Free Software
 ** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/*
 * defrag.cc is derived from frag3.c by Martin Roesch <roesch@sourcefire.com>
 */

/*
 * Notes:
 * Frag3 sports the following improvements over frag2:
 *  - engine-based IP defragmentation, harder to evade
 *  - 8 Anomaly detection event types
 *  - Two separate memory management strategies to tailor
 *    performance for specific environments
 *  - Up to 250% faster than frag2.
 *
 *  The mechanism for processing frags is based on the Linux IP stack
 *  implementation of IP defragmentation with proper amounts of paranoia
 *  and an IDS perspective applied.  Some of this code was derived from
 *  frag2 originally, but it's basically unrecognizeable if you compare
 *  it to frag2 IMO.
 *
 *  I switched from using the UBI libs to using sfxhash and linked lists for
 *  fragment management because I suspected that the management code was
 *  the cause of performance issues that we were observing at Sourcefire
 *  in certain customer situations.  Splay trees are cool and really hard
 *  to screw with from an attack perspective, but they also incur a lot
 *  of overhead for managing the tree and lose the order of the fragments in
 *  the FragTracker's fraglist, so I dropped them.  Originally the
 *  frag3 code was just supposed to migrate away from the splay tree system
 *  that I was using in frag2, but I figured since I was doing the work to
 *  pull out the splay trees I may as well solve some of the other problems
 *  we were seeing.
 *
 *  Initial performance testing that I've done shows that frag3 can be as much
 *  as 250% faster than frag2, but we still need to do more testing and
 *  optimization, we may be able to squeeze out some more performance.
 *
 *  Frag3 is also capable of performing "engine-based" IP defragmentation.
 *  What this means practically is that frag3 can model the IP stack of a
 *  engine on the network to avoid Ptacek-Newsham evasions of the IDS through
 *  sensor/engine desynchronization.  In terms of implentation, this is
 *  reflected by passing a "engine" into the defragmentation engine that has
 *  a specific configuration for a specific engine type.  Windows can put
 *  fragments back together differently than Linux/BSD/etc, so we model that
 *  inside frag3 so we can't be evaded.
 *
 *  Configuration of frag3 is pretty straight forward, there's a global config
 *  that contains data about how the hash tables will be structured, what type
 *  of memory management to use and whether or not to generate alerts, then
 *  specific engine are setup and bound to IP address sets.  Check
 *  the README file for specifics!
 */

/*  I N C L U D E S  ************************************************/
#include "defrag.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <rpc/types.h>
#include <errno.h>

#include "defrag_module.h"
#include "main/analyzer.h"
#include "snort_bounds.h"
#include "log_text.h"
#include "detect.h"
#include "decode.h"
#include "encode.h"
#include "event.h"
#include "util.h"
#include "snort_debug.h"
#include "parser.h"
#include "mstring.h"
#include "perf_monitor/perf.h"
#include "timersub.h"
#include "fpcreate.h"
#include "utils/sflsq.h"
#include "hash/sfxhash.h"
#include "snort.h"
#include "profiler.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq.h"
#include "framework/inspector.h"
#include "framework/share.h"
#include "target_based/sftarget_hostentry.h"
#include "target_based/sftarget_protocol_reference.h"

/*  D E F I N E S  **************************************************/

/* flags for the FragTracker->frag_flags field */
#define FRAG_GOT_FIRST      0x00000001
#define FRAG_GOT_LAST       0x00000002
#define FRAG_REBUILT        0x00000004
#define FRAG_BAD            0x00000008
#define FRAG_NO_BSD_VULN    0x00000010
#define FRAG_DROP_FRAGMENTS 0x00000020

/* default frag timeout, 90-120 might be better values, can we do
 * engine-based quanta?  */
#define FRAG_PRUNE_QUANTA   60

/* default 4MB memcap */
#define FRAG_MEMCAP   4194304

/* min acceptable ttl (should be 1?) */
#define FRAG_MIN_TTL        1

/* engine-based defragmentation policy enums */
// must update parameter in defrag_module.cc if this changes
enum
{
    FRAG_POLICY_FIRST = 1,
    FRAG_POLICY_LINUX,
    FRAG_POLICY_BSD,
    FRAG_POLICY_BSD_RIGHT,
    FRAG_POLICY_LAST,
/* Combo of FIRST & LAST, depending on overlap situation. */
    FRAG_POLICY_WINDOWS,
/* Combo of FIRST & LAST, depending on overlap situation. */
    FRAG_POLICY_SOLARIS
};

#define FRAG_POLICY_DEFAULT     FRAG_POLICY_LINUX

/* max packet size */
#define DATASIZE (ETHERNET_HEADER_LEN+IP_MAXPACKET)

/* max frags in a single frag tracker */
#define DEFAULT_MAX_FRAGS   8192

/* return values for CheckTimeout() */
#define FRAG_TIME_OK            0
#define FRAG_TIMEOUT            1

/* return values for insert() */
#define FRAG_INSERT_OK          0
#define FRAG_INSERT_FAILED      1
#define FRAG_INSERT_REJECTED    2
#define FRAG_INSERT_TIMEOUT     3
#define FRAG_INSERT_ATTACK      4
#define FRAG_INSERT_ANOMALY     5
#define FRAG_INSERT_TTL         6
#define FRAG_INSERT_OVERLAP_LIMIT  7

/* return values for FragCheckFirstLast() */
#define FRAG_FIRSTLAST_OK       0
#define FRAG_LAST_DUPLICATE     1

/* return values for expire() */
#define FRAG_OK                 0
#define FRAG_TRACKER_TIMEOUT    1
#define FRAG_LAST_OFFSET_ADJUST 2

/* flag for detecting attacks/alerting */
#define DEFRAG_DETECT_ANOMALIES  0x01

/*  D A T A   S T R U C T U R E S  **********************************/

/* struct to manage an individual fragment */
typedef struct _Fragment
{
    uint8_t   *data;     /* ptr to adjusted start position */
    uint16_t   size;     /* adjusted frag size */
    uint16_t   offset;   /* adjusted offset position */

    uint8_t   *fptr;     /* free pointer */
    uint16_t   flen;     /* free len, unneeded? */

    struct _Fragment *prev;
    struct _Fragment *next;

    int         ord;
    char        last;

    bool pre;  // FIXIT this is really thread specific data
} Fragment;

typedef struct _fragkey
{
    uint32_t   sip[4];
    uint32_t   dip[4];
    uint32_t   id;
    uint16_t   vlan_tag;
    uint8_t    proto;         /* IP protocol, unused for IPv6 */
    uint8_t    ipver;         /* Version */
    uint32_t   mlabel;
    /* For 64 bit alignment since this is allocated in front of a FragTracker
     * and the structures are laid on top of that allocated memory */
#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
    uint16_t   addressSpaceId;
    uint16_t   addressSpaceIdPad1;
#else
    uint32_t   mpad;
#endif
} FRAGKEY;

/* Only track a certain number of alerts per session */
#define MAX_FRAG_ALERTS  8

/* global configuration data struct for this preprocessor */
typedef struct _FragConfig
{
    const FragCommon* common;
    FragEngine* engine;

} FragConfig;

/* tracker for a fragmented packet set */
typedef struct _FragTracker
{
    uint32_t sip[4];
    uint32_t dip[4];
    uint32_t id;           /* IP ID */
    uint8_t protocol;      /* IP protocol */
    uint8_t ipver;         /* Version */

    uint8_t ttl;           /* ttl used to detect evasions */
    uint8_t alerted;
    uint32_t frag_flags;   /* bit field */

    uint32_t frag_bytes;   /* number of fragment bytes stored, based
                             * on aligned fragment offsets/sizes
                             */

    uint32_t calculated_size; /* calculated size of reassembled pkt, based on
                                * last frag offset
                                */

    uint32_t frag_pkts;   /* nummber of frag pkts stored under this tracker */

    struct timeval frag_time; /* time we started tracking this frag */

    Fragment *fraglist;      /* list of fragments */
    Fragment *fraglist_tail; /* tail ptr for easy appending */
    int fraglist_count;       /* handy dandy counter */

    uint32_t alert_gid[MAX_FRAG_ALERTS]; /* flag alerts seen in a frag list  */
    uint32_t alert_sid[MAX_FRAG_ALERTS]; /* flag alerts seen in a frag list  */
    uint8_t  alert_count;                /* count alerts seen in a frag list */

    uint32_t ip_options_len;  /* length of ip options for this set of frags */
    uint32_t ip_option_count; /* number of ip options for this set of frags */
    uint8_t *ip_options_data; /* ip options from offset 0 packet */

    uint32_t copied_ip_options_len;  /* length of 'copied' ip options */
    uint32_t copied_ip_option_count; /* number of 'copied' ip options */

    FragEngine *engine;

    int ordinal;
    int ipprotocol;
    int application_protocol;
    uint32_t frag_policy;
    /**Count of IP fragment overlap for each packet id.
     */
    uint32_t overlap_count;

    Inspector* handler;
} FragTracker;

/* statistics tracking struct */
struct FragStats
{
    PegCount  total;
    PegCount  reassembles;
    PegCount  discards;
    PegCount  prunes;
    PegCount  timeouts;
    PegCount  overlaps;
    PegCount  anomalies;
    PegCount  alerts;
    PegCount  drops;
    PegCount  fragtrackers_created;
    PegCount  fragtrackers_released;
    PegCount  fragtrackers_autoreleased;
    PegCount  fragnodes_created;
    PegCount  fragnodes_released;

};

static const char* peg_names[] =
{
    "fragments",
    "reassembled",
    "discards",
    "memory faults",
    "timeouts",
    "overlaps",
    "anomalies",
    "alerts",
    "drops",
    "trackers added",
    "trackers freed",
    "trackers auto freed",
    "nodes inserted",
    "nodes deleted"
};

/*  G L O B A L S  **************************************************/
/* Config to use to evaluate
 * If a frag tracker is found in the hash table, the configuration under
 * which it was created will be used */

static THREAD_LOCAL SFXHASH *f_cache = NULL;                 /* fragment hash table */
static THREAD_LOCAL Fragment *prealloc_frag_list = NULL;    /* head for prealloc queue */

static unsigned prealloc_frags = 0;
static unsigned prealloc_high = 0;

static THREAD_LOCAL unsigned long mem_in_use = 0;            /* memory in use, used for self pres */

static THREAD_LOCAL uint32_t prealloc_nodes_in_use;  /* counter for debug */

static THREAD_LOCAL FragStats t_stats;
static FragStats g_stats;

static THREAD_LOCAL Packet* defrag_pkt = NULL;
static THREAD_LOCAL Packet* encap_defrag_pkt = NULL;

static THREAD_LOCAL uint32_t pkt_snaplen = 0;

/* enum for policy names */
static const char *frag_policy_names[] = { "no policy!",
    "FIRST",
    "LINUX",
    "BSD",
    "BSD_RIGHT",
    "LAST",
    "WINDOWS",
    "SOLARIS"};

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats fragPerfStats;
static THREAD_LOCAL PreprocStats fragInsertPerfStats;
static THREAD_LOCAL PreprocStats fragRebuildPerfStats;

static PreprocStats* frag_get_profile(const char* key)
{
    if ( !strcmp(key, "frag" ) )
        return &fragPerfStats;

    if ( !strcmp(key, "fraginsert" ) )
        return &fragInsertPerfStats;

    if ( !strcmp(key, "fragrebuild" ) )
        return &fragRebuildPerfStats;

    return nullptr;
}
#endif

/*  P R O T O T Y P E S  ********************************************/
static FragTracker *FragGetTracker(Packet *, FRAGKEY *);
static void FragRebuild(FragTracker *, Packet *);
static inline int FragIsComplete(FragTracker *);
static int FragHandleIPOptions(FragTracker *, Packet *);

/* deletion funcs */
static THREAD_LOCAL struct timeval *pkttime;    /* packet timestamp */
static void FragRemoveTracker(void *, void *);
static int FragAutoFree(void *, void *);
static int FragUserFree(void *, void *);

/* fraglist handler funcs */
static inline void add_node(FragTracker *, Fragment *, Fragment *);
static void delete_frag(Fragment*);
static void delete_node(FragTracker*, Fragment*);
static void delete_tracker(FragTracker*);

/* prealloc queue handler funcs */
static inline Fragment *FragPreallocPop();
static inline void FragPreallocPush(Fragment *);

char *FragIPToStr(uint32_t ip[4], uint8_t proto)
{
    char *ret_str;
    sfip_t srcip;
    sfip_set_raw(&srcip, ip, proto == 4 ? AF_INET : AF_INET6);

    ret_str = sfip_to_str(&srcip);
    return ret_str;
}

#ifdef DEBUG_FRAG3
/**
 * Print out a FragTracker structure
 *
 * @param ft Pointer to the FragTracker to print
 *
 * @return none
 */
static void PrintFragTracker(FragTracker *ft)
{
    LogMessage("FragTracker %p\n", ft);
    if(ft)
    {
        LogMessage("        sip: %s\n", FragIPToStr(ft->sip, ft->ipver));
        LogMessage("        dip: %s\n", FragIPToStr(ft->dip, ft->ipver));
        LogMessage("         id: %d\n", ft->id);
        LogMessage("      proto: 0x%X\n", ft->protocol);
        LogMessage("      ipver: 0x%X\n", ft->ipver);
        LogMessage("        ttl: %d\n", ft->ttl);
        LogMessage("    alerted: %d\n", ft->alerted);
        LogMessage(" frag_flags: 0x%X\n", ft->frag_flags);
        LogMessage(" frag_bytes: %d\n", ft->frag_bytes);
        LogMessage("  calc_size: %d\n", ft->calculated_size);
        LogMessage("  frag_pkts: %d\n", ft->frag_pkts);
        LogMessage("  frag_time: %lu %lu\n", ft->frag_time.tv_sec,
                ft->frag_time.tv_usec);
        LogMessage("   fraglist: %p\n", ft->fraglist);
        LogMessage("    fl_tail: %p\n", ft->fraglist_tail);
        LogMessage("fraglst cnt: %d\n", ft->fraglist_count);
    }
}

/**
 * Print out a FragKey structure
 *
 * @param fkey Pointer to the FragKey to print
 *
 * @return none
 */
static void PrintFragKey(FRAGKEY *fkey)
{
    LogMessage("FragKey %p\n", fkey);

    if(fkey)
    {
        LogMessage("   sip: %s\n", FragIPToStr(fkey->sip, fkey->ipver));
        LogMessage("   dip: %s\n", FragIPToStr(fkey->dip, fkey->ipver));
        LogMessage("     id: %d\n", fkey->id);
        LogMessage("  proto: 0x%X\n", fkey->proto);
        LogMessage(" mlabel: 0x%08X\n", fkey->mlabel);
#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
        LogMessage(" addr id: %d\n", fkey->addressSpaceId);
#endif
    }
}

/**
 * Print out a Fragment structure
 *
 * @param f Pointer to the Fragment to print
 *
 * @return none
 */
static void PrintFragment(Fragment *f)
{
    LogMessage("Fragment: %p\n", f);

    if(f)
    {
        LogMessage("    data: %p\n", f->data);
        LogMessage("    size: %d\n", f->size);
        LogMessage("  offset: %d\n", f->offset);
        LogMessage("    fptr: %p\n", f->fptr);
        LogMessage("    flen: %d\n", f->flen);
        LogMessage("    prev: %p\n", f->prev);
        LogMessage("    next: %p\n", f->next);
    }
}

#endif  /* DEBUG_FRAG3 */

/**
 * Print out the global runtime configuration
 *
 * @param None
 *
 * @return none
 */
static void FragPrintGlobalConfig(FragConfig *gconfig)
{
    if (gconfig == NULL)
        return;

    LogMessage("Defrag config:\n");
    LogMessage("    Max frags: %d\n", gconfig->common->max_frags);

    if(!gconfig->common->use_prealloc)
        LogMessage("    Fragment memory cap: %lu bytes\n",
                gconfig->common->memcap);
    else
    {
        if (prealloc_frags)
            LogMessage("    Preallocated frag nodes: %u\n", prealloc_frags);

        if (!gconfig->common->use_prealloc_frags)
            LogMessage("    Memory cap used to determine preallocated frag nodes: %lu\n",
                    gconfig->common->memcap);
    }

#ifdef REG_TEST
    LogMessage("    FragTracker Size: %lu\n",sizeof(FragTracker));
#endif
}


/**
 * Print out a defrag engine
 *
 * @param Pointer to the engine structure to print
 *
 * @return none
 */
static void FragPrintEngineConfig(FragEngine* engine)
{

    LogMessage("Defrag engine config:\n");
    LogMessage("    engine-based policy: %s\n",
            frag_policy_names[engine->frag_policy]);
    LogMessage("    Fragment timeout: %d seconds\n",
            engine->frag_timeout);
    LogMessage("    Fragment min_ttl:   %d\n", engine->min_ttl);
    LogMessage("    Fragment Anomalies: %s\n",
            engine->detect ? "Alert" : "No Alert");

    LogMessage("    Overlap Limit:     %d\n",
            engine->overlap_limit);
    LogMessage("    Min fragment Length:     %d\n",
            engine->min_fragment_length);
}

/**
 * Generate an event due to IP options being detected in a frag packet
 *
 * @param engine Current run engine
 *
 * @return none
 */
static inline void EventAnomIpOpts(FragEngine *engine)
{
    if ( !engine->detect )
        return;

    SnortEventqAdd(GID_DEFRAG, DEFRAG_IPOPTIONS);

   t_stats.alerts++;
}

/**
 * Generate an event due to a Teardrop-style attack detected in a frag packet
 *
 * @param engine Current run engine
 *
 * @return none
 */
static inline void EventAttackTeardrop(FragEngine *engine)
{
    if ( !engine->detect )
        return;

    SnortEventqAdd(GID_DEFRAG, DEFRAG_TEARDROP);

   t_stats.alerts++;
}

/**
 * Generate an event for very small fragment
 *
 * @param engine Current run engine
 *
 * @return none
 */
static inline void EventTinyFragments(FragEngine *engine)
{
    if ( !engine->detect )
        return;

    SnortEventqAdd(GID_DEFRAG, DEFRAG_TINY_FRAGMENT);

   t_stats.alerts++;
}

/**
 * Generate an event due to excessive fragment overlap detected in a frag packet
 *
 * @param engine Current run engine
 *
 * @return none
 */
static inline void EventExcessiveOverlap(FragEngine *engine)
{
    //@TBD dschahal do I need this
    if ( !engine->detect )
        return;

    SnortEventqAdd(GID_DEFRAG, DEFRAG_EXCESSIVE_OVERLAP);

   t_stats.alerts++;
}

/**
 * Generate an event due to a fragment being too short, typcially based
 * on a non-last fragment that doesn't properly end on an 8-byte boundary
 *
 * @param engine Current run engine
 *
 * @return none
 */
static inline void EventAnomShortFrag(FragEngine *engine)
{
    if ( !engine->detect )
        return;

    SnortEventqAdd(GID_DEFRAG, DEFRAG_SHORT_FRAG);

   t_stats.alerts++;
   t_stats.anomalies++;
}

/**
 * This fragment's size will end after the already calculated reassembled
 * fragment end, as in a Bonk/Boink/etc attack.
 *
 * @param engine Current run engine
 *
 * @return none
 */
static inline void EventAnomOversize(FragEngine *engine)
{
    if ( !engine->detect )
        return;

    SnortEventqAdd(GID_DEFRAG, DEFRAG_ANOMALY_OVERSIZE);

   t_stats.alerts++;
   t_stats.anomalies++;
}

/**
 * The current fragment will be inserted with a size of 0 bytes, that's
 * an anomaly if I've ever seen one.
 *
 * @param engine Current run engine
 *
 * @return none
 */
static inline void EventAnomZeroFrag(FragEngine *engine)
{
    if ( !engine->detect )
        return;

    SnortEventqAdd(GID_DEFRAG, DEFRAG_ANOMALY_ZERO);

   t_stats.alerts++;
   t_stats.anomalies++;
}

/**
 * The reassembled packet will be bigger than 64k, generate an event.
 *
 * @param engine Current run engine
 *
 * @return none
 */
static inline void EventAnomBadsizeLg(FragEngine *engine)
{
    if ( !engine->detect )
        return;

    SnortEventqAdd(GID_DEFRAG, DEFRAG_ANOMALY_BADSIZE_LG);

   t_stats.alerts++;
   t_stats.anomalies++;
}

/**
 * Fragment size is negative after insertion (end < offset).
 *
 * @param engine Current run engine
 *
 * @return none
 */
static inline void EventAnomBadsizeSm(FragEngine *engine)
{
    if ( !engine->detect )
        return;

    SnortEventqAdd(GID_DEFRAG, DEFRAG_ANOMALY_BADSIZE_SM);

   t_stats.alerts++;
   t_stats.anomalies++;
}

/**
 * There is an overlap with this fragment, someone is probably being naughty.
 *
 * @param engine Current run engine
 *
 * @return none
 */
static inline void EventAnomOverlap(FragEngine *engine)
{
    if ( !engine->detect )
        return;

    SnortEventqAdd(GID_DEFRAG, DEFRAG_ANOMALY_OVLP);

    t_stats.alerts++;
    t_stats.anomalies++;
}

/**
 * Generate an event due to TTL below the configured minimum
 *
 * @param engine Current run engine
 *
 * @return none
 */
static inline void EventAnomScMinTTL(FragEngine *engine)
{
    if ( !engine->detect )
        return;

    SnortEventqAdd(GID_DEFRAG, DEFRAG_MIN_TTL_EVASION);

   t_stats.alerts++;
}

static uint32_t FragKeyHashFunc(SFHASHFCN*, unsigned char *d, int)
{
    uint32_t a,b,c;
    uint32_t offset = 0;
    uint32_t tmp = 0;
#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
    uint32_t tmp2 = 0;
#endif

    a = *(uint32_t *)d;        /* IPv6 sip[0] */
    b = *(uint32_t *)(d+4);    /* IPv6 sip[1] */
    c = *(uint32_t *)(d+8);    /* IPv6 sip[2] */
    mix(a,b,c);

    a += *(uint32_t *)(d+12);  /* IPv6 sip[3] */
    b += *(uint32_t *)(d+16);  /* IPv6 dip[0] */
    c += *(uint32_t *)(d+20);  /* IPv6 dip[1] */
    mix(a,b,c);

    a += *(uint32_t *)(d+24);  /* IPv6 dip[2] */
    b += *(uint32_t *)(d+28);  /* IPv6 dip[3] */
    c += *(uint32_t *)(d+32);  /* IPv6 id */
    mix(a,b,c);

    offset = 36;

    a += *(uint32_t *)(d+offset);  /* vlan, proto, ipver */
    tmp = *(uint32_t*)(d+offset+4);
    if( tmp )
    {
        b += tmp;   /* mpls label */
    }
    offset += 8;    /* skip past vlan/proto/ipver & mpls label */

#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
    tmp2 = *(uint32_t*)(d+offset); /* after offset that has been moved */
    c += tmp2; /* address space id and 16bits of zero'd pad */
#endif

    final(a,b,c);

    return c;
}

static int FragKeyCmpFunc(const void *s1, const void *s2, size_t)
{
#ifndef SPARCV9 /* ie, everything else, use 64bit comparisons */
    uint64_t *a, *b;

    a = (uint64_t*)s1;
    b = (uint64_t*)s2;
    if (*a - *b) return 1;      /* Compares IPv4 sip/dip */
                                /* Compares IPv6 sip[0,1] */
    a++;
    b++;
    if (*a - *b) return 1;      /* Compares IPv6 sip[2,3] */

    a++;
    b++;
    if (*a - *b) return 1;      /* Compares IPv6 dip[0,1] */

    a++;
    b++;
    if (*a - *b) return 1;      /* Compares IPv6 dip[2,3] */

    a++;
    b++;
    if (*a - *b) return 1;      /* Compares IPv4 id/pad, vlan/proto/ipver */
                                /* Compares IPv6 id, vlan/proto/ipver */

    a++;
    b++;
#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
    if (*a - *b) return 1;      /* Compares MPLS label, AddressSpace ID and 16bit pad */
#else
    {
        uint32_t *x, *y;
        x = (uint32_t *)a;
        y = (uint32_t *)b;
        //x++;
        //y++;
        if (*x - *y) return 1;  /* Compares mpls label, no pad */
    }
#endif

#else /* SPARCV9 */
    uint32_t *a,*b;

    a = (uint32_t*)s1;
    b = (uint32_t*)s2;
    if ((*a - *b) || (*(a+1) - *(b+1))) return 1;       /* Compares IPv4 sip/dip */
                                /* Compares IPv6 sip[0,1] */
    a+=2;
    b+=2;
    if ((*a - *b) || (*(a+1) - *(b+1))) return 1;       /* Compares IPv6 sip[2,3] */

    a+=2;
    b+=2;
    if ((*a - *b) || (*(a+1) - *(b+1))) return 1;       /* Compares IPv6 dip[0,1] */

    a+=2;
    b+=2;
    if ((*a - *b) || (*(a+1) - *(b+1))) return 1;       /* Compares IPv6 dip[2,3] */

    a+=2;
    b+=2;
    if ((*a - *b) || (*(a+1) - *(b+1))) return 1;       /* Compares IPv4 id/pad, vlan/proto/ipver */
                                /* Compares IPv6 id, vlan/proto/ipver */

    a+=2;
    b+=2;
    {
        uint32_t *x, *y;
        x = (uint32_t *)a;
        y = (uint32_t *)b;
        //x++;
        //y++;
        if (*x - *y) return 1;  /* Compares mpls label */
    }
#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
    a++;
    b++;
#endif
    {
        uint16_t *x, *y;
        x = (uint16_t *)a;
        y = (uint16_t *)b;
        //x++;
        //y++;
        if (*x - *y) return 1;  /* Compares addressSpaceID, no pad */
    }
#endif /* SPARCV9 */

    return 0;
}

static void FragInitCache (FragConfig* config)
{
    assert(!f_cache);

    /* we keep FragTrackers in the hash table.. */
    unsigned long hashTableSize = (unsigned long) (config->common->max_frags * 1.4);

    unsigned long maxFragMem = config->common->max_frags * (
        sizeof(FragTracker) + sizeof(SFXHASH_NODE) +
        sizeof (FRAGKEY) + sizeof(SFXHASH_NODE *));

    unsigned long tableMem = (hashTableSize + 1) * sizeof(SFXHASH_NODE *);
    unsigned long maxMem = maxFragMem + tableMem;

    f_cache = sfxhash_new(
        hashTableSize,       /* number of hash buckets */
        sizeof(FRAGKEY),     /* size of the key we're going to use */
        sizeof(FragTracker), /* size of the storage node */
        maxMem,              /* memcap for frag trackers */
        1,                   /* use auto node recovery */
        FragAutoFree,       /* anr free function */
        FragUserFree,       /* user free function */
        1);                  /* recycle node flag */

    /* can't proceed if we can't get a fragment cache */
    if(!f_cache)
    {
        LogMessage("WARNING: Unable to generate new sfxhash for frag3, "
                   "defragmentation disabled.\n");
        return;
    }

    sfxhash_set_keyops(f_cache, FragKeyHashFunc, FragKeyCmpFunc);

    if(config->common->use_prealloc)
    {
        // user has decided to prealloc the node structs for performance
        prealloc_frags = config->common->static_frags;

        if ( !prealloc_frags )
        {
            prealloc_frags = (uint32_t)(config->common->memcap /
                (sizeof(Fragment) + sizeof(uint8_t) * pkt_snaplen) + 1);
        }
        prealloc_high = prealloc_frags >> 5;

        for (unsigned i = 0; i < prealloc_frags; i++)
        {
            Fragment* tmp =(Fragment*)SnortAlloc(sizeof(Fragment));
            tmp->fptr = (uint8_t *) SnortAlloc(sizeof(uint8_t) * pkt_snaplen);
            tmp->pre = true;
            FragPreallocPush(tmp);
        }

        prealloc_nodes_in_use = 0;
    }
}

static int FragPolicyIdFromName(char *name)
{
    if (!name)
    {
        return FRAG_POLICY_DEFAULT;
    }

    if(!strcasecmp(name, "bsd"))
    {
        return FRAG_POLICY_BSD;
    }
    else if(!strcasecmp(name, "bsd-right"))
    {
        return FRAG_POLICY_BSD_RIGHT;
    }
    else if(!strcasecmp(name, "linux"))
    {
        return FRAG_POLICY_LINUX;
    }
    else if(!strcasecmp(name, "first"))
    {
        return FRAG_POLICY_FIRST;
    }
    else if(!strcasecmp(name, "windows"))
    {
        return FRAG_POLICY_WINDOWS;
    }
    else if(!strcasecmp(name, "solaris"))
    {
        return FRAG_POLICY_SOLARIS;
    }
    else if(!strcasecmp(name, "last"))
    {
        return FRAG_POLICY_LAST;
    }
    return FRAG_POLICY_DEFAULT;
}

int FragPolicyIdFromHostAttributeEntry(HostAttributeEntry *host_entry)
{
    if (!host_entry)
        return 0;

    host_entry->hostInfo.fragPolicy = FragPolicyIdFromName(host_entry->hostInfo.fragPolicyName);
    host_entry->hostInfo.fragPolicySet = 1;

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
        "Frag3 INIT: %s(%d) for Entry %s\n",
        frag_policy_names[host_entry->hostInfo.fragPolicy],
        host_entry->hostInfo.fragPolicy,
        host_entry->hostInfo.fragPolicyName););

    return 0;
}

/**
 * Check to see if a FragTracker has timed out
 *
 * @param current_time Time at this moment
 * @param start_time Time to compare current_time to
 * @param engine Engine engine
 *
 * @return status
 * @retval  FRAG_TIMEOUT Current time diff is greater than the current
 *                       engine's timeout value
 * @retval  FRAG_TIME_OK Current time diff is within the engine's prune
 *                       window
 */
static inline int CheckTimeout(struct timeval *current_time,
        struct timeval *start_time,
        FragEngine *engine)
{
    struct timeval tv_diff; /* storage struct for the difference between
                               current_time and start_time */

    TIMERSUB(current_time, start_time, &tv_diff);

    if(tv_diff.tv_sec >= (int)engine->frag_timeout)
    {
        return FRAG_TIMEOUT;
    }

    return FRAG_TIME_OK;
}

/**
 * Check to see if we've got the first or last fragment on a FragTracker and
 * set the appropriate frag_flags
 *
 * @param p Packet to get the info from
 * @param ft FragTracker to set the flags on
 *
 * @return none
 */
static inline int FragCheckFirstLast(Packet *p, FragTracker *ft)
{
    uint16_t fragLength;
    int retVal = FRAG_FIRSTLAST_OK;
    uint16_t endOfThisFrag;

    /* set the frag flag if this is the first fragment */
    if(p->mf && p->frag_offset == 0)
    {
        ft->frag_flags |= FRAG_GOT_FIRST;

        DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "Got first frag\n"););
    }
    else if((!p->mf) && (p->frag_offset > 0)) /* set for last frag too */
    {
        /* Use the actual length here, because packet may have been
        * truncated.  Don't want to try to copy more than we actually
        * captured. */
        //fragLength = p->actual_ip_len - GET_IPH_HLEN(p) * 4;
        fragLength = p->ip_frag_len;
        endOfThisFrag = (p->frag_offset << 3) + fragLength;

        if (ft->frag_flags & FRAG_GOT_LAST)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "Got last frag again!\n"););
            switch (ft->frag_policy)
            {
                case FRAG_POLICY_BSD:
                case FRAG_POLICY_LINUX:
                case FRAG_POLICY_BSD_RIGHT:
                case FRAG_POLICY_LAST:
                case FRAG_POLICY_WINDOWS:
                case FRAG_POLICY_FIRST:
                    if (ft->calculated_size > endOfThisFrag)
                    {
                       /* Already have a 'last frag' with a higher
                        * end point.  Leave it as is.
                        *
                        * Some OS's do not respond at all -- we'll
                        * still try to rebuild anyway in that case,
                        * because there is really something wrong
                        * and we should look at it.
                        */
                        retVal = FRAG_LAST_DUPLICATE;
                    }
                    break;
                case FRAG_POLICY_SOLARIS:
                    if (ft->calculated_size > endOfThisFrag)
                    {
                       /* Already have a 'last frag' with a higher
                        * end point.  Leave it as is.
                        *
                        * Some OS's do not respond at all -- we'll
                        * still try to rebuild anyway in that case,
                        * because there is really something wrong
                        * and we should look at it.
                        */
                        retVal = FRAG_LAST_DUPLICATE;
                    }
                    else
                    {
                        /* Solaris does some weird stuff here... */
                        /* Usually, Solaris takes the higher end point.
                         * But in one strange case (when it hasn't seen
                         * any frags beyond the existing last frag), it
                         * actually appends that new last frag to the
                         * end of the previous last frag, regardless of
                         * the offset.  Effectively, it adjusts the
                         * offset of the new last frag to immediately
                         * after the existing last frag.
                         */
                        /* XXX: how to handle that case? punt?  */
                        retVal = FRAG_LAST_OFFSET_ADJUST;
                    }
                    break;
            }
        }

        ft->frag_flags |= FRAG_GOT_LAST;

        /*
         * If this is the last frag (and we don't have a frag that already
         * extends beyond this one), set the size that we're expecting.
         */
        if ((ft->calculated_size < endOfThisFrag) &&
            (retVal != FRAG_LAST_OFFSET_ADJUST))
        {
            ft->calculated_size = endOfThisFrag;

            DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "Got last frag, Bytes: %d, "
                    "Calculated size: %d\n",
                    ft->frag_bytes,
                    ft->calculated_size););
        }
    }

    if (p->frag_offset != 0)
    {
        ft->frag_flags |= FRAG_NO_BSD_VULN;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "Frag Status: %s:%s\n",
                ft->frag_flags&FRAG_GOT_FIRST?"FIRST":"No FIRST",
                ft->frag_flags&FRAG_GOT_LAST?"LAST":"No LAST"););
    return retVal;
}

/**
 * Lookup a FragTracker in the f_cache sfxhash table based on an input key
 *
 * @param p The current packet to get the key info from
 * @param fkey Pointer to a container for the FragKey
 *
 * @return Pointer to the FragTracker in the hash bucket or NULL if there is
 *         no fragment in the hash bucket
 */
static FragTracker *FragGetTracker(Packet *p, FRAGKEY *fkey)
{
    FragTracker *returned; /* FragTracker ptr returned by the lookup */

    /*
     * we have to setup the key first, downstream functions depend on
     * it being setup here
     */
    if (IS_IP4(p))
    {
        COPY4(fkey->sip, p->ip4h->ip_src.ip32);
        COPY4(fkey->dip, p->ip4h->ip_dst.ip32);
        fkey->id = GET_IPH_ID(p);
        fkey->ipver = 4;
        fkey->proto = GET_IPH_PROTO(p);
    }
    else
    {
        IP6Frag *fragHdr;
        COPY4(fkey->sip, p->ip6h->ip_src.ip32);
        COPY4(fkey->dip, p->ip6h->ip_dst.ip32);
        fkey->ipver = 6;
        /* Data points to the offset, and does not include the next hdr
         * and reserved.  Offset it by -2 to get there */
        fragHdr = (IP6Frag *)p->ip6_extensions[p->ip6_frag_index].data;
        /* Can't rely on the next header.  Only the 0 offset packet
         * is required to have it in the frag header */
        //fkey->proto = fragHdr->ip6f_nxt;
        fkey->proto = 0;
        fkey->id = fragHdr->ip6f_ident;
    }
    if (p->vh && !ScVlanAgnostic())
        fkey->vlan_tag = (uint16_t)VTH_VLAN(p->vh);
    else
        fkey->vlan_tag = 0;

    if(ScMplsOverlappingIp() && p->mpls)
        fkey->mlabel = p->mplsHdr.label;
    else
        fkey->mlabel = 0;

#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
    if (!ScAddressSpaceAgnostic())
        fkey->addressSpaceId = DAQ_GetAddressSpaceID(p->pkth);
    else
        fkey->addressSpaceId = 0;
#endif

    /*
     * if the hash table is empty we're done
     */
    if(sfxhash_count(f_cache) == 0)
        return NULL;

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                "[*] Looking up FragTracker using key:\n"););

#ifdef DEBUG_FRAG3
    PrintFragKey(fkey);
#endif

    returned = (FragTracker *) sfxhash_find(f_cache, fkey);

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                "FragGetTracker returning %p for\n", returned););

    return returned;
}

/**
 * Handle IP Options in fragmented packets.
 *
 * @param ft Current frag tracker for this packet
 * @param p Current packet to check for options
 * @param engine In case we get an anomaly
 *
 * @return status
 * @retval 0 on an error
 * @retval 1 on success
 */
static int FragHandleIPOptions(FragTracker *ft,
                                Packet *p)
{
    unsigned int i = 0;          /* counter */
    if(p->frag_offset == 0)
    {
        /*
         * This is the first packet.  If it has IP options,
         * save them off, so we can set them on the reassembled packet.
         */
        if (p->ip_options_len)
        {
            if (ft->ip_options_data)
            {
                /* Already seen 0 offset packet and copied some IP options */
                if ((ft->frag_flags & FRAG_GOT_FIRST)
                        && (ft->ip_option_count != p->ip_option_count))
                {
                    EventAnomIpOpts(ft->engine);
                }
            }
            else
            {
                /* Allocate and copy in the options */
                ft->ip_options_data = (uint8_t*)SnortAlloc(p->ip_options_len);
                memcpy(ft->ip_options_data, p->ip_options_data, p->ip_options_len);
                ft->ip_options_len = p->ip_options_len;
                ft->ip_option_count = p->ip_option_count;
            }
        }
    }
    else
    {
        /* check that options match those from other non-offset 0 packets */

        /* XXX: could check each individual option here, but that
         * would be performance ugly.  So, we'll just check that the
         * option counts match.  Alert if invalid, but still include in
         * reassembly.
         */
        if (ft->copied_ip_option_count)
        {
            if (ft->copied_ip_option_count != p->ip_option_count)
            {
                EventAnomIpOpts(ft->engine);
            }
        }
        else
        {
            ft->copied_ip_option_count = p->ip_option_count;
            for (i = 0;i< p->ip_option_count && i < IP_OPTMAX; i++)
            {
                /* Is the high bit set?  If not, weird anomaly. */
                if (!(p->ip_options[i].code & 0x80))
                    EventAnomIpOpts(ft->engine);
            }
        }
    }
    return 1;
}

int FragGetPolicy(Packet *p, FragEngine *engine)
{
    int frag_policy;
    /* Not caching this host_entry in the frag tracker so we can
     * swap the table out after processing this packet if we need
     * to.  */
    HostAttributeEntry *host_entry;

    if (!IsAdaptiveConfigured())
        return engine->frag_policy;

    host_entry = SFAT_LookupHostEntryByDst(p);

    if (host_entry && (isFragPolicySet(host_entry) == POLICY_SET))
    {
        frag_policy = getFragPolicy(host_entry);

        if (frag_policy != SFAT_UNKNOWN_FRAG_POLICY)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                "FragGetPolicy: Policy Map Entry: %d(%s)\n",
                frag_policy, frag_policy_names[frag_policy]););

            return frag_policy;
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
        "FragGetPolicy: Using configured default %d(%s)\n",
        engine->frag_policy, frag_policy_names[engine->frag_policy]););

    return engine->frag_policy;
}

/** checks for tiny fragments and raises appropriate alarm
 *
 * @param p Current packet to insert
 * @param ft FragTracker to hold the packet
 * @param fkey FragKey with the current FragTracker's key info
 * @param engine engine of the current engine for engine-based defrag info
 *
 * @returns 1 if tiny fragment was detected, 0 otherwise
 */
static inline int checkTinyFragments(
        FragEngine *engine,
        Packet *p,
        unsigned int trimmedLength
        )
{
    //Snort may need to raise a separate event if
    //only trimmed length is tiny.
    if(p->mf)
    {
        ///detect tiny fragments before processing overlaps.
        if (engine->min_fragment_length)
        {
            if (p->ip_frag_len <= engine->min_fragment_length)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                            "Frag3: Received fragment size(%d) is not more than configured min_fragment_length (%d)\n",
                            p->ip_frag_len, engine->min_fragment_length););
                EventTinyFragments(engine);
                return 1;
            }

            ///detect tiny fragments after processing overlaps.
            if (trimmedLength <= engine->min_fragment_length)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                            "Frag3: # of New octets in Received fragment(%d) is not more than configured min_fragment_length (%d)\n",
                            trimmedLength, engine->min_fragment_length););
                EventTinyFragments(engine);
                return 1;
            }
        }
    }

    return 0;
}

int  drop_all_fragments(
        Packet *p
        )
{
    FragTracker *ft = (FragTracker *)p->fragtracker;

    //drop this and all following fragments
    if (ft && !(ft->frag_flags & FRAG_DROP_FRAGMENTS))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                        "Frag3: Will drop all fragments on this packet\n"););
        ft->frag_flags |= FRAG_DROP_FRAGMENTS;
    }

    return 0;
}

/**
 * Check to see if a FragTracker has met all of its completion criteria
 *
 * @param ft FragTracker to check
 *
 * @return status
 * @retval 1 If the FragTracker is ready to be rebuilt
 * @retval 0 If the FragTracker hasn't fulfilled its completion criteria
 */
static inline int FragIsComplete(FragTracker *ft)
{
    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                "[$] Checking completion criteria\n"););

    /*
     * check to see if the first and last frags have arrived
     */
    if((ft->frag_flags & FRAG_GOT_FIRST) &&
            (ft->frag_flags & FRAG_GOT_LAST))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "   Got First and Last frags\n"););

        /*
         * if we've accumulated enough data to match the calculated size
         * of the defragg'd packet, return 1
         */
        if(ft->frag_bytes == ft->calculated_size)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                        "   [!] frag_bytes = calculated_size!\n"););

            sfBase.iFragCompletes++;

            return 1;
        }

        if (ft->frag_bytes > ft->calculated_size)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                        "   [!] frag_bytes > calculated_size!\n"););

            sfBase.iFragCompletes++;

            return 1;
        }

        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "   Calc size (%d) != frag bytes (%d)\n",
                    ft->calculated_size, ft->frag_bytes););

        /*
         * no dice
         */
        return 0;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                "   Missing First or Last frags (frag_flags: 0x%X)\n",
                ft->frag_flags););

    return 0;
}

/**
 * Reassemble the packet from the data in the FragTracker and reinject into
 * Snort's packet analysis system
 *
 * @param ft FragTracker to rebuild
 * @param p Packet to fill in pseudopacket IP structs
 *
 * @return none
 */
static void FragRebuild(FragTracker *ft, Packet *p)
{
    uint8_t *rebuild_ptr = NULL;  /* ptr to the start of the reassembly buffer */
    const uint8_t *rebuild_end;  /* ptr to the end of the reassembly buffer */
    Fragment *frag;    /* frag pointer for managing fragments */
    int ret = 0;
    Packet* dpkt;
    PROFILE_VARS;

// XXX NOT YET IMPLEMENTED - debugging

    PREPROC_PROFILE_START(fragRebuildPerfStats);

    if ( p->encapsulated )
        dpkt = encap_defrag_pkt;
    else
        dpkt = defrag_pkt;

    Encode_Format(ENC_FLAG_DEF|ENC_FLAG_FWD, p, dpkt, PSEUDO_PKT_IP);
    /*
     * set the pointer to the end of the rebuild packet
     */
    rebuild_ptr = (uint8_t*)dpkt->data;
    // the encoder ensures enough space for a maximum datagram
    rebuild_end = (uint8_t*)dpkt->data + IP_MAXPACKET;

    if (IS_IP4(p))
    {
        /*
         * if there are IP options, copy those in as well
         * these are for the inner IP...
         */
        if (ft->ip_options_data && ft->ip_options_len)
        {
            /* Adjust the IP header size in pseudo packet for the new length */
            uint8_t new_ip_hlen = sizeof(*dpkt->iph) + ft->ip_options_len;

            DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "Adjusting IP Header to %d bytes\n",
                    new_ip_hlen););
            SET_IP_HLEN((IPHdr *)dpkt->iph, new_ip_hlen>>2);

            ret = SafeMemcpy(rebuild_ptr, ft->ip_options_data,
                ft->ip_options_len, rebuild_ptr, rebuild_end);

            if (ret == SAFEMEM_ERROR)
            {
                /*XXX: Log message, failed to copy */
                ft->frag_flags = ft->frag_flags | FRAG_REBUILT;
                return;
            }
            rebuild_ptr += ft->ip_options_len;
        }
        else if (ft->copied_ip_options_len)
        {
            /* XXX: should we log a warning here?  there were IP options
             * copied across all fragments, EXCEPT the offset 0 fragment.
             */
        }

        /*
         * clear the packet fragment fields
         */
        ((IPHdr *)dpkt->iph)->ip_off = 0x0000;
        dpkt->frag_flag = 0;

        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "[^^] Walking fraglist:\n"););
    }

    /*
     * walk the fragment list and rebuild the packet
     */
    for(frag = ft->fraglist; frag; frag = frag->next)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "   frag: %p\n"
                    "   frag->data: %p\n"
                    "   frag->offset: %d\n"
                    "   frag->size: %d\n"
                    "   frag->prev: %p\n"
                    "   frag->next: %p\n",
                    frag, frag->data, frag->offset,
                    frag->size, frag->prev, frag->next););

        /*
         * We somehow got a frag that had data beyond the calculated
         * end. Don't want to include it.
         */
        if ((frag->offset + frag->size) > (uint16_t)ft->calculated_size)
            continue;

        /*
         * try to avoid buffer overflows...
         */
        if (frag->size)
        {
            ret = SafeMemcpy(rebuild_ptr+frag->offset, frag->data, frag->size,
                             rebuild_ptr, rebuild_end);

            if (ret == SAFEMEM_ERROR)
            {
                /*XXX: Log message, failed to copy */
                ft->frag_flags = ft->frag_flags | FRAG_REBUILT;
                return;
            }
        }
    }

    if (IS_IP4(p))
    {
        /*
         * tell the rest of the system that this is a rebuilt fragment
         */
        dpkt->packet_flags |= PKT_REBUILT_FRAG;
        dpkt->frag_flag = 0;
        dpkt->dsize = (uint16_t)ft->calculated_size;

        Encode_Update(dpkt);
    }
    else /* Inner/only is IP6 */
    {
        ipv6::IP6RawHdr* rawHdr = (ipv6::IP6RawHdr*)dpkt->raw_ip6h;

        if ( !rawHdr )
        {
            /*XXX: Log message, failed to copy */
            ft->frag_flags = ft->frag_flags | FRAG_REBUILT;
            return;
        }

        /* IPv6 Header is already copied over, as are all of the extensions
         * that were not part of the fragmented piece. */

        /* Set the 'next' protocol */
        if (p->ip6_frag_index > 0)
        {
            // FIXTHIS use of last_extension works but is ugly
            IP6Extension *last_extension = (IP6Extension *)
                (dpkt->pkt + (p->ip6_extensions[p->ip6_frag_index -1].data - p->pkt));
            last_extension->ip6e_nxt = ft->protocol;
        }
        else
        {
            rawHdr->ip6nxt = ft->protocol;
        }
        dpkt->dsize = (uint16_t)ft->calculated_size;
        Encode_Update(dpkt);
    }

    sfBase.iFragFlushes++;

    /* Rebuild is complete */
    PREPROC_PROFILE_END(fragRebuildPerfStats);

    /*
     * process the packet through the detection engine
     */
    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                "Processing rebuilt packet:\n"););

    t_stats.reassembles++;

    UpdateIPReassStats(&sfBase, dpkt->pkth->caplen);

#if defined(DEBUG_FRAG3) && defined(DEBUG)
    /*
     * Note, that this won't print out the IP Options or any other
     * data that is established when the packet is decoded.
     */
    if (DEBUG_FRAG & GetDebugLevel())
        LogIPPkt(dpkt->iph->ip_proto, &dpkt);

#endif
    SnortEventqPush();
    ProcessPacket(dpkt, dpkt->pkth, dpkt->pkt, ft);
    SnortEventqPop();

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                "Done with rebuilt packet, marking rebuilt...\n"););

    ft->frag_flags = ft->frag_flags | FRAG_REBUILT;
}

/**
 * Remove a FragTracker from the f_cache hash table
 *
 * @param key FragKey of the FragTracker to be removed
 * @param data unused in this function
 *
 * @return none
 */
static void FragRemoveTracker(void *key, void*)
{
    /*
     * sfxhash maintains its own self preservation stuff/node freeing stuff
     */
    if(sfxhash_remove(f_cache, key) != SFXHASH_OK)
    {
        ErrorMessage("sfxhash_remove() failed in frag3!\n");
    }

    return;
}

/**
 * This is the auto-node-release function that gets handed to the sfxhash table
 * at initialization.  Handles deletion of sfxhash table data members.
 *
 * @param key FragKey of the element to be freed
 * @param data unused in this implementation
 *
 * Now Returns 0 because we want to say, yes, delete that hash entry!!!
 */
static int FragAutoFree(void*, void *data)
{
    FragTracker *ft = (FragTracker *)data;

    if (ft == NULL)
        return 0;

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                "Calling delete_tracker()\n"););

    ft->handler->rem_ref();
    delete_tracker(ft);

    sfBase.iFragDeletes++;
    sfBase.iFragAutoFrees++;
    sfBase.iCurrentFrags--;
    t_stats.fragtrackers_autoreleased++;

    return 0;
}

/**
 * This is the user free function that gets handed to the sfxhash table
 * at initialization.  Handles deletion of sfxhash table data members.
 *
 * @param key FragKey of the element to be freed
 * @param data unused in this implementation
 *
 * Now Returns 0 because we want to say, yes, delete that hash entry!!!
 */
static int FragUserFree(void*, void *data)
{
    FragTracker *ft = (FragTracker *)data;

    if (ft == NULL)
        return 0;

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                "Calling delete_tracker()\n"););

    ft->handler->rem_ref();
    delete_tracker(ft);

    sfBase.iFragDeletes++;
    sfBase.iCurrentFrags--;
    t_stats.fragtrackers_released++;

    // FIXIT use reference count to delete PP instance
    return 0;
}

/**
 * Get a node from the prealloc_list
 *
 * @return pointer to a Fragment preallocated structure or NULL if the list
 * is empty
 */
static inline Fragment *FragPreallocPop(void)
{
    Fragment *node;

    if(prealloc_frag_list)
    {
        node = prealloc_frag_list;
        prealloc_frag_list = prealloc_frag_list->next;
        if (prealloc_frag_list)
        {
            prealloc_frag_list->prev = NULL;
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                        "Using last prealloc frag node\n"););
        }
        node->next = NULL;
        node->prev = NULL;
        node->offset = 0;
        node->size = 0;
        node->flen = 0;
        node->last = 0;
    }
    else
    {
        return NULL;
    }

    if (!node->fptr)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                        "Fragment fptr is NULL!\n"););
    }

    prealloc_nodes_in_use++;
    return node;
}

/**
 * Put a prealloc node back into the prealloc_cache pool
 *
 * @param node Prealloc node to place back in the pool
 *
 * @return none
 */
static inline void FragPreallocPush(Fragment *node)
{
    if (!prealloc_frag_list)
    {
        node->next = NULL;
        node->prev = NULL;
    }
    else
    {
        node->next = prealloc_frag_list;
        node->prev = NULL;
        prealloc_frag_list->prev = node;
    }

    prealloc_frag_list = node;
    node->data = NULL;
    if (!node->fptr)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                        "Fragment fptr is NULL!\n"););
    }

    prealloc_nodes_in_use--;
    return;
}

/**
 * Plug a Fragment into the fraglist of a FragTracker
 *
 * @param ft FragTracker to put the new node into
 * @param prev ptr to preceeding Fragment in fraglist
 * @param next ptr to following Fragment in fraglist
 * @param node ptr to node to put in list
 *
 * @return none
 */
static inline void add_node(FragTracker *ft, Fragment *prev,
        Fragment *node)
{
    if(prev)
    {
        node->next = prev->next;
        node->prev = prev;
        prev->next = node;
        if (node->next)
            node->next->prev = node;
        else
            ft->fraglist_tail = node;
    }
    else
    {
        node->next = ft->fraglist;
        if (node->next)
            node->next->prev = node;
        else
            ft->fraglist_tail = node;
        ft->fraglist = node;
    }

    ft->fraglist_count++;
    return;
}

/**
 * Delete a Fragment struct
 *
 * @param frag Fragment to delete
 *
 * @return none
 */
static void delete_frag(Fragment *frag)
{
    /*
     * delete the fragment either in prealloc or dynamic mode
     */
    if(!frag->pre)
    {
        free(frag->fptr);
        mem_in_use -= frag->flen;

        free(frag);
        mem_in_use -= sizeof(Fragment);

        sfBase.frag3_mem_in_use = mem_in_use;
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "o %d s %d ptr %p prv %p nxt %p\n",
                    frag->offset, frag->size, frag, frag->prev, frag->next););
        FragPreallocPush(frag);
    }

    t_stats.fragnodes_released++;
}

/**
 * Delete a Fragment from a fraglist
 *
 * @param ft FragTracker to delete the frag from
 * @param node node to be deleted
 *
 * @return none
 */
static inline void delete_node(FragTracker *ft, Fragment *node)
{
    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "Deleting list node %p (p %p n %p)\n",
                node, node->prev, node->next););

    if(node->prev)
    {
        node->prev->next = node->next;
    }
    else
    {
        ft->fraglist = node->next;
    }

    if(node->next)
    {
        node->next->prev = node->prev;
    }
    else
    {
        ft->fraglist_tail = node->prev;
    }

    delete_frag(node);
    ft->fraglist_count--;
}

/**
 * Delete the contents of a FragTracker, in this instance that just means to
 * dump the fraglist.  The sfxhash system deletes the actual FragTracker mem.
 *
 * @param ft FragTracker to delete
 *
 * @return none
 */
static void delete_tracker(FragTracker *ft)
{
    Fragment *idx = ft->fraglist;  /* pointer to the fraglist to delete */
    Fragment *dump_me = NULL;      /* ptr to the Fragment element to drop */

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                "delete_tracker %d nodes to dump\n", ft->fraglist_count););

    /*
     * delete all the nodes in a fraglist
     */
    while(idx)
    {
        dump_me = idx;
        idx = idx->next;
        delete_frag(dump_me);
    }
    ft->fraglist = NULL;
    if (ft->ip_options_data)
    {
        free(ft->ip_options_data);
        ft->ip_options_data = NULL;
    }

    return;
}

/*
**
**  NAME
**    fpAddFragAlert::
**
**  DESCRIPTION
**    This function flags an alert per frag tracker.
**
**  FORMAL INPUTS
**    Packet *      - the packet to inspect
**    OptTreeNode * - the rule that generated the alert
**
**  FORMAL OUTPUTS
**    int - 0 if not flagged
**          1 if flagged
**
*/
int fpAddFragAlert(Packet *p, OptTreeNode *otn)
{
    FragTracker *ft = (FragTracker*)p->fragtracker;

    if ( !ft )
        return 0;

    if ( !otn )
        return 0;

    /* Only track a certain number of alerts per session */
    if ( ft->alert_count >= MAX_FRAG_ALERTS )
        return 0;

    ft->alert_gid[ft->alert_count] = otn->sigInfo.generator;
    ft->alert_sid[ft->alert_count] = otn->sigInfo.id;
    ft->alert_count++;

    return 1;
}

/*
**
**  NAME
**    fpFragAlerted::
**
**  DESCRIPTION
**    This function indicates whether or not an alert has been generated previously
**    in this session, but only if this is a rebuilt packet.
**
**  FORMAL INPUTS
**    Packet *      - the packet to inspect
**    OptTreeNode * - the rule that generated the alert
**
**  FORMAL OUTPUTS
**    int - 0 if alert NOT previously generated
**          1 if alert previously generated
**
*/
int fpFragAlerted(Packet *p, OptTreeNode *otn)
{
    FragTracker *ft = (FragTracker*)p->fragtracker;
    SigInfo *si = &otn->sigInfo;
    int      i;

    if ( !ft )
        return 0;

    for ( i = 0; i < ft->alert_count; i++ )
    {
        /*  If this is a rebuilt packet and we've seen this alert before, return
         *  that we have previously alerted on a non-rebuilt packet.
         */
        if ( (p->packet_flags & PKT_REBUILT_FRAG)
                && ft->alert_gid[i] == si->generator && ft->alert_sid[i] == si->id )
        {
            return 1;
        }
    }

    return 0;
}

int fragGetApplicationProtocolId(Packet *p)
{
    FragTracker *ft;
    /* Not caching this host_entry in the frag tracker so we can
     * swap the table out after processing this packet if we need
     * to.  */
    HostAttributeEntry *host_entry = NULL;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    if (!p || !p->fragtracker)
    {
        return 0;
    }

    /* Must be a rebuilt frag... */
    if (!(p->packet_flags & PKT_REBUILT_FRAG))
    {
        return 0;
    }

    ft = (FragTracker *)p->fragtracker;

    if (ft->application_protocol != 0)
    {
        return ft->application_protocol;
    }

    switch (GET_IPH_PROTO(p))
    {
        case IPPROTO_TCP:
            ft->ipprotocol = protocolReferenceTCP;
            src_port = p->sp;
            dst_port = p->dp;
            break;
        case IPPROTO_UDP:
            ft->ipprotocol = protocolReferenceUDP;
            src_port = p->sp;
            dst_port = p->dp;
            break;
        case IPPROTO_ICMP:
            ft->ipprotocol = protocolReferenceICMP;
            break;
    }

    host_entry = SFAT_LookupHostEntryBySrc(p);
    if (host_entry)
    {
        ft->application_protocol = getApplicationProtocolId(host_entry,
                                    ft->ipprotocol,
                                    src_port,
                                    SFAT_SERVICE);
        if (ft->application_protocol != 0)
        {
            return ft->application_protocol;
        }
    }

    host_entry = SFAT_LookupHostEntryByDst(p);
    if (host_entry)
    {
        ft->application_protocol = getApplicationProtocolId(host_entry,
                                    ft->ipprotocol,
                                    dst_port,
                                    SFAT_SERVICE);
        if (ft->application_protocol != 0)
        {
            return ft->application_protocol;
        }
    }

    return ft->application_protocol;
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

typedef PlugDataType<FragCommon> FragData;

class Defrag : public Inspector {
public:
    Defrag(DefragEngineModule*);
    ~Defrag();

    bool configure(SnortConfig*);
    void show(SnortConfig*);

    void eval(Packet*);

    void pinit();
    void pterm();

private:
    int insert(Packet*, FragTracker*, FRAGKEY*, FragEngine*);
    int new_tracker(Packet *p, FRAGKEY *fkey, FragEngine*);
    int add_frag_node(
        // FIXTHIS too many args
        FragTracker *ft, Packet*, FragEngine*,
        const uint8_t *fragStart, int16_t fragLength,
        char lastfrag, int16_t len,
        uint16_t slide, uint16_t trunc, uint16_t frag_offset,
        Fragment *left, Fragment **retFrag);
    int dup_frag_node(FragTracker*, Fragment* left, Fragment **retFrag);
    int prune(FragTracker*);
    int expire(Packet*, FragTracker*, FragEngine*);

private:
    FragConfig config;
    FragData* global;
};

Defrag::Defrag (DefragEngineModule* mod)
{
    config.engine = mod->get_data();
    config.common = nullptr;
    global = nullptr;
}

Defrag::~Defrag()
{
    if ( config.engine )
        delete config.engine;

    if ( global )
        Share::release(global);
}

bool Defrag::configure(SnortConfig*)
{
    global = (FragData*)Share::acquire(GLOBAL_KEYWORD);
    config.common = global->data;
    SFAT_SetPolicyIds(FragPolicyIdFromHostAttributeEntry);
    return true;
}

void Defrag::pinit()
{
    FragInitCache(&config);

    defrag_pkt = Encode_New();
    encap_defrag_pkt = Encode_New();
    pkt_snaplen = DAQ_GetSnapLen();
}

void Defrag::pterm()
{
    sfxhash_delete(f_cache);
    f_cache = NULL;

    while ( Fragment* tmp = FragPreallocPop() )
    {
        free(tmp->fptr);
        free(tmp);
        tmp = FragPreallocPop();
    }

    Encode_Delete(defrag_pkt);
    defrag_pkt = NULL;

    Encode_Delete(encap_defrag_pkt);
    encap_defrag_pkt = NULL;
}

void Defrag::show(SnortConfig*)
{
    FragPrintGlobalConfig(&config);  // FIXIT only show once; need separate inspector method?
    FragPrintEngineConfig(config.engine);
}

void Defrag::eval(Packet *p)
{
    FRAGKEY fkey;            /* fragkey for this packet */
    FragTracker *ft;         /* FragTracker to process the packet on */
    FragEngine *engine = NULL; /* engine engine */
    int insert_return = 0;   /* return value from the insert function */
    PROFILE_VARS;

    // preconditions - what we registered for
    assert(IPH_IS_VALID(p) && !(p->error_flags & PKT_ERR_CKSUM_IP));

    /* check to make sure this preprocessor should run */
    if ( !p->frag_flag )
        return;

    memset(&fkey, 0, sizeof(FRAGKEY));
    ft = FragGetTracker(p, &fkey);

    if (ft != NULL)
    {
        engine = ft->engine;
    }

    if (ft == NULL)
        engine = config.engine;

    /*
     * First case: if frag offset is 0 & UDP, let that packet go
     * through the rest of the system.  Ugly HACK to detect DNS
     * attack on 0 offset UDP.
     *
     * Second case: If frag offset is 0 & !more frags, this is a
     * full-frame "fragment", let the packet go through the rest
     * of the system.
     *
     * In other words:
     *   a = frag_offset != 0
     *   b = !UDP
     *   c = More Fragments
     *
     * if (a | (b & c))
     *    Disable Inspection since we'll look at the payload in
     *    a rebuilt packet later.  So don't process it further.
     */
    if ((p->frag_offset != 0) || ((GET_IPH_PROTO(p) != IPPROTO_UDP) && (p->mf)))
        DisableDetect(p);

    /*
     * pkt's not going to make it to the engine, bail
     */
    if(GET_IPH_TTL(p) < engine->min_ttl)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                "[FRAG3] Fragment discarded due to low TTL "
                "[0x%X->0x%X], TTL: %d  " "Offset: %d Length: %d\n",
                ntohl(p->iph->ip_src.s_addr),
                ntohl(p->iph->ip_dst.s_addr),
                GET_IPH_TTL(p), p->frag_offset,
                p->dsize););

        EventAnomScMinTTL(engine);
        t_stats.discards++;
        return;
    }

    t_stats.total++;
    UpdateIPFragStats(&sfBase, p->pkth->caplen);

    PREPROC_PROFILE_START(fragPerfStats);

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                "\n++++++++++++++++++++++++++++++++++++++++++++++\n"););
    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                "[**] [FRAG3] Inspecting fragment...\n"););
    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                "[FRAG3] Got frag packet (mem use: %ld frag "
                "trackers: %d  p->pkt_flags: 0x%X "
                "prealloc nodes in use: %lu/%lu)\n",
                mem_in_use,
                sfxhash_count(f_cache),
                p->packet_flags, prealloc_nodes_in_use, prealloc_frags););

    pkttime = (struct timeval *) &p->pkth->ts;

    /*
     * try to get the tracker that this frag should go with
     */
    if (ft == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "Adding New FragTracker...\n"););

        /*
         * first frag for this packet, start a new tracker
         */
        new_tracker(p, &fkey, engine);

        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "[FRAG3] mem use: %ld frag "
                    "trackers: %d  prealloc "
                    "nodes in use: %lu/%lu\n",
                    mem_in_use,
                    sfxhash_count(f_cache),
                    prealloc_nodes_in_use, prealloc_frags););
        /*
         * all done, return control to Snort
         */
        PREPROC_PROFILE_END(fragPerfStats);
        return;
    }
    else if (expire(p, ft, engine) == FRAG_TRACKER_TIMEOUT)
    {
        /* Time'd out FragTrackers are just purged of their packets.
         * Reset the timestamp per this packet.
         * And reset the rest of the tracker as if this is the
         * first packet on the tracker, and continue. */

        /* This fixes an issue raised on bugtraq relating to
         * timeout frags not getting purged correctly when
         * the entire set of frags show up later. */

        ft->ttl = GET_IPH_TTL(p); /* store the first ttl we got */
        ft->calculated_size = 0;
        ft->alerted = 0;
        ft->frag_flags = 0;
        ft->frag_bytes = 0;
        ft->frag_pkts = 0;
        ft->alert_count = 0;
        ft->ip_options_len = 0;
        ft->ip_option_count = 0;
        ft->ip_options_data = NULL;
        ft->copied_ip_options_len = 0;
        ft->copied_ip_option_count = 0;
        ft->engine = engine;
        ft->ordinal = 0;
    }

    // Update frag time when we get a frag associated with this tracker
    ft->frag_time.tv_sec = p->pkth->ts.tv_sec;
    ft->frag_time.tv_usec = p->pkth->ts.tv_usec;

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "Found frag tracker\n"););

    //dont forward fragments to engine if some previous fragment was dropped
    if ( ft->frag_flags & FRAG_DROP_FRAGMENTS )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "Blocking fragments due to earlier fragment drop\n"););
        DisableDetect(p);
        Active_DropPacket();
        t_stats.drops++;
    }

    /*
     * insert the fragment into the FragTracker
     */
    if((insert_return = insert(p, ft, &fkey, engine)) != FRAG_INSERT_OK)
    {
        /*
         * we can pad this switch out for a variety of entertaining behaviors
         * later if we're so inclined
         */
        switch(insert_return)
        {
            case FRAG_INSERT_FAILED:
#ifdef DEBUG
                LogMessage("WARNING: Insert into Fraglist failed, "
                           "(offset: %u).\n", p->frag_offset);
#endif
                PREPROC_PROFILE_END(fragPerfStats);
                return;
            case FRAG_INSERT_TTL:
                DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                        "[FRAG3] Fragment discarded due to large TTL Delta "
                        "[0x%X->0x%X], TTL: %d  orig TTL: %d "
                        "Offset: %d Length: %d\n",
                        ntohl(p->iph->ip_src.s_addr),
                        ntohl(p->iph->ip_dst.s_addr),
                        GET_IPH_TTL(p), ft->ttl, p->frag_offset,
                        p->dsize););
                t_stats.discards++;
                PREPROC_PROFILE_END(fragPerfStats);
                return;
            case FRAG_INSERT_ATTACK:
            case FRAG_INSERT_ANOMALY:
                t_stats.discards++;
                PREPROC_PROFILE_END(fragPerfStats);
                return;
            case FRAG_INSERT_TIMEOUT:
#ifdef DEBUG
                LogMessage("WARNING: Insert into Fraglist failed due to timeout, "
                           "(offset: %u).\n", p->frag_offset);
#endif
                PREPROC_PROFILE_END(fragPerfStats);
                return;
            case FRAG_INSERT_OVERLAP_LIMIT:
#ifdef DEBUG
                LogMessage("WARNING: Excessive IP fragment overlap, "
                           "(More: %u, offset: %u, offsetSize: %u).\n",
                           p->mf, (p->frag_offset<<3), p->ip_frag_len);
#endif
                t_stats.discards++;
                PREPROC_PROFILE_END(fragPerfStats);
                return;
            default:
                break;
        }
    }

    p->fragtracker = (void *)ft;

    /*
     * check to see if it's reassembly time
     */
    if(FragIsComplete(ft))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "[*] Fragment is complete, rebuilding!\n"););

        /*
         * if the frag completes but it's bad we're just going to drop it
         * instead of wasting time on putting it back together
         */
        if(!(ft->frag_flags & FRAG_BAD))
        {
            FragRebuild(ft, p);

            if (p->frag_offset != 0 ||
                (GET_IPH_PROTO(p) != IPPROTO_UDP && ft->frag_flags & FRAG_REBUILT))
            {
                /* Need to reset some things here because the
                 * rebuilt packet will have reset the do_detect
                 * flag when it hits Inspect.
                 */
                do_detect_content = do_detect = 0;
            }
        }

        if (Active_PacketWasDropped())
        {
            delete_tracker(ft);
            ft->frag_flags |= FRAG_DROP_FRAGMENTS;
        }
        else
        {
            FragRemoveTracker(&fkey, ft);
            p->fragtracker = NULL;

            DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                        "[FRAG3] Dumped fragtracker (mem use: %ld frag "
                        "trackers: %d  prealloc nodes in use: %lu/%lu)\n",
                        mem_in_use, sfxhash_count(f_cache),
                        prealloc_nodes_in_use, prealloc_frags););
        }
    }

    PREPROC_PROFILE_END(fragPerfStats);
    return;
}

/**
 * This is where the rubber hits the road.  Insert the new fragment's data
 * into the current FragTracker's fraglist, doing anomaly detection and
 * handling overlaps in a engine-based manner.
 *
 * @param p Current packet to insert
 * @param ft FragTracker to hold the packet
 * @param fkey FragKey with the current FragTracker's key info
 * @param engine engine of the current engine for engine-based defrag info
 *
 * @return status
 * @retval FRAG_INSERT_TIMEOUT FragTracker has timed out and been dropped
 * @retval FRAG_INSERT_ATTACK  Attack detected during insertion
 * @retval FRAG_INSERT_ANOMALY Anomaly detected during insertion
 * @retval FRAG_INSERT_TTL Delta of TTL values beyond configured value
 * @retval FRAG_INSERT_OK Fragment has been inserted successfully
 */
int Defrag::insert(Packet *p, FragTracker *ft, FRAGKEY*,
        FragEngine *engine)
{
    uint16_t orig_offset;    /* offset specified in this fragment header */
    uint16_t frag_offset;    /* calculated offset for this fragment */
    uint16_t frag_end;       /* calculated end point for this fragment */
    int16_t trunc = 0;      /* we truncate off the tail */
    int32_t overlap = 0;    /* we overlap on either end of the frag */
    int16_t len = 0;        /* calculated size of the fragment */
    int16_t slide = 0;      /* slide up the front of the current frag */
    int done = 0;           /* flag for right-side overlap handling loop */
    int addthis = 1;           /* flag for right-side overlap handling loop */
    int i = 0;              /* counter */
    int firstLastOk;
    int ret = FRAG_INSERT_OK;
    unsigned char lastfrag = 0; /* Set to 1 when this is the 'last' frag */
    unsigned char alerted_overlap = 0; /* Set to 1 when alerted */
    Fragment *right = NULL; /* frag ptr for right-side overlap loop */
    Fragment *newfrag = NULL;  /* new frag container */
    Fragment *left = NULL;     /* left-side overlap fragment ptr */
    Fragment *idx = NULL;      /* indexing fragment pointer for loops */
    Fragment *dump_me = NULL;  /* frag ptr for complete overlaps to dump */
    const uint8_t *fragStart;
    int16_t fragLength;
    PROFILE_VARS;

    sfBase.iFragInserts++;

    PREPROC_PROFILE_START(fragInsertPerfStats);

    if (IS_IP6(p) && (p->frag_offset == 0))
    {
        IP6Frag *fragHdr = (IP6Frag *)p->ip6_extensions[p->ip6_frag_index].data;
        if (ft->protocol != fragHdr->ip6f_nxt)
        {
            ft->protocol = fragHdr->ip6f_nxt;
        }
    }

    /*
     * Check to see if this fragment is the first or last one and
     * set the appropriate flags and values in the FragTracker
     */
    firstLastOk = FragCheckFirstLast(p, ft);

    fragStart = p->ip_frag_start;
    //fragStart = (uint8_t *)p->iph + GET_IPH_HLEN(p) * 4;
    /* Use the actual length here, because packet may have been
     * truncated.  Don't want to try to copy more than we actually
     * captured. */
    //len = fragLength = p->actual_ip_len - GET_IPH_HLEN(p) * 4;
    len = fragLength = p->ip_frag_len;
#ifdef DEBUG_MSGS
    if (p->actual_ip_len != ntohs(GET_IPH_LEN(p)))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
            "IP Actual Length (%d) != specified length (%d), "
            "truncated packet (%d)?\n",
            p->actual_ip_len, ntohs(GET_IPH_LEN(p)), pkt_snaplen););
    }
#endif

    /*
     * setup local variables for tracking this frag
     */
    orig_offset = frag_offset = p->frag_offset << 3;
    /* Reset the offset to handle the weird Solaris case */
    if (firstLastOk == FRAG_LAST_OFFSET_ADJUST)
        frag_offset = (uint16_t)ft->calculated_size;
    frag_end = frag_offset + fragLength;

    /*
     * might have last frag...
     */
    if(!p->mf)
    {
        if ((frag_end > ft->calculated_size) &&
            (firstLastOk == FRAG_LAST_OFFSET_ADJUST))
        {
            ft->calculated_size = frag_end;
        }

        //    ft->frag_flags |= FRAG_GOT_LAST;
        //    ft->calculated_size = (p->frag_offset << 3) + fragLength;
        lastfrag = 1;
    }
    else
    {
        uint16_t oldfrag_end;
        /*
         * all non-last frags are supposed to end on 8-byte boundries
         */
        if(frag_end & 7)
        {
            /*
             * bonk/boink/jolt/etc attack...
             */
            DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                        "[..] Short frag (Bonk, etc) attack!\n"););

            EventAnomShortFrag(engine);

            /* don't return, might still be interesting... */
        }

        /* can't have non-full fragments... */
        oldfrag_end = frag_end;
        frag_end &= ~7;

        /* Adjust len to take into account the jolting/non-full fragment. */
        len -= (oldfrag_end - frag_end);

        /*
         * if the end of this frag is greater than the max frag size we have a
         * problem
         */
        if(frag_end > ft->calculated_size)
        {
            if(ft->frag_flags & FRAG_GOT_LAST)
            {
                /* oversize frag attack */
                DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                            "[..] Oversize frag pkt!\n"););

                EventAnomOversize(engine);

                PREPROC_PROFILE_END(fragInsertPerfStats);
                return FRAG_INSERT_ANOMALY;
            }
            ft->calculated_size = frag_end;
        }
    }

    if(frag_end == frag_offset)
    {
        /*
         * zero size frag...
         */
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "[..] Zero size frag!\n"););

        if ( engine->detect )
        {
            EventAnomZeroFrag(engine);
        }

        PREPROC_PROFILE_END(fragInsertPerfStats);
        return FRAG_INSERT_ANOMALY;
    }

    if(ft->calculated_size > IP_MAXPACKET)
    {
        /*
         * oversize pkt...
         */
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "[..] Oversize frag!\n"););

            EventAnomBadsizeLg(engine);

        ft->frag_flags |= FRAG_BAD;

        PREPROC_PROFILE_END(fragInsertPerfStats);
        return FRAG_INSERT_ANOMALY;
    }

    /*
     * This may alert on bad options, but we still want to
     * insert the packet
     */
    FragHandleIPOptions(ft, p);

    ft->frag_pkts++;

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                "Walking frag list (%d nodes), new frag %d@%d\n",
                ft->fraglist_count, fragLength, frag_offset););

    /*
     * Need to figure out where in the frag list this frag should go
     * and who its neighbors are
     */
    for(idx = ft->fraglist; idx; idx = idx->next)
    {
        i++;
        right = idx;

        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "%d right o %d s %d ptr %p prv %p nxt %p\n",
                    i, right->offset, right->size, right,
                    right->prev, right->next););

        if(right->offset >= frag_offset)
        {
            break;
        }

        left = right;
    }

    /*
     * null things out if we walk to the end of the list
     */
    if(idx == NULL) right = NULL;

    /*
     * handle forward (left-side) overlaps...
     */
    if(left)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "Dealing with previous (left) frag %d@%d\n",
                    left->size, left->offset););

        /*
         * generate the overlap of the current packet fragment
         * over this left-side fragment
         */
        /* NOTE: If frag_offset is really large, overlap can be
         * negative because its stored as a 32bit int.
         */
        overlap = left->offset + left->size - frag_offset;

        if(overlap > 0)
        {
            t_stats.overlaps++;
            ft->overlap_count++;

            if(frag_end < ft->calculated_size ||
                    ((ft->frag_flags & FRAG_GOT_LAST) &&
                     frag_end != ft->calculated_size))
            {
                if (!p->mf)
                {
                    /*
                     * teardrop attack...
                     */
                    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                                "[..] Teardrop attack!\n"););

                    EventAttackTeardrop(engine);

                    ft->frag_flags |= FRAG_BAD;

                    PREPROC_PROFILE_END(fragInsertPerfStats);
                    return FRAG_INSERT_ATTACK;
                }
            }

            /*
             * Ok, we've got an overlap so we need to handle it.
             *
             * The engine-based modes here match the data generated by
             * Paxson's Active Mapping paper as do the policy types.
             */
            switch(ft->frag_policy)
            {
                /*
                 * new frag gets moved around
                 */
                case FRAG_POLICY_LINUX:
                case FRAG_POLICY_FIRST:
                case FRAG_POLICY_WINDOWS:
                case FRAG_POLICY_SOLARIS:
                case FRAG_POLICY_BSD:
                    frag_offset += (int16_t)overlap;
                    slide = (int16_t)overlap;

                    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                                "left overlap, new frag moves: %d bytes, "
                                "slide: %d\n", overlap, slide););

                    if(frag_end <= frag_offset)
                    {
                        /*
                         * zero size frag
                         */
                        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                                    "zero size frag\n"););

                        EventAnomZeroFrag(engine);

                        PREPROC_PROFILE_END(fragInsertPerfStats);
                        return FRAG_INSERT_ANOMALY;
                    }

                    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "left overlap, "
                                "truncating new pkt (slide: %d)\n", slide););

                    break;

                    /*
                     * new frag stays where it is, overlapee (existing frag)
                     * gets whacked
                     */
                case FRAG_POLICY_BSD_RIGHT:
                    if (left->offset + left->size >= frag_offset + len)
                    {
                        /* BSD-right (HP Printers) favor new fragments with
                         * lower/equal offset, EXCEPT when the existing
                         * fragment ends with at a higher/equal offset.
                         */
                        frag_offset += (int16_t)overlap;
                        slide = (int16_t)overlap;
                        goto left_overlap_last;
                    }
                    /* fall through */
                case FRAG_POLICY_LAST:
                    if ((left->offset < frag_offset) && (left->offset + left->size > frag_offset + len))
                    {
                        /* The new frag is overlapped on both sides by an
                         * existing frag -- existing frag needs to be split
                         * and the new frag inserted in the middle.
                         *
                         * Need to duplciate left.  Adjust that guys
                         * offset by + (frag_offset + len) and
                         * size by - (frag_offset + len - left->offset).
                         */
                        ret = dup_frag_node(ft, left, &right);
                        if (ret != FRAG_INSERT_OK)
                        {
                            /* Some warning here,
                             * no, its done in add_frag_node */
                            PREPROC_PROFILE_END(fragInsertPerfStats);
                            return ret;
                        }
                        left->size -= (int16_t)overlap;
                        ft->frag_bytes -= (int16_t)overlap;

                        right->offset = frag_offset + len;
                        right->size -= (frag_offset + len - left->offset);
                        right->data += (frag_offset + len - left->offset);
                        ft->frag_bytes -= (frag_offset + len - left->offset);
                    }
                    else
                    {
                        left->size -= (int16_t)overlap;
                        ft->frag_bytes -= (int16_t)overlap;
                    }

left_overlap_last:
                    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "[!!] left overlap, "
                                "truncating old pkt (offset: %d overlap: %d)\n",
                                left->offset, overlap););

                    if (left->size <= 0)
                    {
                        dump_me = left;

                        DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "retrans, "
                                "dumping old frag (offset: %d overlap: %d)\n",
                                dump_me->offset, overlap););

                        left = left->prev;

                        delete_node(ft, dump_me);
                    }

                    break;
            }

            /*
             * frag can't end before it begins...
             */
            if(frag_end < frag_offset)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                            "frag_end < frag_offset!"););

                if ( engine->detect )
                {
                    EventAnomBadsizeSm(engine);
                }

                PREPROC_PROFILE_END(fragInsertPerfStats);
                return FRAG_INSERT_ANOMALY;
            }
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "No left overlap!\n"););
        }
    }

    if ((uint16_t)fragLength > pkt_snaplen)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "Overly large fragment %d 0x%x 0x%x %d\n",
                    fragLength, GET_IPH_LEN(p), GET_IPH_OFF(p),
                    p->frag_offset << 3););
        PREPROC_PROFILE_END(fragInsertPerfStats);
        return FRAG_INSERT_FAILED;
    }

    /*
     * handle tail (right-side) overlaps
     *
     * We have to walk thru all the right side frags until the offset of the
     * existing frag is greater than the end of the new frag
     */
    while(right && (right->offset < frag_end) && !done)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "Next (right)fragment %d@%d\n",
                    right->size, right->offset););

#ifdef DEBUG_FRAG3
        PrintFragment(right);
#endif
        trunc = 0;
        overlap = frag_end - right->offset;

        if (overlap)
        {
            if(frag_end < ft->calculated_size ||
                    ((ft->frag_flags & FRAG_GOT_LAST) &&
                     frag_end != ft->calculated_size))
            {
                if (!p->mf)
                {
                    /*
                     * teardrop attack...
                     */
                    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                                "[..] Teardrop attack!\n"););

                    EventAttackTeardrop(engine);

                    ft->frag_flags |= FRAG_BAD;

                    PREPROC_PROFILE_END(fragInsertPerfStats);
                    return FRAG_INSERT_ATTACK;
                }
            }
        }

        /*
         * partial right-side overlap, this will be the last frag to check
         */
        if(overlap < right->size)
        {
            t_stats.overlaps++;
            ft->overlap_count++;

            DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                        "Right-side overlap %d bytes\n", overlap););

            /*
             * once again, engine-based policy processing
             */
            switch(ft->frag_policy)
            {
                /*
                 * existing fragment gets truncated
                 */
                case FRAG_POLICY_LAST:
                case FRAG_POLICY_LINUX:
                case FRAG_POLICY_BSD:
                    if ((ft->frag_policy == FRAG_POLICY_BSD) &&
                        (right->offset == frag_offset))
                    {
                        slide = (int16_t)(right->offset + right->size - frag_offset);
                        frag_offset += (int16_t)slide;
                    }
                    else
                    {
                        right->offset += (int16_t)overlap;
                        right->data += (int16_t)overlap;
                        right->size -= (int16_t)overlap;
                        ft->frag_bytes -= (int16_t)overlap;
                    }
                    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "[!!] right overlap, "
                                "truncating old frag (offset: %d, "
                                "overlap: %d)\n", right->offset, overlap);
                            DebugMessage(DEBUG_FRAG,
                                "Exiting right overlap loop...\n"););
                    if (right->size <= 0)
                    {
                        dump_me = right;

                        DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "retrans, "
                                "dumping old frag (offset: %d overlap: %d)\n",
                                dump_me->offset, overlap););

                        right = right->next;

                        delete_node(ft, dump_me);
                    }
                    break;

                /*
                 * new frag gets truncated
                 */
                case FRAG_POLICY_FIRST:
                case FRAG_POLICY_WINDOWS:
                case FRAG_POLICY_SOLARIS:
                case FRAG_POLICY_BSD_RIGHT:
                    trunc = (int16_t)overlap;
                    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "[!!] right overlap, "
                                "truncating new frag (offset: %d "
                                "overlap: %d)\n",
                                right->offset, overlap);
                            DebugMessage(DEBUG_FRAG,
                                "Exiting right overlap loop...\n"););
                    break;
            }

            /*
             * all done, bail
             */
            done = 1;
        }
        else
        {
            /*
             * we've got a full overlap
             */
            if ( !alerted_overlap && engine->detect )
            {
                /*
                 * retrans/full overlap
                 */
                EventAnomOverlap(engine);
                alerted_overlap = 1;
                t_stats.overlaps++;
                ft->overlap_count++;
            }

            /*
             * handle the overlap in a engine-based manner
             */
            switch(ft->frag_policy)
            {
                /*
                 * overlap is treated differently if there is more
                 * data beyond the overlapped packet.
                 */
                case FRAG_POLICY_WINDOWS:
                case FRAG_POLICY_SOLARIS:
                case FRAG_POLICY_BSD:
                    /*
                     * Old packet is overlapped on both sides...
                     * Drop the old packet.  This follows a
                     * POLICY_LAST model.
                     */
                    if ((frag_end > right->offset + right->size) &&
                        (frag_offset < right->offset))
                    {
                        dump_me = right;
                        ft->frag_bytes -= right->size;

                        DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "retrans, "
                                "dumping old frag (offset: %d overlap: %d)\n",
                                dump_me->offset, overlap););

                        right = right->next;

                        delete_node(ft, dump_me);
                        break;
                    }
                    else
                    {
                        if ((ft->frag_policy == FRAG_POLICY_SOLARIS) ||
                            (ft->frag_policy == FRAG_POLICY_BSD))
                        {
                            /* SOLARIS & BSD only */
                            if ((frag_end == right->offset + right->size) &&
                                (frag_offset < right->offset))
                            {
                                /* If the frag overlaps an entire frag to the
                                 * right side of that frag, the old frag if
                                 * dumped -- this is a "policy last".
                                 */
                                goto right_overlap_last;
                            }
                        }
                    }
                    /* Otherwise, treat it as a POLICY_FIRST,
                     * and trim accordingly. */

                    /* ie, fall through to the next case */

                /*
                 * overlap is rejected
                 */
                case FRAG_POLICY_FIRST:
                    /* fix for bug 17823 */
                    if (right->offset == frag_offset)
                    {
                        slide = (int16_t)(right->offset + right->size - frag_offset);
                        frag_offset += (int16_t)slide;
                        left = right;
                        right = right->next;
                    }
                    else
                    {
                        trunc = (int16_t)overlap;
                    }

                    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "right overlap, "
                                "rejecting new overlap data (overlap: %d, "
                                "trunc: %d)\n", overlap, trunc););

                    if (frag_end - trunc <= frag_offset)
                    {
                        /*
                         * zero size frag
                         */
                        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                                    "zero size frag (len: %d  overlap: %d)\n",
                                    fragLength, overlap););

                        t_stats.discards++;

                        PREPROC_PROFILE_END(fragInsertPerfStats);
                        return FRAG_INSERT_ANOMALY;
                    }

                    {
                        uint16_t curr_end;
                        /* Full overlapping an already received packet
                         * and there are more packets beyond that fully
                         * overlapped one.
                         * Arrgh.  Need to insert this guy in chunks.
                         */
                        checkTinyFragments(engine, p, len-slide-trunc);

                        ret = add_frag_node(ft, p, engine, fragStart, fragLength, 0, len,
                                slide, trunc, frag_offset, left, &newfrag);
                        if (ret != FRAG_INSERT_OK)
                        {
                            /* Some warning here,
                             * no, its done in add_frag_node */
                            PREPROC_PROFILE_END(fragInsertPerfStats);
                            return ret;
                        }

                        curr_end = newfrag->offset + newfrag->size;

                        /* Find the next gap that this one might fill in */
                        while (right &&
                            (curr_end == right->offset) &&
                            (right->offset < frag_end))
                        {
                            curr_end = right->offset + right->size;
                            left = right;
                            right = right->next;
                        }

                        if (right && (right->offset < frag_end))
                        {
                            /* Adjust offset to end of 'left' */
                            if (left)
                                frag_offset = left->offset + left->size;
                            else
                                frag_offset = orig_offset;

                            /* Overlapping to the left by a good deal now */
                            slide = frag_offset - orig_offset;
                            /*
                             * Reset trunc, in case the next one kicks us
                             * out of the loop.  This packet will become the
                             * right-most entry so far.  Don't truncate any
                             * further.
                             */
                            trunc = 0;
                            if (right)
                                continue;
                        }

                        if (curr_end < frag_end)
                        {
                            /* Insert this guy in his proper spot,
                             * adjust offset to the right-most endpoint
                             * we saw.
                             */
                            slide = left->offset + left->size - frag_offset;
                            frag_offset = curr_end;
                            trunc = 0;
                        }
                        else
                        {
                            addthis = 0;
                        }
                    }
                    break;

                    /*
                     * retrans accepted, dump old frag
                     */
right_overlap_last:
                case FRAG_POLICY_BSD_RIGHT:
                case FRAG_POLICY_LAST:
                case FRAG_POLICY_LINUX:
                    dump_me = right;
                    ft->frag_bytes -= right->size;

                    DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "retrans, "
                                "dumping old frag (offset: %d overlap: %d)\n",
                                dump_me->offset, overlap););

                    right = right->next;

                    delete_node(ft, dump_me);

                    break;
            }
        }
    }

    ///detect tiny fragments but continue processing
    checkTinyFragments(engine, p, len-slide-trunc);

    if ((engine->overlap_limit) &&
            (ft->overlap_count >= engine->overlap_limit))
    {
        //overlap limit exceeded. Raise event on all subsequent fragments
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "Reached overlap limit.\n"););

        EventExcessiveOverlap(engine);

        PREPROC_PROFILE_END(fragInsertPerfStats);
        return FRAG_INSERT_OVERLAP_LIMIT;
    }

    if (addthis)
    {
        ret = add_frag_node(ft, p, engine, fragStart, fragLength, lastfrag, len,
                      slide, trunc, frag_offset, left, &newfrag);
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "Fully truncated right overlap\n"););
    }

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                "insert(): returning normally\n"););

    PREPROC_PROFILE_END(fragInsertPerfStats);
    return ret;
}

/**
 * Didn't find a FragTracker in the hash table, create a new one and put it
 * into the f_cache
 *
 * @param p Current packet to fill in FragTracker fields
 * @param fkey FragKey struct to use for table insertion
 *
 * @return status
 * @retval 0 on an error
 * @retval 1 on success
 */
int Defrag::new_tracker(Packet *p, FRAGKEY *fkey, FragEngine *engine)
{
    FragTracker *tmp;
    Fragment *f = NULL;
    //int ret = 0;
    const uint8_t *fragStart;
    uint16_t fragLength;
    uint16_t frag_end;
    SFXHASH_NODE *hnode;

    fragStart = p->ip_frag_start;
    //fragStart = (uint8_t *)p->iph + GET_IPH_HLEN(p) * 4;
    /* Use the actual length here, because packet may have been
     * truncated.  Don't want to try to copy more than we actually
     * captured. */
    //fragLength = p->actual_ip_len - GET_IPH_HLEN(p) * 4;
    fragLength = p->ip_frag_len;
#ifdef DEBUG_MSGS
    if (p->actual_ip_len != ntohs(GET_IPH_LEN(p)))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
            "IP Actual Length (%d) != specified length (%d), "
            "truncated packet (%d)?\n",
            p->actual_ip_len, ntohs(GET_IPH_LEN(p)), pkt_snaplen););
    }
#endif

    /* Just to double check */
    if (fragLength > pkt_snaplen)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
            "Overly large fragment %d 0x%x 0x%x %d\n",
            fragLength, GET_IPH_LEN(p), GET_IPH_OFF(p),
            p->frag_offset << 3););

        /* Ah, crap.  Return that tracker. */
        return 0;
    }

    // Try to get a new one
    if (!(hnode = sfxhash_get_node(f_cache, fkey)) || !hnode->data)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "Defrag::new_tracker: sfxhash_get_node() failed\n"););
        return 0;
    }

    tmp = (FragTracker *)hnode->data;
    memset(tmp, 0, sizeof(FragTracker));
    
    /*
     * setup the frag tracker
     */
    COPY4(tmp->sip,fkey->sip);
    COPY4(tmp->dip,fkey->dip);
    tmp->id = fkey->id;
    if (IS_IP4(p))
    {
        tmp->protocol = fkey->proto;
        tmp->ipver = 4;
    }
    else /* IPv6 */
    {
        if (p->frag_offset == 0)
        {
            IP6Frag *fragHdr = (IP6Frag *)p->ip6_extensions[p->ip6_frag_index].data;
            tmp->protocol = fragHdr->ip6f_nxt;
        }
        tmp->ipver = 6;
    }
    tmp->ttl = GET_IPH_TTL(p); /* store the first ttl we got */
    tmp->calculated_size = 0;
    tmp->alerted = 0;
    tmp->frag_flags = 0;
    tmp->frag_bytes = 0;
    tmp->frag_pkts = 0;
    tmp->frag_time.tv_sec = p->pkth->ts.tv_sec;
    tmp->frag_time.tv_usec = p->pkth->ts.tv_usec;
    tmp->alert_count = 0;
    tmp->ip_options_len = 0;
    tmp->ip_option_count = 0;
    tmp->ip_options_data = NULL;
    tmp->copied_ip_options_len = 0;
    tmp->copied_ip_option_count = 0;
    tmp->ordinal = 0;
    tmp->frag_policy = FragGetPolicy(p, engine);
    tmp->engine = engine;

    tmp->handler = this;
    add_ref();

    /*
     * get our first fragment storage struct
     */
    if(!config.common->use_prealloc)
    {
        if(mem_in_use > config.common->memcap)
        {
            if (prune(tmp) == 0)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "Defrag::new_tracker: Pruning failed\n"););

                return 0;
            }
        }

        f = (Fragment *) SnortAlloc(sizeof(Fragment));
        mem_in_use += sizeof(Fragment);
        f->pre = false;

        f->fptr = (uint8_t *) SnortAlloc(fragLength);
        mem_in_use += fragLength;

        sfBase.frag3_mem_in_use = mem_in_use;
    }
    else
    {
        while((f = FragPreallocPop()) == NULL)
        {
            if (prune(tmp) == 0)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "Defrag::new_tracker: Pruning failed\n"););

                return 0;
            }
        }
    }

    t_stats.fragnodes_created++;
    sfBase.iFragCreates++;
    sfBase.iCurrentFrags++;
    if (sfBase.iCurrentFrags > sfBase.iMaxFrags)
        sfBase.iMaxFrags = sfBase.iCurrentFrags;

    /* initialize the fragment list */
    tmp->fraglist = NULL;

    /*
     * setup the Fragment struct with the current packet's data
     */
    memcpy(f->fptr, fragStart, fragLength);

    f->size = f->flen = fragLength;
    f->offset = p->frag_offset << 3;
    frag_end = f->offset + fragLength;
    f->ord = tmp->ordinal++;
    f->data = f->fptr;     /* ptr to adjusted start position */
    if (!p->mf)
    {
        f->last = 1;
    }
    else
    {
        /*
         * all non-last frags are supposed to end on 8-byte boundries
         */
        if(frag_end & 7)
        {
            /*
             * bonk/boink/jolt/etc attack...
             */
            DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                        "[..] Short frag (Bonk, etc) attack!\n"););

            EventAnomShortFrag(engine);

            /* don't return, might still be interesting... */
        }

        /* can't have non-full fragments... */
        frag_end &= ~7;

        /* Adjust len to take into account the jolting/non-full fragment. */
        f->size = frag_end - f->offset;
    }

    /* insert the fragment into the frag list */
    tmp->fraglist = f;
    tmp->fraglist_tail = f;
    tmp->fraglist_count = 1;  /* XXX: Are these duplciates? */
    tmp->frag_pkts = 1;

    /*
     * mark the FragTracker if this is the first/last frag
     */
    FragCheckFirstLast(p, tmp);

    tmp->frag_bytes += fragLength;

    FragHandleIPOptions(tmp, p);

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                "[#] accumulated bytes on FragTracker: %d\n",
                tmp->frag_bytes););

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                "Initial fragment for tracker, ptr %p, offset %d, "
                "size %d\n", f, f->offset, f->size););

#ifdef DEBUG_FRAG3
    PrintFragKey(fkey);
#endif

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                "Calling sfxhash(add), overhead at %lu\n",
                f_cache->overhead_bytes););

    t_stats.fragtrackers_created++;

    p->fragtracker = (void *)tmp;

    return 1;
}

/**
 * Handle the creation of the new frag node and list insertion.
 * Separating this from actually calculating the values.
 *
 * @param ft FragTracker to hold the packet
 * @param fragStart Pointer to start of the packet data
 * @param fragLength Length of packet data
 * @param len Length of this fragment
 * @param slide Adjustment to make to left side of data (for left overlaps)
 * @param trunc Adjustment to maek to right side of data (for right overlaps)
 * @param frag_offset Offset for this fragment
 * @prarm left FragNode prior to this one
 * @param retFrag this one after its inserted (returned)
 *
 * @return status
 * @retval FRAG_INSERT_FAILED Memory problem, insertion failed
 * @retval FRAG_INSERT_OK All okay
 */
int Defrag::add_frag_node(FragTracker *ft,
                Packet*,
                FragEngine*,
                const uint8_t *fragStart,
                int16_t fragLength,
                char lastfrag,
                int16_t len,
                uint16_t slide,
                uint16_t trunc,
                uint16_t frag_offset,
                Fragment *left,
                Fragment **retFrag)
{
    Fragment *newfrag = NULL;  /* new frag container */
    int16_t newSize = len - slide - trunc;

    if (newSize <= 0)
    {
        /*
         * zero size frag
         */
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
            "zero size frag after left & right trimming "
            "(len: %d  slide: %d  trunc: %d)\n",
            len, slide, trunc););

        t_stats.discards++;

#ifdef DEBUG_MSGS
        newfrag = ft->fraglist;
        while (newfrag)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                   "Size: %d, offset: %d, len %d, "
                   "Prev: 0x%x, Next: 0x%x, This: 0x%x, Ord: %d, %s\n",
                   newfrag->size, newfrag->offset,
                   newfrag->flen, newfrag->prev,
                   newfrag->next, newfrag, newfrag->ord,
                   newfrag->last ? "Last":""););
            newfrag = newfrag->next;
        }
#endif

        return FRAG_INSERT_ANOMALY;
    }

    /*
     * grab/generate a new frag node
     */
    if(!config.common->use_prealloc)
    {
        if(mem_in_use > config.common->memcap)
        {
            if (prune(ft) == 0)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "insert: Pruning failed\n"););

                return FRAG_INSERT_FAILED;
            }
        }

        /*
         * build a frag struct to track this particular fragment
         */
        newfrag = (Fragment *) SnortAlloc(sizeof(Fragment));
        mem_in_use += sizeof(Fragment);
        newfrag->pre = false;

        /*
         * allocate some space to hold the actual data
         */
        newfrag->fptr = (uint8_t*)SnortAlloc(fragLength);
        mem_in_use += fragLength;

        sfBase.frag3_mem_in_use = mem_in_use;
    }
    else
    {
        /*
         * fragments are preallocated, grab one from the list
         */
        while((newfrag = FragPreallocPop()) == NULL)
        {
            if (prune(ft) == 0)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "insert: Pruning failed\n"););

                return FRAG_INSERT_FAILED;
            }
        }

        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "got newfrag (%p) from prealloc\n", newfrag););
    }

    t_stats.fragnodes_created++;

    newfrag->flen = fragLength;
    memcpy(newfrag->fptr, fragStart, fragLength);
    newfrag->ord = ft->ordinal++;

    /*
     * twiddle the frag values for overlaps
     */
    newfrag->data = newfrag->fptr + slide;
    newfrag->size = newSize;
    newfrag->offset = frag_offset;
    newfrag->last = lastfrag;

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                "[+] Adding new frag, offset %d, size %d\n"
                "   nf->data = nf->fptr(%p) + slide (%d)\n"
                "   nf->size = len(%d) - slide(%d) - trunc(%d)\n",
                newfrag->offset, newfrag->size, newfrag->fptr,
                slide, fragLength, slide, trunc););

    /*
     * insert the new frag into the list
     */
    add_node(ft, left, newfrag);

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                "[*] Inserted new frag %d@%d ptr %p data %p prv %p nxt %p\n",
                newfrag->size, newfrag->offset, newfrag, newfrag->data,
                newfrag->prev, newfrag->next););

    /*
     * record the current size of the data in the fraglist
     */
    ft->frag_bytes += newfrag->size;

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                "[#] accumulated bytes on FragTracker %d, count"
                " %d\n", ft->frag_bytes, ft->fraglist_count););

    *retFrag = newfrag;
    return FRAG_INSERT_OK;
}

/**
 * Duplicate a frag node and insert it into the list.
 *
 * @param ft FragTracker to hold the packet
 * @prarm left FragNode prior to this one (to be dup'd)
 * @param retFrag this one after its inserted (returned)
 *
 * @return status
 * @retval FRAG_INSERT_FAILED Memory problem, insertion failed
 * @retval FRAG_INSERT_OK All okay
 */
int Defrag::dup_frag_node(FragTracker *ft,
                Fragment *left,
                Fragment **retFrag)
{
    Fragment *newfrag = NULL;  /* new frag container */

    /*
     * grab/generate a new frag node
     */
    if(!config.common->use_prealloc)
    {
        if(mem_in_use > config.common->memcap)
        {
            if (prune(ft) == 0)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "insert: Pruning failed\n"););

                return FRAG_INSERT_FAILED;
            }
        }

        /*
         * build a frag struct to track this particular fragment
         */
        newfrag = (Fragment *) SnortAlloc(sizeof(Fragment));
        mem_in_use += sizeof(Fragment);
        newfrag->pre = false;

        /*
         * allocate some space to hold the actual data
         */
        newfrag->fptr = (uint8_t*)SnortAlloc(left->flen);
        mem_in_use += left->flen;

        sfBase.frag3_mem_in_use = mem_in_use;
    }
    else
    {
        /*
         * fragments are preallocated, grab one from the list
         */
        while((newfrag = FragPreallocPop()) == NULL)
        {
            if (prune(ft) == 0)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "insert: Pruning failed\n"););

                return FRAG_INSERT_FAILED;
            }
        }

        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "got newfrag (%p) from prealloc\n", newfrag););
    }

    t_stats.fragnodes_created++;

    newfrag->ord = ft->ordinal++;
    /*
     * twiddle the frag values for overlaps
     */
    newfrag->flen = left->flen;
    memcpy(newfrag->fptr, left->fptr, newfrag->flen);
    newfrag->data = newfrag->fptr + (left->data - left->fptr);
    newfrag->size = left->size;
    newfrag->offset = left->offset;
    newfrag->last = left->last;

    /*
     * insert the new frag into the list
     */
    add_node(ft, left, newfrag);

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                "[*] Inserted new frag %d@%d ptr %p data %p prv %p nxt %p\n",
                newfrag->size, newfrag->offset, newfrag, newfrag->data,
                newfrag->prev, newfrag->next););

    /*
     * record the current size of the data in the fraglist
     */
    ft->frag_bytes += newfrag->size;

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                "[#] accumulated bytes on FragTracker %d, count"
                " %d\n", ft->frag_bytes, ft->fraglist_count););

    *retFrag = newfrag;
    return FRAG_INSERT_OK;
}

/**
 * This function gets called either when we run out of prealloc nodes or when
 * the memcap is exceeded.  Its job is to free memory up in frag3 by deleting
 * old/stale data.  Currently implemented using a simple LRU pruning
 * technique, could probably benefit from having some sort of tail selection
 * randomization added to it.  Additonally, right now when we hit the wall we
 * try to drop at least enough memory to satisfy the prealloc_high value.
 * Hopefully that's not too aggressive, salt to taste!
 *
 * @param none
 *
 * @return none
 */
int Defrag::prune(FragTracker *not_me)
{
    SFXHASH_NODE *hnode;
    int found_this = 0;
    int pruned = 0;
#ifdef DEBUG
    /* Use these to print out whether the frag tracker has
     * expired or not.
     */
    FragTracker *ft;
    struct timeval *fttime;     /* FragTracker timestamp */
#endif

    sfBase.iFragFaults++;
    t_stats.prunes++;

    if(!config.common->use_prealloc)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "(spp_frag3) prune: Pruning by memcap! "););
        while((mem_in_use > config.common->memcap) ||
              (f_cache->count > (config.common->max_frags - 5)))
        {
            hnode = sfxhash_lru_node(f_cache);
            if(!hnode)
            {
                break;
            }

            if (hnode && hnode->data == not_me)
            {
                if (found_this)
                {
                    /* Uh, problem... we've gone through the entire list */
                    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                        "(spp_frag3) prune: Pruning by memcap - empty list! "););
                    return pruned;
                }
                sfxhash_gmovetofront(f_cache, hnode);
                found_this = 1;
                continue;
            }
#ifdef DEBUG
            ft = (FragTracker*)hnode->data;
            fttime = &(ft->frag_time);

            if (CheckTimeout(pkttime,fttime,ft->engine)==FRAG_TIMEOUT)
            {
                char *src_str = SnortStrdup(FragIPToStr(ft->sip, ft->ipver));
                LogMessage("(spp_frag3) prune: Fragment dropped (timeout)! "
                    "[%s->%s ID: %d Count: %d]\n", src_str, FragIPToStr(ft->dip, ft->ipver),
                    ft->id, ft->fraglist_count);
                free(src_str);
                t_stats.timeouts++;
                sfBase.iFragTimeouts++;
            }
            else
            {
                char *src_str = SnortStrdup(FragIPToStr(ft->sip, ft->ipver));
                LogMessage("(spp_frag3) prune: Fragment dropped (memory)! "
                    "[%s->%s ID: %d Count: %d]\n", src_str, FragIPToStr(ft->dip, ft->ipver),
                    ft->id, ft->fraglist_count);
                free(src_str);
            }
#endif
            FragRemoveTracker(hnode->key, hnode->data);
            //sfBase.iFragDeletes++;
            //t_stats.fragtrackers_released++;
            pruned++;
        }
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                    "(spp_frag3) prune: Pruning by prealloc! "););

        while (prealloc_nodes_in_use >
               (prealloc_frags - prealloc_high))
        {
            hnode = sfxhash_lru_node(f_cache);
            if(!hnode)
            {
                break;
            }

            if (hnode && hnode->data == not_me)
            {
                if (found_this)
                {
                    /* Uh, problem... we've gone through the entire list */
                    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                              "(spp_frag3) prune: Pruning by prealloc - empty list! "););
                    return pruned;
                }
                sfxhash_gmovetofront(f_cache, hnode);
                found_this = 1;
                continue;
            }

#ifdef DEBUG
            ft = (FragTracker*)hnode->data;
            fttime = &(ft->frag_time);

            if (CheckTimeout(pkttime,fttime,ft->engine)==FRAG_TIMEOUT)
            {
                char *src_str = SnortStrdup(FragIPToStr(ft->sip, ft->ipver));
                LogMessage("(spp_frag3) prune: Fragment dropped (timeout)! "
                    "[%s->%s ID: %d Count: %d]\n", src_str, FragIPToStr(ft->dip, ft->ipver),
                    ft->id, ft->fraglist_count);
                free(src_str);
                t_stats.timeouts++;
                sfBase.iFragTimeouts++;
            }
            else
            {
                char *src_str = SnortStrdup(FragIPToStr(ft->sip, ft->ipver));
                LogMessage("(spp_frag3) prune: Fragment dropped (memory)! "
                    "[%s->%s ID: %d Count: %d]\n", src_str, FragIPToStr(ft->dip, ft->ipver),
                    ft->id, ft->fraglist_count);
                free(src_str);
            }
#endif

            FragRemoveTracker(hnode->key, hnode->data);
            //sfBase.iFragDeletes++;
            //t_stats.fragtrackers_released++;
            pruned++;
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_FRAG,
                "(spp_frag3) prune: Pruned %d nodes\n", pruned););
    return pruned;
}

/**
 * Time-related expiration of fragments from the system.  Checks the current
 * FragTracker for timeout, then walks up the LRU list looking to see if
 * anyone should have timed out.
 *
 * @param p Current packet (contains pointer to the current timestamp)
 * @param ft FragTracker to check for a timeout
 * @param fkey FragKey of the current FragTracker for sfxhash lookup
 * @param engine instance of the defrag engine, contains the timeout value
 *
 * @return status
 * @retval FRAG_TRACKER_TIMEOUT The current FragTracker has timed out
 * @retval FRAG_OK The current FragTracker has not timed out
 */
inline int Defrag::expire(Packet*, FragTracker *ft, FragEngine *engine)
{
    /*
     * Check the FragTracker that was passed in first
     */
    if(CheckTimeout(
                pkttime,
                &(ft)->frag_time,
                engine) == FRAG_TIMEOUT)
    {
        /*
         * Oops, we've timed out, whack the FragTracker
         */
#if defined(DEBUG_FRAG3) && defined(DEBUG)
        if (DEBUG_FRAG & GetDebugLevel())
        {
            char *src_str = SnortStrdup(FragIPToStr(ft->sip, ft->ipver));
            LogMessage("(spp_frag3) Current Fragment dropped due to timeout! "
                "[%s->%s ID: %d]\n", src_str, FragIPToStr(ft->dip, ft->ipver), ft->id);
            free(src_str);
        }
#endif

        /*
         * Don't remove the tracker.
         * Remove all of the packets that are stored therein.
         *
         * If the existing tracker times out because of a delay
         * relative to the timeout
         */
        //FragRemoveTracker(fkey, ft);
        delete_tracker(ft);

        t_stats.timeouts++;
        sfBase.iFragTimeouts++;

        return FRAG_TRACKER_TIMEOUT;
    }

    return FRAG_OK;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* dg_mod_ctor()
{ return new DefragModule; }

static void mod_dtor(Module* m)
{ delete m; }

static PlugData* dg_ctor(Module* m)
{
    DefragModule* mod = (DefragModule*)m;
    FragCommon* fc = mod->get_data();
    FragData* fd = new FragData(fc);
    return fd;
}

static void dg_dtor(PlugData* p)
{
    delete p;
}

static const DataApi dg_api =
{
    {
        PT_DATA,
        GLOBAL_KEYWORD,
        INSAPI_PLUGIN_V0,
        0,
        dg_mod_ctor,
        mod_dtor
    },
    dg_ctor,
    dg_dtor,
};

//-------------------------------------------------------------------------

static Module* de_mod_ctor()
{ return new DefragEngineModule; }

static void de_init()
{
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile(
        "frag", &fragPerfStats, 0, &totalPerfStats, frag_get_profile);
    RegisterPreprocessorProfile(
        "fraginsert", &fragInsertPerfStats, 1, &fragPerfStats, frag_get_profile);
    RegisterPreprocessorProfile(
        "fragrebuild", &fragRebuildPerfStats, 1, &fragPerfStats, frag_get_profile);
#endif
}

static void de_sum()
{
    sum_stats((PegCount*)&g_stats, (PegCount*)&t_stats, array_size(peg_names));
}

static void de_stats()
{
    show_stats((PegCount*)&g_stats, peg_names, array_size(peg_names), ENGINE_KEYWORD);
}

static void de_reset()
{
    if (f_cache != NULL)
        sfxhash_make_empty(f_cache);

    memset(&g_stats, 0, sizeof(g_stats));
}

static Inspector* de_ctor(Module* m)
{
    return new Defrag((DefragEngineModule*)m);
}

static void de_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi de_api =
{
    {
        PT_INSPECTOR,
        ENGINE_KEYWORD,
        INSAPI_PLUGIN_V0,
        0,
        de_mod_ctor,
        mod_dtor
    },
    PRIORITY_NETWORK,
    PROTO_BIT__IP,
    de_init,
    nullptr, // term
    de_ctor,
    de_dtor,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // purge
    de_sum,
    de_stats,
    de_reset
};

const BaseApi* nin_defrag_global = &dg_api.base;
const BaseApi* nin_defrag_engine = &de_api.base;


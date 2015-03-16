//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
// Copyright (C) 1998-2005 Martin Roesch <roesch@sourcefire.com>
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

#ifndef SNORT_H
#define SNORT_H

/*  I N C L U D E S  **********************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <sys/types.h>
#include <stdio.h>

#include "main/snort_config.h"
#include "events/event_queue.h"
#include "filters/sfrf.h"

struct Packet;
class Flow;
struct NetworkPolicy;
struct InspectionPolicy;
struct IpsPolicy;

// defined in daq_common.h
struct _daq_pkthdr;
typedef _daq_pkthdr DAQ_PktHdr_t;

SnortConfig* get_reload_config();
void snort_setup(int argc, char* argv[]);
void snort_cleanup();

bool snort_is_starting();
bool snort_is_reloading();

void snort_thread_init(const char* intf);
void snort_thread_term();

void snort_thread_idle();
void snort_thread_rotate();

void CapturePacket();
void DecodeRebuiltPacket(Packet*, const DAQ_PktHdr_t*, const uint8_t* pkt, Flow*);
void DetectRebuiltPacket(Packet*);
void LogRebuiltPacket(Packet*);

DAQ_Verdict ProcessPacket(Packet*, const DAQ_PktHdr_t*, const uint8_t* pkt, bool is_frag=false);

DAQ_Verdict fail_open(void*, const DAQ_PktHdr_t*, const uint8_t*);
DAQ_Verdict packet_callback(void*, const DAQ_PktHdr_t*, const uint8_t*);

typedef void (* MainHook_f)(Packet*);
void set_main_hook(MainHook_f);

//-------------------------------------------------------------------------
// FIXIT-L most of what follows belongs in snort_config.h
//-------------------------------------------------------------------------

/*  D E F I N E S  ************************************************************/

#define TIMEBUF_SIZE    26

/* This feature allows us to change the state of a rule,
 * independent of it appearing in a rules file.
 */
#define RULE_STATE_DISABLED 0
#define RULE_STATE_ENABLED 1

/*  D A T A  S T R U C T U R E S  *********************************************/

enum RunFlag
{
    RUN_FLAG__READ                = 0x00000001,     /* -r --pcap-dir, etc. */
    RUN_FLAG__DAEMON              = 0x00000002,     /* -D */
    RUN_FLAG__DAEMON_RESTART      = 0x00000004,     /* --restart */
    RUN_FLAG__NO_PROMISCUOUS      = 0x00000008,     /* -p */

    RUN_FLAG__INLINE              = 0x00000010,     /* -Q */
    RUN_FLAG__STATIC_HASH         = 0x00000020,     /* -H */
    RUN_FLAG__CREATE_PID_FILE     = 0x00000040,     /* --pid-path and --create-pidfile */
    RUN_FLAG__NO_LOCK_PID_FILE    = 0x00000080,     /* --nolock-pidfile */

    RUN_FLAG__TREAT_DROP_AS_ALERT = 0x00000100,     /* --treat-drop-as-alert */
    RUN_FLAG__ALERT_BEFORE_PASS   = 0x00000200,     /* --alert-before-pass */
    RUN_FLAG__CONF_ERROR_OUT      = 0x00000400,     /* -x and --conf-error-out */
    RUN_FLAG__MPLS_MULTICAST      = 0x00000800,     /* --enable_mpls_multicast */

    RUN_FLAG__MPLS_OVERLAPPING_IP = 0x00001000,     /* --enable_mpls_overlapping_ip */
    RUN_FLAG__PROCESS_ALL_EVENTS  = 0x00002000,
    RUN_FLAG__INLINE_TEST         = 0x00004000,     /* --enable-inline-test*/
    RUN_FLAG__PCAP_SHOW           = 0x00008000,

    RUN_FLAG__DISABLE_FAILOPEN    = 0x00010000,     /* --disable-inline-init-failopen */
    RUN_FLAG__PAUSE               = 0x00020000,     // --pause
    RUN_FLAG__NO_PCRE             = 0x00040000,
    /* If stream is configured, the STATEFUL flag is set.  This is
     * somewhat misnamed and is used to assure a session is established */
    RUN_FLAG__ASSURE_EST          = 0x00080000,

    RUN_FLAG__TREAT_DROP_AS_IGNORE= 0x00100000,     /* --treat-drop-as-ignore */
    RUN_FLAG__PCAP_RELOAD         = 0x00200000,     /* --pcap-reload */
    RUN_FLAG__TEST                = 0x00400000,     /* -T */
#ifdef BUILD_SHELL
    RUN_FLAG__SHELL               = 0x00800000      /* --shell */
#endif
};

enum OutputFlag
{
    OUTPUT_FLAG__LINE_BUFFER       = 0x00000001,      /* -f */
    OUTPUT_FLAG__VERBOSE_DUMP      = 0x00000002,      /* -X */
    OUTPUT_FLAG__CHAR_DATA         = 0x00000004,      /* -C */
    OUTPUT_FLAG__APP_DATA          = 0x00000008,      /* -d */

    OUTPUT_FLAG__SHOW_DATA_LINK    = 0x00000010,      /* -e */
    OUTPUT_FLAG__SHOW_WIFI_MGMT    = 0x00000020,      /* -w */
    OUTPUT_FLAG__USE_UTC           = 0x00000040,      /* -U */
    OUTPUT_FLAG__INCLUDE_YEAR      = 0x00000080,      /* -y */

    /* Note using this alters the packet - can't be used inline */
    OUTPUT_FLAG__OBFUSCATE         = 0x00000100,      /* -B */
    OUTPUT_FLAG__ALERT_IFACE       = 0x00000200,      /* -I */
    OUTPUT_FLAG__NO_TIMESTAMP      = 0x00000400,      /* --nostamps */

    OUTPUT_FLAG__NO_ALERT          = 0x00001000,      /* -A none */
    OUTPUT_FLAG__NO_LOG            = 0x00002000,      /* -K none */
};

enum LoggingFlag
{
    LOGGING_FLAG__VERBOSE         = 0x00000001,      /* -v */
    LOGGING_FLAG__QUIET           = 0x00000002,      /* -q */
    LOGGING_FLAG__SYSLOG          = 0x00000004,      /* -M */
    LOGGING_FLAG__SHOW_PLUGINS    = 0x00000008,      // --show-plugins
};

enum TunnelFlags
{
    TUNNEL_GTP    = 0x01,
    TUNNEL_TEREDO = 0x02,
    TUNNEL_6IN4   = 0x04,
    TUNNEL_4IN6   = 0x08
};

/*  E X T E R N S  ************************************************************/
SO_PUBLIC extern THREAD_LOCAL SnortConfig* snort_conf;

/*  P R O T O T Y P E S  ******************************************************/

static inline int ScTestMode(void)
{
    return snort_conf->run_flags & RUN_FLAG__TEST;
}

static inline int ScDaemonMode(void)
{
    return snort_conf->run_flags & RUN_FLAG__DAEMON;
}

static inline int ScDaemonRestart(void)
{
    return snort_conf->run_flags & RUN_FLAG__DAEMON_RESTART;
}

static inline int ScReadMode(void)
{
    return snort_conf->run_flags & RUN_FLAG__READ;
}

static inline int ScLogSyslog(void)
{
    return snort_conf->logging_flags & LOGGING_FLAG__SYSLOG;
}

static inline int ScLogVerbose(void)
{
    return snort_conf->logging_flags & LOGGING_FLAG__VERBOSE;
}

static inline int ScLogQuiet(void)
{
    return snort_conf->logging_flags & LOGGING_FLAG__QUIET;
}

//-------------------------------------------------------------------------
// FIXIT-L should be calling NetworkPolicy methods

static inline bool ScChecksumDrop(uint16_t codec_cksum_err_flag)
{
    return get_network_policy()->checksum_drop & codec_cksum_err_flag;
}

static inline int ScIpChecksums(void)
{
    return get_network_policy()->checksum_eval & CHECKSUM_FLAG__IP;
}

static inline int ScIpChecksumDrops(void)
{
    return get_network_policy()->checksum_drop & CHECKSUM_FLAG__IP;
}

static inline int ScUdpChecksums(void)
{
    return get_network_policy()->checksum_eval & CHECKSUM_FLAG__UDP;
}

static inline int ScUdpChecksumDrops(void)
{
    return get_network_policy()->checksum_drop & CHECKSUM_FLAG__UDP;
}

static inline int ScTcpChecksums(void)
{
    return get_network_policy()->checksum_eval & CHECKSUM_FLAG__TCP;
}

static inline int ScTcpChecksumDrops(void)
{
    return get_network_policy()->checksum_drop & CHECKSUM_FLAG__TCP;
}

static inline int ScIcmpChecksums(void)
{
    return get_network_policy()->checksum_eval & CHECKSUM_FLAG__ICMP;
}

static inline int ScIcmpChecksumDrops(void)
{
    return get_network_policy()->checksum_drop & CHECKSUM_FLAG__ICMP;
}

static inline uint8_t ScMinTTL(void)
{
    return get_network_policy()->min_ttl;
}

static inline uint8_t ScNewTTL(void)
{
    return get_network_policy()->new_ttl;
}

static inline int ScInlineMode(void)
{
    return ((get_ips_policy()->policy_mode) == POLICY_MODE__INLINE );
}

static inline int ScInlineTestMode(void)
{
    return ((get_ips_policy()->policy_mode) == POLICY_MODE__INLINE_TEST );
}

//-------------------------------------------------------------------------

static inline int ScProcessAllEvents(void)
{
    return snort_conf->event_queue_config->process_all_events;
}

static inline int ScAdapterInlineMode(void)
{
    return snort_conf->run_flags & RUN_FLAG__INLINE;
}

static inline long int ScMplsStackDepth(void)
{
    return snort_conf->mpls_stack_depth;
}

static inline long int ScMplsPayloadType(void)
{
    return snort_conf->mpls_payload_type;
}

static inline int ScMplsOverlappingIp(void)
{
    return snort_conf->run_flags & RUN_FLAG__MPLS_OVERLAPPING_IP;
}

static inline int ScMplsMulticast(void)
{
    return snort_conf->run_flags & RUN_FLAG__MPLS_MULTICAST;
}

static inline uint32_t ScEventLogId(void)
{
    return snort_conf->event_log_id;
}

static inline int ScConfErrorOut(void)
{
    return snort_conf->run_flags & RUN_FLAG__CONF_ERROR_OUT;
}

static inline int ScAssureEstablished(void)
{
    return snort_conf->run_flags & RUN_FLAG__ASSURE_EST;
}

static inline long int ScPcreMatchLimit(void)
{
    return snort_conf->pcre_match_limit;
}

static inline long int ScPcreMatchLimitRecursion(void)
{
    return snort_conf->pcre_match_limit_recursion;
}

#ifdef PERF_PROFILING
static inline int ScProfilePreprocs(void)
{
    return snort_conf->profile_preprocs->num;
}

static inline int ScProfileRules(void)
{
    return snort_conf->profile_rules->num;
}

#endif

static inline int ScStaticHash(void)
{
    // FIXIT-L snort_conf needed for static hash before initialized
    return snort_conf && snort_conf->run_flags & RUN_FLAG__STATIC_HASH;
}

static inline int ScAdapterInlineTestMode(void)
{
    return snort_conf->run_flags & RUN_FLAG__INLINE_TEST;
}

static inline int ScOutputIncludeYear(void)
{
    return snort_conf->output_flags & OUTPUT_FLAG__INCLUDE_YEAR;
}

static inline int ScOutputUseUtc(void)
{
    return snort_conf->output_flags & OUTPUT_FLAG__USE_UTC;
}

static inline int ScOutputDataLink(void)
{
    return snort_conf->output_flags & OUTPUT_FLAG__SHOW_DATA_LINK;
}

static inline int ScVerboseByteDump(void)
{
    return snort_conf->output_flags & OUTPUT_FLAG__VERBOSE_DUMP;
}

static inline int ScObfuscate(void)
{
    return snort_conf->output_flags & OUTPUT_FLAG__OBFUSCATE;
}

static inline int ScOutputAppData(void)
{
    return snort_conf->output_flags & OUTPUT_FLAG__APP_DATA;
}

static inline int ScOutputCharData(void)
{
    return snort_conf->output_flags & OUTPUT_FLAG__CHAR_DATA;
}

static inline int ScAlertInterface(void)
{
    return snort_conf->output_flags & OUTPUT_FLAG__ALERT_IFACE;
}

static inline int ScNoOutputTimestamp(void)
{
    return snort_conf->output_flags & OUTPUT_FLAG__NO_TIMESTAMP;
}

static inline int ScLineBufferedLogging(void)
{
    return snort_conf->output_flags & OUTPUT_FLAG__LINE_BUFFER;
}

static inline int ScDefaultRuleState(void)
{
    return snort_conf->default_rule_state;
}

static inline int ScDisableInlineFailopen(void)
{
    return snort_conf->run_flags & RUN_FLAG__DISABLE_FAILOPEN;
}

static inline int ScNoLockPidFile(void)
{
    return snort_conf->run_flags & RUN_FLAG__NO_LOCK_PID_FILE;
}

static inline long int ScTaggedPacketLimit(void)
{
    return snort_conf->tagged_packet_limit;
}

static inline int ScCreatePidFile(void)
{
    return snort_conf->run_flags & RUN_FLAG__CREATE_PID_FILE;
}

static inline int ScPcapShow(void)
{
    return snort_conf->run_flags & RUN_FLAG__PCAP_SHOW;
}

static inline int ScOutputWifiMgmt(void)
{
    return snort_conf->output_flags & OUTPUT_FLAG__SHOW_WIFI_MGMT;
}

static inline uint32_t ScMaxAttrHosts(void)
{
    return snort_conf->max_attribute_hosts;
}

static inline uint32_t ScMaxAttrServicesPerHost(void)
{
    return snort_conf->max_attribute_services_per_host;
}

static inline int ScTreatDropAsAlert(void)
{
    return snort_conf->run_flags & RUN_FLAG__TREAT_DROP_AS_ALERT;
}

static inline int ScTreatDropAsIgnore(void)
{
    return snort_conf->run_flags & RUN_FLAG__TREAT_DROP_AS_IGNORE;
}

static inline int ScAlertBeforePass(void)
{
    return snort_conf->run_flags & RUN_FLAG__ALERT_BEFORE_PASS;
}

static inline int ScNoPcre(void)
{
    return snort_conf->run_flags & RUN_FLAG__NO_PCRE;
}

static inline int ScGetEvalIndex(RuleType type)
{
    return snort_conf->evalOrder[type];
}

static inline int ScUid(void)
{
    return snort_conf->user_id;
}

static inline int ScGid(void)
{
    return snort_conf->group_id;
}

// FIXIT-L this should be feature of otn
#define EventIsInternal(gid) (gid == GENERATOR_INTERNAL)

static inline void EnableInternalEvent(RateFilterConfig* config, uint32_t sid)
{
    if (config == NULL)
        return;

    config->internal_event_mask |= (1 << sid);
}

static inline int InternalEventIsEnabled(RateFilterConfig* config, uint32_t sid)
{
    if (config == NULL)
        return 0;

    return (config->internal_event_mask & (1 << sid));
}

static inline int ScDeepTeredoInspection(void)
{
    return snort_conf->enable_teredo;
}

static inline bool ScGTPDecoding(void)
{
    return snort_conf->gtp_ports;
}

static inline int ScIsGTPPort(uint16_t port)
{
    return snort_conf->gtp_ports->test(port);
}

static inline int ScESPDecoding(void)
{
    return snort_conf->enable_esp;
}

static inline int ScVlanAgnostic(void)
{
    return snort_conf->vlan_agnostic;
}

static inline int ScAddressSpaceAgnostic(void)
{
    return snort_conf->addressspace_agnostic;
}

static inline int ScLogIPv6Extra(void)
{
    return snort_conf->log_ipv6_extra;
}

static inline uint32_t ScSoRuleMemcap(void)
{
    return snort_conf->so_rule_memcap;
}

static inline bool ScTunnelBypassEnabled(uint8_t proto)
{
    return !(snort_conf->tunnel_mask & proto);
}

#endif


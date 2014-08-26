/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2013-2013 Sourcefire, Inc.
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

#include "snort_config.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snort_types.h"
#include "detection/treenodes.h"
#include "events/event_queue.h"
#include "stream/stream_api.h"
#include "port_scan/ps_detect.h"  // FIXIT-L for PS_PROTO_*
#include "utils/strvec.h"
#include "file_api/file_service.h"
#include "target_based/sftarget_reader.h"
#include "parser/parser.h"
#include "parser/config_file.h"
#include "parser/vars.h"
#include "filters/rate_filter.h"
#include "managers/mpse_manager.h"
#include "managers/inspector_manager.h"

//-------------------------------------------------------------------------
// private implementation
//-------------------------------------------------------------------------

static void FreeRuleStateList(RuleState *head)
{
    while (head != NULL)
    {
        RuleState *tmp = head;

        head = head->next;

        free(tmp);
    }
}

static void FreeClassifications(ClassType *head)
{
    while (head != NULL)
    {
        ClassType *tmp = head;

        head = head->next;

        if (tmp->name != NULL)
            free(tmp->name);

        if (tmp->type != NULL)
            free(tmp->type);

        free(tmp);
    }
}

static void FreeReferences(ReferenceSystemNode *head)
{
    while (head != NULL)
    {
        ReferenceSystemNode *tmp = head;

        head = head->next;

        if (tmp->name != NULL)
            free(tmp->name);

        if (tmp->url != NULL)
            free(tmp->url);

        free(tmp);
    }
}

typedef struct _IgnoredRuleList
{
    OptTreeNode *otn;
    struct _IgnoredRuleList *next;
} IgnoredRuleList;

#if 0
/** Get rule list for a specific protocol
 *
 * @param rule
 * @param ptocool protocol type
 * @returns RuleTreeNode* rule list for specific protocol
 */
static inline RuleTreeNode * protocolRuleList(RuleListNode *rule, int protocol)
{
    switch (protocol)
    {
        case IPPROTO_TCP:
            return rule->RuleList->TcpList;
        case IPPROTO_UDP:
            return rule->RuleList->UdpList;
        case IPPROTO_ICMP:
            break;
        default:
            break;
    }
    return NULL;
}

static inline const char* getProtocolName (int protocol)
{
    static const char *protocolName[] = {"TCP", "UDP", "ICMP"};
    switch (protocol)
    {
        case IPPROTO_TCP:
            return protocolName[0];
        case IPPROTO_UDP:
            return protocolName[1];
        case IPPROTO_ICMP:
            return protocolName[2];
            break;
        default:
            break;
    }
    return NULL;
}
#endif

//-------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

/* Alot of this initialization can be skipped if not running in IDS mode
 * but the goal is to minimize config checks at run time when running in
 * IDS mode so we keep things simple and enforce that the only difference
 * among run_modes is how we handle packets via the log_func. */
SnortConfig * SnortConfNew(void)
{
    SnortConfig *sc = (SnortConfig *)SnortAlloc(sizeof(SnortConfig));

    sc->pkt_cnt = 0;
    sc->pkt_skip = 0;
    sc->pkt_snaplen = -1;
    sc->output_flags = 0;

    /*user_id and group_id should be initialized to -1 by default, because
     * chown() use this later, -1 means no change to user_id/group_id*/
    sc->user_id = -1;
    sc->group_id = -1;

    sc->tagged_packet_limit = 256;
    sc->default_rule_state = RULE_STATE_ENABLED;

    // FIXIT-L pcre_match_limit* are interdependent
    // somehow a packet thread needs a much lower setting 
    sc->pcre_match_limit = 1500;
    sc->pcre_match_limit_recursion = 1500;

    memset(sc->pid_filename, 0, sizeof(sc->pid_filename));

    /* Default max size of the attribute table */
    sc->max_attribute_hosts = DEFAULT_MAX_ATTRIBUTE_HOSTS;
    sc->max_attribute_services_per_host = DEFAULT_MAX_ATTRIBUTE_SERVICES_PER_HOST;

    /* Default max number of services per rule */
    sc->max_metadata_services = DEFAULT_MAX_METADATA_SERVICES;
    sc->mpls_stack_depth = DEFAULT_LABELCHAIN_LENGTH;

    InspectorManager::new_config(sc);

    sc->var_list = NULL;

    sc->state = (SnortState*)SnortAlloc(sizeof(SnortState)*get_instance_max());

    sc->policy_map = new PolicyMap();

    set_inspection_policy(sc->get_inspection_policy());
    set_ips_policy(sc->get_ips_policy());
    set_network_policy(sc->get_network_policy());

    sc->max_encapsulations = -1;

    return sc;
}

void SnortConfFree(SnortConfig *sc)
{
    if (sc == NULL)
        return;

    if (sc->log_dir != NULL)
        free(sc->log_dir);

    if (sc->orig_log_dir != NULL)
        free(sc->orig_log_dir);

    if (sc->bpf_file != NULL)
        free(sc->bpf_file);

    if (sc->chroot_dir != NULL)
        free(sc->chroot_dir);

    if (sc->bpf_filter != NULL)
        free(sc->bpf_filter);

    if (sc->event_trace_file != NULL)
        free(sc->event_trace_file);

    FreeRuleStateList(sc->rule_state_list);
    FreeClassifications(sc->classifications);
    FreeReferences(sc->references);

    FreeRuleLists(sc);
    OtnLookupFree(sc->otn_map);
    PortTablesFree(sc->port_tables);

    ThresholdConfigFree(sc->threshold_config);
    RateFilter_ConfigFree(sc->rate_filter_config);
    DetectionFilterConfigFree(sc->detection_filter_config);

    if ( sc->event_queue_config )
        EventQueueConfigFree(sc->event_queue_config);

    if (sc->ip_proto_only_lists != NULL)
    {
        unsigned int j;

        for (j = 0; j < NUM_IP_PROTOS; j++)
            sflist_free_all(sc->ip_proto_only_lists[j], NULL);

        free(sc->ip_proto_only_lists);
    }

    fpDeleteFastPacketDetection(sc);

    InspectorManager::delete_config(sc);

    if ( sc->daq_type )
        free(sc->daq_type);

    if ( sc->daq_mode )
        free(sc->daq_mode);

    if ( sc->daq_vars )
        StringVector_Delete(sc->daq_vars);

    if ( sc->daq_dirs )
        StringVector_Delete(sc->daq_dirs);

    if ( sc->respond_device )
        free(sc->respond_device);

     if (sc->eth_dst )
        free(sc->eth_dst);

    if (sc->gtp_ports)
        free(sc->gtp_ports);

    if ( sc->output )
        free(sc->output);

    free_file_config(sc->file_config);

    if ( sc->var_list )
        FreeVarList(sc->var_list);

    if ( !snort_conf || sc == snort_conf ||
         (sc->fast_pattern_config &&
         (sc->fast_pattern_config->search_api !=
             snort_conf->fast_pattern_config->search_api)) )
    {
        MpseManager::stop_search_engine(sc->fast_pattern_config->search_api);
    }
    FastPatternConfigFree(sc->fast_pattern_config);

    delete sc->policy_map;

    free(sc->state);
    free(sc);
}

SnortConfig* MergeSnortConfs(SnortConfig *cmd_line, SnortConfig *config_file)
{
    /* Move everything from the command line config over to the
     * config_file config */

    if (cmd_line == NULL)
    {
        FatalError("%s(%d) Merging snort configs: snort conf is NULL.\n",
                   __FILE__, __LINE__);
    }

    if (config_file == NULL)
    {
        if (cmd_line->log_dir == NULL)
            cmd_line->log_dir = SnortStrdup(DEFAULT_LOG_DIR);
    }
    else if ((cmd_line->log_dir == NULL) && (config_file->log_dir == NULL))
    {
        config_file->log_dir = SnortStrdup(DEFAULT_LOG_DIR);
    }
    else if (cmd_line->log_dir != NULL)
    {
        if (config_file->log_dir != NULL)
            free(config_file->log_dir);

        config_file->log_dir = SnortStrdup(cmd_line->log_dir);
    }

    if (config_file == NULL)
        return cmd_line;

    config_file->run_prefix = cmd_line->run_prefix;
    cmd_line->run_prefix = nullptr;

    config_file->id_subdir = cmd_line->id_subdir;
    config_file->id_zero = cmd_line->id_zero;

    /* Used because of a potential chroot */
    config_file->orig_log_dir = SnortStrdup(config_file->log_dir);

    config_file->event_log_id = cmd_line->event_log_id;

    config_file->run_flags |= cmd_line->run_flags;
    config_file->output_flags |= cmd_line->output_flags;
    config_file->logging_flags |= cmd_line->logging_flags;

    if ((cmd_line->run_flags & RUN_FLAG__TEST) &&
        (config_file->run_flags & RUN_FLAG__DAEMON))
    {
        /* Just ignore deamon setting in conf file */
        config_file->run_flags &= ~RUN_FLAG__DAEMON;
    }

    config_file->stdin_rules = cmd_line->stdin_rules;

    // only set by cmd_line to override other conf output settings
    config_file->output = cmd_line->output;
    cmd_line->output = nullptr;

    /* Merge checksum flags.  If command line modified them, use from the
     * command line, else just use from config_file. */

    int cl_chk = cmd_line->get_network_policy()->checksum_eval;
    int cl_drop = cmd_line->get_network_policy()->checksum_drop;

    for ( auto p : config_file->policy_map->network_policy )
    {
        if ( !(cl_chk & CHECKSUM_FLAG__DEF) )
            p->checksum_eval = cl_chk;

        if ( !(cl_drop & CHECKSUM_FLAG__DEF) )
            p->checksum_eval = cl_drop;
    }

    if (cmd_line->obfuscation_net.family != 0)
        memcpy(&config_file->obfuscation_net, &cmd_line->obfuscation_net, sizeof(sfip_t));

    if (cmd_line->homenet.family != 0)
        memcpy(&config_file->homenet, &cmd_line->homenet, sizeof(sfip_t));

    if (cmd_line->bpf_file != NULL)
    {
        if (config_file->bpf_file != NULL)
            free(config_file->bpf_file);
        config_file->bpf_file = SnortStrdup(cmd_line->bpf_file);
    }

    if (cmd_line->bpf_filter != NULL)
        config_file->bpf_filter = SnortStrdup(cmd_line->bpf_filter);

    if (cmd_line->pkt_snaplen != -1)
        config_file->pkt_snaplen = cmd_line->pkt_snaplen;

    if (cmd_line->pkt_cnt != 0)
        config_file->pkt_cnt = cmd_line->pkt_cnt;

    if (cmd_line->pkt_skip != 0)
        config_file->pkt_skip = cmd_line->pkt_skip;

    if (cmd_line->group_id != -1)
        config_file->group_id = cmd_line->group_id;

    if (cmd_line->user_id != -1)
        config_file->user_id = cmd_line->user_id;

    /* Only configurable on command line */
    if (cmd_line->file_mask != 0)
        config_file->file_mask = cmd_line->file_mask;

    if (cmd_line->chroot_dir != NULL)
    {
        if (config_file->chroot_dir != NULL)
            free(config_file->chroot_dir);
        config_file->chroot_dir = SnortStrdup(cmd_line->chroot_dir);
    }

    if ( cmd_line->daq_type )
        config_file->daq_type = SnortStrdup(cmd_line->daq_type);

    if ( cmd_line->daq_mode )
        config_file->daq_mode = SnortStrdup(cmd_line->daq_mode);

    if ( cmd_line->dirty_pig )
        config_file->dirty_pig = cmd_line->dirty_pig;

    if ( cmd_line->daq_vars )
    {
        /* Command line overwrites daq_vars */
        if (config_file->daq_vars)
            StringVector_Delete(config_file->daq_vars);

        config_file->daq_vars = StringVector_New();
        StringVector_AddVector(config_file->daq_vars, cmd_line->daq_vars);
    }
    if ( cmd_line->daq_dirs )
    {
        /* Command line overwrites daq_dirs */
        if (config_file->daq_dirs)
            StringVector_Delete(config_file->daq_dirs);

        config_file->daq_dirs = StringVector_New();
        StringVector_AddVector(config_file->daq_dirs, cmd_line->daq_dirs);
    }
    if (cmd_line->mpls_stack_depth != DEFAULT_LABELCHAIN_LENGTH)
        config_file->mpls_stack_depth = cmd_line->mpls_stack_depth;

    /* Set MPLS payload type here if it hasn't been defined */
    if ((cmd_line->mpls_payload_type == 0) &&
        (config_file->mpls_payload_type == 0))
    {
        config_file->mpls_payload_type = DEFAULT_MPLS_PAYLOADTYPE;
    }
    else if (cmd_line->mpls_payload_type != 0)
    {
        config_file->mpls_payload_type = cmd_line->mpls_payload_type;
    }

    if (cmd_line->run_flags & RUN_FLAG__PROCESS_ALL_EVENTS)
        config_file->event_queue_config->process_all_events = 1;

    if ( cmd_line->remote_control )
        config_file->remote_control = cmd_line->remote_control;

    if ( cmd_line->max_encapsulations )
        config_file->max_encapsulations = cmd_line->max_encapsulations;

    // config file vars are stored differently
    // FIXIT-M should config_file and cmd_line use the same var list / table?
    config_file->var_list = NULL;

    free(config_file->state);
    config_file->state = (SnortState*)SnortAlloc(
        sizeof(SnortState)*get_instance_max());

    return config_file;
}

int VerifyReload(SnortConfig *sc)
{
    if (sc == NULL)
        return -1;

    if (snort_conf->asn1_mem != sc->asn1_mem)
    {
        ErrorMessage("Snort Reload: Changing the asn1 memory configuration "
                     "requires a restart.\n");
        return -1;
    }

    if ((sc->bpf_filter == NULL) && (sc->bpf_file != NULL))
        sc->bpf_filter = read_infile(sc->bpf_file);

    if ((sc->bpf_filter != NULL) && (snort_conf->bpf_filter != NULL))
    {
        if (strcasecmp(snort_conf->bpf_filter, sc->bpf_filter) != 0)
        {
            ErrorMessage("Snort Reload: Changing the bpf filter configuration "
                         "requires a restart.\n");
            return -1;
        }
    }
    else if (sc->bpf_filter != snort_conf->bpf_filter)
    {
        ErrorMessage("Snort Reload: Changing the bpf filter configuration "
                     "requires a restart.\n");
        return -1;
    }

    if ( sc->respond_attempts != snort_conf->respond_attempts ||
         sc->respond_device != snort_conf->respond_device )
    {
        ErrorMessage("Snort Reload: Changing config response "
                     "requires a restart.\n");
        return -1;
    }

    if ((snort_conf->chroot_dir != NULL) &&
        (sc->chroot_dir != NULL))
    {
        if (strcasecmp(snort_conf->chroot_dir, sc->chroot_dir) != 0)
        {
            ErrorMessage("Snort Reload: Changing the chroot directory "
                         "configuration requires a restart.\n");
            return -1;
        }
    }
    else if (snort_conf->chroot_dir != sc->chroot_dir)
    {
        ErrorMessage("Snort Reload: Changing the chroot directory "
                     "configuration requires a restart.\n");
        return -1;
    }

    if ((snort_conf->run_flags & RUN_FLAG__DAEMON) !=
        (sc->run_flags & RUN_FLAG__DAEMON))
    {
        ErrorMessage("Snort Reload: Changing to or from daemon mode "
                     "requires a restart.\n");
        return -1;
    }

    /* Orig log dir because a chroot might have changed it */
    if ((snort_conf->orig_log_dir != NULL) &&
        (sc->orig_log_dir != NULL))
    {
        if (strcasecmp(snort_conf->orig_log_dir, sc->orig_log_dir) != 0)
        {
            ErrorMessage("Snort Reload: Changing the log directory "
                         "configuration requires a restart.\n");
            return -1;
        }
    }
    else if (snort_conf->orig_log_dir != sc->orig_log_dir)
    {
        ErrorMessage("Snort Reload: Changing the log directory "
                     "configuration requires a restart.\n");
        return -1;
    }

    if (snort_conf->max_attribute_hosts != sc->max_attribute_hosts)
    {
        ErrorMessage("Snort Reload: Changing max_attribute_hosts "
                     "configuration requires a restart.\n");
        return -1;
    }
    if (snort_conf->max_attribute_services_per_host != sc->max_attribute_services_per_host)
    {
        ErrorMessage("Snort Reload: Changing max_attribute_services_per_host "
                     "configuration requires a restart.\n");
        return -1;
    }

    if ( (snort_conf->output_flags & OUTPUT_FLAG__NO_LOG) != 
         (sc->output_flags & OUTPUT_FLAG__NO_LOG) )
    {
        ErrorMessage("Snort Reload: Changing from log to no log or vice "
                     "versa requires a restart.\n");
        return -1;
    }

    if ((snort_conf->run_flags & RUN_FLAG__NO_PROMISCUOUS) !=
        (sc->run_flags & RUN_FLAG__NO_PROMISCUOUS))
    {
        ErrorMessage("Snort Reload: Changing to or from promiscuous mode "
                     "requires a restart.\n");
        return -1;
    }

#ifdef PPM_MGR
    /* XXX XXX Not really sure we need to disallow this */
    if (snort_conf->ppm_cfg.rule_log != sc->ppm_cfg.rule_log)
    {
        ErrorMessage("Snort Reload: Changing the ppm rule_log "
                     "configuration requires a restart.\n");
        return -1;
    }
#endif

    if (snort_conf->group_id != sc->group_id)
    {
        ErrorMessage("Snort Reload: Changing the group id "
                     "configuration requires a restart.\n");
        return -1;
    }

    if (snort_conf->user_id != sc->user_id)
    {
        ErrorMessage("Snort Reload: Changing the user id "
                     "configuration requires a restart.\n");
        return -1;
    }

    if (snort_conf->pkt_snaplen != sc->pkt_snaplen)
    {
        ErrorMessage("Snort Reload: Changing the packet snaplen "
                     "configuration requires a restart.\n");
        return -1;
    }

    if (snort_conf->threshold_config->memcap !=
        sc->threshold_config->memcap)
    {
        ErrorMessage("Snort Reload: Changing the threshold memcap "
                     "configuration requires a restart.\n");
        return -1;
    }

    if (snort_conf->rate_filter_config->memcap !=
        sc->rate_filter_config->memcap)
    {
        ErrorMessage("Snort Reload: Changing the rate filter memcap "
                     "configuration requires a restart.\n");
        return -1;
    }

    if (snort_conf->detection_filter_config->memcap !=
        sc->detection_filter_config->memcap)
    {
        ErrorMessage("Snort Reload: Changing the detection filter memcap "
                     "configuration requires a restart.\n");
        return -1;
    }

    if (snort_conf->so_rule_memcap != sc->so_rule_memcap)
    {
        ErrorMessage("Snort Reload: Changing the so rule memcap "
                     "configuration requires a restart.\n");
        return -1;
    }

    return 0;
}


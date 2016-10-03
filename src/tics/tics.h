/**
 * @file    tics.h
 * @author  Titan IC Systems <support@titanicsystems.com>
 *
 * @section DESCRIPTION
 *
 *   Titan IC cronus header file
 *
 * @section LICENSE
 *
 *   GPL LICENSE
 *
 *   This program is free software; you can redistribute it and/or modify it
 *   under the terms of the GNU General Public License Version 2 as published
 *   by the Free Software Foundation.  You may not use, modify or distribute
 *   this program under any other version of the GNU General Public License.
 *
 *   This program is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef __TICS_H__
#define __TICS_H__

/* TICS code functionality enabler */
#include "tics_macro_enabler.h"

#define TICS_VERSION     "0.8" //Current test version

#ifdef TICS_USE_LOAD_BALANCE
#define TICS_DEFAULT_RXP_QUEUE_CNT  8
extern int enabled_rxp_queue_cnt;
extern int launched_inspect_thread_cnt;
#endif /* TICS_USE_LOAD_BALANCE */

#ifdef TICS_GENERATE_RULE_FILE
#include <vector>
#include "ports/port_group.h"
#include "detection/fp_create.h"
#include "detection/treenodes.h"
#include "detection/pattern_match_data.h"

/* *
 * In the tics_add_fp(), it is very difficult to decide a right/suitable fp_id and fp_subset_id,
 * so they are assigned a meaningful value in the final tics_finalize_fp_subsets()
 * */
typedef struct tics_fp_elem {
    OptTreeNode *otn;          /* snort rule infomation */
    PatternMatchData *pmd;     /* Both original snort fast pattern and tics fast pattern info */

    PMX *pmx;                  /* a combination of otn and pmd */
    void *rule_option_tree;
    void *neg_list;            /* pmx, rule_option_tree, and neg_list are used in fast pattern results interface */ 

    char *pattern;             /* tics_style fp string */
    uint16_t pattern_len;      /* tis_style fp string length */
    uint32_t fp_id;            /* It is the same as the id in rule file, 0 is illegal */
    int dup_flag;              /* if this elem is a duplicate, it is not print out to tics rule file */

    /* *
     * These ids are used in snort rule file and snort rule's internal processing
     * as there are duplicate, so the relationship between fp_id and them is 1-2-N
     * */
    uint32_t *snort_rule_file_ids;
    uint32_t *snort_rule_internal_ids;
    uint32_t snort_rule_file_ids_cnt;

    /* *
     * It means this pattern's adding sequence in add_pattern() called by fpFinishPortGroupRule()
     * */
    uint32_t snort_add_seq_in_subset;
    /* *
     * This is a collection of snort_add_seq_in_subset for the same fast-pattern
     * as there are duplicate, so the relationship between fp_id and snort_add_seqs is 1-2-N
     * These seqs are used in snort'3 mpse search db construction as the fast-pattern ids in a db
     * */
    uint32_t *snort_add_seqs;
    uint32_t snort_add_seqs_cnt;
       uint32_t tics_pg_type;
    struct tics_fp_elem *next;
} tics_fp_elem_t;

typedef struct tics_fp_subset {
    tics_fp_elem_t *fp_elem;
    uint32_t fp_elem_count;
    uint32_t fp_subset_id;     /* It is the same as the id in rule file, 0 is illegal */
} tics_fp_subset_t;

typedef struct tics_subsets_of_1_portgroup {
    struct PortGroup *pg;
    tics_fp_subset_t *subsets[PM_TYPE_MAX];
    struct tics_subsets_of_1_portgroup *next;
} tics_subsets_1g_t;
extern tics_subsets_1g_t *tics_subsets;

extern FILE *tics_rule_file_handle;
#define TICS_RULE_FILE_PATH "/tmp/tics_snort3.rules"
typedef struct snort_2_tics_subset_map {
    PortGroup *snort_pg;
    PmType snort_pm_type;
    tics_fp_subset_t *tics_subset;
    uint32_t tics_subset_id;
    struct snort_2_tics_subset_map *next;
} s2t_subset_map_t;
extern s2t_subset_map_t *s2t_subset_maps;

#define TICS_ROF_FILE_DIR_PATH "/tmp/snort-rof"
extern uint32_t tics_total_subset_cnt;
extern uint32_t tics_total_fp_cnt;
extern uint32_t tics_total_duplicate_fp_cnt;
extern uint32_t snort_add_pattern_cnt;
extern uint32_t snort_prep_patterns_cnt;
extern uint32_t max_tics_pattern_len;
extern uint32_t global_tics_pg_type;

/**
 * tics fp to hyperscan fp id map per subset
 * The index of t2s_psb_id_map is tics_fp_id-1, as tics_fp_id starts from 1
 * */
typedef struct tics_2_snort_per_subset_fp_id_map {
    PortGroup *pg;
    PmType pm_type;
    uint32_t tics_subset_id;
    tics_fp_elem_t *tics_fp_elem;
} t2s_psb_id_map_t;
extern std::vector<t2s_psb_id_map_t> t2s_psb_id_map;

int tics_create_fp_elem(tics_fp_elem_t **elem,
                        PatternMatchData *pmd,
                        OptTreeNode *otn);
int tics_add_fp(tics_fp_elem_t *fp_elem,
                PmType fp_pm_type,
                PortGroup *pg);
int tics_finalize_fp_subsets();
int tics_generate_rule_file();
int tics_generate_t2s_psb_id_map();
void print_t2s_psb_id_map();
int ChangeFpPatternFormat(const char *fast_pattern,
                          char *transformed_fast_pattern,
                          uint16_t *transformed_fp_len);
int TicsGenerateFpPattern(const char *orig_pattern,
                          char*& tics_fp_pattern,
                          uint16_t& tics_fp_len);

#define TICS_PORT_GROUP_SRC       0
#define TICS_PORT_GROUP_DST       1
#define TICS_PORT_GROUP_ANY       2
#define TICS_PORT_GROUP_IP_GROUP  0
#define TICS_PORT_GROUP_TYPE      0
#define TICS_PORT_GROUP_FILE      3
#define TICS_PORT_GROUP_SVC       4
/* The value of TICS_PORT_GROUP_LIMIT is the max count of the TICS_PORT_GROUP_XXX */

/* tics max pattern length when compiling the ruleset*/
extern uint32_t max_tics_pattern_len;
#define TICS_MAX_RXP_JOB_LENGTH (16384) //Overlapping limit value
#endif /* TICS_GENERATE_RULE_FILE */

#ifdef TICS_USE_RXP_MATCH
#include <rxp.h>
#include <rte_config.h>
#include <rte_lcore.h>

#include "sfip/sf_ip.h"
#include "managers/action_manager.h"
#include "protocols/packet_manager.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "protocols/icmp4.h"
#include "search_engines/pat_stats.h"
#include "detection/fp_detect.h"
#include "detection/fp_config.h"
#include "detection/detection_util.h"
#include "detection/detect.h"
#include "detection/service_map.h"
#include "main/thread.h"
#include "framework/mpse.h"
#include "utils/stats.h"

#define TICS_MAX_RXP_PACKET_LENGTH     64 //data size limit to perform match with rxp
#define TICS_PORT_GROUP_LIMIT     8 //data size limit to perform match with rxp
#define TICS_MAX_RXP_JOB_LENGTH (16384) //Overlapping limit value
#define TICS_RXP_MATCH_LIMIT 62 //Need to increase in the future
#define TICS_RXP_MATCH_LIMIT_DETECTED 255 //Need to increase in the future
#define MAX_NUMBER_QUEUES 8

typedef struct
{
    uint32_t index;
    uint32_t id[TICS_RXP_MATCH_LIMIT]; //rule_id
    uint32_t from[TICS_RXP_MATCH_LIMIT]; //start_ptr
    uint32_t to[TICS_RXP_MATCH_LIMIT]; //start_ptr + length
} PMQ;

extern THREAD_LOCAL PMQ rxp_response_queues[PM_TYPE_MAX][TICS_PORT_GROUP_LIMIT];
extern THREAD_LOCAL bool rxp_response_queues_status[PM_TYPE_MAX];
extern THREAD_LOCAL int PM_TYPE_search;
extern THREAD_LOCAL int port_group_search;
extern THREAD_LOCAL uint32_t global_rxp_job_id;
extern THREAD_LOCAL uint16_t current_subsets[PM_TYPE_MAX][TICS_PORT_GROUP_LIMIT];
extern THREAD_LOCAL int count_subsets[PM_TYPE_MAX];

typedef struct rxp_job_descriptor
{
    uint32_t job_id;
    uint32_t flow_id;
    uint16_t ctrl;
    uint16_t job_length;
    uint16_t subset_id_0;
    uint16_t subset_id_1;
    uint16_t subset_id_2;
    uint16_t subset_id_3;
} rxp_job_desc_t;

int tics_program_rxp_rule_file(unsigned rxp_port_id,
                               unsigned rxp_queue_id);
int tics_dpdk_init(unsigned rxp_port_id,
                   unsigned rxp_num_queues);
void tics_get_sid(PortGroup* group,
                  int count_subsets[],
                  uint16_t current_subsets[][TICS_PORT_GROUP_LIMIT]);
void tics_reset_rxp_resp_queue();
void tics_reset_sid(int count_subsets[],
                    uint16_t current_subsets[][TICS_PORT_GROUP_LIMIT]);
void tics_get_tcp_sid(int count_subsets[],
                      uint16_t current_subsets[][TICS_PORT_GROUP_LIMIT],
                      Packet *p,
                      PortGroup **src,
                      PortGroup **dst,
                      PortGroup **any);
void tics_get_udp_sid(int count_subsets[],
                      uint16_t current_subsets[][TICS_PORT_GROUP_LIMIT],
                      Packet *p,
                      PortGroup **src,
                      PortGroup **dst,
                      PortGroup **any);
void tics_get_ip_sid(int count_subsets[],
                     uint16_t current_subsets[][TICS_PORT_GROUP_LIMIT],
                     PortGroup **ip_group,
                     PortGroup **any);
void tics_get_icmp_sid(int count_subsets[],
                       uint16_t current_subsets[][TICS_PORT_GROUP_LIMIT],
                       Packet *p,
                       PortGroup **type,
                       PortGroup **any);
void tics_get_svc_sid(int count_subsets[],
                      uint16_t current_subsets[][TICS_PORT_GROUP_LIMIT],
                      Packet *p,
                      int proto,
                      PortGroup **file,
                      PortGroup **svc);
void tics_scan_pkt(Packet* p);


#ifdef TICS_GENERATE_RXP_JOB_FILE
int TicsGenerateRxpJobFile(const rxp_job_desc_t * rxp_job_desc_ptr,
                           const unsigned char * rxp_job_data_ptr);
#endif /* TICS_GENERATE_RXP_JOB_FILE */


bool fpWriteAllRxpJobFiles(const unsigned char * T,
                           int n,
                           uint16_t * current_subsets,
                           int count_subset,
                           int PM_TYPE);
int fpScanJob(const rxp_job_desc_t * rxp_job_desc_ptr,
              const uint8_t * rxp_job_data_ptr,
              int PM_TYPE);
bool tics_rxp_process(Packet* p,
                      char ip_rule,
                      int count_subsets[],
                      uint16_t current_subsets[][TICS_PORT_GROUP_LIMIT]);
#endif /* TICS_USE_RXP_MATCH */

#endif /* __TICS_H__ */

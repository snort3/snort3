/**
 * @file    tics_compile.cc
 * @author  Titan IC Systems <support@titanicsystems.com>
 *
 * @section DESCRIPTION
 *
 *   Titan IC cronus RXP compilation functions
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
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tics.h"
#ifdef TICS_GENERATE_RULE_FILE
tics_subsets_1g_t *tics_subsets = NULL;
s2t_subset_map_t *s2t_subset_maps = NULL;
std::vector<t2s_psb_id_map_t> t2s_psb_id_map;
uint32_t tics_total_subset_cnt = 0;
uint32_t tics_total_fp_cnt = 0;
uint32_t tics_total_duplicate_fp_cnt = 0;
uint32_t snort_add_pattern_cnt = 0;
uint32_t snort_prep_patterns_cnt = 0;
uint32_t max_tics_pattern_len = 0;
uint32_t global_tics_pg_type = 0;

int tics_create_fp_elem(tics_fp_elem_t **elem,
                        PatternMatchData *pmd,
                        OptTreeNode *otn)
{
    tics_fp_elem_t *fp_elem = (tics_fp_elem_t *)calloc(1, sizeof(tics_fp_elem_t));
    if (!fp_elem)
    {
        printf("fp_elem allocation failure in %s\n", __FUNCTION__);
        return (-1);
    }
    fp_elem->pmd = pmd;
    fp_elem->otn = otn;
    fp_elem->pattern = pmd->tics_fp_pattern;
    fp_elem->pattern_len = pmd->tics_fp_len;
    if (fp_elem->pattern_len > max_tics_pattern_len)
    {
        max_tics_pattern_len = fp_elem->pattern_len;

        if (TICS_MAX_RXP_JOB_LENGTH < max_tics_pattern_len)
        {
            fprintf(stdout,"Error: TICS The max job size value (%d) is smaller than the max_pattern_size (%d)\n", TICS_MAX_RXP_JOB_LENGTH, max_tics_pattern_len);
            exit (-1);
        }
    }
    fp_elem->next = NULL;
    fp_elem->snort_rule_internal_ids = (uint32_t *)calloc(1, sizeof(uint32_t));
    if (!fp_elem->snort_rule_internal_ids)
    {
        printf("snort rule internal ids allocation failure in %s\n", __FUNCTION__);
        return (-1);
    }
    fp_elem->snort_rule_internal_ids[0] = otn->ruleIndex;
    fp_elem->snort_rule_file_ids = (uint32_t *)calloc(1, sizeof(uint32_t));
    if (!fp_elem->snort_rule_file_ids)
    {
        printf("snort rule file ids allocation failure in %s\n", __FUNCTION__);
        return (-1);
    }
    fp_elem->snort_rule_file_ids[0] = otn->sigInfo.id;
    fp_elem->snort_rule_file_ids_cnt = 1;
    fp_elem->tics_pg_type = global_tics_pg_type;
    *elem = fp_elem;
    return (0);
}

int tics_add_fp(tics_fp_elem_t *fp_elem,
                PmType fp_pm_type,
                PortGroup *pg)
{
    tics_subsets_1g_t *subsets_1g = NULL;
    tics_fp_subset_t *subset = NULL;
    tics_fp_elem_t *head = NULL;
    uint32_t i = 0;

    if (fp_elem == NULL)
    {
        printf("fp_elem is NULL in %s\n", __FUNCTION__);
        return (-1);
    }
    if ((!tics_subsets) || (pg != tics_subsets->pg))
    {
        subsets_1g = (tics_subsets_1g_t *)calloc(1, sizeof(tics_subsets_1g_t));
        if (!subsets_1g)
        {
            printf("subsets_1g allocation failure in %s\n", __FUNCTION__);
            return (-1);
        }
        subsets_1g->pg = pg;

        if (tics_subsets == NULL)
        {
            tics_subsets = subsets_1g;
        }
        else
        {
            /* Always insert the current portgroup as the head */
            subsets_1g->next = tics_subsets;
            tics_subsets = subsets_1g;
        }
    }

    if (! tics_subsets->subsets[fp_pm_type])
    {
        subset = (tics_fp_subset_t *)calloc(1, sizeof(tics_fp_subset_t));
        if (!(subset))
        {
            printf("subsets_1g's subset allocation failure in %s\n", __FUNCTION__);
            return (-1);
        }
        subset->fp_elem = fp_elem;
        tics_subsets->subsets[fp_pm_type] = subset;
    }
    else
    {
        /* Flag whether this new fp_elem is a duplicate of the previous fp-elems */
        head = tics_subsets->subsets[fp_pm_type]->fp_elem;
        while (head)
        {
            if (strcmp(head->pattern, fp_elem->pattern) == 0)
            {
                tics_total_duplicate_fp_cnt++;
                head->dup_flag = 1;
                fp_elem->snort_rule_file_ids = (uint32_t *)realloc(fp_elem->snort_rule_file_ids,
                                               (1 + head->snort_rule_file_ids_cnt) * sizeof(uint32_t));
                if (!fp_elem->snort_rule_file_ids)
                {
                    printf("snort_rule_file_ids reallocation failure in %s\n", __FUNCTION__);
                    return (-1);
                }
                fp_elem->snort_rule_internal_ids = (uint32_t *)realloc(fp_elem->snort_rule_internal_ids,
                            (1 + head->snort_rule_file_ids_cnt) * sizeof(uint32_t));
                if (!fp_elem->snort_rule_internal_ids)
                {
                    printf("snort_rule_internal_ids reallocation failure in %s\n", __FUNCTION__);
                    return (-1);
                }
                fp_elem->snort_rule_file_ids_cnt = 1 + head->snort_rule_file_ids_cnt;
                for (i = 0; i < head->snort_rule_file_ids_cnt; i++)
                {
                    fp_elem->snort_rule_file_ids[i + 1] = head->snort_rule_file_ids[i];
                    fp_elem->snort_rule_internal_ids[i + 1] = head->snort_rule_internal_ids[i];
                }
                fp_elem->snort_add_seqs = (uint32_t *)calloc(1 + head->snort_add_seqs_cnt, sizeof(uint32_t));
                if (!fp_elem->snort_add_seqs)
                {
                    printf("snort_add_seqs allocation failure in %s\n", __FUNCTION__);
                    return (-1);
                }
                fp_elem->snort_add_seqs_cnt = 1 + head->snort_add_seqs_cnt;
                for (i = 0; i < head->snort_add_seqs_cnt; i++)
                {
                    fp_elem->snort_add_seqs[i] = head->snort_add_seqs[i];
                }
                break;
            }
            head = head->next;
        }

        /* Always insert the new fp_elem as the head */
        fp_elem->next = tics_subsets->subsets[fp_pm_type]->fp_elem;
        tics_subsets->subsets[fp_pm_type]->fp_elem = fp_elem;

    }

    fp_elem->snort_add_seq_in_subset = tics_subsets->subsets[fp_pm_type]->fp_elem_count;
    if (fp_elem->snort_add_seqs)
    {
        fp_elem->snort_add_seqs[fp_elem->snort_add_seqs_cnt - 1] = fp_elem->snort_add_seq_in_subset;
    }
    else
    {
        fp_elem->snort_add_seqs = (uint32_t *)calloc(1, sizeof(uint32_t));
        if (!fp_elem->snort_add_seqs)
        {
            printf("snort_add_seqs allocation failure in %s\n", __FUNCTION__);
            return (-1);
        }
        fp_elem->snort_add_seqs_cnt = 1;
        fp_elem->snort_add_seqs[0] = fp_elem->snort_add_seq_in_subset;
    }
    tics_subsets->subsets[fp_pm_type]->fp_elem_count++;

    return (0);
}

int tics_finalize_fp_subsets()
{
    uint32_t i = 0;
    tics_subsets_1g_t * subsets_1g = tics_subsets;
    tics_fp_subset_t * subset = NULL;
    tics_fp_elem_t * elem = NULL;
    tics_total_subset_cnt = 0;
    tics_total_fp_cnt = 0;
    s2t_subset_map_t * s2t_map = NULL;

    if (tics_subsets == NULL)
    {
        printf("tics_subsets is NULL in %s\n", __FUNCTION__);
        return (-1);
    }

    while (subsets_1g)
    {
        for (i = 0; i < PM_TYPE_MAX; i++)
        {
            subset = subsets_1g->subsets[i];
            if (subset)
            {
                subset->fp_subset_id = ++tics_total_subset_cnt;
                elem = subset->fp_elem;
                while (elem)
                {
                    if (elem->dup_flag == 0)
                    {
                        elem->fp_id = ++tics_total_fp_cnt;
                    }
                    elem = elem->next;
                }
                subsets_1g->pg->tics_subset_id[i] = subset->fp_subset_id;
                /* Generate s2t_subset_maps */
                s2t_map = (s2t_subset_map_t *)calloc(1, sizeof(s2t_subset_map_t));
                if (!s2t_map)
                {
                    printf("s2t_map allocation failure in %s\n", __FUNCTION__);
                    return (-1);
                }
                s2t_map->snort_pg = subsets_1g->pg;
                s2t_map->snort_pm_type = PmType(i);
                s2t_map->tics_subset = subset;
                s2t_map->tics_subset_id = subset->fp_subset_id;
                if (!s2t_subset_maps)
                {
                    s2t_subset_maps = s2t_map;
                }
                else
                {
                    s2t_map->next = s2t_subset_maps;
                    s2t_subset_maps = s2t_map;
                }
            }
        }
        subsets_1g = subsets_1g->next;
    }
    return (0);
}

int tics_generate_rule_file()
{
    uint32_t i = 0;
    uint32_t j = 0;
    FILE *fp = tics_rule_file_handle;
    tics_subsets_1g_t * subsets_1g = tics_subsets;
    tics_fp_subset_t * subset = NULL;
    tics_fp_elem_t * elem = NULL;

    if (fp == NULL)
    {
        printf("rule file is not opend yet in %s\n", __FUNCTION__);
        return (-1);
    }
    else if(tics_subsets == NULL)
    {
        printf("tics_subsets is NULL in %s\n", __FUNCTION__);
        return (-1);
    }

    fprintf(fp, "#TICS subsets file for Snort-3.0 @ %s of %s\n", __TIME__, __DATE__);

    while (subsets_1g)
    {
        for (i = 0; i < PM_TYPE_MAX; i++)
        {
            subset = subsets_1g->subsets[i];
            if (subset)
            {
                fprintf(fp, "#port_group = %p, pm_type = %d\n", subsets_1g->pg, i);
                fprintf(fp, "subset_id = %d\n", subset->fp_subset_id);
                fprintf(fp, "#total_rule_cnt = %d\n", subset->fp_elem_count);

                elem = subset->fp_elem;
                /* We should remove the duplicate fp in the same subset */
                while (elem)
                {
                    fprintf(fp, "#Original [%d] rules with rule_ids: ",
                            elem->snort_rule_file_ids_cnt);
                    for (j = 0; j < elem->snort_rule_file_ids_cnt; j++)
                    {
                        fprintf(fp, "%d, ", elem->snort_rule_file_ids[j]);
                    }
                    fprintf(fp, "\n");
                    fprintf(fp, "#Original fp: %s\n", elem->pmd->orig_pattern);
                    if (elem->dup_flag == 0)
                    {
                        fprintf(fp, "%d, %s\n", elem->fp_id, elem->pattern);
                    }
                    else
                    {
                        fprintf(fp, "#This is a duplicate pattern\n");
                    }
                    elem = elem->next;
                }
            }
        }
        subsets_1g = subsets_1g->next;
    }
    fprintf(fp, "#total non-duplicate fp count : %d\n", tics_total_fp_cnt);
    fprintf(fp, "#total duplicate fp count : %d\n", tics_total_duplicate_fp_cnt);
    fprintf(fp, "#total subset count : %d\n", tics_total_subset_cnt);
    fclose(tics_rule_file_handle);
    fp = NULL;
    tics_rule_file_handle = NULL;
    return (0);
}

int tics_generate_t2s_psb_id_map()
{
    uint32_t i = 0;
    tics_subsets_1g_t *subsets_1g = tics_subsets;
    tics_fp_subset_t *subset = NULL;
    tics_fp_elem_t *elem = NULL;
    t2s_psb_id_map_t tmp;

    if(tics_subsets == NULL)
    {
        printf("tics_subsets is NULL in %s\n", __FUNCTION__);
        return (-1);
    }
    while (subsets_1g)
    {
        for (i = 0; i < PM_TYPE_MAX; i++)
        {
            subset = subsets_1g->subsets[i];
            if (subset)
            {
                elem = subset->fp_elem;
                /* We should remove the duplicate fp in the same subset */
                while (elem)
                {
                    if (elem->dup_flag == 0)
                    {
                        tmp.tics_fp_elem = elem;
                        tmp.pg = subsets_1g->pg;
                        tmp.pm_type = PmType(i);
                        tmp.tics_subset_id = subset->fp_subset_id;
                        t2s_psb_id_map.push_back(tmp);
                    }
                    elem = elem->next;
                }
            }
        }
        subsets_1g = subsets_1g->next;
    }
    return (0);
}

void print_t2s_psb_id_map()
{
    uint32_t i = 0;
    uint32_t j = 0;
    for (i = 0; i < tics_total_fp_cnt; i++)
    {
        printf("tics_fp_id = %d:\n"
               "pm_type = %d, "
               "port_group = %p, "
               "tics_subset_id = %d, "
               "snort_fp_id_cnt = %d, (",
               i + 1,
               t2s_psb_id_map[i].pm_type,
               t2s_psb_id_map[i].pg,
               t2s_psb_id_map[i].tics_subset_id,
               t2s_psb_id_map[i].tics_fp_elem->snort_add_seqs_cnt);
        for (j = 0; j < t2s_psb_id_map[i].tics_fp_elem->snort_add_seqs_cnt; j++)
        {
            printf("%d, ", t2s_psb_id_map[i].tics_fp_elem->snort_add_seqs[j]);
        }
        printf(")\n");
        printf("--Its pattern str: %s\n", t2s_psb_id_map[i].tics_fp_elem->pattern);
    }
}

/*
 *  Analyse each pattern and transform into the RXP rules format:
 *  1. Change all non-alphanumeric characters to hex e.g. * to \x2A
 *  2. Change all | ... | sequences to RegEx compatible format e.g.
 *     | 2A 0B 12 | to \x2A\x0B\x12
 *
 */
int ChangeFpPatternFormat(const char *fast_pattern,
                          char *transformed_fast_pattern,
                          uint16_t *transformed_fp_len)
{
    if ((!fast_pattern) || (!transformed_fast_pattern) || (!transformed_fp_len))
    {
        printf("Error: NULL ptr is used in %s\n", __FUNCTION__);
        return (-1);
    }
    int size=strlen(fast_pattern);
    char delimited_hex[5];
    memset(delimited_hex, 0, 5);
    int ti=0;
    int i=0;
    uint16_t fpl = 0;
    int vertical_bar_group_started=0;

    for(i=0;i<size;i++)
    {
        if((i==0 || i==size-1) && fast_pattern[i]== '\"')
        {
            continue;
        }
        if(!vertical_bar_group_started)
        {
            if(isalnum(fast_pattern[i]))
            {
                fpl++;
                transformed_fast_pattern[ti++] = fast_pattern[i];
            }
            else if(fast_pattern[i]=='|')
            {
                vertical_bar_group_started=1;
                continue;
            }
            else
            {
                fpl++;
                sprintf(delimited_hex, "\\x%02X", fast_pattern[i]);
                strcat(transformed_fast_pattern, delimited_hex);
                ti+=4;
            }
        }
        else
        {
            if(isxdigit(fast_pattern[i]))
            {
                if(i+1<size)
                {
                    if(fast_pattern[i+1] == ' ')
                    {
                        if(i+2<size)
                        {
                            fpl++;
                            sprintf(delimited_hex, "\\x%c%c", fast_pattern[i], fast_pattern[i+2]);
                            i++;
                        }
                        else
                        {
                            return(-1);
                        }
                    }
                    else
                    {
                        fpl++;
                        sprintf(delimited_hex, "\\x%c%c", fast_pattern[i],fast_pattern[i+1]);
                    }
                    i++;
                    strcat(transformed_fast_pattern, delimited_hex);
                    ti+=4;
                }
                else
                {
                    /* invalid fast pattern as hex digits must occur
                     * in pairs between vertical bars and be terminated */
                    return (-1);
                }
            }
            else if(isblank(fast_pattern[i]))
            {
                /* eat any whitespace */
                continue;
            }
            else if(fast_pattern[i]=='|')
            {
                vertical_bar_group_started=0;
                continue;
            }
            else
            {
                /* invalid fast pattern as only hex digits
                 * can occur between vertical bars */
                return (-1);
            }
        }
    }
    *transformed_fp_len = fpl;
    return (0);
}

int TicsGenerateFpPattern(const char *orig_pattern,
                          char*& tics_fp_pattern,
                          uint16_t& tics_fp_len)
{
    if (!orig_pattern)
    {
        printf("Null ptr in %s\n", __FUNCTION__);
        return (-1);
    }
    /* using 4096 for this as snort sets its maximum length for a
     * fast pattern string to 1024. Worst case we will use 4x
     * bytes when it is transformed */
    tics_fp_pattern = (char *)calloc(4096, sizeof(char));
    if (!tics_fp_pattern)
    {
        printf("Error: tics-fp-pattern allocation failed in %s\n", __FUNCTION__);
        return (-1);
    }

    if (ChangeFpPatternFormat(orig_pattern, tics_fp_pattern, &tics_fp_len) != 0)
    {
        printf("Error: tics fp pattern change format failure in %s\n", __FUNCTION__);
        return (-1);
    }
    return (0);
}

#endif /* TICS_GENERATE_RULE_FILE */

#ifdef TICS_USE_RXP_MATCH

int tics_dpdk_init(unsigned rxp_port_id,
                   unsigned rxp_num_queues)
{
    if (rxp_num_queues > MAX_NUMBER_QUEUES)
    {
        printf("Error: TICS The number of queues cannot exceed %u (value inserted %u)\n",MAX_NUMBER_QUEUES,rxp_num_queues);
        return (-1);
    }
    else if (rxp_num_queues == 0)
    {
        printf("Error: TICS The number of queues cannot be %u\n",rxp_num_queues);
        return (-1);
    }

#ifdef TICS_USE_LOAD_BALANCE
        int i = 0;
        int start_offset = 0;
        int end_offset = 0;
        int cp_cnt = 0;
        char *tmp_str;
        char * & orig_str = SnortConfig::get_dpdk_eal_cmd_cstr();
        int & data_port_cnt = SnortConfig::get_dpdk_data_port_cnt();
        int dpdk_argc = 4 + data_port_cnt;
        char **dpdk_cmd = (char **)malloc(sizeof(char *) * dpdk_argc);
        if (!dpdk_cmd)
        {
            fprintf(stdout, "%s: Couldn't allocate memory for the dpdk_cmd!", __FUNCTION__);
            exit (-1);
        }
        dpdk_cmd[0] = strdup("snort");
        dpdk_cmd[1] = strdup("-c");
        dpdk_cmd[2] = strdup("1");
        for (i = 0; i < data_port_cnt; i++)
        {
            if (i == 0)
            {
                start_offset = 0;
            }
            tmp_str = strstr(orig_str + start_offset + 2, "--");
            if (tmp_str)
            {
                end_offset = (int)(tmp_str - orig_str);
                cp_cnt = end_offset - start_offset;
            }
            else
            {
                cp_cnt = strlen(orig_str) - start_offset;
            }
            dpdk_cmd[3 + i] = strndup(orig_str + start_offset, cp_cnt);
            start_offset = end_offset;
        }
        dpdk_cmd[dpdk_argc - 1] = strdup("--");
        for (i = 0; i < dpdk_argc; i++)
        {
            fprintf(stdout, "dpdk cmd arg [%d]: %s\n", i, dpdk_cmd[i]);
        }

        if ((rte_eal_init(dpdk_argc, dpdk_cmd)) < 0)
        {
            fprintf(stdout, "%s: Invalid EAL arguments!\n", __FUNCTION__);
            exit (-1);
        }
#else /* TICS_USE_LOAD_BALANCE */
        char *dpdk_argv[4];
        dpdk_argv[0] = strdup("snort");
        dpdk_argv[1] = strdup("-c");
        dpdk_argv[2] = strdup("1");
        dpdk_argv[3] = strdup("--");
        if ((rte_eal_init(4, dpdk_argv)) < 0)
        {
            fprintf(stdout, "%s: Invalid EAL arguments!\n", __FUNCTION__);
            exit (-1);
        }
#endif /* TICS_USE_LOAD_BALANCE */
    /*
     * Initialize the DPDK port used to communicate with the RXP.
     */
    if (rxp_port_init(rxp_port_id, rxp_num_queues, 1))
    {
        printf("Error: rxp_port_init() failed\n");
        return (-1);
    }
    /*
     * Initialize (reset) the RXP core.
     */
    else if (rxp_init(rxp_port_id))
    {
        printf("Error: rxp_init() failed\n");
        return (-1);
    }

    return (0);
}

int tics_program_rxp_rule_file(unsigned rxp_port_id,
                               unsigned rxp_queue_id)
{
    char rxpc_cmd_str[1024];

    sprintf(rxpc_cmd_str, "rxpc -f %s -o %s/synthetic --ptpb 0 -F -i",
            TICS_RULE_FILE_PATH, TICS_ROF_FILE_DIR_PATH);
    if (system(rxpc_cmd_str))
    {
        printf("Error: failed to exec rxpc in %s\n", __FUNCTION__);
        return (-1);
    }

    if (rxp_program_rules_memories(rxp_port_id, rxp_queue_id,
                                   TICS_ROF_FILE_DIR_PATH"/synthetic.rof"))
    {
        printf("Error: failed to program rxp rule memeory %s\n", __FUNCTION__);
        return (-1);
    }
    else if (rxp_enable(rxp_port_id))
    {
        printf("Error: rxp enable failed %s\n", __FUNCTION__);
        return (-1);
    }
    return (0);
}

#endif /* TICS_USE_RXP_MATCH */

#if defined(TICS_USE_RXP_MATCH) && defined(TICS_GENERATE_RXP_JOB_FILE)
/*
 * Generate a rxp job file
 * It is just for debug purpose
 */
int TicsGenerateRxpJobFile(const rxp_job_desc_t * rxp_job_desc_ptr,
                           const unsigned char * rxp_job_data_ptr)
{
    FILE * fp= NULL;
    DIR * dir = NULL;
    char file_name[32];
    int i = 0;

    if (!rxp_job_desc_ptr)
    {
        fprintf(stdout,"Error: rxp job descriptor is NULL!\n");
        return (-1);
    }
    if (!rxp_job_data_ptr)
    {
        fprintf(stdout,"Error: rxp job data is NULL!\n");
        return (-1);
    }

    /* Make a dir for job files */
    if (! (dir = opendir("./jobset")))
    {
        if (mkdir("./jobset", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH))
        {
            fprintf(stdout,"Error: cannot create jobset directory!\n");
            perror("System Error Info: ");
            return (-1);
        }
    }
    /* Close a dir */
    closedir(dir);

    /* For job descriptor file */
    sprintf(file_name, "./jobset/job_0x%08x.des", rxp_job_desc_ptr->job_id);
    if (! (fp = fopen(file_name, "w")))
    {
        fprintf(stdout,"Error: job descriptor file cannot be opened!\n");
        perror("System Error Info: ");
        return (-1);
    }

    fprintf(fp, "# job_id,flow_id,ctrl,job_length,subset_id_0,subset_id_1,subset_id_2,subset_id_3\n");
    fprintf(fp, "%d,%d,%d,%d,%d,%d,%d,%d\n",
            rxp_job_desc_ptr->job_id,
            rxp_job_desc_ptr->flow_id,
            rxp_job_desc_ptr->ctrl,
            rxp_job_desc_ptr->job_length,
            rxp_job_desc_ptr->subset_id_0,
            rxp_job_desc_ptr->subset_id_1,
            rxp_job_desc_ptr->subset_id_2,
            rxp_job_desc_ptr->subset_id_3);
    fclose(fp);

    /* For job pkt file */
    sprintf(file_name, "./jobset/job_0x%08x.pkt", rxp_job_desc_ptr->job_id);
    if (! (fp = fopen(file_name, "w")))
    {
        fprintf(stdout,"Error: job pkt file cannot be opened!\n");
        perror("System Error Info: ");
        return (-1);
    }
    for (i = 0; i < rxp_job_desc_ptr->job_length; i++)
    {
        fprintf(fp, "%1x%1x", ((rxp_job_data_ptr[i] & 0xf0) >> 4), (rxp_job_data_ptr[i] & 0x0f));
    }
    fclose(fp);

    fp = NULL;
    return (0);
}
#endif /* TICS_USE_RXP_MATCH && TICS_GENERATE_RXP_JOB_FILE */


#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tics.h"

#ifdef TICS_USE_RXP_MATCH

THREAD_LOCAL PMQ rxp_response_queues[PM_TYPE_MAX][TICS_PORT_GROUP_LIMIT];
THREAD_LOCAL bool rxp_response_queues_status[PM_TYPE_MAX];
THREAD_LOCAL uint32_t global_rxp_job_id = 0;
THREAD_LOCAL uint16_t current_subsets[PM_TYPE_MAX][TICS_PORT_GROUP_LIMIT];
THREAD_LOCAL int count_subsets[PM_TYPE_MAX];

void tics_get_sid(PortGroup* group,
                  int count_subsets[],
                  uint16_t current_subsets[][TICS_PORT_GROUP_LIMIT])
{
    int PM_TYPE;
    for (PM_TYPE = PM_TYPE_PKT; PM_TYPE < PM_TYPE_MAX; PM_TYPE++)
    {
        Mpse* so;
        so = group->mpse[PM_TYPE];
        if ( so && so->get_pattern_count() > 0 )
        {
            current_subsets[PM_TYPE][count_subsets[PM_TYPE]++] = group->tics_subset_id[PM_TYPE];
        }
    }
}

bool fpWriteAllRxpJobFiles(const unsigned char * T,
                           int n,
                           uint16_t * current_subsets,
                           int count_subset,
                           int PM_TYPE)
{
    uint16_t current_job_length = 0;
    int bytes_processed = 0;

    while (n > 0)
    {
        if (n > TICS_MAX_RXP_JOB_LENGTH)
        {
            n -= (TICS_MAX_RXP_JOB_LENGTH - max_tics_pattern_len);
            current_job_length = TICS_MAX_RXP_JOB_LENGTH;
        }
        else
        {
            current_job_length = n;
            n = 0;
        }

        if (n < 0)
        {
            fprintf(stdout,"Error: TICS The job size value (n = %d) is negative\n", n);
            exit (-1);
        }

        global_rxp_job_id ++;

        rxp_job_desc_t rxp_job_desc = {.job_id = global_rxp_job_id,
                                       .flow_id = 0,
                                       .ctrl = 0,
                                       .job_length = current_job_length,
                                       .subset_id_0 = count_subset>0 ? current_subsets[0] : (uint16_t)0,
                                       .subset_id_1 = count_subset>1 ? current_subsets[1] : current_subsets[0],
                                       .subset_id_2 = count_subset>2 ? current_subsets[2] : current_subsets[0],
                                       .subset_id_3 = count_subset>3 ? current_subsets[3] : current_subsets[0]};

        if (fpScanJob(&rxp_job_desc, T+bytes_processed, PM_TYPE))
        {
            fprintf(stdout,"#job_%08x scan job failed\n", global_rxp_job_id);
            return false;
        }

        bytes_processed += (current_job_length - max_tics_pattern_len);
    }
    return true;
}

int fpScanJob(const rxp_job_desc_t * rxp_job_desc_ptr,
              const uint8_t * rxp_job_data_ptr,
              int PM_TYPE)
{
    struct rte_mbuf* buf;
    unsigned jobs_sent;
    unsigned jobs_pending;
    unsigned num_rx_pkts = 0;
    struct rte_mbuf *pkts_burst[32];
    struct rxp_response_data resp_data;
    uint32_t i;
    int rxp_port_id = 0;
    #ifdef TICS_USE_LOAD_BALANCE
        rxp_port_id = SnortConfig::get_dpdk_data_port_cnt();
    #endif /* TICS_USE_LOAD_BALANCE */

    /*Get the snort instance id to associate it with the rxp queue*/
    unsigned rxp_queue_id=get_instance_id();

    if(rxp_queue_id > 7)
    {
        fprintf(stdout,"Error: TICS rxp_queue_id value is invalid (%d) must fall within the range 0 - 7\n",rxp_queue_id);
        exit(-1);
    }

    if (!rxp_job_desc_ptr)
    {
        fprintf(stdout,"Error: TICS rxp job descriptor is NULL!\n");
        return (-1);
    }
    if (!rxp_job_data_ptr)
    {
        fprintf(stdout,"Error: TICS rxp job data is NULL!\n");
        return (-1);
    }
    if (rxp_prepare_job(rxp_port_id,
                       rxp_job_desc_ptr->job_id,
                       const_cast<uint8_t *>(rxp_job_data_ptr),
                       rxp_job_desc_ptr->job_length,
                       rxp_job_desc_ptr->ctrl,
                       rxp_job_desc_ptr->subset_id_0,
                       rxp_job_desc_ptr->subset_id_1,
                       rxp_job_desc_ptr->subset_id_2,
                       rxp_job_desc_ptr->subset_id_3,
                       &buf))
    {
        fprintf(stdout,"Error: TICS rxp_prepare_job() failed\n");
        return (-1);
    }

    if (rxp_enqueue_job(rxp_port_id, rxp_queue_id, buf))
    {
        fprintf(stdout,"Error: TICS rxp_enqueue_job() failed\n");
        return (-1);
    }

    if (rxp_dispatch_jobs(rxp_port_id, rxp_queue_id, &jobs_sent, &jobs_pending))
    {
        fprintf(stdout,"Error: TICS rxp_dispatch_jobs() failed\n");
        return (-1);
    }

    while (num_rx_pkts == 0)
    {
        if (rxp_get_responses(rxp_port_id, rxp_queue_id, pkts_burst, 1, &num_rx_pkts))
        {
            fprintf(stdout,"Error: TICS rxp_get_responses() failed\n");
            return (-1);
        }
    }

    if (rxp_get_response_data(pkts_burst[0], &resp_data))
    {
        fprintf(stdout,"Error: TICS rxp_get_response_data() failed\n");
        rxp_free_buffer(pkts_burst[0]);
        return (-1);
    }

    if (resp_data.match_count != 0)
    {
        if(resp_data.match_count >= TICS_RXP_MATCH_LIMIT || resp_data.detected_match_count > TICS_RXP_MATCH_LIMIT)
        {
            pc.tics_match_limit_reach++;
            fprintf(stdout,"Error: TICS RXP ERROR match count bigger as 64 (resp_data.match_count %u, detected value %u)\n", resp_data.match_count, resp_data.detected_match_count);
            rxp_free_buffer(pkts_burst[0]);
            return (-1);
        }

        if(resp_data.detected_match_count >= TICS_RXP_MATCH_LIMIT_DETECTED)
        {
            pc.tics_match_limit_reach++;
            fprintf(stdout,"Error: TICS RXP ERROR detected match count bigger as 256 (resp_data.match_count %u)\n",resp_data.detected_match_count);
            rxp_free_buffer(pkts_burst[0]);
            return (-1);
        }

        rxp_response_queues_status[PM_TYPE]=true;
        for (i = 0; i < resp_data.match_count; i++)
        {
            int tics_rule_id = resp_data.match_data[i].rule_id;
            int port_group = t2s_psb_id_map[tics_rule_id - 1].tics_fp_elem->tics_pg_type;
            PMQ *tmp_resps = &(rxp_response_queues[PM_TYPE][port_group]);
            uint32_t j = 0;

            tmp_resps->id[tmp_resps->index] = resp_data.match_data[i].rule_id;
            tmp_resps->from[tmp_resps->index] = resp_data.match_data[i].start_ptr;
            tmp_resps->to[tmp_resps->index] = resp_data.match_data[i].start_ptr +
                                              resp_data.match_data[i].length;
            tmp_resps->index++;
        }
    }
    else
    {
        rxp_response_queues_status[PM_TYPE]=true;
    }

    rxp_free_buffer(pkts_burst[0]);

    return (0);
}

void tics_reset_rxp_resp_queue()
{
    uint32_t i = 0, j = 0;
    for (i = 0; i < PM_TYPE_MAX; i++)
    {
        for (j = 0; j < TICS_PORT_GROUP_LIMIT; j++)
        {
            rxp_response_queues[i][j].index = 0;
        }
        rxp_response_queues_status[i] = false;
    }
}

void tics_reset_sid(int count_subsets[],
                    uint16_t current_subsets[][TICS_PORT_GROUP_LIMIT])
{
    uint32_t i = 0;
    uint32_t j = 0;
    for (i = PM_TYPE_PKT; i < PM_TYPE_MAX; i++)
    {
        count_subsets[i] = 0;
        for (j = 0; j < TICS_PORT_GROUP_LIMIT; j++)
        {
            current_subsets[i][j] = 0;
        }
    }
}

void tics_get_tcp_sid(int count_subsets[],
                      uint16_t current_subsets[][TICS_PORT_GROUP_LIMIT],
                      Packet *p,
                      PortGroup **src,
                      PortGroup **dst,
                      PortGroup **any)
{
    if (!prmFindRuleGroupTcp(snort_conf->prmTcpRTNX, p->ptrs.dp, p->ptrs.sp, src, dst, any))
        return;
    DebugFormat(DEBUG_ATTRIBUTE,
        "fpEvalHeaderTcp: sport=%d, dport=%d, src:%p, dst:%p, any:%p\n",
        p->ptrs.sp,p->ptrs.dp,(void*)(*src),(void*)(*dst),(void*)(*any));

    if (*dst)
    {
        tics_get_sid(*dst, count_subsets, current_subsets);
    }
    if (*src)
    {
        tics_get_sid(*src, count_subsets, current_subsets);
    }
    if (*any)
    {
        tics_get_sid(*any, count_subsets, current_subsets);
    }
}

void tics_get_udp_sid(int count_subsets[],
                      uint16_t current_subsets[][TICS_PORT_GROUP_LIMIT],
                      Packet *p,
                      PortGroup **src,
                      PortGroup **dst,
                      PortGroup **any)
{
    if (!prmFindRuleGroupUdp(snort_conf->prmUdpRTNX, p->ptrs.dp, p->ptrs.sp, src, dst, any))
        return;
    DebugFormat(DEBUG_ATTRIBUTE,
        "fpEvalHeaderUdp: sport=%d, dport=%d, src:%p, dst:%p, any:%p\n",
        p->ptrs.sp,p->ptrs.dp,(void*)(*src),(void*)(*dst),(void*)(*any));

    if (*dst)
    {
        tics_get_sid(*dst, count_subsets, current_subsets);
    }
    if (*src)
    {
        tics_get_sid(*src, count_subsets, current_subsets);
    }
    if (*any)
    {
        tics_get_sid(*any, count_subsets, current_subsets);
    }
}

void tics_get_ip_sid(int count_subsets[],
                     uint16_t current_subsets[][TICS_PORT_GROUP_LIMIT],
                     PortGroup **ip_group,
                     PortGroup **any)
{
    if (!prmFindRuleGroupIp(snort_conf->prmIpRTNX, ANYPORT, ip_group, any))
        return;

    if ( snort_conf->fast_pattern_config->get_debug_print_nc_rules() )
        LogMessage("fpEvalHeaderIp: ip_group=%p, any=%p\n", (void*)(*ip_group), (void*)(*any));

    if (*ip_group)
    {
        tics_get_sid(*ip_group, count_subsets, current_subsets);
    }
    if (*any)
    {
        tics_get_sid(*any, count_subsets, current_subsets);
    }
}

void tics_get_icmp_sid(int count_subsets[],
                       uint16_t current_subsets[][TICS_PORT_GROUP_LIMIT],
                       Packet *p,
                       PortGroup **type,
                       PortGroup **any)
{
    if (!prmFindRuleGroupIcmp(snort_conf->prmIcmpRTNX, p->ptrs.icmph->type, type, any))
        return;

    if (*type)
    {
        tics_get_sid(*type, count_subsets, current_subsets);
    }
    if (*any)
    {
        tics_get_sid(*any, count_subsets, current_subsets);
    }
}

void tics_get_svc_sid(int count_subsets[],
                      uint16_t current_subsets[][TICS_PORT_GROUP_LIMIT],
                      Packet *p,
                      int proto,
                      PortGroup **file,
                      PortGroup **svc)
{
    int16_t proto_ordinal = p->get_application_protocol();
    DebugFormat(DEBUG_ATTRIBUTE, "proto_ordinal=%d\n", proto_ordinal);

    if (proto_ordinal > 0)
    {
        if (p->is_from_server()) /* to cli */
        {
            DebugMessage(DEBUG_ATTRIBUTE, "pkt_from_server\n");

            *svc = snort_conf->sopgTable->get_port_group(proto, false, proto_ordinal);
            *file = snort_conf->sopgTable->get_port_group(proto, false, SNORT_PROTO_FILE);
        }

        if (p->is_from_client()) /* to srv */
        {
            DebugMessage(DEBUG_ATTRIBUTE, "pkt_from_client\n");

            *svc = snort_conf->sopgTable->get_port_group(proto, true, proto_ordinal);
            *file = snort_conf->sopgTable->get_port_group(proto, true, SNORT_PROTO_FILE);
        }

        DebugFormat(DEBUG_ATTRIBUTE,
            "fpEvalHeaderSvc:targetbased-ordinal-lookup: "
            "sport=%d, dport=%d, proto_ordinal=%d, proto=%d, src:%p, "
            "file:%p\n",p->ptrs.sp,p->ptrs.dp,proto_ordinal,proto,(void*)(*svc),(void*)(*file));
    }

    if (*file)
    {
        tics_get_sid(*file, count_subsets, current_subsets);
    }
    if (*svc)
    {
        tics_get_sid(*svc, count_subsets, current_subsets);
    }
}

bool tics_rxp_process(Packet* p,
                      char ip_rule,
                      int count_subsets[],
                      uint16_t current_subsets[][TICS_PORT_GROUP_LIMIT])
{
    bool rxp_evaluated = false;

    const uint8_t* tmp_payload;
    uint16_t tmp_dsize;
    FastPatternConfig *fp = snort_conf->fast_pattern_config;
    int8_t curr_ip_layer = 0;

    if (ip_rule)
    {
        tmp_payload = p->data;
        tmp_dsize = p->dsize;
        if (layer::set_outer_ip_api(p, p->ptrs.ip_api, curr_ip_layer))
        {
            p->data = p->ptrs.ip_api.ip_data();
            p->dsize = p->ptrs.ip_api.pay_len();
        }
    }
    if (do_detect_content)
    {
        if (fp->get_stream_insert() || !(p->packet_flags & PKT_STREAM_INSERT))
        {
            int PM_TYPE;
            for (PM_TYPE = PM_TYPE_PKT; PM_TYPE < PM_TYPE_MAX; PM_TYPE++)
            {
                bool user_mode = snort_conf->sopgTable->user_mode;
                Inspector* gadget = p->flow ? p->flow->gadget : nullptr;

                if (count_subsets[PM_TYPE] && PM_TYPE == PM_TYPE_PKT)
                {
                    if ((!user_mode) and p->data and p->dsize)
                    {
                        uint16_t pattern_match_size = p->dsize;

                        if (IsLimitedDetect(p) && (p->alt_dsize < p->dsize))
                        {
                            pattern_match_size = p->alt_dsize;
                        }
                    #ifdef TICS_USE_HYPERSCAN_RXP_HYBRID_MATCH
                        if (pattern_match_size && (pattern_match_size > TICS_MAX_RXP_PACKET_LENGTH))
                    #else //TICS_USE_HYPERSCAN_RXP_HYBRID_MATCH
                        if (pattern_match_size)
                    #endif //TICS_USE_HYPERSCAN_RXP_HYBRID_MATCH
                        {
                            rxp_evaluated = fpWriteAllRxpJobFiles(p->data,
                                pattern_match_size, current_subsets[PM_TYPE],
                                count_subsets[PM_TYPE], PM_TYPE);

                            /*If the job analysis return and error we can't use the responses*/
                            if(rxp_evaluated == false)
                            {
                                rxp_response_queues_status[PM_TYPE]=false;
                                pc.tics_scan_errors++;
                            }
                            else
                            {
                                pc.tics_pkt_searches++;
                                p->is_cooked()? pc.tics_cooked_searches++ : pc.tics_raw_searches++;
                                pc.tics_scan_pm_type_pkt_cnt += count_subsets[PM_TYPE];
                            }
                        }
                        else
                        {
                            pc.tics_rxp_len_err_searches++;
                        }
                    }
                }
                else if (count_subsets[PM_TYPE] && (PM_TYPE != PM_TYPE_FILE) && (!user_mode) and gadget)
                {

                    InspectionBuffer buf;
                    bool get_fp_buf_return = false;

                    if (PM_TYPE == PM_TYPE_KEY)
                    {
                        get_fp_buf_return = gadget->get_fp_buf(buf.IBT_KEY, p, buf);
                    }
                    else if (PM_TYPE == PM_TYPE_HEADER)
                    {
                        get_fp_buf_return = gadget->get_fp_buf(buf.IBT_HEADER, p, buf);
                    }
                    else if (PM_TYPE == PM_TYPE_BODY)
                    {
                        get_fp_buf_return = gadget->get_fp_buf(buf.IBT_BODY, p, buf);
                    }
                    // FIXIT-L PM_TYPE_ALT will never be set unless we add
                    // norm_data keyword or telnet, rpc_decode, smtp keywords
                    // until then we must use the standard packet mpse
                    else if (PM_TYPE == PM_TYPE_ALT)
                    {
                        get_fp_buf_return = gadget->get_fp_buf(buf.IBT_ALT, p, buf);
                    }

#ifdef TICS_USE_HYPERSCAN_RXP_HYBRID_MATCH
                    if (get_fp_buf_return && buf.data &&
                            (buf.len > TICS_MAX_RXP_PACKET_LENGTH))
#else /* TICS_USE_HYPERSCAN_RXP_HYBRID_MATCH */
                    if (get_fp_buf_return && buf.data)
#endif /* TICS_USE_HYPERSCAN_RXP_HYBRID_MATCH */
                    {
                        rxp_evaluated = fpWriteAllRxpJobFiles(buf.data, buf.len,
                                current_subsets[PM_TYPE], count_subsets[PM_TYPE],
                                PM_TYPE);

                        /*If the job analysis return and error we can't use the responses*/
                        if(rxp_evaluated == false)
                        {
                            rxp_response_queues_status[PM_TYPE]=false;
                            pc.tics_scan_errors++;
                        }
                        else
                        {
                             if (PM_TYPE == PM_TYPE_KEY)
                            {
                                pc.tics_key_searches++;
                                pc.tics_scan_pm_type_key_cnt += count_subsets[PM_TYPE];
                            }
                            else if (PM_TYPE == PM_TYPE_HEADER)
                            {
                                pc.tics_header_searches++;
                                pc.tics_scan_pm_type_header_cnt += count_subsets[PM_TYPE];
                            }
                            else if (PM_TYPE == PM_TYPE_BODY)
                            {
                                pc.tics_body_searches++;
                                pc.tics_scan_pm_type_body_cnt += count_subsets[PM_TYPE];
                            }
                            else if (PM_TYPE == PM_TYPE_ALT)
                            {
                                pc.tics_alt_searches++;
                                pc.tics_scan_pm_type_alt_cnt += count_subsets[PM_TYPE];
                            }
                        }
                    }
                    else
                    {
                        pc.tics_rxp_len_err_searches++;
                    }
                }
                //else if (count_subsets[PM_TYPE] && (PM_TYPE == PM_TYPE_FILE) &&
                //        (!user_mode or type > 0))
                else if (count_subsets[PM_TYPE] && (PM_TYPE == PM_TYPE_FILE) &&
                        (!user_mode))
                {
                /* FIXIT-M file data should be obtained from
                   inspector gadget as is done with SEARCH_BUFFER
                   gadget->get_fp_buf(buf.IBT_FILE, p, buf)

                   rxp_evaluated = fpWriteAllRxpJobFiles(buf.data, buf.len,
                            current_subsets[PM_TYPE], count_subsets[PM_TYPE],
                            PM_TYPE);
                */
                #ifdef TICS_USE_HYPERSCAN_RXP_HYBRID_MATCH
                    if (g_file_data.len && (g_file_data.len > TICS_MAX_RXP_PACKET_LENGTH))
                #else //TICS_USE_HYPERSCAN_RXP_HYBRID_MATCH
                    if (g_file_data.len)
                #endif //TICS_USE_HYPERSCAN_RXP_HYBRID_MATCH
                    {
                        rxp_evaluated = fpWriteAllRxpJobFiles(g_file_data.data,
                                g_file_data.len, current_subsets[PM_TYPE],
                                count_subsets[PM_TYPE], PM_TYPE);

                        /*If the job analysis return and error we can't use the responses*/
                        if(rxp_evaluated == false)
                        {
                            rxp_response_queues_status[PM_TYPE]=false;
                            pc.tics_scan_errors++;
                        }
                        else
                        {
                            pc.tics_file_searches++;
                            pc.tics_scan_pm_type_file_cnt += count_subsets[PM_TYPE];
                        }
                    }
                    else
                    {
                        pc.tics_rxp_len_err_searches++;
                    }
                }
            }
        }
    }

    /*Restore the values of the packet*/
    if (ip_rule)
    {
        p->data = tmp_payload;
        p->dsize = tmp_dsize;
    }

    return rxp_evaluated;
}

void tics_scan_pkt(Packet* p)
{
    PortGroup *src = nullptr, *dst = nullptr, *any = nullptr;
    PortGroup *ip_group = nullptr;
    PortGroup *type = nullptr;
    PortGroup *svc = nullptr, *file = nullptr;

    tics_reset_rxp_resp_queue();
    tics_reset_sid(count_subsets, current_subsets);

    if (p->type() == PktType::IP)
    {
        tics_get_ip_sid(count_subsets, current_subsets, &ip_group, &any);
        tics_get_svc_sid(count_subsets, current_subsets, p, SNORT_PROTO_IP, &file, &svc);
    }
    else if (p->type() == PktType::ICMP)
    {
        tics_get_icmp_sid(count_subsets, current_subsets, p, &type, &any);
        tics_get_svc_sid(count_subsets, current_subsets, p, SNORT_PROTO_ICMP, &file, &svc);
    }
    else if (p->type() == PktType::TCP)
    {
        tics_get_tcp_sid(count_subsets, current_subsets, p, &src, &dst, &any);
        tics_get_svc_sid(count_subsets, current_subsets, p, SNORT_PROTO_TCP, &file, &svc);
    }
    else if (p->type() == PktType::UDP)
    {
        tics_get_udp_sid(count_subsets, current_subsets, p, &src, &dst, &any);
        tics_get_svc_sid(count_subsets, current_subsets, p, SNORT_PROTO_UDP, &file, &svc);
    }
    else if (p->type() == PktType::PDU)
    {
        if (snort_conf->sopgTable->user_mode)
        {
            tics_get_svc_sid(count_subsets, current_subsets, p, SNORT_PROTO_USER, &file, &svc);
        }
        else if (p->proto_bits & PROTO_BIT__TCP)
        {
            tics_get_svc_sid(count_subsets, current_subsets, p, SNORT_PROTO_TCP, &file, &svc);
            if (!p->get_application_protocol() or !svc)
            {
                tics_get_tcp_sid(count_subsets, current_subsets, p, &src, &dst, &any);
            }
        }
        else if (p->proto_bits & PROTO_BIT__UDP)
        {
            tics_get_svc_sid(count_subsets, current_subsets, p, SNORT_PROTO_UDP, &file, &svc);
            if (!p->get_application_protocol() or !svc)
            {
                tics_get_udp_sid(count_subsets, current_subsets, p, &src, &dst, &any);
            }
        }
    }
    else if (p->type() == PktType::FILE)
    {
        tics_get_svc_sid(count_subsets, current_subsets, p, SNORT_PROTO_USER, &file, &svc);
    }
    else
    {
        return;
    }

    if (p->type() != PktType::IP)
    {
        tics_rxp_process (/*Packet*/ p, /*ip_rule*/ 0, count_subsets, current_subsets);
    }
    else
    {
        tics_rxp_process (/*Packet*/ p, /*ip_rule*/ 1, count_subsets, current_subsets);
    }
}

#endif /* TICS_USE_RXP_MATCH */


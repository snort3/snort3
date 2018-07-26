//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// config_api.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef CONFIG_API_H
#define CONFIG_API_H

#include "config_states/config_api.h"

namespace config
{
extern const ConvertMap* addressspace_agnostic_map;
extern const ConvertMap* alert_with_interface_name_map;
extern const ConvertMap* alertfile_map;
extern const ConvertMap* asn1_map;
extern const ConvertMap* autogenerate_preprocessor_decoder_rules_map;
extern const ConvertMap* binding_map;
extern const ConvertMap* bpf_file_map;
extern const ConvertMap* checksum_mode_map;
extern const ConvertMap* checksum_drop_map;
extern const ConvertMap* chroot_map;
extern const ConvertMap* classification_map;
extern const ConvertMap* cs_dir_map;
extern const ConvertMap* daemon_map;
extern const ConvertMap* daq_map;
extern const ConvertMap* daq_dir_map;
extern const ConvertMap* daq_mode_map;
extern const ConvertMap* daq_var_map;
extern const ConvertMap* decode_data_link_map;
extern const ConvertMap* decode_esp_map;
extern const ConvertMap* default_rule_state_map;
extern const ConvertMap* detection_map;
extern const ConvertMap* detection_filter_map;
extern const ConvertMap* disable_attribute_reload_thread_map;
extern const ConvertMap* disable_decode_alerts_map;
extern const ConvertMap* disable_decode_drops_map;
extern const ConvertMap* disable_inline_init_failopen_map;
extern const ConvertMap* disable_ipopt_alerts_map;
extern const ConvertMap* disable_ipopt_drops_map;
extern const ConvertMap* disable_replace_map;
extern const ConvertMap* disable_tcpopt_alerts_map;
extern const ConvertMap* disable_tcpopt_drops_map;
extern const ConvertMap* disable_tcpopt_experimental_alerts_map;
extern const ConvertMap* disable_tcpopt_experimental_drops_map;
extern const ConvertMap* disable_tcpopt_obsolete_alerts_map;
extern const ConvertMap* disable_tcpopt_obsolete_drops_map;
extern const ConvertMap* disable_tcpopt_ttcp_alerts_map;
extern const ConvertMap* disable_ttcp_alerts_map;
extern const ConvertMap* disable_ttcp_drops_map;
extern const ConvertMap* dirty_pig_map;
extern const ConvertMap* dump_chars_only_map;
extern const ConvertMap* dump_dynamic_rules_path_map;
extern const ConvertMap* dump_payload_map;
extern const ConvertMap* dump_payload_verbose_map;
extern const ConvertMap* enable_decode_drops_map;
extern const ConvertMap* enable_decode_oversized_alerts_map;
extern const ConvertMap* enable_decode_oversized_drops_map;
extern const ConvertMap* enable_deep_teredo_inspection_map;
extern const ConvertMap* enable_ipopt_drops_map;
extern const ConvertMap* enable_gtp_map;
extern const ConvertMap* enable_mpls_multicast_map;
extern const ConvertMap* enable_mpls_overlapping_ip_map;
extern const ConvertMap* enable_tcpopt_drops_map;
extern const ConvertMap* enable_tcpopt_experimental_drops_map;
extern const ConvertMap* enable_tcpopt_obsolete_drops_map;
extern const ConvertMap* enable_tcpopt_ttcp_drops_map;
extern const ConvertMap* enable_ttcp_drops_map;
extern const ConvertMap* event_filter_map;
extern const ConvertMap* event_queue_map;
extern const ConvertMap* event_trace_map;
extern const ConvertMap* file_map;
extern const ConvertMap* flexresp2_attempts_map;
extern const ConvertMap* flexresp2_interface_map;
extern const ConvertMap* flexresp2_memcap_map;
extern const ConvertMap* flexresp2_rows_map;
extern const ConvertMap* flowbits_size_map;
extern const ConvertMap* ignore_ports_map;
extern const ConvertMap* include_vlan_in_alerts_map;
extern const ConvertMap* interface_map;
extern const ConvertMap* layer2resets_map;
extern const ConvertMap* ipv6_frag_map;
extern const ConvertMap* log_ipv6_extra_data_map;
extern const ConvertMap* logdir_map;
extern const ConvertMap* max_attribute_hosts_map;
extern const ConvertMap* max_attribute_services_per_host_map;
extern const ConvertMap* max_ip6_extensions_map;
extern const ConvertMap* max_metadata_services_map;
extern const ConvertMap* max_mpls_labelchain_len_map;
extern const ConvertMap* mpls_payload_type_map;
extern const ConvertMap* min_ttl_map;
extern const ConvertMap* na_policy_mode_map;
extern const ConvertMap* new_ttl_map;
extern const ConvertMap* nolog_map;
extern const ConvertMap* nopcre_map;
extern const ConvertMap* no_promisc_map;
extern const ConvertMap* obfuscate_map;
extern const ConvertMap* order_map;
extern const ConvertMap* paf_max_map;
extern const ConvertMap* pcre_match_limit_map;
extern const ConvertMap* pcre_match_limit_recursion_map;
extern const ConvertMap* pkt_count_map;
extern const ConvertMap* ppm_map;
extern const ConvertMap* policy_id_map;
extern const ConvertMap* policy_uuid_map;
extern const ConvertMap* policy_mode_map;
extern const ConvertMap* profile_preprocs_map;
extern const ConvertMap* profile_rules_map;
extern const ConvertMap* protected_content_map;
extern const ConvertMap* quiet_map;
extern const ConvertMap* rate_filter_map;
extern const ConvertMap* react_map;
extern const ConvertMap* reference_map;
extern const ConvertMap* reference_net_map;
extern const ConvertMap* response_map;
extern const ConvertMap* set_gid_map;
extern const ConvertMap* set_uid_map;
extern const ConvertMap* show_year_map;
extern const ConvertMap* sidechannel_map;
extern const ConvertMap* snaplen_map;
extern const ConvertMap* so_rule_memcap_map;
extern const ConvertMap* stateful_map;
extern const ConvertMap* tagged_packet_limit_map;
extern const ConvertMap* threshold_map;
extern const ConvertMap* tunnel_verdicts_map;
extern const ConvertMap* umask_map;
extern const ConvertMap* utc_map;
extern const ConvertMap* verbose_map;
extern const ConvertMap* vlan_agnostic_map;

const std::vector<const ConvertMap*> config_api =
{
    addressspace_agnostic_map,
    alert_with_interface_name_map,
    alertfile_map,
    asn1_map,
    autogenerate_preprocessor_decoder_rules_map,
    binding_map,
    bpf_file_map,
    checksum_mode_map,
    checksum_drop_map,
    chroot_map,
    classification_map,
    cs_dir_map,
    daemon_map,
    daq_map,
    daq_dir_map,
    daq_mode_map,
    daq_var_map,
    decode_data_link_map,
    decode_esp_map,
    default_rule_state_map,
    detection_map,
    detection_filter_map,
    disable_attribute_reload_thread_map,
    disable_decode_alerts_map,
    disable_decode_drops_map,
    disable_inline_init_failopen_map,
    disable_ipopt_alerts_map,
    disable_ipopt_drops_map,
    disable_replace_map,
    disable_tcpopt_alerts_map,
    disable_tcpopt_drops_map,
    disable_tcpopt_experimental_alerts_map,
    disable_tcpopt_experimental_drops_map,
    disable_tcpopt_obsolete_alerts_map,
    disable_tcpopt_obsolete_drops_map,
    disable_tcpopt_ttcp_alerts_map,
    disable_ttcp_alerts_map,
    disable_ttcp_drops_map,
    dirty_pig_map,
    dump_chars_only_map,
    dump_dynamic_rules_path_map,
    dump_payload_map,
    dump_payload_verbose_map,
    enable_decode_drops_map,
    enable_decode_oversized_alerts_map,
    enable_decode_oversized_drops_map,
    enable_deep_teredo_inspection_map,
    enable_ipopt_drops_map,
    enable_gtp_map,
    enable_mpls_multicast_map,
    enable_mpls_overlapping_ip_map,
    enable_tcpopt_drops_map,
    enable_tcpopt_experimental_drops_map,
    enable_tcpopt_obsolete_drops_map,
    enable_tcpopt_ttcp_drops_map,
    enable_ttcp_drops_map,
    event_queue_map,
    event_filter_map,
    event_trace_map,
    file_map,
    flexresp2_attempts_map,
    flexresp2_interface_map,
    flexresp2_memcap_map,
    flexresp2_rows_map,
    flowbits_size_map,
    ignore_ports_map,
    include_vlan_in_alerts_map,
    interface_map,
    ipv6_frag_map,
    layer2resets_map,
    log_ipv6_extra_data_map,
    logdir_map,
    min_ttl_map,
    max_attribute_hosts_map,
    max_attribute_services_per_host_map,
    max_ip6_extensions_map,
    max_metadata_services_map,
    max_mpls_labelchain_len_map,
    mpls_payload_type_map,
    na_policy_mode_map,
    new_ttl_map,
    nolog_map,
    nopcre_map,
    no_promisc_map,
    obfuscate_map,
    order_map,
    paf_max_map,
    pcre_match_limit_map,
    pcre_match_limit_recursion_map,
    pkt_count_map,
    ppm_map,
    policy_id_map,
    policy_uuid_map,
    policy_mode_map,
    profile_preprocs_map,
    profile_rules_map,
    protected_content_map,
    quiet_map,
    rate_filter_map,
    react_map,
    reference_map,
    reference_net_map,
    response_map,
    set_gid_map,
    set_uid_map,
    show_year_map,
    sidechannel_map,
    snaplen_map,
    so_rule_memcap_map,
    stateful_map,
    tagged_packet_limit_map,
    threshold_map,
    tunnel_verdicts_map,
    umask_map,
    utc_map,
    verbose_map,
    vlan_agnostic_map,
};
} // namespace config

#endif


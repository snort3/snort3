//--------------------------------------------------------------------------
// Copyright (C) 2017-2017 Cisco and/or its affiliates. All rights reserved.
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
// pps_firewall.cc author Michael Altizer <mialtize@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace preprocessors
{
    namespace
    {
        class Firewall : public ConversionState
        {
        public:
            Firewall(Converter& c) : ConversionState(c) { }
            ~Firewall() { }
            bool convert(std::istringstream& data) override;
        };
    } // namespace

    bool Firewall::convert(std::istringstream& data_stream)
    {
        bool retval = true;

        table_api.open_table("firewall");

        std::string keyword;
        while (data_stream >> keyword)
        {
            bool tmpval = true;

            if (!keyword.compare("fw_rule_path"))
                tmpval = parse_string_option("fw_rule_path", data_stream);
            else if (!keyword.compare("qos_rule_path"))
                tmpval = parse_string_option("qos_rule_path", data_stream);
            else if (!keyword.compare("dns_rule_path"))
                tmpval = parse_string_option("dns_rule_path", data_stream);
            else if (!keyword.compare("url_rule_path"))
                tmpval = parse_string_option("url_rule_path", data_stream);
            else if (!keyword.compare("file_rule_path"))
                // FIXIT-L This is currently just not implemented, not actually deleted
                tmpval = parse_deleted_option("file_rule_path", data_stream);
            else if (!keyword.compare("whitelist"))
                tmpval = parse_string_option("whitelist_path", data_stream);
            else if (!keyword.compare("blacklist"))
                tmpval = parse_string_option("blacklist_path", data_stream);
            else if (!keyword.compare("fw_log_name"))
                tmpval = parse_deleted_option("fw_log_name", data_stream);
            else if (!keyword.compare("fw_log_time"))
                tmpval = parse_int_option("fw_roll_log_interval", data_stream, false);
            else if (!keyword.compare("fw_log_size"))
                tmpval = parse_int_option("max_log_file_size", data_stream, false);
            else if (!keyword.compare("fw_log_dns"))
                tmpval = table_api.add_option("dns_log_enabled", true);
            else if (!keyword.compare("fw_log_url"))
                tmpval = table_api.add_option("url_log_enabled", true);
            else if (!keyword.compare("fw_url_file"))
                tmpval = parse_deleted_option("fw_url_file", data_stream);
            else if (!keyword.compare("fw_url_perf"))
                tmpval = parse_string_option("url_perf_filename", data_stream);
            else if (!keyword.compare("fw_url_len"))
                tmpval = parse_int_option("max_url_log_len", data_stream, false);
            else if (!keyword.compare("enable_url_cache_miss"))
                tmpval = table_api.add_option("url_cache_miss_enabled", true);
            else if (!keyword.compare("fw_user_stats"))
                tmpval = parse_string_option("user_stats_filename", data_stream);
            else if (!keyword.compare("fw_app_stats"))
                tmpval = parse_string_option("app_stats_filename", data_stream);
            else if (!keyword.compare("fw_qos_rule_stats"))
                tmpval = parse_string_option("qos_rule_stats_filename", data_stream);
            else if (!keyword.compare("fw_intf_stats"))
                tmpval = parse_string_option("intf_stats_filename", data_stream);
            else if (!keyword.compare("fw_stats_time"))
                tmpval = parse_int_option("fw_stats_interval", data_stream, false);
            else if (!keyword.compare("fw_urlq_memcap"))
                tmpval = parse_int_option("url_queue_memcap", data_stream, false);
            else if (!keyword.compare("fw_urlc_memcap"))
                tmpval = parse_int_option("url_cache_memcap", data_stream, false);
            else if (!keyword.compare("fw_usrq_memcap"))
                tmpval = parse_int_option("user_queue_memcap", data_stream, false);
            else if (!keyword.compare("fw_usrc_memcap"))
                tmpval = parse_int_option("user_cache_memcap", data_stream, false);
            else if (!keyword.compare("fw_malwq_memcap"))
                tmpval = parse_int_option("malware_queue_memcap", data_stream, false);
            else if (!keyword.compare("fw_malwc_memcap"))
                tmpval = parse_int_option("malware_cache_memcap", data_stream, false);
            else if (!keyword.compare("fw_archiveq_memcap"))
                tmpval = parse_int_option("archive_queue_memcap", data_stream, false);
            else if (!keyword.compare("fw_archivec_memcap"))
                tmpval = parse_int_option("archive_cache_memcap", data_stream, false);
            else if (!keyword.compare("fw_log_iprep"))
                tmpval = parse_yn_bool_option("iprep_logging_enabled", data_stream, false, "enable", "disable");
            else if (!keyword.compare("fw_log_file_id"))
                tmpval = parse_deleted_option("fw_log_file_id", data_stream);
            else if (!keyword.compare("fw_skip_cert"))
                tmpval = table_api.add_option("skip_https_cert", true);
            else if (!keyword.compare("fw_log_host"))
                tmpval = table_api.add_option("log_host_only", true);
            else if (!keyword.compare("fw_ips_classic"))
                tmpval = table_api.add_option("log_orig_ips", true);
            else if (!keyword.compare("fw_required"))
                tmpval = table_api.add_option("externally_required", true);
            else if (!keyword.compare("ha_http"))
                tmpval = parse_int_option("ha_http_len", data_stream, false);
            else if (!keyword.compare("fw_bypass_time"))
                tmpval = parse_int_option("bypass_timeout", data_stream, false);
            else if (!keyword.compare("fw_file_memcap"))
                tmpval = parse_int_option("file_queue_memcap", data_stream, false);
            else if (!keyword.compare("fw_file_geo4map"))
                tmpval = parse_string_option("geo_ipv4_map_path", data_stream);
            else if (!keyword.compare("fw_file_geo6map"))
                tmpval = parse_string_option("geo_ipv6_map_path", data_stream);
            else if (!keyword.compare("fw_file_storage_path"))
                tmpval = parse_string_option("file_storage_path", data_stream);
            else if (!keyword.compare("fw_file_extraction_mode"))
                tmpval = parse_int_option("file_extraction_mode", data_stream, false);
            else if (!keyword.compare("file_sandbox_min"))
                tmpval = parse_int_option("file_sandbox_min", data_stream, false);
            else if (!keyword.compare("file_sandbox_max"))
                tmpval = parse_int_option("file_sandbox_max", data_stream, false);
            else if (!keyword.compare("file_cache_test"))
                tmpval = table_api.add_option("file_cache_test_enabled", true);
            else if (!keyword.compare("fw_file_perf"))
                tmpval = parse_string_option("file_perf_filename", data_stream);
            else if (!keyword.compare("capture_missed_disp"))
                tmpval = table_api.add_option("capture_missed_disp", true);
            else if (!keyword.compare("debug_future_date"))
                tmpval = table_api.add_option("future_date_debug_enabled", true);
            else if (!keyword.compare("identity_rule_path"))
                tmpval = parse_string_option("identity_rule_path", data_stream);
            else if (!keyword.compare("interface_ip_map_path"))
                tmpval = parse_string_option("intf_ip_map_path", data_stream);
            else if (!keyword.compare("daqif_path"))
                tmpval = parse_string_option("daq_intf_path", data_stream);
            else if (!keyword.compare("running_config_network_path"))
                tmpval = parse_string_option("running_network_config_path", data_stream);
            else
                tmpval = false;

            if (!tmpval)
            {
                data_api.failed_conversion(data_stream, keyword);
                retval = false;
            }
        }

        return retval;
    }

    /**************************
     *******  A P I ***********
     **************************/

    static ConversionState* ctor(Converter& c)
    {
        return new Firewall(c);
    }

    static const ConvertMap firewall_api =
    {
        "firewall",
        ctor,
    };

    const ConvertMap* firewall_map = &firewall_api;
} // namespace preprocessors


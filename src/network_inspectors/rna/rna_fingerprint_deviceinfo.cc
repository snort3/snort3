//--------------------------------------------------------------------------
// Copyright (C) 2019-2026 Cisco and/or its affiliates. All rights reserved.
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

// rna_fingerprint_deviceinfo.cc author Umang Sharma <umasharm@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rna_fingerprint_deviceinfo.h"

#include <cstring>
#include <sstream>

#include "helpers/discovery_filter.h"
#include "log/messages.h"
#include "main/thread.h"
#include "pub_sub/deviceinfo_events.h"

#include "rna_flow.h"
#include "rna_logger.h"
#include "rna_logger_common.h"
#include "rna_module.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

static THREAD_LOCAL DeviceInfoFpProcessor* deviceinfo_fp_processor = nullptr;

DeviceInfoFpProcessor* get_deviceinfo_fp_processor()
{
    return deviceinfo_fp_processor;
}

void set_deviceinfo_fp_processor(DeviceInfoFpProcessor* processor)
{
    deviceinfo_fp_processor = processor;
}

namespace snort {

void DeviceInfoRowFingerprint::set_field(DeviceInfoFieldType type, const std::string& pattern, 
    const std::string& value)
{
    if (pattern.empty())
        return;
    patterns[type] = pattern;
    values[type] = value;
    field_mask |= DEVICEINFO_FIELD_TO_MASK[type];
}

void DeviceInfoRowFingerprint::set_mac(const std::string& mac)
{
    if (mac.empty())
        return;
    std::istringstream ss(mac);
    std::string tmp;
    int i = 0;
    while (std::getline(ss, tmp, ':') && i < 3)
        mac_addr[i++] = static_cast<uint8_t>(std::stoul(tmp, nullptr, 16));
    mac_addr_set = true;
}

DeviceInfoFpProcessor::~DeviceInfoFpProcessor()
{
    delete protocol_type_mpse;
}

void DeviceInfoFpProcessor::make_mpse(bool priority)
{
    if (priority)
    {
        delete protocol_type_mpse;
        protocol_type_mpse = nullptr;
    }

    if (protocol_type_mpse or protocol_type_fps.empty())
        return;

    protocol_type_mpse = new SearchTool;
    for (std::pair<const std::string, DeviceInfoProtoFingerprint>& kv : protocol_type_fps)
        protocol_type_mpse->add(kv.second.protocol_type.c_str(), kv.second.protocol_type.size(), &kv.second);
    protocol_type_mpse->prep();
}

static int collect_rows(void* id, void*, int, void* data, void*)
{
    DeviceInfoProtoFingerprint* proto_fp = static_cast<DeviceInfoProtoFingerprint*>(id);
    std::vector<const DeviceInfoRowFingerprint*>* rows = static_cast<std::vector<const DeviceInfoRowFingerprint*>*>(data);
    for (const DeviceInfoRowFingerprint& row : proto_fp->rows)
        rows->push_back(&row);
    return 0;
}

void DeviceInfoFpProcessor::get_rows(const char* protocol, 
    std::vector<const DeviceInfoRowFingerprint*>& rows)
{
    rows.clear();
    if (!protocol_type_mpse)
        return;
    protocol_type_mpse->find_all(protocol, strlen(protocol), collect_rows, false, &rows);
}

void DeviceInfoFpProcessor::push(const DeviceInfoRawFingerprint& raw_fp)
{
    DeviceInfoProtoFingerprint& proto_fp = protocol_type_fps[raw_fp.protocol_type];
    proto_fp.protocol_type = raw_fp.protocol_type;

    DeviceInfoRowFingerprint row;
    row.fpid = raw_fp.fpid;
    row.fpuuid = raw_fp.fpuuid;
    row.fp_type = raw_fp.fp_type;
    row.set_field(DEVICEINFO_FIELD_MANUFACTURER, raw_fp.manufacturer_pattern, raw_fp.manufacturer);
    row.set_field(DEVICEINFO_FIELD_MODEL, raw_fp.model_pattern, raw_fp.model);
    row.set_field(DEVICEINFO_FIELD_DEVICENAME, raw_fp.devicename_pattern, raw_fp.devicename);
    row.set_field(DEVICEINFO_FIELD_OS, raw_fp.os_pattern, raw_fp.os_value);
    row.os_prefix = raw_fp.os_prefix;
    row.os_postfix = raw_fp.os_postfix;
    row.set_mac(raw_fp.mac_addr);

    proto_fp.rows.push_back(std::move(row));
}

}

static bool is_printable_string(const char* str)
{
    if (!str || !*str)
        return false;
    for (const char* p = str; *p; ++p)
    {
        if (!std::isprint(static_cast<unsigned char>(*p)))
            return false;
    }
    return true;
}

static std::string clean_field_value(const std::string& value)
{
    std::string clean;
    for (char c : value)
    {
        if (static_cast<unsigned char>(c) < 128 && std::isprint(c) && c != ',')
            clean += c;
    }
    return clean;
}

static bool match_row_fields(const snort::DeviceInfoRowFingerprint* row,
    const std::vector<std::pair<std::string, std::string>>& kv_pairs,
    std::string* extracted_values)
{
    uint8_t matched_mask = 0;
    
    for (const std::pair<std::string, std::string>& kv : kv_pairs)
    {
        std::string kv_string = kv.first + "=" + kv.second;
        
        for (uint8_t t = 0; t < snort::DEVICEINFO_FIELD_MAX; t++)
        {
            if (row->patterns[t].empty())
                continue;
            
            if (kv_string.find(row->patterns[t]) != std::string::npos)
            {
                matched_mask |= snort::DEVICEINFO_FIELD_TO_MASK[t];
                if (row->values[t].empty())
                    extracted_values[t] = kv.second;
                else
                    extracted_values[t] = row->values[t];
            }
        }
    }
    
    return (matched_mask == row->field_mask);
}

static RnaTracker get_client_rna_tracker(const snort::Packet* p, RNAFlow* rna_flow)
{
    return rna_flow->get_client(p->flow->client_ip);
}

void RnaDeviceDiscovery::process(const snort::DeviceInfoEvent* event, RnaLogger& logger, DiscoveryFilter& filter)
{
    DeviceInfoFpProcessor* processor = get_deviceinfo_fp_processor();
    if (!processor)
        return;

    if (!processor->has_pattern())
        return;

    const Packet* pkt = event->get_packet();
    const DeviceInfoEvent::DeviceInfoMap& device_info_map = event->get_device_info_map();
    
    if (device_info_map.empty())
        return;

    RNAFlow* rna_flow = static_cast<RNAFlow*>(pkt->flow->get_flow_data(RNAFlow::inspector_id));
    if (!rna_flow)
        return;

    if (!filter.is_host_monitored(pkt, nullptr, nullptr, FlowCheckDirection::DF_CLIENT))
        return;

    RnaTracker rt = get_client_rna_tracker(pkt, rna_flow);
    if (!rt)
        return;

    if (!rt->is_visible())
        return;
    rt->update_last_seen();

    uint8_t mac_addr[MAC_SIZE];

    for (const std::pair<const std::pair<std::string, std::string>, std::vector<std::pair<std::string, std::string>>>& entry : device_info_map)
    {
        const std::string& protocol_type = entry.first.first;
        const std::string& device_name = entry.first.second;
        const std::vector<std::pair<std::string, std::string>>& txt_kv_pairs = entry.second;

        if (device_name.empty() || protocol_type.empty())
            continue;
        
        if (!is_printable_string(device_name.c_str()))
            continue;

        std::vector<const DeviceInfoRowFingerprint*> rows;
        processor->get_rows(protocol_type.c_str(), rows);

        if (rows.empty())
        {
            debug_logf(rna_trace, pkt, "DeviceInfo: no fingerprint rows found for protocol %s\n", protocol_type.c_str());
            continue;
        }

        std::string global_hardware_info;

        for (const DeviceInfoRowFingerprint* row : rows)
        {
            std::string extracted_values[DEVICEINFO_FIELD_MAX];
            
            if (!match_row_fields(row, txt_kv_pairs, extracted_values))
                continue;

            if (!rt->add_deviceinfo_fingerprint(row->fpid))
                continue;

            std::string field_values[DEVICEINFO_FIELD_MAX];
            for (uint8_t i = 0; i < DEVICEINFO_FIELD_MAX; i++)
                field_values[i] = clean_field_value(extracted_values[i]);
            
            field_values[DEVICEINFO_FIELD_DEVICENAME] = clean_field_value(device_name);

            uint8_t mask = row->field_mask;
            std::string hardware_info = field_values[DEVICEINFO_FIELD_MANUFACTURER] + 
                (field_values[DEVICEINFO_FIELD_MANUFACTURER].empty() || field_values[DEVICEINFO_FIELD_MODEL].empty() ? "" : " ") + 
                field_values[DEVICEINFO_FIELD_MODEL];

            if (global_hardware_info.empty() && !hardware_info.empty())
                global_hardware_info = hardware_info;

            if (is_printable_string(field_values[DEVICEINFO_FIELD_DEVICENAME].c_str()))
            {
                debug_logf(rna_trace, pkt, "DeviceInfo: logging CHANGE_DEVICE_NAME event for fingerprint %u, name='%s'\n",
                    row->fpid, field_values[DEVICEINFO_FIELD_DEVICENAME].c_str());
                logger.log(RNA_EVENT_CHANGE, CHANGE_DEVICE_NAME, pkt, rt,
                    reinterpret_cast<const struct in6_addr*>(pkt->flow->client_ip.get_ip6_ptr()),
                    rt->get_last_seen_mac(mac_addr), row, packet_time(),
                    hardware_info.c_str(), field_values[DEVICEINFO_FIELD_DEVICENAME].c_str());
                
                rt->set_device_name(field_values[DEVICEINFO_FIELD_DEVICENAME].c_str());
            }

            const std::string& hw_for_os = hardware_info.empty() ? global_hardware_info : hardware_info;
            if ((mask & DEVICEINFO_MASK_OS) && is_printable_string(hw_for_os.c_str()))
            {
                std::string os_cpe = row->os_prefix + field_values[DEVICEINFO_FIELD_OS] + row->os_postfix;
                debug_logf(rna_trace, pkt, "DeviceInfo: logging NEW_OS event for fingerprint %u, os_cpe='%s'\n",
                    row->fpid, os_cpe.c_str());
                std::vector<const char*> cpes;
                cpes.push_back(os_cpe.c_str());
                FpFingerprint fp;
                fp.fpid = row->fpid;
                fp.fpuuid = row->fpuuid;
                fp.fp_type = FpFingerprint::FpType::FP_TYPE_DEVICEINFO;

                logger.log(RNA_EVENT_NEW, NEW_OS, pkt, rt, 
                    reinterpret_cast<const struct in6_addr*>(pkt->flow->client_ip.get_ip6_ptr()),
                    rt->get_last_seen_mac(mac_addr), &fp, &cpes, packet_time(), hw_for_os.c_str());
            }

            if ((mask & (DEVICEINFO_MASK_MODEL | DEVICEINFO_MASK_MANUFACTURER)) && is_printable_string(hardware_info.c_str()))
            {
                bool is_high_priority = (mask & DEVICEINFO_MASK_MODEL) && !row->values[DEVICEINFO_FIELD_MODEL].empty();
                if (rt->set_deviceinfo_hardware(hardware_info, is_high_priority))
                {
                    debug_logf(rna_trace, pkt, "DeviceInfo: logging NEW_OS hardware event for fingerprint %u, hardware='%s'\n",
                        row->fpid, hardware_info.c_str());
                    logger.log(RNA_EVENT_NEW, NEW_OS, pkt, rt, 
                        reinterpret_cast<const struct in6_addr*>(pkt->flow->client_ip.get_ip6_ptr()),
                        rt->get_last_seen_mac(mac_addr), row, packet_time(),
                        hardware_info.c_str(), nullptr);
                }
            }
        }
    }
}

#ifdef UNIT_TEST

TEST_CASE("get_rows_basic", "[rna_fingerprint_deviceinfo]")
{
    DeviceInfoFpProcessor deviceinfo_processor;
    set_deviceinfo_fp_processor(&deviceinfo_processor);
    DeviceInfoFpProcessor* processor = get_deviceinfo_fp_processor();
    CHECK(processor == &deviceinfo_processor);

    DeviceInfoRawFingerprint rawfp;
    rawfp.fpid = 100606;
    rawfp.fp_type = 15;
    rawfp.fpuuid = "680f888c-8f20-4fed-ad9b-c9875d206fcb";
    rawfp.protocol_type = "_airplay._tcp.local";
    rawfp.manufacturer_pattern = "manufacturer=";
    rawfp.model_pattern = "model=";
    processor->push(rawfp);
    processor->make_mpse(true);

    std::vector<const DeviceInfoRowFingerprint*> rows;
    processor->get_rows("_airplay._tcp.local", rows);
    CHECK(rows.size() == 1);
    CHECK(rows[0]->fpid == 100606);
    CHECK(rows[0]->has_field(DEVICEINFO_FIELD_MODEL));
    CHECK(rows[0]->has_field(DEVICEINFO_FIELD_MANUFACTURER));
    CHECK(rows[0]->patterns[DEVICEINFO_FIELD_MODEL] == "model=");
    CHECK(rows[0]->patterns[DEVICEINFO_FIELD_MANUFACTURER] == "manufacturer=");
}

TEST_CASE("get_rows_with_values", "[rna_fingerprint_deviceinfo]")
{
    DeviceInfoFpProcessor processor;

    DeviceInfoRawFingerprint rawfp;
    rawfp.fpid = 100604;
    rawfp.fp_type = 15;
    rawfp.fpuuid = "6a23f14f-e02a-46bd-95d3-e18853083dc3";
    rawfp.protocol_type = "_printer._tcp.local";
    rawfp.manufacturer_pattern = "usb_MFG=";
    rawfp.manufacturer = "HP";
    rawfp.model_pattern = "usb_MDL=";
    rawfp.model = "LaserJet";
    processor.push(rawfp);
    processor.make_mpse(true);

    std::vector<const DeviceInfoRowFingerprint*> rows;
    processor.get_rows("_printer._tcp.local", rows);
    CHECK(rows.size() == 1);
    CHECK(rows[0]->fpid == 100604);
    CHECK(rows[0]->values[DEVICEINFO_FIELD_MANUFACTURER] == "HP");
    CHECK(rows[0]->values[DEVICEINFO_FIELD_MODEL] == "LaserJet");
}

TEST_CASE("get_rows_multiple_same_protocol", "[rna_fingerprint_deviceinfo]")
{
    DeviceInfoFpProcessor processor;

    DeviceInfoRawFingerprint fp1;
    fp1.fpid = 100601;
    fp1.fp_type = 15;
    fp1.fpuuid = "ecd3e238-44e1-4cb3-8383-49d83f4f8d5b";
    fp1.protocol_type = "_mediaremotetv._tcp.local";
    fp1.model_pattern = "model=";
    processor.push(fp1);

    DeviceInfoRawFingerprint fp2;
    fp2.fpid = 100602;
    fp2.fp_type = 15;
    fp2.fpuuid = "cefa3bb2-eb5f-447e-aa7d-64bda5a49ae5";
    fp2.protocol_type = "_mediaremotetv._tcp.local";
    fp2.model_pattern = "model=";
    fp2.manufacturer_pattern = "mfg=";
    processor.push(fp2);

    processor.make_mpse(true);

    std::vector<const DeviceInfoRowFingerprint*> rows;
    processor.get_rows("_mediaremotetv._tcp.local", rows);
    CHECK(rows.size() == 2);
    CHECK(rows[0]->fpid == 100601);
    CHECK(rows[1]->fpid == 100602);
}

TEST_CASE("get_rows_no_patterns_loaded", "[rna_fingerprint_deviceinfo]")
{
    DeviceInfoFpProcessor processor;
    processor.make_mpse(true);
    // cppcheck-suppress comparisonOfFuncReturningBoolError
    CHECK_FALSE(processor.has_pattern());

    std::vector<const DeviceInfoRowFingerprint*> rows;
    processor.get_rows("_airplay._tcp.local", rows);
    CHECK(rows.empty());
}

TEST_CASE("get_rows_with_predefined_values", "[rna_fingerprint_deviceinfo]")
{
    DeviceInfoFpProcessor processor;

    DeviceInfoRawFingerprint rawfp;
    rawfp.fpid = 100611;
    rawfp.fp_type = 15;
    rawfp.fpuuid = "google-cast-uuid";
    rawfp.protocol_type = "_googlecast._tcp.local";
    rawfp.model_pattern = "md=";
    rawfp.model = "Chromecast";
    rawfp.manufacturer_pattern = "fn=";
    rawfp.manufacturer = "Google";
    processor.push(rawfp);
    processor.make_mpse(true);

    std::vector<const DeviceInfoRowFingerprint*> rows;
    processor.get_rows("_googlecast._tcp.local", rows);
    CHECK(rows.size() == 1);
    CHECK(rows[0]->fpid == 100611);
    CHECK(rows[0]->patterns[DEVICEINFO_FIELD_MODEL] == "md=");
    CHECK(rows[0]->values[DEVICEINFO_FIELD_MODEL] == "Chromecast");
    CHECK(rows[0]->patterns[DEVICEINFO_FIELD_MANUFACTURER] == "fn=");
    CHECK(rows[0]->values[DEVICEINFO_FIELD_MANUFACTURER] == "Google");
}

TEST_CASE("get_rows_mac_address", "[rna_fingerprint_deviceinfo]")
{
    DeviceInfoFpProcessor processor;

    DeviceInfoRawFingerprint rawfp;
    rawfp.fpid = 100600;
    rawfp.fp_type = 15;
    rawfp.fpuuid = "d827d911-e50e-404f-9f5d-5aa56b580b35";
    rawfp.protocol_type = "_hap._tcp.local";
    rawfp.manufacturer_pattern = "md=";
    rawfp.manufacturer = "Apple";
    rawfp.mac_addr = "A4:83:E7";
    processor.push(rawfp);
    processor.make_mpse(true);

    std::vector<const DeviceInfoRowFingerprint*> rows;
    processor.get_rows("_hap._tcp.local", rows);
    CHECK(rows.size() == 1);
    CHECK(rows[0]->mac_addr_set == true);
    CHECK(rows[0]->mac_addr[0] == 0xA4);
    CHECK(rows[0]->mac_addr[1] == 0x83);
    CHECK(rows[0]->mac_addr[2] == 0xE7);
}

TEST_CASE("get_rows_field_mask", "[rna_fingerprint_deviceinfo]")
{
    DeviceInfoFpProcessor processor;

    DeviceInfoRawFingerprint rawfp;
    rawfp.fpid = 100700;
    rawfp.fp_type = 15;
    rawfp.fpuuid = "field-mask-test-uuid";
    rawfp.protocol_type = "_test._tcp.local";
    rawfp.manufacturer_pattern = "mfg=";
    rawfp.model_pattern = "mdl=";
    rawfp.os_pattern = "os=";
    processor.push(rawfp);
    processor.make_mpse(true);

    std::vector<const DeviceInfoRowFingerprint*> rows;
    processor.get_rows("_test._tcp.local", rows);
    CHECK(rows.size() == 1);
    CHECK(rows[0]->has_field(DEVICEINFO_FIELD_MANUFACTURER));
    CHECK(rows[0]->has_field(DEVICEINFO_FIELD_MODEL));
    CHECK(rows[0]->has_field(DEVICEINFO_FIELD_OS));
    CHECK_FALSE(rows[0]->has_field(DEVICEINFO_FIELD_DEVICENAME));
    CHECK(rows[0]->field_mask == 0b1011);
}

#endif

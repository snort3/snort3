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

// rna_fingerprint_deviceinfo.h author Umang Sharma <umasharm@cisco.com>

#ifndef RNA_FINGERPRINT_DEVICEINFO_H
#define RNA_FINGERPRINT_DEVICEINFO_H

#include <sstream>
#include <unordered_map>

#include "main/snort_types.h"
#include "search_engines/search_tool.h"

#include "rna_fingerprint.h"

class DiscoveryFilter;
class RnaLogger;

namespace snort
{
class DeviceInfoEvent;

enum DeviceInfoFieldType : uint8_t
{
    DEVICEINFO_FIELD_MANUFACTURER = 0, 
    DEVICEINFO_FIELD_MODEL = 1,
    DEVICEINFO_FIELD_DEVICENAME = 2,
    DEVICEINFO_FIELD_OS = 3,
    DEVICEINFO_FIELD_MAX = 4,
};

const uint8_t DEVICEINFO_MASK_MANUFACTURER = 0x01;
const uint8_t DEVICEINFO_MASK_MODEL = 0x02;
const uint8_t DEVICEINFO_MASK_DEVICENAME = 0x04;
const uint8_t DEVICEINFO_MASK_OS = 0x08;

const uint8_t DEVICEINFO_FIELD_TO_MASK[DEVICEINFO_FIELD_MAX] = {
    DEVICEINFO_MASK_MANUFACTURER,
    DEVICEINFO_MASK_MODEL,
    DEVICEINFO_MASK_DEVICENAME,
    DEVICEINFO_MASK_OS
};

class SO_PUBLIC DeviceInfoRowFingerprint : public FpFingerprint
{
public:
    uint8_t field_mask = 0;
    std::string patterns[DEVICEINFO_FIELD_MAX];
    std::string values[DEVICEINFO_FIELD_MAX];
    std::string os_prefix;
    std::string os_postfix;
    uint8_t mac_addr[3] = {0};
    bool mac_addr_set = false;

    void set_field(DeviceInfoFieldType type, const std::string& pattern, const std::string& value);
    void set_mac(const std::string& mac);
    bool has_field(DeviceInfoFieldType type) const { return (field_mask & DEVICEINFO_FIELD_TO_MASK[type]) != 0; }
};

class SO_PUBLIC DeviceInfoProtoFingerprint
{
public:
    std::string protocol_type;
    std::vector<DeviceInfoRowFingerprint> rows;
};

class SO_PUBLIC DeviceInfoRawFingerprint : public FpFingerprint
{
public:
    std::string protocol_type;
    std::string manufacturer_pattern;
    std::string manufacturer;
    std::string model_pattern;
    std::string model;
    std::string devicename_pattern;
    std::string devicename;
    std::string os_pattern;
    std::string os_value;
    std::string mac_addr;
    std::string os_prefix;
    std::string os_postfix;
};

class SO_PUBLIC DeviceInfoFpProcessor
{
public:
    ~DeviceInfoFpProcessor();

    void make_mpse(bool priority = false);
    void push(const DeviceInfoRawFingerprint&);
    void get_rows(const char* protocol, std::vector<const DeviceInfoRowFingerprint*>& rows);

    bool has_pattern() const { return protocol_type_mpse != nullptr; }

private:
    std::unordered_map<std::string, DeviceInfoProtoFingerprint> protocol_type_fps;
    snort::SearchTool* protocol_type_mpse = nullptr;
};

}

class RnaDeviceDiscovery
{
public:
    static void process(const snort::DeviceInfoEvent*, RnaLogger&, DiscoveryFilter&);
};

snort::DeviceInfoFpProcessor* get_deviceinfo_fp_processor();
SO_PUBLIC void set_deviceinfo_fp_processor(snort::DeviceInfoFpProcessor*);

#endif

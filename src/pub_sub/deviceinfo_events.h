//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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
// deviceinfo_events.h author Umang Sharma <umasharm@cisco.com>

#ifndef DEVICEINFO_EVENTS_H
#define DEVICEINFO_EVENTS_H

// The DeviceInfoEvent class is used to store device information extracted from
// network protocols such as MDNS (multicast DNS)
// Device information includes device names and key-value attribute pairs
// that describe device characteristics like model, manufacturer, services, etc.
// Subscribers can register handlers to receive and process these events for network analysis purposes.

#include "framework/data_bus.h"
#include <vector>
#include <string>
#include <utility>
#include <map>

namespace snort
{

// Event IDs for device information events published via DataBus
// DEVICEINFO: Primary event type for device information extracted from network protocols
struct DeviceInfoEventIds { enum : unsigned { DEVICEINFO, num_ids }; };

const PubKey deviceinfo_pub_key { "deviceinfo", DeviceInfoEventIds::num_ids };

// DataEvent that contains device identification data including protocol type, device name, and attributes
class DeviceInfoEvent : public DataEvent
{
public:
    // Composite key for unique device identification consisting of protocol type and device name
    // The protocol type identifies the network protocol (e.g., "_airplay._tcp.local", "_http._tcp.local")
    // The device name identifies the specific device instance (e.g., "John's iPhone", "Office Printer")
    using DeviceKey = std::pair<std::string, std::string>;

    // Collection of device attributes extracted from network protocols as key-value pairs
    // Contains device characteristics like model, manufacturer, version, services, etc.
    // Example: [("model", "iPhone12"), ("manufacturer", "Apple"), ("os", "iOS 15.0")]
    using KeyValueVector = std::vector<std::pair<std::string, std::string>>;

    // Maps device identifiers to their corresponding attribute collections
    // Allows multiple devices to be tracked within a single event, each with their own attributes
    // Key: (protocol_type, device_name), Value: vector of device attribute key-value pairs
    using DeviceInfoMap = std::map<DeviceKey, KeyValueVector>;

    // Constructor for creating an event containing multiple devices with their attributes
    // Used when a single network packet or protocol exchange reveals information about multiple devices
    // For example, a network scan response that contains information about several discovered devices
    DeviceInfoEvent(const snort::Packet* p, const DeviceInfoMap& device_map)
        : pkt(p), device_info_map(device_map) { }

    // Constructor for creating an event containing a single device with its attributes
    // Used when network protocol analysis identifies a specific device and its characteristics
    // The device is uniquely identified by protocol type and device name combination
    DeviceInfoEvent(const snort::Packet* p, const std::string& protocol_type,
                   const std::string& device_name, const KeyValueVector& kv_pairs)
        : pkt(p)
    {
        device_info_map[std::make_pair(protocol_type, device_name)] = kv_pairs;
    }

    const Packet* get_packet() const override
    { return pkt; }

    const DeviceInfoMap& get_device_info_map() const
    { return device_info_map; }

    // Retrieve device attributes for a specific device identified by protocol type and device name
    // Returns nullptr if the specified device is not found in this event
    // Used by subscribers to extract specific device information from the event
    const KeyValueVector* get_key_value_pairs(const std::string& protocol_type,
                                             const std::string& device_name) const
    {
        auto it = device_info_map.find(std::make_pair(protocol_type, device_name));
        return (it != device_info_map.end()) ? &it->second : nullptr;
    }

    size_t get_device_count() const
    { return device_info_map.size(); }

    size_t get_total_kv_count() const
    {
        size_t total = 0;
        for (const auto& entry : device_info_map)
            total += entry.second.size();
        return total;
    }

private:
    const Packet* pkt;
    DeviceInfoMap device_info_map;
};

}

#endif

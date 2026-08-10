//--------------------------------------------------------------------------
// Copyright (C) 2017-2026 Cisco and/or its affiliates. All rights reserved.
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

// appid_app_descriptor.h author davis mcpherson <davmcphe@cisco.com>

#ifndef APPID_APP_DESCRIPTOR_H
#define APPID_APP_DESCRIPTOR_H

// The ApplicationDescriptor class and its subclasses contain the state info for
// detected applications.  It provides and API for detectors to call when an
// application is detected to set, get, update, or reset this information.
// When the application is first detected or when it is updated to a different
// application than the current setting the PegCount statistic for that application
// is incremented.

#include <string>
#include <utility>

#include "protocols/packet.h"
#include "pub_sub/appid_events.h"
#include "utils/util.h"

#include "appid_types.h"
#include "application_ids.h"

#define MAX_APPID_SUBTYPES_ENTRIES 30

struct AppIdServiceSubtype
{
    std::string service;
    std::string vendor;
    std::string version;
};

struct AppIdServiceSubtypeListNode
{
    AppIdServiceSubtypeListNode() = default;
    ~AppIdServiceSubtypeListNode() = default;

    AppIdServiceSubtype data;
    AppIdServiceSubtypeListNode* next = nullptr;
};

class AppIdServiceSubtypeList
{
public:
    AppIdServiceSubtypeList() = default;

    ~AppIdServiceSubtypeList()
    {
        clear();
    }

    AppIdServiceSubtypeList(const AppIdServiceSubtypeList& other)
    {
        for (const AppIdServiceSubtypeListNode* node = other.subtypes_head; node; node = node->next)
            append() = node->data;
    }

    AppIdServiceSubtypeList& operator=(const AppIdServiceSubtypeList& other)
    {
        if (this != &other)
        {
            clear();
            for (const AppIdServiceSubtypeListNode* node = other.subtypes_head; node; node = node->next)
                append() = node->data;
        }
        return *this;
    }

    AppIdServiceSubtypeList(AppIdServiceSubtypeList&& other) noexcept
        : subtypes_head(other.subtypes_head), subtypes_tail(other.subtypes_tail),
          subtypes_size(other.subtypes_size)
    {
        other.subtypes_head = nullptr;
        other.subtypes_tail = nullptr;
        other.subtypes_size = 0;
    }

    AppIdServiceSubtypeList& operator=(AppIdServiceSubtypeList&& other) noexcept
    {
        if (this != &other)
        {
            clear();
            subtypes_head = other.subtypes_head;
            subtypes_tail = other.subtypes_tail;
            subtypes_size = other.subtypes_size;
            other.subtypes_head = nullptr;
            other.subtypes_tail = nullptr;
            other.subtypes_size = 0;
        }
        return *this;
    }

    void clear()
    {
        AppIdServiceSubtypeListNode* node = subtypes_head;
        while (node)
        {
            AppIdServiceSubtypeListNode* next = node->next;
            delete node;
            node = next;
        }
        subtypes_head = nullptr;
        subtypes_tail = nullptr;
        subtypes_size = 0;
    }

    bool empty() const
    {
        return subtypes_head == nullptr;
    }

    uint16_t size() const
    {
        return subtypes_size;
    }

    const AppIdServiceSubtypeListNode* head() const
    {
        return subtypes_head;
    }

    const AppIdServiceSubtypeListNode* tail() const
    {
        return subtypes_tail;
    }

    AppIdServiceSubtype* emplace_front()
    {
        if (!have_space())
            return nullptr;
        AppIdServiceSubtypeListNode* node = new AppIdServiceSubtypeListNode();
        node->next = subtypes_head;
        subtypes_head = node;
        if (subtypes_tail == nullptr)
            subtypes_tail = node;
        ++subtypes_size;
        return &node->data;
    }

    AppIdServiceSubtype* emplace()
    {
        if (!have_space())
            return nullptr;
        return &append();
    }

    void splice(AppIdServiceSubtypeList& other, uint16_t limit = UINT16_MAX)
    {
        if (other.subtypes_head == nullptr)
            return;

        if (subtypes_tail)
            subtypes_tail->next = other.subtypes_head;
        else
            subtypes_head = other.subtypes_head;
        subtypes_tail = other.subtypes_tail;

        uint32_t combined_len = static_cast<uint32_t>(subtypes_size) + other.subtypes_size;

        other.subtypes_head = nullptr;
        other.subtypes_tail = nullptr;
        other.subtypes_size = 0;

        while (combined_len > limit)
        {
            AppIdServiceSubtypeListNode* node = subtypes_head;
            subtypes_head = node->next;
            delete node;
            --combined_len;
        }
        if (subtypes_head == nullptr)
            subtypes_tail = nullptr;

        subtypes_size = static_cast<uint16_t>(combined_len);
    }

    void add(const AppIdServiceSubtype& subtype, uint16_t limit = UINT16_MAX)
    {
        if (limit != 0 and subtypes_size >= limit)
            pop_front();

        if (!have_space())
            return;
        append() = subtype;
    }

private:
    AppIdServiceSubtype& append()
    {
        AppIdServiceSubtypeListNode* node = new AppIdServiceSubtypeListNode();
        if (subtypes_tail)
            subtypes_tail->next = node;
        else
            subtypes_head = node;
        subtypes_tail = node;
        ++subtypes_size;
        return node->data;
    }

    void pop_front()
    {
        AppIdServiceSubtypeListNode* node = subtypes_head;
        subtypes_head = node->next;
        if (subtypes_head == nullptr)
            subtypes_tail = nullptr;
        delete node;
        --subtypes_size;
    }

    bool have_space()
    {
        return subtypes_size < UINT16_MAX;
    }

    AppIdServiceSubtypeListNode* subtypes_head = nullptr;
    AppIdServiceSubtypeListNode* subtypes_tail = nullptr;
    uint16_t subtypes_size = 0;
};

class AppIdDetector;
class AppIdSession;
class OdpContext;

class ApplicationDescriptor
{
public:
    ApplicationDescriptor() = default;
    virtual ~ApplicationDescriptor() = default;

    virtual void reset()
    {
        my_id = APP_ID_NONE;
        my_version.clear();
    }

    // The mutable version parameter is part of the installed plugin interface.
    virtual void update(AppId id, char* app_version)
    {
        set_id(id);
        set_version(app_version);
    }

    AppId get_id() const
    {
        return my_id;
    }

    virtual void set_id(AppId app_id);

    virtual void set_id(const snort::Packet& p, AppIdSession& asd, AppidSessionDirection dir, AppId app_id, AppidChangeBits& change_bits);

    const char* get_version() const
    {
        return my_version.empty() ? nullptr : my_version.c_str();
    }

    void set_version(const char* app_version)
    {
        if ( app_version )
            my_version = app_version;
    }

    void reset_version()
    {
        my_version.clear();
    }

private:
    AppId my_id = APP_ID_NONE;
    std::string my_version;
};

class ServiceAppDescriptor : public ApplicationDescriptor
{
public:
    ServiceAppDescriptor()
    {
        service_ip.clear();
    }

    void set_id(AppId app_id, OdpContext& odp_ctxt);

    void reset() override
    {
        ApplicationDescriptor::reset();
        my_vendor.clear();
        port_service_id = APP_ID_NONE;

        subtypes.clear();
        service_ip.clear();
        service_port = 0;
        service_group = DAQ_PKTHDR_UNKNOWN;
    }

    AppId get_port_service_id() const
    {
        return port_service_id;
    }

    void set_port_service_id(AppId id);

    bool get_deferred() const
    {
        return deferred;
    }

    const char* get_vendor() const
    {
        return my_vendor.empty() ? nullptr : my_vendor.c_str();
    }

    void set_vendor(const char* vendor, AppidChangeBits& change_bits)
    {
        if ( vendor )
        {
            my_vendor = vendor;
            change_bits.set(APPID_SERVICE_INFO_BIT);
        }
    }

    void add_subtype(const AppIdServiceSubtype& more_subtype, AppidChangeBits& change_bits)
    {
        subtypes.add(more_subtype, MAX_APPID_SUBTYPES_ENTRIES);
        change_bits.set(APPID_SERVICE_INFO_BIT);
    }

    void add_subtype_list(AppIdServiceSubtypeList& more_subtypes, AppidChangeBits& change_bits)
    {
        if (more_subtypes.empty())
            return;
        subtypes.splice(more_subtypes, MAX_APPID_SUBTYPES_ENTRIES);
        change_bits.set(APPID_SERVICE_INFO_BIT);
    }

    const AppIdServiceSubtypeList& get_subtypes() const
    {
        return subtypes;
    }

    void set_service_ip(const snort::SfIp& ip)
    {
        service_ip = ip;
    }

    const snort::SfIp& get_service_ip() const
    {
        return service_ip;
    }

    bool is_service_ip_set() const
    {
        return service_ip.is_set();
    }

    void set_service_port(uint16_t port)
    {
        service_port = port;
    }

    uint16_t get_service_port() const
    {
        return service_port;
    }

    void set_service_group(int16_t group)
    {
        service_group = group;
    }

    int16_t get_service_group() const
    {
        return service_group;
    }

    void set_alpn_service_app_id(AppId id)
    {
        alpn_service_app_id = id;
    }

    AppId get_alpn_service_app_id() const
    {
        return alpn_service_app_id;
    }

private:
    AppId port_service_id = APP_ID_NONE;
    AppId alpn_service_app_id = APP_ID_NONE;
    bool deferred = false;
    using ApplicationDescriptor::set_id;
    std::string my_vendor;
    AppIdServiceSubtypeList subtypes;
    snort::SfIp service_ip;
    uint16_t service_port = 0;
    int16_t service_group = DAQ_PKTHDR_UNKNOWN;
};

class ClientAppDescriptor : public ApplicationDescriptor
{
public:
    ClientAppDescriptor() = default;

    void reset() override
    {
        ApplicationDescriptor::reset();
        my_username.clear();
        my_user_id = APP_ID_NONE;
        my_client_detect_type = CLIENT_APP_DETECT_APPID;
    }

    void update_user(AppId app_id, const char* username, AppidChangeBits& change_bits);

    AppId get_user_id() const
    {
        return my_user_id;
    }

    const char* get_username() const
    {
        return my_username.empty() ? nullptr : my_username.c_str();
    }

    void set_eve_client_app_id(AppId id)
    {
        eve_client_app_id = id;
    }

    AppId get_eve_client_app_id() const
    {
        return eve_client_app_id;
    }

    void set_eve_client_app_detect_type(ClientAppDetectType client_app_detect_type)
    {
        my_client_detect_type = client_app_detect_type;
    }

    ClientAppDetectType get_client_app_detect_type() const
    {
        return my_client_detect_type;
    }

private:
    std::string my_username;
    AppId my_user_id = APP_ID_NONE;
    AppId eve_client_app_id = APP_ID_NONE;
    ClientAppDetectType my_client_detect_type = CLIENT_APP_DETECT_APPID;
};

class PayloadAppDescriptor : public ApplicationDescriptor
{
public:
    PayloadAppDescriptor() = default;
};

#endif

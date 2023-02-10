//--------------------------------------------------------------------------
// Copyright (C) 2017-2023 Cisco and/or its affiliates. All rights reserved.
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

#include "protocols/packet.h"
#include "pub_sub/appid_events.h"
#include "utils/util.h"

#include "appid_types.h"
#include "application_ids.h"

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

    virtual void update(AppId id, char* version)
    {
        set_id(id);
        set_version(version);
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

    void set_version(const char* version)
    {
        if ( version )
            my_version = version;
    }

private:
    AppId my_id = APP_ID_NONE;
    std::string my_version;
};

struct AppIdServiceSubtype
{
    AppIdServiceSubtype* next = nullptr;
    std::string service;
    std::string vendor;
    std::string version;
};

class ServiceAppDescriptor : public ApplicationDescriptor
{
public:
    ServiceAppDescriptor()
    {
        service_ip.clear();
    }

    ~ServiceAppDescriptor() override
    {
        AppIdServiceSubtype* tmp_subtype = subtype;
        while (tmp_subtype)
        {
            subtype = tmp_subtype->next;
            delete tmp_subtype;
            tmp_subtype = subtype;
        }
    }

    void set_id(AppId app_id, OdpContext& odp_ctxt);

    void reset() override
    {
        ApplicationDescriptor::reset();
        my_vendor.clear();
        port_service_id = APP_ID_NONE;

        AppIdServiceSubtype* tmp_subtype = subtype;
        while (tmp_subtype)
        {
            subtype = tmp_subtype->next;
            delete tmp_subtype;
            tmp_subtype = subtype;
        }
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

    void add_subtype(AppIdServiceSubtype& more_subtype, AppidChangeBits& change_bits)
    {
        AppIdServiceSubtype** tmp_subtype;

        for (tmp_subtype = &subtype; *tmp_subtype; tmp_subtype = &(*tmp_subtype)->next)
            ;
        *tmp_subtype = &more_subtype;
        change_bits.set(APPID_SERVICE_INFO_BIT);
    }

    const AppIdServiceSubtype* get_subtype() const
    {
        return subtype;
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
    AppIdServiceSubtype* subtype = nullptr;
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

    void reset() override
    {
        ApplicationDescriptor::reset();
    }
};

#endif

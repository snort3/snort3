//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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
// sip_events.h author Carter Waxman <cwaxman@cisco.com>

#ifndef SIP_EVENTS_H
#define SIP_EVENTS_H

// This event conveys data published by the SIP service inspector to be consumed
// by data bus subscribers

#include <list>

#include "framework/data_bus.h"
#include "protocols/packet.h"

#define SIP_EVENT_TYPE_SIP_DIALOG_KEY "sip_event_type_sip_dialog"

enum SipEventType
{
    SIP_EVENT_TYPE_SIP_DIALOG
};

struct SIPMsg;
struct SIP_DialogData;
struct SIP_MediaSession;
struct SIP_MediaData;

class SipEventMediaData
{
public:
    SipEventMediaData(SIP_MediaData* data)
    { this->data = data; }

    const sfip_t* get_address() const;
    uint16_t get_port() const;

private:
    SIP_MediaData* data;
};

class SipEventMediaSession
{
public:
    SipEventMediaSession(SIP_MediaSession* session)
    { this->session = session; }

    ~SipEventMediaSession();

    uint32_t get_id() const;

    void begin_media_data();
    SipEventMediaData* next_media_data();

private:
    SIP_MediaSession* session;

    std::list<SipEventMediaData*> data;
    SIP_MediaData* current_media_data = nullptr;
};

class SipEvent : public DataEvent
{
public:
    SipEvent(const Packet*, const SIPMsg*, const SIP_DialogData*);
    ~SipEvent();

    const Packet* get_packet() override
    { return p; }

    const std::string* get_from() const
    { return from.size() ? &from : nullptr; }

    const std::string* get_user_name() const
    { return user_name.size() ? &user_name : nullptr; }

    const std::string* get_user_agent() const
    { return user_agent.size() ? &user_agent : nullptr; }

    const std::string* get_server() const
    { return server.size() ? &server : nullptr; }

    bool is_invite() const;
    bool is_media_updated() const;
    bool has_dialog() const;
    bool is_dialog_established() const;

    void begin_media_sessions();
    SipEventMediaSession* next_media_session();

private:
    const Packet* p;

    const SIPMsg* msg;
    const SIP_DialogData* dialog;

    std::string from;
    std::string user_name;
    std::string user_agent;
    std::string server;

    std::list<SipEventMediaSession*> sessions;
    SIP_MediaSession* current_media_session = nullptr;
};

#endif

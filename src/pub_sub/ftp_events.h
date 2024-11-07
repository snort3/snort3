//--------------------------------------------------------------------------
// Copyright (C) 2024 Cisco and/or its affiliates. All rights reserved.
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

// ftp_events.h author Anna Norokh <anorokh@cisco.com>

#ifndef FTP_EVENTS_H
#define FTP_EVENTS_H

#include "framework/data_bus.h"
#include "service_inspectors/ftp_telnet/ftpp_si.h"

namespace snort
{

struct FtpEventIds
{
    enum : unsigned
    {
        FTP_REQUEST,
        FTP_RESPONSE,
        MAX
    };
};

const snort::PubKey ftp_pub_key { "ftp", FtpEventIds::MAX };

class SO_PUBLIC FtpRequestEvent : public snort::DataEvent
{
public:
    FtpRequestEvent(const FTP_SESSION& ssn) : session(ssn) { }

    const FTP_CLIENT_REQ& get_request() const
    { return session.client.request; }

    uint64_t get_client_port() const
    { return (uint64_t)session.clientPort; }

    const snort::SfIp& get_client_ip() const
    { return session.clientIP; }

private:
    const FTP_SESSION& session;
};

class SO_PUBLIC FtpResponseEvent : public snort::DataEvent
{
public:
    FtpResponseEvent(const FTP_SESSION& ssn) : session(ssn) { }

    const FTP_SERVER_RSP& get_response() const
    { return session.server.response; }

    uint64_t get_client_port() const
    { return (uint64_t)session.clientPort; }

    uint64_t get_server_port() const
    { return (uint64_t)session.serverPort; }

    const snort::SfIp& get_client_ip() const
    { return session.clientIP; }

    const snort::SfIp& get_server_ip() const
    { return session.serverIP; }

    int8_t get_mode() const
    { return session.mode; }

    bool is_passive() const
    {  return session.mode == FTPP_XFER_PASSIVE ? true : false; }

private:
    const FTP_SESSION& session;
};

}

#endif

//--------------------------------------------------------------------------
// Copyright (C) 2022-2025 Cisco and/or its affiliates. All rights reserved.
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
// domain_fronting.h author Bhumika Sachdeva <bsachdev@cisco.com>

#ifndef DOMAIN_FRONTING_H
#define DOMAIN_FRONTING_H

#include "framework/data_bus.h"
#include <string>

enum class DomainFrontingStatus  
{
     MISMATCH,  
     MATCHES,  
     CERT_NOT_IN_CACHE  
};

class TLSDomainFrontCheckEvent : public snort::DataEvent 
{
public: 
     TLSDomainFrontCheckEvent(const snort::Packet& packet, const std::string& certificate_id, 
     const std::string& hostname): cert_id(certificate_id), hostname(hostname), pkt(&packet) {}

     const snort::Packet* get_packet() const override
     { return pkt; }

private:
     const std::string cert_id;
     const std::string hostname;
     const snort::Packet* pkt;
};

#endif

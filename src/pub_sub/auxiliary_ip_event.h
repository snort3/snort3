//--------------------------------------------------------------------------
// Copyright (C) 2021-2025 Cisco and/or its affiliates. All rights reserved.
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
// auxiliary_ip_event.h author Masud Hasan <mashasan@cisco.com>

#ifndef AUXILIARY_IP_EVENT_H
#define AUXILIARY_IP_EVENT_H

#include "pub_sub/intrinsic_event_ids.h"
#include "sfip/sf_ip.h"

class AuxiliaryIpEvent : public snort::DataEvent
{
public:
   AuxiliaryIpEvent(const snort::SfIp& aux_ip) : ip(aux_ip) { }

   const snort::SfIp* get_ip()
   { return &ip; }

private:
   const snort::SfIp& ip;
};

#endif

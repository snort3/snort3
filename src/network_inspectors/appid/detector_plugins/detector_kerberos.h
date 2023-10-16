//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// detector_kerberos.h author Sourcefire Inc.

#ifndef DETECTOR_KERBEROS_H
#define DETECTOR_KERBEROS_H

#include "protocols/packet.h"
#include "client_plugins/client_detector.h"
#include "service_plugins/service_detector.h"

namespace snort
{
struct Packet;
}

struct KRBState;
struct KerberosDetectorData;
class KerberosServiceDetector;

class KerberosClientDetector : public ClientDetector
{
public:
    KerberosClientDetector(ClientDiscovery*);

    int validate(AppIdDiscoveryArgs&) override;
    KerberosDetectorData* get_common_data(AppIdSession&);
    void set_service_detector(KerberosServiceDetector* s)
    {
        krb_service_detector = s;
    }

    bool failed_login = false;

private:
    int krb_walk_client_packet(KRBState*, const uint8_t*, const uint8_t*,
        AppIdSession&, AppidChangeBits&);
    KerberosServiceDetector* krb_service_detector = nullptr;
};

class KerberosServiceDetector : public ServiceDetector
{
public:
    KerberosServiceDetector(ServiceDiscovery*);

    int validate(AppIdDiscoveryArgs&) override;
    int krb_walk_server_packet(KRBState*, const uint8_t*, const uint8_t*, AppIdSession&, snort::Packet*,
        const AppidSessionDirection, const char*, AppidChangeBits&);
    void set_client_detector(KerberosClientDetector* c)
    {
        krb_client_detector = c;
    }

private:
    KerberosClientDetector* krb_client_detector = nullptr;
};

#endif


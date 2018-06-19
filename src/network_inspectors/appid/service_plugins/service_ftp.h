//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// service_ftp.h author Sourcefire Inc.

#ifndef SERVICE_FTP_H
#define SERVICE_FTP_H

#include "service_detector.h"

class ServiceDiscovery;

class FtpServiceDetector : public ServiceDetector
{
public:
    FtpServiceDetector(ServiceDiscovery*);

    int validate(AppIdDiscoveryArgs&) override;

private:
    void create_expected_session(AppIdSession& asd,const snort::Packet* pkt,
        const snort::SfIp* cliIp, uint16_t cliPort, const snort::SfIp* srvIp,
        uint16_t srvPort, IpProtocol proto, int flags, AppidSessionDirection dir);
};
#endif


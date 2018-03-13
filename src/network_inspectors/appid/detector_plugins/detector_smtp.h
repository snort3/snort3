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

// detector_smtp.h author Sourcefire Inc.

#ifndef DETECTOR_SMTP_H
#define DETECTOR_SMTP_H

#include "client_plugins/client_detector.h"
#include "service_plugins/service_detector.h"
#include "framework/counts.h"

struct ClientSMTPData;
struct SMTPDetectorData;

class SmtpClientDetector : public ClientDetector
{
public:
    SmtpClientDetector(ClientDiscovery*);

    int validate(AppIdDiscoveryArgs&) override;
    SMTPDetectorData* get_common_data(AppIdSession&);

private:
    int extract_version_and_add_client_app(AppId, const int prefix_len,
        const uint8_t* product, const uint8_t* product_end, ClientSMTPData* const,
        AppIdSession&, AppId);
    int identify_client_version(ClientSMTPData* const, const uint8_t* product,
        const uint8_t* data_end, AppIdSession&, snort::Packet*);
};

class SmtpServiceDetector : public ServiceDetector
{
public:
    SmtpServiceDetector(ServiceDiscovery*);

    int validate(AppIdDiscoveryArgs&) override;
};

#endif


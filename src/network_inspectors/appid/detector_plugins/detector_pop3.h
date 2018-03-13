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

// detector_imap.h author Sourcefire Inc.

#ifndef DETECTOR_POP3_H
#define DETECTOR_POP3_H

#include "client_plugins/client_detector.h"
#include "service_plugins/service_detector.h"

struct POP3DetectorData;

class Pop3ClientDetector : public ClientDetector
{
public:
    Pop3ClientDetector(ClientDiscovery*);
    ~Pop3ClientDetector() override;

    void do_custom_init() override;
    int validate(AppIdDiscoveryArgs&) override;
    POP3DetectorData* get_common_data(AppIdSession&);

private:
    snort::SearchTool* cmd_matcher = nullptr;
    unsigned longest_pattern = 0;
};

class Pop3ServiceDetector : public ServiceDetector
{
public:
    Pop3ServiceDetector(ServiceDiscovery*);

    int validate(AppIdDiscoveryArgs&) override;
};

#endif


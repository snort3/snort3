//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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

// client_discovery.h author Sourcefire Inc.

#ifndef CLIENT_DISCOVERY_H
#define CLIENT_DISCOVERY_H

#include "flow/flow.h"
#include "log/messages.h"

#include "appid_discovery.h"
#include "appid_types.h"

class ClientDetector;
class AppIdInspector;
class AppIdSession;

struct ClientAppMatch
{
    struct ClientAppMatch* next;
    unsigned count;
    const ClientDetector* detector = nullptr;
};

class ClientDiscovery : public AppIdDiscovery
{
public:
    void initialize(AppIdInspector&) override;
    void reload() override;

    void finalize_client_patterns();
    void reload_client_patterns();
    bool do_client_discovery(AppIdSession&, snort::Packet*,
        AppidSessionDirection direction, AppidChangeBits& change_bits);

private:
    void exec_client_detectors(AppIdSession&, snort::Packet*,
        AppidSessionDirection direction, AppidChangeBits& change_bits);
    ClientAppMatch* find_detector_candidates(const snort::Packet* pkt, const AppIdSession&);
    void create_detector_candidates_list(AppIdSession&, snort::Packet*);
    int get_detector_candidates_list(AppIdSession&, snort::Packet*, AppidSessionDirection direction);
};

#endif


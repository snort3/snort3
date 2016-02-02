//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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

/**
**  @file       hi_si.h
**
**  @author     Daniel J. Roelker <droelker@sourcefire.com>
**
**  @brief      This file contains structures and functions for the
**              session Inspection Module.
**
**  The session Inspection Module has several data structures that are
**  very important to the functionality of the module.  The two major
**  structures are the HI_SESSION and the HI_SI_INPUT.
**
**  NOTES:
**  - 2.25.03:  Initial Development.  DJR
*/
#ifndef HI_SI_H
#define HI_SI_H

#include "hi_include.h"
#include "hi_ui_config.h"
#include "hi_client.h"
#include "hi_server.h"
#include "hi_ad.h"
#include "sfip/sfip_t.h"

struct Packet;

/*
**  These are the defines for the different types of
**  inspection modes.  We have a server mode, client mode and a "no" mode which
**  looks for anomalous HTTP server detection and tunneling.
*/
#define HI_SI_NO_MODE     0
#define HI_SI_CLIENT_MODE 1
#define HI_SI_SERVER_MODE 2

/**
**  The HI_SESSION structure contains the complete HTTP session, both the
**  client and the server constructs.  This structure is the structure that
**  is saved per session in the Stream Interface Module.  This structure
**  gets sent through the detection engine process (Normalization,
**  Detection).
*/
struct HI_SESSION
{
    /*
    **  The client construct contains all the info associated with a
    **  client request.
    */
    HI_CLIENT client;

    /*
    **  The server construct contains all the info associated with a
    **  server response.
    */
    HI_SERVER server;

    /*
    **  The server configuration for this session
    */
    HTTPINSPECT_CONF* server_conf;

    /*
    **  If this HTTP request came from a proxy, we
    **  have to see if it was configured.
    */
    HTTPINSPECT_CONF* client_conf;

    /*
    **  The global configuration for this session
    */
    HTTPINSPECT_GLOBAL_CONF* global_conf;

    uint32_t norm_flags;
};

#define HI_BODY 1

/**
**  The HI_SI_INPUT structure holds the information that the session
**  Inspection Module needs to determine the type of inspection mode
**  (client, server, neither) and to retrieve the appropriate server
**  configuration.
**
**  The input is the source and destination IP addresses, and the
**  source and destination ports (since this should always be a
**  TCP packet).
*/
typedef struct s_HI_SI_INPUT
{
    sfip_t sip;
    sfip_t dip;
    unsigned short sport;
    unsigned short dport;
    unsigned char pdir;
} HI_SI_INPUT;

int hi_si_session_inspection(HTTPINSPECT_CONF* GlobalConf,
    HI_SESSION** session, HI_SI_INPUT* SiInput, int* piInspectMode,
    Packet* p);

extern int CheckChunkEncoding(HI_SESSION*, const u_char*, const u_char*, const u_char **, u_char*,
uint32_t, uint32_t, uint32_t*, uint32_t*, HttpSessionData*, int);
extern int IsHttpVersion(const u_char**, const u_char*);
extern const u_char* extract_http_cookie(const u_char* p, const u_char* end, HEADER_PTR*,
    HEADER_FIELD_PTR*);
extern const u_char* extract_http_content_length(HI_SESSION*, HTTPINSPECT_CONF*, const u_char*,
    const u_char*, const u_char*, HEADER_PTR*, HEADER_FIELD_PTR*);

extern const u_char* extract_http_transfer_encoding(HI_SESSION*, HttpSessionData*,
    const u_char*, const u_char*, const u_char*, HEADER_PTR*, int);
#endif


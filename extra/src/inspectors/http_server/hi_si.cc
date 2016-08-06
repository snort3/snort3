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
**  @file       hi_si.c
**
**  @author     Daniel J. Roelker <droelker@sourcefire.com>
**
**  @brief      This file contains functions to select server configurations
**              and begin the HttpInspect process.
**
**  The session Inspection Module interfaces with the Stream Inspection
**  Module and the User Interface Module to select the appropriate
**  HttpInspect configuration and in the case of stateful inspection the
**  session Inspection Module retrieves the user-data from the Stream
**  Module.  For stateless inspection, the session Inspection Module uses
**  the same structure for use by each packet.
**
**  The main responsibility of this module is to supply the appropriate
**  data structures and configurations for the rest of the HttpInspect
**  process.  The module also determines what type of data is being
**  inspected, whether it is client, server, or neither.
**
**  NOTES:
**
**  - 2.25.03:  Initial Development.  DJR
*/
#include "hi_si.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "hi_return_codes.h"
#include "hi_ui_config.h"
#include "hi_ad.h"
#include "hi_main.h"
#include "stream/stream_api.h"

/*
**  NAME
**    InitServerConf::
*/
/*
**  IMPORTANT NOTE:
**    We should check to make sure that there are some unique configurations,
**    otherwise we can just default to the global default and work some magic
**    that way.
**
**  @param GlobalConf     pointer to the global configuration
**  @param ServerConf     pointer to the address of the server config so we can
**                        set it.
**  @param SiInput        pointer to the packet info (sip,dip,sport,dport)
**  @param piInspectMode  pointer so we can set the inspection mode
**
**  @return integer
**
**  @retval HI_SUCCESS  function successful
*/
static int InitServerConf(HTTPINSPECT_CONF* GlobalConf,
    HTTPINSPECT_CONF** ServerConf,
    HTTPINSPECT_CONF** ClientConf,
    HI_SI_INPUT* SiInput, int* piInspectMode, Packet* p)
{
    HTTPINSPECT_CONF* ServerConfSip;
    HTTPINSPECT_CONF* ServerConfDip;
    int iServerSip;
    int iServerDip;
    int http_id_found = 0;
    sfip_t sip;
    sfip_t dip;

    //structure copy
    sip = SiInput->sip;
    dip = SiInput->dip;

    if (sip.family == AF_INET)
    {
        sip.ip32[0] = ntohl(sip.ip32[0]);
    }
    if (dip.family == AF_INET)
    {
        dip.ip32[0] = ntohl(dip.ip32[0]);
    }

    ServerConfDip = ServerConfSip = GlobalConf;

    /*
    **  We check the IP and the port to see if the HTTP server is talking in
    **  the session.  This should tell us whether it is client communication
    **  or server configuration.  If both IPs and ports are servers, then there
    **  is a sort of problem.  We don't know which side is the client and which
    **  side is the server so we have to assume one.
    **
    **  In stateful processing, we only do this stage on the startup of a
    **  session, so we can still assume that the initial packet is the client
    **  talking.
    */
    iServerSip = (p->is_from_server());
    iServerDip = (p->is_from_client());

    /*
    **  We default to the no HTTP traffic case
    */
    *piInspectMode = HI_SI_NO_MODE;
    *ServerConf = NULL;

    /*
    **  Depending on the type of packet direction we get from the
    **  state machine, we evaluate client/server differently.
    */
    switch (SiInput->pdir)
    {
    case HI_SI_NO_MODE:
        /*
        **  We check for the case where both SIP and DIP
        **  appear to be servers.  In this case, we assume client
        **  and process that way.
        */
        if (iServerSip && iServerDip)
        {
            *piInspectMode = HI_SI_CLIENT_MODE;
            *ServerConf = ServerConfDip;
            *ClientConf = ServerConfSip;
        }
        else if (iServerSip)
        {
            *piInspectMode = HI_SI_SERVER_MODE;
            *ServerConf = ServerConfSip;
            *ClientConf = ServerConfDip;
        }
        else if (iServerDip)
        {
            *piInspectMode = HI_SI_CLIENT_MODE;
            *ServerConf = ServerConfDip;
            *ClientConf = ServerConfSip;
        }
        break;

    case HI_SI_CLIENT_MODE:
        if (iServerDip || http_id_found)
        {
            *piInspectMode = HI_SI_CLIENT_MODE;
            *ServerConf = ServerConfDip;
            *ClientConf = ServerConfSip;
        }
        break;

    case HI_SI_SERVER_MODE:
        if (iServerSip || http_id_found)
        {
            *piInspectMode = HI_SI_SERVER_MODE;
            *ServerConf = ServerConfSip;
            *ClientConf = ServerConfDip;
        }
        break;

    default:
        *piInspectMode = HI_SI_NO_MODE;
        *ServerConf = NULL;
        *ClientConf = NULL;
        break;
    }

    return HI_SUCCESS;
}

/*
**  NAME
**    Resetsession::
*/
/**
**  This function resets all the variables that need to be initialized for
**  a new session.  I've tried to keep this to a minimum, so we don't have
**  to worry about initializing big structures.
**
**  @param session  pointer to the session to reset
**
**  @return integer
**
**  @retval HI_SUCCESS
*/
static inline int Resetsession(HI_SESSION* session)
{
    memset(&session->client.request, 0, sizeof(session->client.request));
    memset(&session->server.response, 0, sizeof(session->server.response));

    return HI_SUCCESS;
}

/*
**  NAME
**    StatelesssessionInspection::
*/
/**
**  Initialize the session and server configurations for this packet/stream.
**
**  It is important to note in stateless mode that we assume no knowledge of the
**  state of a connection, other than the knowledge that we can glean from an
**  individual packet.  So in essence, each packet is it's own session and there
**  is no knowledge retained from one packet to another.  If you want to track
**  an HTTP session for real, use stateful mode.
**
**  In this function, we set the session pointer (which includes the correct
**  server configuration).  The actual processing to find which IP is the
**  server and which is the client, is done in the InitServerConf() function.
**
**  @param GlobalConf    pointer to the global configuration
**  @param session       double pointer to the session structure
**  @param SiInput       pointer to the session information
**  @param piInspectMode pointer so the inspection mode can be set
**
**  @return integer
**
**  @retval HI_SUCCESS function successful
*/
int hi_si_session_inspection(
    HTTPINSPECT_CONF* conf, HI_SESSION** session,
    HI_SI_INPUT* SiInput, int* piInspectMode, Packet* p)
{
    static THREAD_LOCAL HI_SESSION Staticsession;
    HTTPINSPECT_CONF* ServerConf = NULL;
    HTTPINSPECT_CONF* ClientConf = NULL;
    int iRet;

    Resetsession(&Staticsession);

    iRet = InitServerConf(conf, &ServerConf, &ClientConf, SiInput, piInspectMode, p);
    if (iRet)
    {
        return iRet;
    }

    Staticsession.server_conf = ServerConf;
    Staticsession.client_conf = ClientConf;
    Staticsession.global_conf = conf->global;

    *session = &Staticsession;

    return HI_SUCCESS;
}


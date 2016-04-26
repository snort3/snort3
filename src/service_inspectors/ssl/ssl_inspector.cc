//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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
//

/*
 * SSL inspector
 *
 */

#include "ssl_inspector.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>

#include "events/event_queue.h"
#include "log/messages.h"
#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "profiler/profiler.h"
#include "stream/stream_api.h"
#include "parser/parser.h"
#include "framework/inspector.h"
#include "utils/sfsnprintfappend.h"
#include "target_based/snort_protocols.h"
#include "detection/detect.h"
#include "protocols/ssl.h"

#include "ssl_module.h"

THREAD_LOCAL ProfileStats sslPerfStats;
THREAD_LOCAL SslStats sslstats;

/*
 * Function prototype(s)
 */
static void snort_ssl(SSL_PROTO_CONF* GlobalConf, Packet* p);

unsigned SslFlowData::flow_id = 0;

const PegInfo ssl_peg_names[] =
{
    { "packets", "total packets processed" },
    { "decoded", "ssl packets decoded" },
    { "client hello", "total client hellos" },
    { "server hello", "total server hellos" },
    { "certificate", "total ssl certificates" },
    { "server done", "total server done" },
    { "client key exchange", "total client key exchanges" },
    { "server key exchange", "total server key exchanges" },
    { "change cipher", "total change cipher records" },
    { "finished", "total handshakes finished" },
    { "client application", "total client application records" },
    { "server application", "total server application records" },
    { "alert", "total ssl alert records" },
    { "unrecognized records", "total unrecognized records" },
    { "handshakes completed", "total completed ssl handshakes" },
    { "bad handshakes", "total bad handshakes" },
    { "sessions ignored", "total sessions ignore" },
    { "detection disabled", "total detection disabled" },

    { nullptr, nullptr }
};

static SSLData* SetNewSSLData(Packet* p)
{
    SslFlowData* fd = new SslFlowData;
    p->flow->set_application_data(fd);
    return &fd->session;
}

SSLData* get_ssl_session_data(Flow* flow)
{
    SslFlowData* fd = (SslFlowData*)flow->get_application_data(
        SslFlowData::flow_id);

    return fd ? &fd->session : NULL;
}

static void PrintSslConf(SSL_PROTO_CONF* config)
{
    if (config == NULL)
        return;
    LogMessage("SSL config:\n");
    if ( config->trustservers )
    {
        LogMessage("    Server side data is trusted\n");
    }

    LogMessage("\n");
}

static void SSL_UpdateCounts(const uint32_t new_flags)
{
    if (new_flags & SSL_CHANGE_CIPHER_FLAG)
        sslstats.cipher_change++;

    if (new_flags & SSL_ALERT_FLAG)
        sslstats.alerts++;

    if (new_flags & SSL_CLIENT_HELLO_FLAG)
        sslstats.hs_chello++;

    if (new_flags & SSL_SERVER_HELLO_FLAG)
        sslstats.hs_shello++;

    if (new_flags & SSL_CERTIFICATE_FLAG)
        sslstats.hs_cert++;

    if (new_flags & SSL_SERVER_KEYX_FLAG)
        sslstats.hs_skey++;

    if (new_flags & SSL_CLIENT_KEYX_FLAG)
        sslstats.hs_ckey++;

    if (new_flags & SSL_SFINISHED_FLAG)
        sslstats.hs_finished++;

    if (new_flags & SSL_HS_SDONE_FLAG)
        sslstats.hs_sdone++;

    if (new_flags & SSL_SAPP_FLAG)
        sslstats.sapp++;

    if (new_flags & SSL_CAPP_FLAG)
        sslstats.capp++;
}

static inline bool SSLPP_is_encrypted(SSL_PROTO_CONF* config, uint32_t ssl_flags, Packet* packet)
{
    if (config->trustservers)
    {
        if (ssl_flags & SSL_SAPP_FLAG)
            return true;
    }

    if (SSL_IS_CLEAN(ssl_flags))
    {
        if (((ssl_flags & SSLPP_ENCRYPTED_FLAGS) == SSLPP_ENCRYPTED_FLAGS) ||
            ((ssl_flags & SSLPP_ENCRYPTED_FLAGS2) == SSLPP_ENCRYPTED_FLAGS2))
        {
            sslstats.completed_hs++;
            return true;
        }
        /* Check if we're either midstream or if packets were missed after the
         *          * connection was established */
        else if ((packet->flow->get_session_flags() & SSNFLAG_MIDSTREAM) ||
            (stream.missed_packets(packet->flow, SSN_DIR_BOTH)))
        {
            if ((ssl_flags & (SSL_CAPP_FLAG | SSL_SAPP_FLAG)) == (SSL_CAPP_FLAG | SSL_SAPP_FLAG))
            {
                return true;
            }
        }
    }

    return false;
}

static inline uint32_t SSLPP_process_alert(
    SSL_PROTO_CONF*, uint32_t ssn_flags, uint32_t new_flags, const Packet* packet)
{
    DebugMessage(DEBUG_SSL, "Process Alert\n");

    ssn_flags |= new_flags;

    /* Check if we've seen a handshake, that this isn't it,
     *      * that the cipher flags is not set, and that we are disabling detection */
    if (SSL_IS_HANDSHAKE(ssn_flags) &&
        !SSL_IS_HANDSHAKE(new_flags) &&
        !(new_flags & SSL_CHANGE_CIPHER_FLAG) &&
        !(new_flags & SSL_HEARTBEAT_SEEN))
    {
        DebugMessage(DEBUG_SSL, "Disabling detect\n");
        DisableDetect();
    }

    /* Need to negate the application flags from the opposing side. */

    if (packet->is_from_client())
        return ssn_flags & ~SSL_SAPP_FLAG;

    else if (packet->is_from_server())
        return ssn_flags & ~SSL_CAPP_FLAG;

    return ssn_flags;
}

static inline uint32_t SSLPP_process_hs(uint32_t ssl_flags, uint32_t new_flags)
{
    DebugMessage(DEBUG_SSL, "Process Handshake\n");

    if (!SSL_BAD_HS(new_flags))
    {
        ssl_flags |= new_flags & (SSL_CLIENT_HELLO_FLAG |
            SSL_SERVER_HELLO_FLAG |
            SSL_CLIENT_KEYX_FLAG |
            SSL_SFINISHED_FLAG);
    }
    else
    {
        sslstats.bad_handshakes++;
    }

    return ssl_flags;
}

static inline uint32_t SSLPP_process_app(SSL_PROTO_CONF* config, uint32_t ssn_flags, uint32_t
    new_flags, Packet* packet)
{
    DebugMessage(DEBUG_SSL, "Process Application\n");

    if (SSLPP_is_encrypted(config, ssn_flags | new_flags, packet) )
    {
        ssn_flags |= SSL_ENCRYPTED_FLAG;

        // Heartbleed check is disabled. Stop inspection on this session.
        if (!config->max_heartbeat_len)
        {
            DebugMessage(DEBUG_SSL, "STOPPING INSPECTION (process_app)\n");
            stream.stop_inspection(packet->flow, packet, SSN_DIR_BOTH, -1, 0);
            sslstats.stopped++;
        }
        else if (!(new_flags & SSL_HEARTBEAT_SEEN))
        {
            DisableDetect();
        }
    }

    return ssn_flags | new_flags;
}

static inline void SSLPP_process_other(SSL_PROTO_CONF* config, SSLData* sd, uint32_t new_flags,
    Packet* packet)
{
    /* Encrypted SSLv2 will appear unrecognizable.  Check if the handshake was
     *      * seen and stop inspecting if so. */
    /* Check for an existing handshake from both sides */
    if ((sd->ssn_flags & SSL_VER_SSLV2_FLAG) &&
        SSL_IS_CHELLO(sd->ssn_flags) && SSL_IS_SHELLO(sd->ssn_flags) &&
        !(new_flags & SSL_CHANGE_CIPHER_FLAG) &&
        !(new_flags & SSL_HEARTBEAT_SEEN))
    {
        sd->ssn_flags |= SSL_ENCRYPTED_FLAG | new_flags;

        if (!config->max_heartbeat_len)
        {
            DebugMessage(DEBUG_SSL, "STOPPING INSPECTION (process_other)\n");
            stream.stop_inspection(packet->flow, packet, SSN_DIR_BOTH, -1, 0);
        }
        else if (!(new_flags & SSL_HEARTBEAT_SEEN))
        {
            DisableDetect();
        }
    }
    else
    {
        sslstats.unrecognized++;

        /* Special handling for SSLv2 */
        if (new_flags & SSL_VER_SSLV2_FLAG)
            sd->ssn_flags |= new_flags;

        if (new_flags & SSL_UNKNOWN_FLAG)
            sd->ssn_flags |= new_flags;
    }
}

/* Main runtime entry point for SSL preprocessor.
 * Analyzes SSL packets for anomalies/exploits.
 *
 * PARAMETERS:
 *
 * p:    Pointer to current packet to process.
 * contextp:    Pointer to context block, not used.
 *
 * RETURNS:     Nothing.
 */
static void snort_ssl(SSL_PROTO_CONF* config, Packet* p)
{
    Profile profile(sslPerfStats);

    /* Attempt to get a previously allocated SSL block. */
    SSLData* sd = get_ssl_session_data(p->flow);

    if (sd == NULL)
    {
        /* Check the stream session. If it does not currently
         * have our SSL data-block attached, create one.
         */
        sd = SetNewSSLData(p);

        if ( !sd )
            // Could not get/create the session data for this packet.
            return;
    }

    SSL_CLEAR_TEMPORARY_FLAGS(sd->ssn_flags);

    uint8_t dir = (p->is_from_server()) ? 1 : 0;
    uint8_t index = (p->packet_flags & PKT_REBUILT_STREAM) ? 2 : 0;

    uint8_t heartbleed_type = 0;
    uint32_t new_flags = SSL_decode(p->data, (int)p->dsize, p->packet_flags, sd->ssn_flags,
        &heartbleed_type, &(sd->partial_rec_len[dir+index]), config->max_heartbeat_len);

    if (heartbleed_type & SSL_HEARTBLEED_REQUEST)
    {
        SnortEventqAdd(GID_SSL, SSL_ALERT_HB_REQUEST);
    }
    else if (heartbleed_type & SSL_HEARTBLEED_RESPONSE)
    {
        SnortEventqAdd(GID_SSL, SSL_ALERT_HB_RESPONSE);
    }
    else if (heartbleed_type & SSL_HEARTBLEED_UNKNOWN)
    {
        if (!dir)
        {
            SnortEventqAdd(GID_SSL, SSL_ALERT_HB_REQUEST);
        }
        else
        {
            SnortEventqAdd(GID_SSL, SSL_ALERT_HB_RESPONSE);
        }
    }
    if (sd->ssn_flags & SSL_ENCRYPTED_FLAG )
    {
        sslstats.decoded++;

        SSL_UpdateCounts(new_flags);

        if (!(new_flags & SSL_HEARTBEAT_SEEN))
        {
            DisableDetect();
        }

        sd->ssn_flags |= new_flags;

        return;
    }

// If the client used an SSLv2 ClientHello with an SSLv3/TLS version and
// the server replied with an SSLv3/TLS ServerHello, remove the backward
// compatibility flag and the SSLv2 flag since this session will continue
// as SSLv3/TLS.

    if ((sd->ssn_flags & SSL_V3_BACK_COMPAT_V2) && SSL_V3_SERVER_HELLO(new_flags))
        sd->ssn_flags &= ~(SSL_VER_SSLV2_FLAG|SSL_V3_BACK_COMPAT_V2);

    if ( (SSL_IS_CHELLO(new_flags) && SSL_IS_CHELLO(sd->ssn_flags) && SSL_IS_SHELLO(sd->ssn_flags) )
            || (SSL_IS_CHELLO(new_flags) && SSL_IS_SHELLO(sd->ssn_flags) ))
    {
        SnortEventqAdd(GID_SSL, SSL_INVALID_CLIENT_HELLO);
    }
    else if (!(config->trustservers))
    {
        if ( (SSL_IS_SHELLO(new_flags) && !SSL_IS_CHELLO(sd->ssn_flags) ))
        {
            if (!(stream.missed_packets(p->flow, SSN_DIR_FROM_CLIENT)))
                SnortEventqAdd(GID_SSL, SSL_INVALID_SERVER_HELLO);
        }
    }

    sslstats.decoded++;

    SSL_UpdateCounts(new_flags);

    /* Note, there can be multiple record types in each SSL packet.
     *      * Processing them in this order is intentional.  If there is an
     *           * Alert, we don't care about the other records */

    if (SSL_IS_ALERT(new_flags))
    {
        sd->ssn_flags = SSLPP_process_alert(config, sd->ssn_flags, new_flags, p);
    }
    else if (SSL_IS_HANDSHAKE(new_flags))
    {
        sd->ssn_flags = SSLPP_process_hs(sd->ssn_flags, new_flags);
    }
    else if (SSL_IS_APP(new_flags))
    {
        sd->ssn_flags = SSLPP_process_app(config, sd->ssn_flags, new_flags, p);
    }
    else
    {
        /* Different record type that we don't care about.
         *          * Either it's a 'change cipher spec' or we failed to recognize the
         *                   * record type.  Do not update session data */
        SSLPP_process_other(config, sd, new_flags, p);

        /* Application data is updated inside of SSLPP_process_other */

        return;
    }

    sd->ssn_flags |= new_flags;
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Ssl : public Inspector
{
public:
    Ssl(SSL_PROTO_CONF*);
    ~Ssl();

    void show(SnortConfig*) override;
    void eval(Packet*) override;

private:
    SSL_PROTO_CONF* config;
};

Ssl::Ssl(SSL_PROTO_CONF* pc)
{
    config = pc;
}

Ssl::~Ssl()
{
    if ( config )
        delete config;
}

void Ssl::show(SnortConfig*)
{
    PrintSslConf(config);
}

void Ssl::eval(Packet* p)
{
    // precondition - what we registered for
    assert(p->has_tcp_data());
    assert(p->flow);

    sslstats.packets++;
    snort_ssl(config, p);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new SslModule; }

static void mod_dtor(Module* m)
{ delete m; }

static void ssl_init()
{
    SslFlowData::init();
}

static Inspector* ssl_ctor(Module* m)
{
    SslModule* mod = (SslModule*)m;
    return new Ssl(mod->get_data());
}

static void ssl_dtor(Inspector* p)
{
    delete p;
}

const InspectApi ssl_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        SSL_NAME,
        SSL_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    (uint16_t)PktType::PDU,
    nullptr, // buffers
    "ssl",
    ssl_init,
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ssl_ctor,
    ssl_dtor,
    nullptr, // ssn
    nullptr  // reset
};

// can't be linked dynamically yet
//#ifdef BUILDING_SO
//SO_PUBLIC const BaseApi* snort_plugins[] =
//{
//    &ssl_api.base,
//    nullptr
//};
//#else
const BaseApi* sin_ssl = &ssl_api.base;
//#endif


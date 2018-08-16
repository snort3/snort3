//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// SSL inspector

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ssl_inspector.h"

#include "detection/detect.h"
#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "log/messages.h"
#include "main/snort_debug.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "protocols/ssl.h"
#include "stream/stream.h"
#include "stream/stream_splitter.h"

#include "ssl_module.h"
#include "ssl_splitter.h"

using namespace snort;

THREAD_LOCAL ProfileStats sslPerfStats;
THREAD_LOCAL SslStats sslstats;

unsigned SslFlowData::inspector_id = 0;

const PegInfo ssl_peg_names[] =
{
    { CountType::SUM, "packets", "total packets processed" },
    { CountType::SUM, "decoded", "ssl packets decoded" },
    { CountType::SUM, "client_hello", "total client hellos" },
    { CountType::SUM, "server_hello", "total server hellos" },
    { CountType::SUM, "certificate", "total ssl certificates" },
    { CountType::SUM, "server_done", "total server done" },
    { CountType::SUM, "client_key_exchange", "total client key exchanges" },
    { CountType::SUM, "server_key_exchange", "total server key exchanges" },
    { CountType::SUM, "change_cipher", "total change cipher records" },
    { CountType::SUM, "finished", "total handshakes finished" },
    { CountType::SUM, "client_application", "total client application records" },
    { CountType::SUM, "server_application", "total server application records" },
    { CountType::SUM, "alert", "total ssl alert records" },
    { CountType::SUM, "unrecognized_records", "total unrecognized records" },
    { CountType::SUM, "handshakes_completed", "total completed ssl handshakes" },
    { CountType::SUM, "bad_handshakes", "total bad handshakes" },
    { CountType::SUM, "sessions_ignored", "total sessions ignore" },
    { CountType::SUM, "detection_disabled", "total detection disabled" },
    { CountType::NOW, "concurrent_sessions", "total concurrent ssl sessions" },
    { CountType::MAX, "max_concurrent_sessions", "maximum concurrent ssl sessions" },

    { CountType::END, nullptr, nullptr }
};

SslFlowData::SslFlowData() : FlowData(inspector_id)
{
    memset(&session, 0, sizeof(session));
    sslstats.concurrent_sessions++;
    if(sslstats.max_concurrent_sessions < sslstats.concurrent_sessions)
        sslstats.max_concurrent_sessions = sslstats.concurrent_sessions;
}

SslFlowData::~SslFlowData()
{
    assert(sslstats.concurrent_sessions > 0);
    sslstats.concurrent_sessions--;
}

static SSLData* SetNewSSLData(Packet* p)
{
    SslFlowData* fd = new SslFlowData;
    p->flow->set_flow_data(fd);
    return &fd->session;
}

SSLData* get_ssl_session_data(Flow* flow)
{
    SslFlowData* fd = (SslFlowData*)flow->get_flow_data(SslFlowData::inspector_id);
    return fd ? &fd->session : nullptr;
}

static void PrintSslConf(SSL_PROTO_CONF* config)
{
    if (config == nullptr)
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
        else if ( packet->test_session_flags(SSNFLAG_MIDSTREAM) ||
            (Stream::missed_packets(packet->flow, SSN_DIR_BOTH)))
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
    SSL_PROTO_CONF*, uint32_t ssn_flags, uint32_t new_flags, Packet* packet)
{
    ssn_flags |= new_flags;

    /* Check if we've seen a handshake, that this isn't it,
     *      * that the cipher flags is not set, and that we are disabling detection */
    if (SSL_IS_HANDSHAKE(ssn_flags) &&
        !SSL_IS_HANDSHAKE(new_flags) &&
        !(new_flags & SSL_CHANGE_CIPHER_FLAG) &&
        !(new_flags & SSL_HEARTBEAT_SEEN))
    {
        DetectionEngine::disable_content(packet);
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
    if (SSLPP_is_encrypted(config, ssn_flags | new_flags, packet) )
    {
        ssn_flags |= SSL_ENCRYPTED_FLAG;

        // Heartbleed check is disabled. Stop inspection on this session.
        if (!config->max_heartbeat_len)
        {
            Stream::stop_inspection(packet->flow, packet, SSN_DIR_BOTH, -1, 0);
            sslstats.stopped++;
        }
        else if (!(new_flags & SSL_HEARTBEAT_SEEN))
        {
            DetectionEngine::disable_content(packet);
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
            Stream::stop_inspection(packet->flow, packet, SSN_DIR_BOTH, -1, 0);
        }
        else if (!(new_flags & SSL_HEARTBEAT_SEEN))
        {
            DetectionEngine::disable_content(packet);
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

    if (sd == nullptr)
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
        DetectionEngine::queue_event(GID_SSL, SSL_ALERT_HB_REQUEST);
    }
    else if (heartbleed_type & SSL_HEARTBLEED_RESPONSE)
    {
        DetectionEngine::queue_event(GID_SSL, SSL_ALERT_HB_RESPONSE);
    }
    else if (heartbleed_type & SSL_HEARTBLEED_UNKNOWN)
    {
        if (!dir)
        {
            DetectionEngine::queue_event(GID_SSL, SSL_ALERT_HB_REQUEST);
        }
        else
        {
            DetectionEngine::queue_event(GID_SSL, SSL_ALERT_HB_RESPONSE);
        }
    }
    if (sd->ssn_flags & SSL_ENCRYPTED_FLAG )
    {
        sslstats.decoded++;

        SSL_UpdateCounts(new_flags);

        if (!(new_flags & SSL_HEARTBEAT_SEEN))
        {
            DetectionEngine::disable_content(p);
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
        DetectionEngine::queue_event(GID_SSL, SSL_INVALID_CLIENT_HELLO);
    }
    else if (!(config->trustservers))
    {
        if ( (SSL_IS_SHELLO(new_flags) && !SSL_IS_CHELLO(sd->ssn_flags) ))
        {
            if (!(Stream::missed_packets(p->flow, SSN_DIR_FROM_CLIENT)))
                DetectionEngine::queue_event(GID_SSL, SSL_INVALID_SERVER_HELLO);
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
    ~Ssl() override;

    void show(SnortConfig*) override;
    void eval(Packet*) override;

    StreamSplitter* get_splitter(bool c2s) override
    { return new SslSplitter(c2s); }

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
    PROTO_BIT__PDU,
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

#undef BUILDING_SO  // FIXIT-L can't be linked dynamically yet

extern const BaseApi* ips_ssl_state;
extern const BaseApi* ips_ssl_version;

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* sin_ssl[] =
#endif
{
    &ssl_api.base,
    ips_ssl_state,
    ips_ssl_version,
    nullptr
};


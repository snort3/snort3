//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2004-2013 Sourcefire, Inc.
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

/*
 * SSH preprocessor
 * Author: Chris Sherwin
 * Contributors: Adam Keeton, Ryan Jordan
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ssh.h"

#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "stream/stream.h"

#include "ssh_module.h"

using namespace snort;

THREAD_LOCAL ProfileStats sshPerfStats;
THREAD_LOCAL SshStats sshstats;

/*
 * Function prototype(s)
 */
static void snort_ssh(SSH_PROTO_CONF* GlobalConf, Packet* p);
static unsigned int ProcessSSHProtocolVersionExchange(SSH_PROTO_CONF*, SSHData*, Packet*, uint8_t);
static unsigned int ProcessSSHKeyExchange(SSHData*, Packet*, uint8_t, unsigned int);
static unsigned int ProcessSSHKeyInitExchange(SSHData*, Packet*, uint8_t, unsigned int);

unsigned SshFlowData::inspector_id = 0;

SshFlowData::SshFlowData() : FlowData(inspector_id)
{
    memset(&session, 0, sizeof(session));
    sshstats.concurrent_sessions++;
    if(sshstats.max_concurrent_sessions < sshstats.concurrent_sessions)
        sshstats.max_concurrent_sessions = sshstats.concurrent_sessions;
}

SshFlowData::~SshFlowData()
{
    assert(sshstats.concurrent_sessions > 0);
    sshstats.concurrent_sessions--;
}

static SSHData* SetNewSSHData(Packet* p)
{
    SshFlowData* fd = new SshFlowData;
    p->flow->set_flow_data(fd);
    return &fd->session;
}

static SSHData* get_session_data(Flow* flow)
{
    SshFlowData* fd = (SshFlowData*)flow->get_flow_data(SshFlowData::inspector_id);
    return fd ? &fd->session : nullptr;
}

static void PrintSshConf(SSH_PROTO_CONF* config)
{
    if ( !config )
        return;

    LogMessage("SSH config: \n");

    LogMessage("    Max Encrypted Packets: %d\n", config->MaxEncryptedPackets);
    LogMessage("    Max Server Version String Length: %d\n", config->MaxServerVersionLen);
    LogMessage("    MaxClientBytes: %d\n", config->MaxClientBytes);

    LogMessage("\n");
}

/* Returns the true length of the ssh packet, including
 * the ssh packet header and all padding.
 *
 * If the packet length is invalid, 0 is returned.
 * The return value is never larger than buflen.
 *
 * PARAMETERS:
 * p: Pointer to the SSH packet.
 * buflen: the size of packet buffer.
*/
static unsigned int SSHPacket_GetLength(const SSH2Packet* p, size_t buflen)
{
    unsigned int ssh_length;

    if (buflen < sizeof(SSH2Packet))
        return 0;

    ssh_length = ntohl(p->packet_length);
    if ((ssh_length < sizeof(SSH2Packet) + 1) || ssh_length > SSH2_PACKET_MAX_SIZE)
        return 0;

    /* Everything after packet length field (including padding) is included in the packet_length */
    ssh_length += sizeof(p->packet_length);

    if (buflen < ssh_length)
        return buflen; /* truncated */

    return ssh_length;
}

/* Main runtime entry point for SSH preprocessor.
 * Analyzes SSH packets for anomalies/exploits.
 *
 * PARAMETERS:
 *
 * p:    Pointer to current packet to process.
 * contextp:    Pointer to context block, not used.
 *
 * RETURNS:     Nothing.
 */
static void snort_ssh(SSH_PROTO_CONF* config, Packet* p)
{
    Profile profile(sshPerfStats);

    // Attempt to get a previously allocated SSH block.
    SSHData* sessp = get_session_data(p->flow);

    if (sessp == nullptr)
    {
        /* Check the stream session. If it does not currently
         * have our SSH data-block attached, create one.
         */
        sessp = SetNewSSHData(p);

        if ( !sessp )
            // Could not get/create the session data for this packet.
            return;

    }

    // Don't process if we've missed packets
    if (sessp->state_flags & SSH_FLG_MISSED_PACKETS)
        return;

    // Make sure this preprocessor should run.
    // check if we're waiting on stream reassembly
    if ( p->packet_flags & PKT_STREAM_INSERT )
        return;

    // If we picked up mid-stream or missed any packets (midstream pick up
    // means we've already missed packets) set missed packets flag and make
    // sure we don't do any more reassembly on this session
    if ( p->test_session_flags(SSNFLAG_MIDSTREAM)
        || Stream::missed_packets(p->flow, SSN_DIR_BOTH) )
    {
        // Order only matters if the packets are not encrypted
        if ( !(sessp->state_flags & SSH_FLG_SESS_ENCRYPTED ))
        {
            sessp->state_flags |= SSH_FLG_MISSED_PACKETS;
            return;
        }
    }

    uint8_t direction;
    uint32_t search_dir_ver;
    uint32_t search_dir_keyinit;

    // Get the direction of the packet.
    if ( p->is_from_server() )
    {
        direction = SSH_DIR_FROM_SERVER;
        search_dir_ver = SSH_FLG_SERV_IDSTRING_SEEN;
        search_dir_keyinit = SSH_FLG_SERV_PKEY_SEEN | SSH_FLG_SERV_KEXINIT_SEEN;
    }
    else
    {
        direction = SSH_DIR_FROM_CLIENT;
        search_dir_ver = SSH_FLG_CLIENT_IDSTRING_SEEN;
        search_dir_keyinit = SSH_FLG_CLIENT_SKEY_SEEN | SSH_FLG_CLIENT_KEXINIT_SEEN;
    }

    unsigned int offset = 0;

    if ( !(sessp->state_flags & SSH_FLG_SESS_ENCRYPTED ))
    {
        // If server and client have not performed the protocol
        // version exchange yet, must look for version strings.
        if ( !(sessp->state_flags & search_dir_ver) )
        {
            offset = ProcessSSHProtocolVersionExchange(config, sessp, p, direction);
            if (!offset)
                // Error processing protovers exchange msg 
                return;

            // found protocol version.
            // Stream reassembly might have appended an ssh packet,
            // such as the key exchange init.
            // Thus call ProcessSSHKeyInitExchange() too.
        }

        // Expecting to see the key init exchange at this point
        // (in SSH2) or the actual key exchange if SSH1
        if ( !(sessp->state_flags & search_dir_keyinit) )
        {
            offset = ProcessSSHKeyInitExchange(sessp, p, direction, offset);

            if (!offset)
            {
                if ( !(sessp->state_flags & SSH_FLG_SESS_ENCRYPTED ))
                    return;
            }
        }

        // If SSH2, need to process the actual key exchange msgs.
        // The actual key exchange type was negotiated in the
        // key exchange init msgs. SSH1 won't arrive here.
        offset = ProcessSSHKeyExchange(sessp, p, direction, offset);
        if (!offset)
            return;
    }

    if ( (sessp->state_flags & SSH_FLG_SESS_ENCRYPTED ))
    {
        // Traffic on this session is currently encrypted.
        // Two of the major SSH exploits, SSH1 CRC-32 and
        // the Challenge-Response Overflow attack occur within
        // the encrypted portion of the SSH session. Therefore,
        // the only way to detect these attacks is by examining
        // amounts of data exchanged for anomalies.
        sessp->num_enc_pkts++;

        if ( sessp->num_enc_pkts <= config->MaxEncryptedPackets )
        {
            if ( direction == SSH_DIR_FROM_CLIENT )
            {
                if (!offset)
                    sessp->num_client_bytes += p->dsize;

                else
                    sessp->num_client_bytes += (p->dsize - offset);

                if ( sessp->num_client_bytes >= config->MaxClientBytes )
                {
                    // Probable exploit in progress.
                    if (sessp->version == SSH_VERSION_1)
                        DetectionEngine::queue_event(GID_SSH, SSH_EVENT_CRC32);

                    else
                        DetectionEngine::queue_event(GID_SSH, SSH_EVENT_RESPOVERFLOW);

                    Stream::stop_inspection(p->flow, p, SSN_DIR_BOTH, -1, 0);
                }
            }

            else
            {
                 // Have seen a server response, so this appears to be a valid
                 // exchange. Reset suspicious byte count to zero
                sessp->num_client_bytes = 0;
            }
        }

        else
        {
            // Have already examined more than the limit
            // of encrypted packets. Both the Gobbles and
            // the CRC32 attacks occur during authentication
            // and therefore cannot be used late in an
            // encrypted session. For performance purposes,
            // stop examining this session.
            Stream::stop_inspection(p->flow, p, SSN_DIR_BOTH, -1, 0);
        }
    }
}

/* Checks if the string 'str' is 'max' bytes long or longer.
 * Returns 0 if 'str' is less than or equal to 'max' bytes;
 * returns 1 otherwise.
*/

static inline int SSHCheckStrlen(const char* str, int max)
{
    if ( memchr(str, '\0', max) )
        return 0;           /* str size is <= max bytes */

    return 1;
}

/* Attempts to process current packet as a protocol version exchange
 * packet. This function will be called if either the client or server
 * protocol version message (or both) has not been sent.
 *
 * PARAMETERS:
 *
 * sessionp:    Pointer to SSH data for packet's session.
 * p:    Pointer to the packet to inspect.
 * direction:     Which direction the packet is going.
 *
 * RETURNS:  offset processed
 */
static unsigned int ProcessSSHProtocolVersionExchange(SSH_PROTO_CONF* config, SSHData* sessionp,
    Packet* p, uint8_t direction)
{
    const char* version_stringp = (const char*)p->data;
    const char* version_end;

    /* Get the version. */
    if ( p->dsize >= 6 &&
        !strncasecmp(version_stringp, "SSH-1.", 6))
    {
        if (( p->dsize > 7 ) && ( version_stringp[6] == '9')
            && (version_stringp[7] == '9'))
        {
            /* SSH 1.99 which is the same as SSH2.0 */
            sessionp->version = SSH_VERSION_2;
        }
        else
        {
            sessionp->version = SSH_VERSION_1;
        }

        /* CAN-2002-0159 */
        /* Verify the version string is not greater than
         * the configured maximum.
         * We've already verified the first 6 bytes, so we'll start
         * check from &version_string[6] */
        /* First make sure the data itself is sufficiently large */
        if ((p->dsize > config->MaxServerVersionLen) &&
            /* CheckStrlen will check if the version string up to
             * MaxServerVersionLen+1 since there's no reason to
             * continue checking after that point*/
            (SSHCheckStrlen(&version_stringp[6], config->MaxServerVersionLen-6)))
        {
            DetectionEngine::queue_event(GID_SSH, SSH_EVENT_SECURECRT);
        }
    }
    else if ( p->dsize >= 6 &&
        !strncasecmp(version_stringp, "SSH-2.", 6))
    {
        sessionp->version = SSH_VERSION_2;
    }
    else
    {
        /* unknown version */ 
        sessionp->version =  SSH_VERSION_UNKNOWN;

        DetectionEngine::queue_event(GID_SSH, SSH_EVENT_VERSION);
        
        return 0;
    }

    /* Saw a valid protocol exchange message. Mark the session
     * according to the direction.
     */
    switch ( direction )
    {
    case SSH_DIR_FROM_SERVER:
        sessionp->state_flags |= SSH_FLG_SERV_IDSTRING_SEEN;
        break;
    case SSH_DIR_FROM_CLIENT:
        sessionp->state_flags |= SSH_FLG_CLIENT_IDSTRING_SEEN;
        break;
    }

    version_end = (char*)memchr(version_stringp, '\n', p->dsize);
    if (version_end)
        return ((version_end - version_stringp) + 1);
    /* incomplete version string, should end with \n or \r\n for sshv2 */
    return p->dsize;
}

/* Called to process SSH1 key exchange or SSH2 key exchange init
 * messages.  On failure, inspection will be continued, but the packet
 * will be alerted on, and ignored.
 *
 * PARAMETERS:
 *
 * sessionp:    Pointer to SSH data for packet's session.
 * p:    Pointer to the packet to inspect.
 * direction:     Which direction the packet is going.
 *
 * RETURNS:  offset processed
 */
static unsigned int ProcessSSHKeyInitExchange(SSHData* sessionp, Packet* p,
    uint8_t direction, unsigned int offset)
{
    const SSH2Packet* ssh2p = nullptr;
    uint16_t dsize = p->dsize;
    const unsigned char* data = p->data;
    unsigned int ssh_length = 0;

    if (dsize < sizeof(SSH2Packet) || (dsize < (offset + sizeof(SSH2Packet)))
        || (dsize <= offset))
        return 0;

    dsize -= offset;
    data += offset;

    if ( sessionp->version == SSH_VERSION_1 )
    {
        uint32_t length;
        uint8_t padding_length;
        uint8_t message_type;

        /*
         * Validate packet data.
         * First 4 bytes should have the SSH packet length,
         * minus any padding.
         */
        if ( dsize < 4 )
        {
            {
                DetectionEngine::queue_event(GID_SSH, SSH_EVENT_PAYLOAD_SIZE);
            }

            return 0;
        }

        /*
         * SSH1 key exchange is very simple and
          * consists of only two messages, a server
         * key and a client key message.`
         */
        memcpy(&length, data, sizeof(length));
        length = ntohl(length);

        /* Packet data should be larger than length, due to padding. */
        if ( dsize < length )
        {
            {
                DetectionEngine::queue_event(GID_SSH, SSH_EVENT_PAYLOAD_SIZE);
            }

            return 0;
        }

        padding_length = (uint8_t)(8 - (length % 8));

        /*
         * With the padding calculated, verify data is sufficiently large
         * to include the message type.
         */
        if ( dsize < (padding_length + 4 + 1 + offset))
        {
            if (offset == 0)
            {
                DetectionEngine::queue_event(GID_SSH, SSH_EVENT_PAYLOAD_SIZE);
            }

            return 0;
        }

        message_type = *( (const uint8_t*)(data + padding_length + 4));

        switch ( message_type )
        {
        case SSH_MSG_V1_SMSG_PUBLIC_KEY:
            if ( direction == SSH_DIR_FROM_SERVER )
            {
                sessionp->state_flags |=
                    SSH_FLG_SERV_PKEY_SEEN;
            }
            else
            {
                /* Server msg not from server. */
                DetectionEngine::queue_event(GID_SSH, SSH_EVENT_WRONGDIR);
            }
            break;
        case SSH_MSG_V1_CMSG_SESSION_KEY:
            if ( direction == SSH_DIR_FROM_CLIENT )
            {
                sessionp->state_flags |=
                    SSH_FLG_CLIENT_SKEY_SEEN;
            }
            else
            {
                /* Client msg not from client. */
                DetectionEngine::queue_event(GID_SSH, SSH_EVENT_WRONGDIR);
            }
            break;
        default:
            /* Invalid msg type*/
            break;
        }

        /* Once the V1 key exchange is done, remainder of
         * communications are encrypted.
         */
        ssh_length = length + padding_length + sizeof(length) + offset;

        if ( (sessionp->state_flags & SSH_FLG_V1_KEYEXCH_DONE) ==
            SSH_FLG_V1_KEYEXCH_DONE )
        {
            sessionp->state_flags |= SSH_FLG_SESS_ENCRYPTED;
        }
    }
    else if ( sessionp->version == SSH_VERSION_2 )
    {
        /* We want to overlay the data on our data packet struct,
         * so first verify that the data size is big enough.
         * This may legitimately occur such as in the case of a
         * retransmission.
         */
        if ( dsize < sizeof(SSH2Packet) )
        {
            return 0;
        }

        /* Overlay the SSH2 binary data packet struct on the packet */
        ssh2p = (const SSH2Packet*)data;
        if ( dsize < SSH2_HEADERLEN + 1)
        {
            /* Invalid packet length. */

            return 0;
        }

        ssh_length = offset + ntohl(ssh2p->packet_length) + sizeof(ssh2p->packet_length);

        switch ( data[SSH2_HEADERLEN] )
        {
        case SSH_MSG_KEXINIT:
            sessionp->state_flags |=
                (direction == SSH_DIR_FROM_SERVER ?
                SSH_FLG_SERV_KEXINIT_SEEN :
                SSH_FLG_CLIENT_KEXINIT_SEEN );
            break;
        default:
            /* Unrecognized message type. */
            break;
        }
    }
    else
    {
        return 0;
    }

    if (ssh_length < p->dsize)
        return ssh_length;
    else
        return 0;
}

/* Called to process SSH2 key exchange msgs (key exch init msgs already
 * processed earlier). On failure, inspection will be continued, but the
 * packet will be alerted on, and ignored.
 *
 * PARAMETERS:
 *
 * sessionp:    Pointer to SSH data for packet's session.
 * p:    Pointer to the packet to inspect.
 * direction:     Which direction the packet is going.
 *
 * RETURNS:  offset processed
 */
static unsigned int ProcessSSHKeyExchange(SSHData* sessionp, Packet* p,
    uint8_t direction, unsigned int offset)
{
    uint16_t dsize = p->dsize;
    const unsigned char* data = p->data;
    bool next_packet = true;
    unsigned int npacket_offset = 0;

    if (dsize < sizeof(SSH2Packet) || (dsize < (offset + sizeof(SSH2Packet)))
        || (dsize <= offset))
    {
        return 0;
    }

    dsize -= offset;
    data += offset;

    while (next_packet)
    {
        const SSH2Packet* ssh2p = (const SSH2Packet*)(data + npacket_offset);
        unsigned ssh_length = SSHPacket_GetLength(ssh2p, dsize);

        if (ssh_length == 0)
        {
            if ( sessionp->state_flags & SSH_FLG_SESS_ENCRYPTED )
            {
                return ( npacket_offset + offset );
            }
            {
                /* Invalid packet length. */
                DetectionEngine::queue_event(GID_SSH, SSH_EVENT_PAYLOAD_SIZE);
            }

            return 0;
        }

        switch (data[npacket_offset + SSH2_HEADERLEN] )
        {
        case SSH_MSG_KEXDH_INIT:
            if ( direction == SSH_DIR_FROM_CLIENT )
            {
                sessionp->state_flags |=
                    SSH_FLG_KEXDH_INIT_SEEN;
            }
            else
            {
                /* Client msg from server. */
                DetectionEngine::queue_event(GID_SSH, SSH_EVENT_WRONGDIR);
            }
            break;
        case SSH_MSG_KEXDH_REPLY:
            if ( direction == SSH_DIR_FROM_SERVER )
            {
                /* KEXDH_REPLY has the same msg
                  * type as the new style GEX_REPLY
                 */
                sessionp->state_flags |=
                    SSH_FLG_KEXDH_REPLY_SEEN |
                    SSH_FLG_GEX_REPLY_SEEN;
            }
            else
            {
                /* Server msg from client. */
                DetectionEngine::queue_event(GID_SSH, SSH_EVENT_WRONGDIR);
            }
            break;
        case SSH_MSG_KEXDH_GEX_REQ:
            if ( direction == SSH_DIR_FROM_CLIENT )
            {
                sessionp->state_flags |=
                    SSH_FLG_GEX_REQ_SEEN;
            }
            else
            {
                /* Server msg from client. */
                DetectionEngine::queue_event(GID_SSH, SSH_EVENT_WRONGDIR);
            }
            break;
        case SSH_MSG_KEXDH_GEX_GRP:
            if ( direction == SSH_DIR_FROM_SERVER )
            {
                sessionp->state_flags |=
                    SSH_FLG_GEX_GRP_SEEN;
            }
            else
            {
                /* Client msg from server. */
                DetectionEngine::queue_event(GID_SSH, SSH_EVENT_WRONGDIR);
            }
            break;
        case SSH_MSG_KEXDH_GEX_INIT:
            if ( direction == SSH_DIR_FROM_CLIENT )
            {
                sessionp->state_flags |=
                    SSH_FLG_GEX_INIT_SEEN;
            }
            else
            {
                /* Server msg from client. */
                DetectionEngine::queue_event(GID_SSH, SSH_EVENT_WRONGDIR);
            }
            break;
        case SSH_MSG_NEWKEYS:
            /* This message is required to complete the
             * key exchange. Both server and client should
             * send one, but as per Alex Kirk's note on this,
             * in some implementations the server does not
             * actually send this message. So receiving a new
             * keys msg from the client is sufficient.
             */
            if ( direction == SSH_DIR_FROM_CLIENT )
            {
                sessionp->state_flags |= SSH_FLG_NEWKEYS_SEEN;
            }
            break;
        default:
            /* Unrecognized message type. Possibly encrypted */
            sessionp->state_flags |= SSH_FLG_SESS_ENCRYPTED;
            return ( npacket_offset + offset);
        }

        /* If either an old-style or new-style Diffie Helman exchange
         * has completed, the session will enter encrypted mode.
         */
        if (( (sessionp->state_flags &
            SSH_FLG_V2_DHOLD_DONE) == SSH_FLG_V2_DHOLD_DONE )
            || ( (sessionp->state_flags &
            SSH_FLG_V2_DHNEW_DONE) == SSH_FLG_V2_DHNEW_DONE ))
        {
            sessionp->state_flags |= SSH_FLG_SESS_ENCRYPTED;
            if (ssh_length < dsize)
            {
                if ( ssh_length >= 4 )
                {
                    npacket_offset += ssh_length;
                    dsize -= ssh_length;
                    continue;
                }
                return ( npacket_offset + offset );
            }
            else
                return 0;
        }

        if ((ssh_length < dsize) && (ssh_length >= 4))
        {
            npacket_offset += ssh_length;
            dsize -= ssh_length;
        }
        else
        {
            next_packet = false;
            npacket_offset = 0;
        }
    }

    return (npacket_offset + offset);
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Ssh : public Inspector
{
public:
    Ssh(SSH_PROTO_CONF*);
    ~Ssh() override;

    void show(SnortConfig*) override;
    void eval(Packet*) override;

private:
    SSH_PROTO_CONF* config;
};

Ssh::Ssh(SSH_PROTO_CONF* pc)
{
    config = pc;
}

Ssh::~Ssh()
{
    if ( config )
        delete config;
}

void Ssh::show(SnortConfig*)
{
    PrintSshConf(config);
}

void Ssh::eval(Packet* p)
{
    // precondition - what we registered for
    assert(p->has_tcp_data());
    assert(p->flow);

    ++sshstats.total_packets;
    snort_ssh(config, p);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new SshModule; }

static void mod_dtor(Module* m)
{ delete m; }

static void ssh_init()
{
    SshFlowData::init();
}

static Inspector* ssh_ctor(Module* m)
{
    SshModule* mod = (SshModule*)m;
    return new Ssh(mod->get_data());
}

static void ssh_dtor(Inspector* p)
{
    delete p;
}

const InspectApi ssh_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        SSH_NAME,
        SSH_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__PDU,
    nullptr, // buffers
    "ssh",
    ssh_init,
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ssh_ctor,
    ssh_dtor,
    nullptr, // ssn
    nullptr  // reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &ssh_api.base,
    nullptr
};
#else
const BaseApi* sin_ssh = &ssh_api.base;
#endif


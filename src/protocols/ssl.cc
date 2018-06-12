//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2007-2013 Sourcefire, Inc.
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

// ssl.h author Adam Keeton

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "ssl.h"

#include "packet.h"

#define THREE_BYTE_LEN(x) ((x)[2] | (x)[1] << 8 | (x)[0] << 16)

#define SSL_ERROR_FLAGS \
    (SSL_BOGUS_HS_DIR_FLAG | \
    SSL_BAD_VER_FLAG | \
    SSL_BAD_TYPE_FLAG | \
    SSL_UNKNOWN_FLAG)

#define SSL3_FIRST_BYTE 0x16
#define SSL3_SECOND_BYTE 0x03
#define SSL2_CHELLO_BYTE 0x01
#define SSL2_SHELLO_BYTE 0x04

static uint32_t SSL_decode_version_v3(uint8_t major, uint8_t minor)
{
    /* Should only be called internally and by functions which have previously
     * validated their arguments */

    if (major == 3)
    {
        /* Minor version */
        switch (minor)
        {
        case 0: return SSL_VER_SSLV3_FLAG;
        case 1: return SSL_VER_TLS10_FLAG;
        case 2: return SSL_VER_TLS11_FLAG;
        case 3: return SSL_VER_TLS12_FLAG;
        default: return SSL_BAD_VER_FLAG;
        }
    }
    /* This is a special case. Technically, major == 0, minor == 2 is SSLv2.
     * But if this traffic was SSLv2, this code path would not have been
     * exercised. */
    else if (minor == 2)
    {
        return SSL_BAD_VER_FLAG;
    }

    return SSL_BAD_VER_FLAG;
}

static uint32_t SSL_decode_handshake_v3(const uint8_t* pkt, int size,
    uint32_t cur_flags, uint32_t pkt_flags)
{
    const SSL_handshake_hello_t* hello;
    uint32_t retval = 0;

    while (size > 0)
    {
        if (size < (int)SSL_HS_PAYLOAD_OFFSET)
        {
            retval |= SSL_TRUNCATED_FLAG;
            break;
        }

        /* Note, handhshake version field is optional depending on type
           Will recast to different type as necessary. */
        const SSL_handshake_t* handshake = (const SSL_handshake_t*)pkt;
        pkt += SSL_HS_PAYLOAD_OFFSET;
        size -= SSL_HS_PAYLOAD_OFFSET;

        /* The code below effectively implements the following:
         *      hs_len = 0;
         *      memcpy(&hs_len, handshake->length, 3);
         *      hs_len = ntohl(hs_len);
         * It was written this way for performance */
        uint32_t hs_len = THREE_BYTE_LEN(handshake->length);

        switch (handshake->type)
        {
        case SSL_HS_CHELLO:
            if (pkt_flags & PKT_FROM_SERVER)
                retval |= SSL_BOGUS_HS_DIR_FLAG;
            else
                retval |= SSL_CLIENT_HELLO_FLAG | SSL_CUR_CLIENT_HELLO_FLAG;

            /* This type of record contains a version string.
               Make sure there is room for a version. */
            if (size < (int)sizeof(uint16_t))
            {
                retval |= SSL_TRUNCATED_FLAG;
                break;
            }

            hello = (const SSL_handshake_hello_t*)handshake;
            retval |= SSL_decode_version_v3(hello->major, hello->minor);

            /* Compare version of record with version of handshake */
            if ((cur_flags & SSL_VERFLAGS) != (retval & SSL_VERFLAGS))
                retval |= SSL_BAD_VER_FLAG;

            break;

        case SSL_HS_SHELLO:
            if (pkt_flags & PKT_FROM_SERVER)
                retval |= SSL_SERVER_HELLO_FLAG | SSL_CUR_SERVER_HELLO_FLAG;
            else
                retval |= SSL_BOGUS_HS_DIR_FLAG;

            /* This type of record contains a version string. */
            if (size < (int)sizeof(uint16_t))
            {
                retval |= SSL_TRUNCATED_FLAG;
                break;
            }

            hello = (const SSL_handshake_hello_t*)handshake;
            retval |= SSL_decode_version_v3(hello->major, hello->minor);

            /* Compare version of record with version of handshake */
            if ((cur_flags & SSL_VERFLAGS) != (retval & SSL_VERFLAGS))
                retval |= SSL_BAD_VER_FLAG;

            break;

        case SSL_HS_SHELLO_DONE:
            if (pkt_flags & PKT_FROM_SERVER)
                retval |= SSL_HS_SDONE_FLAG;
            else
                retval |= SSL_BOGUS_HS_DIR_FLAG;
            break;

        case SSL_HS_SKEYX:
            if (pkt_flags & PKT_FROM_SERVER)
                retval |= SSL_SERVER_KEYX_FLAG | SSL_CUR_SERVER_KEYX_FLAG;
            else
                retval |= SSL_BOGUS_HS_DIR_FLAG;
            break;

        case SSL_HS_CKEYX:
            if (pkt_flags & PKT_FROM_SERVER)
                retval |= SSL_BOGUS_HS_DIR_FLAG;
            else
                retval |= SSL_CLIENT_KEYX_FLAG | SSL_CUR_CLIENT_KEYX_FLAG;
            break;

        case SSL_HS_CERT:
            retval |= SSL_CERTIFICATE_FLAG;
            break;

        /* The following types are not presently of interest */
        case SSL_HS_HELLO_REQ:
        case SSL_HS_CERT_VERIFY:
        case SSL_HS_CERT_REQ:
        case SSL_CERT_URL:      /* RFC 3546 */
        case SSL_CERT_STATUS:     /* RFC 3546 */
            break;

        /* Will never see this since it's always encrypted */
        case SSL_HS_FINISHED:
        default:
            /* Could be either a bad type or an encrypted handshake record
               If the record is encrypted, the type will likely appear bogus. */
            return SSL_POSSIBLE_HS_FLAG | SSL_POSSIBLY_ENC_FLAG;
        }

        size -= hs_len;
        pkt += hs_len;
    }

    if (size < 0)
        retval |= SSL_TRUNCATED_FLAG;

    return retval;
}

static uint32_t SSL_decode_v3(const uint8_t* pkt, int size, uint32_t pkt_flags,
    uint8_t* alert_flags, uint16_t* partial_rec_len, int max_hb_len)
{
    uint32_t retval = 0;
    uint16_t hblen;
    int ccs = 0;   /* Set if we see a Change Cipher Spec and reset after the next record */
    const SSL_heartbeat* heartbeat;
    uint16_t psize = 0;

    if ( size && partial_rec_len && *partial_rec_len > 0)
    {
        if (size < (int)(*partial_rec_len))
        {
            *partial_rec_len = *partial_rec_len - size;
            retval |= SSL_TRUNCATED_FLAG;
            return retval;
        }
        else
        {
            pkt += *partial_rec_len;
            size -= *partial_rec_len;
        }
        *partial_rec_len = 0;
    }

    while (size > 0)
    {
        if (size < (int)SSL_REC_PAYLOAD_OFFSET)
        {
            retval |= SSL_TRUNCATED_FLAG;
            break;
        }

        const SSL_record_t* record = (const SSL_record_t*)pkt;
        pkt += SSL_REC_PAYLOAD_OFFSET;
        size -= SSL_REC_PAYLOAD_OFFSET;

        retval |= SSL_decode_version_v3(record->major, record->minor);

        uint16_t reclen = ntohs(record->length);

        psize = (size < reclen) ? (reclen - size) : 0;

        switch (record->type)
        {
        case SSL_CHANGE_CIPHER_REC:
            retval |= SSL_CHANGE_CIPHER_FLAG;

            /* If there is another record, mark it as possibly encrypted */
            if ((size - (int)reclen) > 0)
                retval |= SSL_POSSIBLY_ENC_FLAG;

            ccs = 1;
            break;

        case SSL_ALERT_REC:
            retval |= SSL_ALERT_FLAG;
            ccs = 0;
            break;
        case SSL_HEARTBEAT_REC:
            retval |= SSL_HEARTBEAT_SEEN;
            ccs = 0;
            if( size < 0 || (unsigned int)size < sizeof(SSL_heartbeat) || !max_hb_len || !alert_flags )
                break;
            heartbeat = (const SSL_heartbeat*)pkt;
            if ((heartbeat->type) == SSL_HEARTBEAT_REQUEST)
            {
                hblen = ntohs(heartbeat->length);
                if (hblen > max_hb_len)
                    *alert_flags = SSL_HEARTBLEED_REQUEST;
            }
            else if ((heartbeat->type) == SSL_HEARTBEAT_RESPONSE)
            {
                if (reclen > max_hb_len )
                    *alert_flags = SSL_HEARTBLEED_RESPONSE;
            }
            else if (!(retval & SSL_BAD_VER_FLAG))
            {
                if (reclen > max_hb_len )
                    *alert_flags = SSL_HEARTBLEED_UNKNOWN;
            }
            break;

        case SSL_HANDSHAKE_REC:
            /* If the CHANGE_CIPHER_FLAG is set, the following handshake
             * record should be encrypted */
            if (!(retval & SSL_CHANGE_CIPHER_FLAG))
            {
                int hsize = size < (int)reclen ? size : (int)reclen;
                retval |= SSL_decode_handshake_v3(pkt, hsize, retval, pkt_flags);
            }
            else if (ccs)
            {
                /* If we just got a change cipher spec, the next record must
                 * be a finished encrypted, which has no type, so it will fall
                 * into this default case, but it's good and we still need to
                 * see client and server app data */
                retval |= SSL_HS_SDONE_FLAG;
            }

            ccs = 0;
            break;

        case SSL_APPLICATION_REC:
            if (pkt_flags & PKT_FROM_SERVER)
                retval |= SSL_SAPP_FLAG;
            else
                retval |= SSL_CAPP_FLAG;
            ccs = 0;
            break;

        default:
            retval |= SSL_BAD_TYPE_FLAG;
            ccs = 0;
            break;
        }

        size -= reclen;
        pkt += reclen;
    }

    if (size < 0)
        retval |= SSL_TRUNCATED_FLAG;

    if (!(retval & SSL_VERFLAGS) || (retval & SSL_BAD_VER_FLAG))
    {
        psize = 0;
        retval = retval | SSL_UNKNOWN_FLAG;
    }

    if (partial_rec_len)
        *partial_rec_len = psize;

    return retval;
}

// See RFCs 6101, 2246, 4346 and 5246 for SSL 3.0, TLS 1.0, 1.1 and 1.2 respectively
// Appendix E. Backward Compatibility With SSL
static inline bool SSL_v3_back_compat_v2(const SSLv2_chello_t* chello)
{
    if ((chello->major == 3) && (chello->minor <= 3))
        return true;
    return false;
}

static uint32_t SSL_decode_v2(const uint8_t* pkt, int size, uint32_t pkt_flags)
{
    const SSLv2_chello_t* chello;
    const SSLv2_shello_t* shello;
    uint32_t retval = 0;
    const SSLv2_record_t* record = (const SSLv2_record_t*)pkt;

    while (size > 0)
    {
        if (size < SSL_V2_MIN_LEN)
        {
            retval |= SSL_TRUNCATED_FLAG | SSL_UNKNOWN_FLAG;
            break;
        }

        /* Note: top bit has special meaning and is not included
         * with the length */
        uint16_t reclen = ntohs(record->length) & 0x7fff;

        switch (record->type)
        {
        case SSL_V2_CHELLO:
            if (pkt_flags & PKT_FROM_SERVER)
                retval |= SSL_BOGUS_HS_DIR_FLAG;
            else
                retval |= SSL_CLIENT_HELLO_FLAG | SSL_CUR_CLIENT_HELLO_FLAG;

            if (size < (int)sizeof(SSLv2_chello_t))
            {
                retval |= SSL_TRUNCATED_FLAG | SSL_UNKNOWN_FLAG;
                break;
            }

            chello = (const SSLv2_chello_t*)pkt;

            // Check for SSLv3/TLS backward compatibility
            if (SSL_v3_back_compat_v2(chello))
                retval |= SSL_V3_BACK_COMPAT_V2;
            else if (chello->minor != 2)
                retval |= SSL_BAD_VER_FLAG | SSL_UNKNOWN_FLAG;

            break;

        case SSL_V2_SHELLO:
            if (pkt_flags & PKT_FROM_CLIENT)
                retval |= SSL_BOGUS_HS_DIR_FLAG;
            else
                retval |= SSL_SERVER_HELLO_FLAG | SSL_CUR_SERVER_HELLO_FLAG;

            if (size < (int)sizeof(SSLv2_shello_t))
            {
                retval |= SSL_TRUNCATED_FLAG | SSL_UNKNOWN_FLAG;
                break;
            }

            shello = (const SSLv2_shello_t*)pkt;

            if (shello->minor != 2)
            {
                retval |= SSL_BAD_VER_FLAG | SSL_UNKNOWN_FLAG;
                break;
            }

            break;

        case SSL_V2_CKEY:
            retval |= SSL_CLIENT_KEYX_FLAG |  SSL_CUR_CLIENT_KEYX_FLAG;
            break;

        default:
            return retval | SSL_BAD_TYPE_FLAG | SSL_UNKNOWN_FLAG;
        }

        size -= (reclen + 2);
        pkt += (reclen + 2);
    }

    if (size < 0)
        retval |= SSL_TRUNCATED_FLAG;

    return retval | SSL_VER_SSLV2_FLAG;
}

namespace snort
{
uint32_t SSL_decode(
    const uint8_t* pkt, int size, uint32_t pkt_flags, uint32_t prev_flags,
    uint8_t* alert_flags, uint16_t* partial_rec_len, int max_hb_len)
{
    if (!pkt || !size)
        return SSL_ARG_ERROR_FLAG;

    if (size < (int)SSL_REC_PAYLOAD_OFFSET)
        return SSL_TRUNCATED_FLAG | SSL_UNKNOWN_FLAG;

    if (!( prev_flags & SSL_HS_SDONE_FLAG ))
    {
        /* Determine the protocol type. */

        /* Only SSL v2 will have these bits set */
        if (((pkt[0] & 0x80) || (pkt[0] & 0x40)) && !(partial_rec_len && *partial_rec_len))
            return SSL_decode_v2(pkt, size, pkt_flags);

        /* If this packet is only 5 bytes, it inconclusive whether its SSLv2 or TLS.
         * If it is v2, it's definitely truncated anyway.  By decoding a 5 byte
         * SSLv2 as TLS,the decoder will either catch a bad type, bad version, or
         * indicate that it is truncated. */
        if (size == 5)
            return SSL_decode_v3(pkt, size, pkt_flags, alert_flags, partial_rec_len, max_hb_len);

        /* At this point, 'size' has to be > 5 */

        /* If the field below contains a 2, it's either an SSLv2 client hello or
         * it is TLS and is containing a server hello. */
        if (pkt[4] == 2)
        {
            /* This could be a TLS server hello.  Check for a TLS version string */
            if (size >= 10)
            {
                if (pkt[9] == 3)
                {
                    /* Saw a TLS version, but this could also be an SSHv2 length.
                      * If it is, check if a hypothetical TLS record-data length agrees
                      * with its record length */
                    uint32_t datalen = THREE_BYTE_LEN( (pkt+6) );

                    const SSL_record_t* record = (const SSL_record_t*)pkt;
                    uint16_t reclen = ntohs(record->length);

                    /* If these lengths match, it's v3
                       Otherwise, it's v2 */
                    if (reclen - SSL_HS_PAYLOAD_OFFSET != datalen)
                        return SSL_decode_v2(pkt, size, pkt_flags);
                }
            }
        }
        /* Check if it's possibly a SSLv2 server-hello, in which case the version
         * is at byte 7 */
        else if (size >= 8 && pkt[7] == 2)
        {
            /* A version of '2' at byte 7 overlaps with TLS record-data length.
             * Check if a hypothetical TLS record-data length agrees with its
             * record length */
            uint32_t datalen = THREE_BYTE_LEN( (pkt+6) );

            const SSL_record_t* record = (const SSL_record_t*)pkt;
            uint16_t reclen = ntohs(record->length);

            /* If these lengths match, it's v3
               Otherwise, it's v2 */
            if (reclen - SSL_HS_PAYLOAD_OFFSET != datalen)
                return SSL_decode_v2(pkt, size, pkt_flags);
        }
    }

    return SSL_decode_v3(pkt, size, pkt_flags, alert_flags, partial_rec_len, max_hb_len);
}

/* very simplistic - just enough to say this is binary data - the rules will make a final
* judgement.  Should maybe add an option to the imap configuration to enable the
* continuing of command inspection like ftptelnet. */
bool IsTlsClientHello(const uint8_t* ptr, const uint8_t* end)
{
    /* at least 3 bytes of data - see below */
    if ((end - ptr) < 3)
        return false;

    if ((ptr[0] == SSL3_FIRST_BYTE) && (ptr[1] == SSL3_SECOND_BYTE))
    {
        /* TLS v1 or SSLv3 */
        return true;
    }
    else if ((ptr[2] == SSL2_CHELLO_BYTE) || (ptr[3] == SSL2_CHELLO_BYTE))
    {
        /* SSLv2 */
        return true;
    }

    return false;
}

/* this may at least tell us whether the server accepted the client hello by the presence
 * of binary data */

bool IsTlsServerHello(const uint8_t* ptr, const uint8_t* end)
{
    /* at least 3 bytes of data - see below */
    if ((end - ptr) < 3)
        return false;

    if ((ptr[0] == SSL3_FIRST_BYTE) && (ptr[1] == SSL3_SECOND_BYTE))
    {
        /* TLS v1 or SSLv3 */
        return true;
    }
    else if (ptr[2] == SSL2_SHELLO_BYTE)
    {
        /* SSLv2 */
        return true;
    }

    return false;
}

bool IsSSL(const uint8_t* ptr, int len, int pkt_flags)
{
    uint32_t ssl_flags = SSL_decode(ptr, len, pkt_flags, 0, nullptr, nullptr, 0);

    if ((ssl_flags != SSL_ARG_ERROR_FLAG) &&
        !(ssl_flags & SSL_ERROR_FLAGS))
    {
        return true;
    }

    return false;
}

} // namespace snort

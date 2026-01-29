//--------------------------------------------------------------------------
// Copyright (C) 2025 Cisco and/or its affiliates. All rights reserved.
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
// socks_curse.cc - author Raza Shafiq <rshafiq@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "socks_curse.h"
#include "curse_book.h"

// SOCKS protocol constants
#define SOCKS4_VERSION 0x04
#define SOCKS5_VERSION 0x05

#define SOCKS_CMD_CONNECT       0x01
#define SOCKS_CMD_BIND          0x02
#define SOCKS_CMD_UDP_ASSOCIATE 0x03

// SOCKS5 authentication methods
#define SOCKS5_AUTH_NONE              0x00
#define SOCKS5_AUTH_GSSAPI            0x01
#define SOCKS5_AUTH_USERNAME_PASSWORD 0x02
#define SOCKS5_AUTH_NO_ACCEPTABLE     0xFF

// Limits to prevent DoS
#define SOCKS_MAX_USERID_LEN  255
#define SOCKS_MAX_DOMAIN_LEN  255
#define SOCKS5_MAX_METHODS    32

bool CurseBook::socks_curse(const uint8_t* data, unsigned len, CurseTracker* tracker)
{
    SocksTracker& socks = tracker->socks;

    // Check terminal states first (matches ssl_curse.cc pattern)
    // NOT_FOUND is sticky: assumes initial invocation begins at protocol boundary
    // (start of application data in correct direction). This avoids repeated work
    // on flows that are clearly not SOCKS.
    if ( socks.state == SOCKS_STATE__NOT_FOUND )
        return false;
    else if ( socks.state == SOCKS_STATE__FOUND )
        return true;

    for ( unsigned idx = 0; idx < len; ++idx )
    {
        uint8_t val = data[idx];

        switch ( socks.state )
        {
            case SOCKS_STATE__VERSION:
            {
                // SOCKS version: 0x04 (SOCKS4) or 0x05 (SOCKS5)
                if ( val == SOCKS4_VERSION )
                {
                    socks.version = val;
                    socks.state = SOCKS_STATE__V4_COMMAND;
                }
                else if ( val == SOCKS5_VERSION )
                {
                    socks.version = val;
                    socks.state = SOCKS_STATE__V5_NMETHODS;
                }
                else
                {
                    socks.state = SOCKS_STATE__NOT_FOUND;
                    return false;
                }
                break;
            }

            // ==================== SOCKS4/4a States ====================

            case SOCKS_STATE__V4_COMMAND:
            {
                // SOCKS4: VER(1) CMD(1) PORT(2) IP(4) USERID(variable) NULL(1)
                // SOCKS4a: VER(1) CMD(1) PORT(2) IP=0.0.0.x(4) USERID(var) NULL(1) DOMAIN(var) NULL(1)
                // Validate command is CONNECT or BIND
                if ( val == SOCKS_CMD_CONNECT || val == SOCKS_CMD_BIND )
                {
                    socks.command = val;
                    socks.state = SOCKS_STATE__V4_PORT_MSB;
                }
                else
                {
                    socks.state = SOCKS_STATE__NOT_FOUND;
                    return false;
                }
                break;
            }

            case SOCKS_STATE__V4_PORT_MSB:
            {
                // Port MSB - store it (network byte order, MSB first)
                socks.port = (uint16_t)val << 8;
                socks.state = SOCKS_STATE__V4_PORT_LSB;
                break;
            }

            case SOCKS_STATE__V4_PORT_LSB:
            {
                // Port LSB - complete port
                socks.port |= val;
                
                // Validate port: Port 0 is invalid for CONNECT
                // (BIND can have port 0 meaning server chooses)
                if ( socks.command == SOCKS_CMD_CONNECT && socks.port == 0 )
                {
                    socks.state = SOCKS_STATE__NOT_FOUND;
                    return false;
                }
                
                socks.state = SOCKS_STATE__V4_IP_1;
                socks.ip_addr = 0;
                break;
            }

            case SOCKS_STATE__V4_IP_1:
            {
                // First IP octet (most significant)
                socks.ip_addr = (uint32_t)val << 24;
                socks.state = SOCKS_STATE__V4_IP_2;
                break;
            }

            case SOCKS_STATE__V4_IP_2:
            {
                // Second IP octet
                socks.ip_addr |= (uint32_t)val << 16;
                socks.state = SOCKS_STATE__V4_IP_3;
                break;
            }

            case SOCKS_STATE__V4_IP_3:
            {
                // Third IP octet
                socks.ip_addr |= (uint32_t)val << 8;
                socks.state = SOCKS_STATE__V4_IP_4;
                break;
            }

            case SOCKS_STATE__V4_IP_4:
            {
                // Last IP octet - complete the address
                socks.ip_addr |= val;
                
                // Determine if this is SOCKS4a (domain name follows)
                // SOCKS4a uses IP 0.0.0.x where x != 0 to indicate domain name follows
                uint8_t first_octet = (socks.ip_addr >> 24) & 0xFF;
                
                // Initialize is_socks4a to false
                socks.is_socks4a = false;
                
                if ( socks.command == SOCKS_CMD_BIND )
                {
                    // BIND command: IP 0.0.0.0 is valid (server chooses address)
                    // Any IP is acceptable for BIND
                    // No validation needed - proceed to userid
                }
                else if ( socks.command == SOCKS_CMD_CONNECT )
                {
                    // CONNECT command: validate IP address
                    if ( first_octet == 0 )
                    {
                        if ( socks.ip_addr == 0 )
                        {
                            // 0.0.0.0 is invalid for CONNECT
                            socks.state = SOCKS_STATE__NOT_FOUND;
                            return false;
                        }
                        // Check if it's SOCKS4a format: 0.0.0.x where x > 0
                        if ( (socks.ip_addr & 0xFFFFFF00) != 0 )
                        {
                            // Not 0.0.0.x format (e.g., 0.1.2.3) - invalid
                            socks.state = SOCKS_STATE__NOT_FOUND;
                            return false;
                        }
                        // Valid SOCKS4a indicator: 0.0.0.1-255
                        socks.is_socks4a = true;
                    }
                    // Reject loopback and multicast for CONNECT
                    else if ( first_octet == 127 || first_octet >= 224 )
                    {
                        socks.state = SOCKS_STATE__NOT_FOUND;
                        return false;
                    }
                }
                
                // Now expect USERID (variable length, null-terminated)
                socks.state = SOCKS_STATE__V4_USERID;
                socks.userid_length = 0;
                break;
            }

            case SOCKS_STATE__V4_USERID:
            {
                // USERID is variable length, terminated by NULL byte
                // Empty USERID (just NULL terminator) is valid per RFC
                if ( val == 0x00 )
                {
                    // Found null terminator for userid
                    if ( socks.is_socks4a )
                    {
                        // SOCKS4a: Domain name follows the userid null
                        socks.state = SOCKS_STATE__V4A_DOMAIN;
                        socks.domain_length = 0;
                    }
                    else
                    {
                        // Regular SOCKS4: We're done
                        socks.state = SOCKS_STATE__FOUND;
                        return true;
                    }
                }
                else
                {
                    // SOCKS4 USERID: any byte except NULL is valid per RFC
                    // Real-world clients may use non-ASCII bytes
                    if ( socks.userid_length >= SOCKS_MAX_USERID_LEN )
                    {
                        // Userid too long - DoS protection
                        socks.state = SOCKS_STATE__NOT_FOUND;
                        return false;
                    }
                    socks.userid_length++;
                }
                break;
            }

            case SOCKS_STATE__V4A_DOMAIN:
            {
                // SOCKS4a domain name: variable length, null-terminated
                // Detector heuristic: allow common hostname/domain bytes
                // (alphanumeric, hyphen, dot, underscore for robustness)
                // Strict validation reduces false positives vs other protocols
                if ( val == 0x00 )
                {
                    // Found null terminator for domain
                    // Domain must be at least 1 character
                    if ( socks.domain_length == 0 )
                    {
                        socks.state = SOCKS_STATE__NOT_FOUND;
                        return false;
                    }
                    
                    socks.state = SOCKS_STATE__FOUND;
                    return true;
                }
                // Allow hostname-like characters (underscore included for robustness)
                else if ( (val >= 'a' && val <= 'z') ||
                          (val >= 'A' && val <= 'Z') ||
                          (val >= '0' && val <= '9') ||
                          val == '-' || val == '.' || val == '_' )
                {
                    if ( socks.domain_length >= SOCKS_MAX_DOMAIN_LEN )
                    {
                        // Domain too long
                        socks.state = SOCKS_STATE__NOT_FOUND;
                        return false;
                    }
                    socks.domain_length++;
                }
                else
                {
                    // Domain heuristic reject: non-hostname character
                    socks.state = SOCKS_STATE__NOT_FOUND;
                    return false;
                }
                break;
            }

            // ==================== SOCKS5 States ====================

            case SOCKS_STATE__V5_NMETHODS:
            {
                // SOCKS5 Client Greeting: VER(1) NMETHODS(1) METHODS(1-255)
                // RFC 1928 Section 3
                socks.nmethods = val;

                // RFC 1928: NMETHODS must be at least 1
                if ( socks.nmethods == 0 )
                {
                    socks.state = SOCKS_STATE__NOT_FOUND;
                    return false;
                }

                // Practical limit: Real clients don't send many methods
                // Standard methods (0x00-0x09) + private (0x80-0xFE) = ~32 is generous
                if ( socks.nmethods > SOCKS5_MAX_METHODS )
                {
                    socks.state = SOCKS_STATE__NOT_FOUND;
                    return false;
                }

                // Reset method tracking fields (important for segmented data)
                socks.unique_methods = 0;
                socks.has_common = false;
                socks.saw_duplicate = false;
                socks.v5_confirm_budget = 0;
                socks.methods_seen[0] = 0;
                socks.methods_seen[1] = 0;
                socks.methods_seen[2] = 0;
                socks.methods_seen[3] = 0;

                // Note: Don't check total length here - handle segmentation
                // by processing methods one at a time in V5_METHODS state
                socks.methods_remaining = socks.nmethods;
                socks.state = SOCKS_STATE__V5_METHODS;
                break;
            }

            case SOCKS_STATE__V5_METHODS:
            {
                // Validate method values per RFC 1928:
                // 0x00-0x09: IANA assigned methods
                // 0x03-0x7F: IANA assigned/reserved (allow for robustness)
                // 0x80-0xFE: Private methods
                // 0xFF: NO ACCEPTABLE METHODS (server-only - reject)
                if ( val == 0xFF )
                {
                    socks.state = SOCKS_STATE__NOT_FOUND;
                    return false;
                }
                
                // LPD false positive prevention: reject 0x0A (LF) as a method value
                // RFC 1179: LPD commands are terminated with LF (0x0A)
                // While 0x0A is technically in the IANA range, it's never used in practice
                // and its presence is a strong indicator of LPD traffic, not SOCKS5
                if ( val == 0x0A )
                {
                    socks.state = SOCKS_STATE__NOT_FOUND;
                    return false;
                }
                
                // Track method using 256-bit bitmask
                unsigned mask_word = val / 64;
                uint64_t bit = 1ULL << (val % 64);
                
                if ( socks.methods_seen[mask_word] & bit )
                {
                    // Already seen this method - duplicate
                    socks.saw_duplicate = true;
                }
                else
                {
                    // New unique method
                    socks.methods_seen[mask_word] |= bit;
                    socks.unique_methods++;
                    
                    // Check for common methods (0x00, 0x01, 0x02)
                    if ( val <= 0x02 )
                        socks.has_common = true;
                }
                
                if ( socks.methods_remaining > 0 )
                    socks.methods_remaining--;
                
                if ( socks.methods_remaining == 0 )
                {
                    // Greeting complete - apply validation to avoid false positives
                    
                    // LPD false positive check: Extra bytes after greeting
                    // LPD pattern: greeting followed by 0x0A (line feed terminator)
                    // RFC 1179: LPD commands are terminated with LF (0x0A)
                    // This byte is never valid in SOCKS5 (not a version byte, not in any valid position)
                    unsigned remaining = len - (idx + 1);
                    if ( remaining > 0 )
                    {
                        const uint8_t* p = &data[idx + 1];
                        
                        // Specifically reject 0x0A (LF) as it's the LPD terminator
                        // Don't reject other values - they might be legitimate SOCKS5 or need more analysis
                        if ( p[0] == 0x0A )
                        {
                            socks.state = SOCKS_STATE__NOT_FOUND;
                            return false;
                        }
                    }
                    
                    // Fast accept for greetings with common methods (no RTT delay)
                    // Common methods (0x00-0x02) are strong SOCKS5 indicators
                    if ( socks.has_common )
                    {
                        socks.state = SOCKS_STATE__FOUND;
                        return true;
                    }
                    
                    // No common methods - apply stricter checks to avoid false positives
                    // Trade-off: Private/non-common method auth exchanges that occur BEFORE
                    // the request header will cause NOT_FOUND. This prioritizes false-positive
                    // suppression over detection of rare private-auth SOCKS5 implementations.
                    
                    // Check: nmethods >= 2 but only 1 unique NON-COMMON method
                    // Example: 0x05 0x05 0x05 0x05 0x05 (all same non-common method)
                    if ( socks.nmethods >= 2 && socks.unique_methods == 1 )
                    {
                        socks.state = SOCKS_STATE__NOT_FOUND;
                        return false;
                    }
                    
                    // Slow path: Only non-common methods - need 4-byte request header to confirm
                    // This adds ~1 RTT delay but only for rare non-common-method greetings
                    socks.state = SOCKS_STATE__V5_REQ_VER;
                    socks.v5_confirm_budget = 8;
                }
                break;
            }

            // 4-byte request header confirmation states
            // Validates: VER(0x05) CMD(0x01-0x03) RSV(0x00) ATYP(0x01/0x03/0x04)
            // Budget prevents staying in these states forever on trickle/junk data
            case SOCKS_STATE__V5_REQ_VER:
            {
                if ( socks.v5_confirm_budget == 0 )
                {
                    socks.state = SOCKS_STATE__NOT_FOUND;
                    return false;
                }
                socks.v5_confirm_budget--;

                if ( val == SOCKS5_VERSION )
                {
                    socks.state = SOCKS_STATE__V5_REQ_CMD;
                }
                else
                {
                    socks.state = SOCKS_STATE__NOT_FOUND;
                    return false;
                }
                break;
            }

            case SOCKS_STATE__V5_REQ_CMD:
            {
                if ( socks.v5_confirm_budget == 0 )
                {
                    socks.state = SOCKS_STATE__NOT_FOUND;
                    return false;
                }
                socks.v5_confirm_budget--;

                // CMD must be CONNECT(1), BIND(2), or UDP_ASSOCIATE(3)
                if ( val >= SOCKS_CMD_CONNECT && val <= SOCKS_CMD_UDP_ASSOCIATE )
                {
                    socks.state = SOCKS_STATE__V5_REQ_RSV;
                }
                else
                {
                    socks.state = SOCKS_STATE__NOT_FOUND;
                    return false;
                }
                break;
            }

            case SOCKS_STATE__V5_REQ_RSV:
            {
                if ( socks.v5_confirm_budget == 0 )
                {
                    socks.state = SOCKS_STATE__NOT_FOUND;
                    return false;
                }
                socks.v5_confirm_budget--;

                // RSV must be 0x00
                if ( val == 0x00 )
                {
                    socks.state = SOCKS_STATE__V5_REQ_ATYP;
                }
                else
                {
                    socks.state = SOCKS_STATE__NOT_FOUND;
                    return false;
                }
                break;
            }

            case SOCKS_STATE__V5_REQ_ATYP:
            {
                if ( socks.v5_confirm_budget == 0 )
                {
                    socks.state = SOCKS_STATE__NOT_FOUND;
                    return false;
                }
                socks.v5_confirm_budget--;

                // ATYP must be IPv4(1), Domain(3), or IPv6(4)
                if ( val == 0x01 || val == 0x03 || val == 0x04 )
                {
                    socks.state = SOCKS_STATE__FOUND;
                    return true;
                }
                else
                {
                    socks.state = SOCKS_STATE__NOT_FOUND;
                    return false;
                }
            }

            case SOCKS_STATE__FOUND:
            case SOCKS_STATE__NOT_FOUND:
                // These are handled at function entry - should not reach here
                // but keep for safety
                return (socks.state == SOCKS_STATE__FOUND);

            default:
                // Unknown state - should never happen
                socks.state = SOCKS_STATE__NOT_FOUND;
                return false;
        }
    }

    // Ran out of data before completing detection
    // Return false but DON'T change state - allows continuation with more data
    // This is critical for handling TCP segmentation
    return false;
}

#ifdef CATCH_TEST_BUILD

#include "catch/catch.hpp"
#include <cstring>

// ==================== Valid SOCKS5 Test Data ====================
// Detection logic (POLICY):
// - Fast accept if common methods (0x00-0x02) and no suspicious suffix → FOUND (no RTT delay)
// - Reject if nmethods >= 2 but only 1 unique non-common method → NOT_FOUND (pattern attack)
// - Reject if extra bytes after greeting don't parse as valid C2S request header → NOT_FOUND (LPD/junk)
// - Slow path for non-common methods only → need 4-byte request header to confirm
//   VER(0x05) CMD(0x01-0x03) RSV(0x00) ATYP(0x01/0x03/0x04)

// Valid SOCKS5: 1 method (NO_AUTH = 0x00) + 4-byte request header to confirm
// Greeting: VER(0x05) NMETHODS(0x01) METHOD(0x00)
// Request: VER(0x05) CMD(0x01=CONNECT) RSV(0x00) ATYP(0x01=IPv4)
static const uint8_t socks5_1method[] = { 0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01 };

// Valid SOCKS5: 2 methods (NO_AUTH, USERNAME_PASSWORD) + 4-byte request header
static const uint8_t socks5_2methods[] = { 0x05, 0x02, 0x00, 0x02, 0x05, 0x01, 0x00, 0x01 };

// Valid SOCKS5: 3 methods (NO_AUTH, GSSAPI, USERNAME_PASSWORD) + 4-byte request header
static const uint8_t socks5_3methods[] = { 0x05, 0x03, 0x00, 0x01, 0x02, 0x05, 0x01, 0x00, 0x01 };

// Valid SOCKS5: private method with NO_AUTH + 4-byte request header
static const uint8_t socks5_private_method[] = { 0x05, 0x02, 0x00, 0x80, 0x05, 0x01, 0x00, 0x01 };

// ==================== Valid SOCKS4 Test Data ====================

// Valid SOCKS4 CONNECT: port 80, IP 192.168.1.1, empty userid
static const uint8_t socks4_connect_empty_userid[] = { 
    0x04, 0x01,              // VER, CMD (CONNECT)
    0x00, 0x50,              // PORT (80)
    0xC0, 0xA8, 0x01, 0x01,  // IP (192.168.1.1)
    0x00                     // USERID (empty, just null)
};

// Valid SOCKS4 CONNECT: port 443, IP 8.8.8.8, userid "user"
static const uint8_t socks4_connect_with_userid[] = { 
    0x04, 0x01,              // VER, CMD (CONNECT)
    0x01, 0xBB,              // PORT (443)
    0x08, 0x08, 0x08, 0x08,  // IP (8.8.8.8)
    'u', 's', 'e', 'r', 0x00 // USERID "user"
};

// Valid SOCKS4 BIND: port 0 (server chooses), IP 10.0.0.1
static const uint8_t socks4_bind[] = { 
    0x04, 0x02,              // VER, CMD (BIND)
    0x00, 0x00,              // PORT (0 - server chooses)
    0x0A, 0x00, 0x00, 0x01,  // IP (10.0.0.1)
    0x00                     // USERID (empty)
};

// Valid SOCKS4 BIND: port 0, IP 0.0.0.0 (server chooses both) - like the test pcap!
static const uint8_t socks4_bind_all_zeros[] = { 
    0x04, 0x02,              // VER, CMD (BIND)
    0x00, 0x00,              // PORT (0 - server chooses)
    0x00, 0x00, 0x00, 0x00,  // IP (0.0.0.0 - server chooses)
    'u', 's', 'e', 'r', '1', 0x00  // USERID "user1"
};

// ==================== Valid SOCKS4a Test Data ====================

// Valid SOCKS4a CONNECT: domain "example.com"
static const uint8_t socks4a_connect[] = { 
    0x04, 0x01,              // VER, CMD (CONNECT)
    0x00, 0x50,              // PORT (80)
    0x00, 0x00, 0x00, 0x01,  // IP (0.0.0.1 = SOCKS4a indicator)
    0x00,                    // USERID (empty)
    'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x00  // DOMAIN
};

// Valid SOCKS4a with userid and domain
static const uint8_t socks4a_with_userid[] = { 
    0x04, 0x01,              // VER, CMD
    0x01, 0xBB,              // PORT (443)
    0x00, 0x00, 0x00, 0xFF,  // IP (0.0.0.255 = SOCKS4a indicator)
    'u', 's', 'e', 'r', 0x00,// USERID "user"
    't', 'e', 's', 't', '.', 'c', 'o', 'm', 0x00  // DOMAIN "test.com"
};

// ==================== Invalid Test Data ====================

// Invalid: wrong version
static const uint8_t invalid_version[] = { 0x03, 0x01, 0x00 };

// Invalid: SOCKS5 with 0 methods
static const uint8_t socks5_zero_methods[] = { 0x05, 0x00 };

// Invalid: SOCKS5 with NO_ACCEPTABLE (0xFF is server-only)
static const uint8_t socks5_ff_method[] = { 0x05, 0x01, 0xFF };

// Invalid: SOCKS4 with invalid command
static const uint8_t socks4_invalid_cmd[] = { 0x04, 0x03, 0x00, 0x50, 0xC0, 0xA8, 0x01, 0x01, 0x00 };

// Invalid: SOCKS4 CONNECT with port 0
static const uint8_t socks4_connect_port0[] = { 0x04, 0x01, 0x00, 0x00, 0xC0, 0xA8, 0x01, 0x01, 0x00 };

// Invalid: SOCKS4 with loopback IP
static const uint8_t socks4_loopback[] = { 0x04, 0x01, 0x00, 0x50, 0x7F, 0x00, 0x00, 0x01, 0x00 };

// Invalid: SOCKS4 with multicast IP
static const uint8_t socks4_multicast[] = { 0x04, 0x01, 0x00, 0x50, 0xE0, 0x00, 0x00, 0x01, 0x00 };

// Invalid: SOCKS4 with 0.0.0.0 IP
static const uint8_t socks4_zero_ip[] = { 0x04, 0x01, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00 };

// Invalid: SOCKS4 with 0.x.x.x IP (not 0.0.0.1-255)
static const uint8_t socks4_invalid_zero_ip[] = { 0x04, 0x01, 0x00, 0x50, 0x00, 0x01, 0x02, 0x03, 0x00 };

// Invalid: SOCKS4a with empty domain
static const uint8_t socks4a_empty_domain[] = { 
    0x04, 0x01, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00  // no domain chars
};

// ==================== Edge Cases (Allowed for Robustness) ====================

// Edge case: SOCKS5 with reserved method (0x0A-0x7F) + common method + 4-byte request header
static const uint8_t socks5_reserved_method[] = { 0x05, 0x02, 0x00, 0x50, 0x05, 0x01, 0x00, 0x01 };

// Edge case: SOCKS5 with only reserved method - needs 4-byte request header to confirm
// Greeting: VER(0x05) NMETHODS(0x01) METHOD(0x50=reserved)
// Request: VER(0x05) CMD(0x01=CONNECT) RSV(0x00) ATYP(0x01=IPv4)
static const uint8_t socks5_only_reserved[] = { 0x05, 0x01, 0x50, 0x05, 0x01, 0x00, 0x01 };

// Edge case: SOCKS4 with non-printable byte in USERID - allowed per RFC
static const uint8_t socks4_nonprintable_userid[] = { 
    0x04, 0x01, 0x00, 0x50, 0xC0, 0xA8, 0x01, 0x01, 0x01, 0x00  // userid has 0x01
};

// ==================== Tests ====================

// Helper to build SOCKS5 packet with 32 methods (max allowed) + 4-byte request header
// Array reference enforces buffer size at compile time
// 34 bytes for greeting (VER + NMETHODS + 32 methods) + 4 bytes for request header = 38 bytes
// Includes method 0x00 (NO_AUTH) so has_common=true
static void build_socks5_32methods(uint8_t (&buffer)[38])
{
    buffer[0] = 0x05;  // version
    buffer[1] = 32;    // nmethods
    // Use different methods: 0-9 (skip 0x0A which is rejected as LPD), then 11-32
    // This avoids 0x0A (LF) which is LPD line feed terminator, never used in SOCKS5
    for (int i = 0; i < 32; i++)
    {
        uint8_t method = (uint8_t)i;
        if (method >= 10)  // Skip over 0x0A by shifting up by 1
            method++;
        buffer[2 + i] = method;  // methods: 0-9, 11-33 (includes 0x00, 0x01, 0x02)
    }
    // 4-byte request header to confirm
    buffer[34] = 0x05;  // VER
    buffer[35] = 0x01;  // CMD (CONNECT)
    buffer[36] = 0x00;  // RSV
    buffer[37] = 0x01;  // ATYP (IPv4)
}

TEST_CASE("socks5 greeting detection", "[SocksCurse]")
{
    SECTION("common method - completes immediately")
    {
        // RFC 1928: Common methods 0x00 (NO_AUTH), 0x01 (GSSAPI), 0x02 (USERNAME_PASSWORD)
        // Wizard binds immediately, inspector validates
        CurseTracker tracker{};
        CHECK(true == CurseBook::socks_curse(socks5_2methods, sizeof(socks5_2methods), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__FOUND);
        CHECK(tracker.socks.nmethods == 2);
        CHECK(tracker.socks.has_common == true);
    }

    SECTION("non-common method - requires request header")
    {
        // Non-common methods need 4-byte request header confirmation
        CurseTracker tracker{};
        CHECK(true == CurseBook::socks_curse(socks5_only_reserved, sizeof(socks5_only_reserved), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__FOUND);
        CHECK(tracker.socks.has_common == false);
    }

    SECTION("max methods (32) - boundary")
    {
        // RFC 1928: NMETHODS field is 1 byte, but reasonable limit is 32
        uint8_t socks5_32methods[38];
        build_socks5_32methods(socks5_32methods);
        CurseTracker tracker{};
        CHECK(true == CurseBook::socks_curse(socks5_32methods, sizeof(socks5_32methods), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__FOUND);
        CHECK(tracker.socks.nmethods == 32);
    }

    SECTION("excessive methods (33) - sanity reject")
    {
        // Exceeds reasonable limit - sanity check
        uint8_t greeting[35];
        greeting[0] = 0x05;
        greeting[1] = 0x21; // 33 methods
        for (int i = 0; i < 33; i++)
            greeting[2 + i] = (i < 3) ? i : (i + 0x10);
        CurseTracker tracker{};
        CHECK(false == CurseBook::socks_curse(greeting, sizeof(greeting), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__NOT_FOUND);
        // NOT_FOUND is sticky within a tracker - verify it stays NOT_FOUND
        CHECK(false == CurseBook::socks_curse(socks5_1method, sizeof(socks5_1method), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__NOT_FOUND);
        // Fresh tracker with valid data should work
        CurseTracker tracker2{};
        CHECK(true == CurseBook::socks_curse(socks5_1method, sizeof(socks5_1method), &tracker2));
        CHECK(tracker2.socks.state == SOCKS_STATE__FOUND);
    }
}

TEST_CASE("segmentation handling", "[SocksCurse]")
{
    SECTION("SOCKS5 byte-by-byte")
    {
        // RFC 1928: VER(1) + NMETHODS(1) + METHODS(N)
        CurseTracker tracker{};
        CHECK(false == CurseBook::socks_curse(&socks5_2methods[0], 1, &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__V5_NMETHODS);
        
        CHECK(false == CurseBook::socks_curse(&socks5_2methods[1], 1, &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__V5_METHODS);
        
        CHECK(false == CurseBook::socks_curse(&socks5_2methods[2], 1, &tracker));
        CHECK(tracker.socks.has_common == true);
        
        CHECK(true == CurseBook::socks_curse(&socks5_2methods[3], 1, &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__FOUND);
    }

    SECTION("SOCKS4 byte-by-byte")
    {
        // RFC 1928: VER(1) + CMD(1) + PORT(2) + IP(4) + USERID(N) + NULL(1)
        CurseTracker tracker{};
        const uint8_t* data = socks4_connect_empty_userid;
        unsigned len = sizeof(socks4_connect_empty_userid);
        
        for (unsigned i = 0; i < len - 1; i++)
            CHECK(false == CurseBook::socks_curse(&data[i], 1, &tracker));
        
        CHECK(true == CurseBook::socks_curse(&data[len-1], 1, &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__FOUND);
    }

    SECTION("SOCKS4a domain split")
    {
        // RFC 1928: Domain can be split across packets
        const uint8_t socks4a_full[] = { 
            0x04, 0x01, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00,
            'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x00
        };
        
        CurseTracker tracker{};
        const size_t split_point = 14; // Split in middle of "example.com"
        CHECK(false == CurseBook::socks_curse(socks4a_full, split_point, &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__V4A_DOMAIN);
        
        const size_t remaining = sizeof(socks4a_full) - split_point;
        CHECK(true == CurseBook::socks_curse(&socks4a_full[split_point], remaining, &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__FOUND);
        CHECK(tracker.socks.domain_length == 11);
    }
}

TEST_CASE("socks5 edge cases", "[SocksCurse]")
{
    SECTION("reserved method with common method (allowed)")
    {
        // Reserved methods (0x0A-0x7F) are ALLOWED when combined with common method
        CurseTracker tracker{};
        CHECK(true == CurseBook::socks_curse(socks5_reserved_method, sizeof(socks5_reserved_method), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__FOUND);
        CHECK(tracker.socks.has_common == true);
    }

    SECTION("only reserved method - needs 4-byte request header to confirm")
    {
        // Reserved method alone needs full 4-byte request header to confirm
        // VER(0x05) CMD(0x01) RSV(0x00) ATYP(0x01)
        CurseTracker tracker{};
        CHECK(true == CurseBook::socks_curse(socks5_only_reserved, sizeof(socks5_only_reserved), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__FOUND);
    }

    SECTION("only reserved method - no confirmation data")
    {
        // Reserved method alone without request header - stays in V5_REQ_VER
        CurseTracker tracker{};
        uint8_t only_reserved_no_confirm[] = { 0x05, 0x01, 0x50 };  // no follow-up
        CHECK(false == CurseBook::socks_curse(only_reserved_no_confirm, sizeof(only_reserved_no_confirm), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__V5_REQ_VER);
    }

    SECTION("only reserved method - wrong request header VER")
    {
        // Reserved method with wrong VER in request header -> NOT_FOUND
        CurseTracker tracker{};
        uint8_t wrong_ver[] = { 0x05, 0x01, 0x50, 0x04 };  // VER=0x04 is wrong
        CHECK(false == CurseBook::socks_curse(wrong_ver, sizeof(wrong_ver), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__NOT_FOUND);
    }

    SECTION("only reserved method - wrong request header CMD")
    {
        // Reserved method with wrong CMD in request header -> NOT_FOUND
        CurseTracker tracker{};
        uint8_t wrong_cmd[] = { 0x05, 0x01, 0x50, 0x05, 0x04 };  // CMD=0x04 is invalid
        CHECK(false == CurseBook::socks_curse(wrong_cmd, sizeof(wrong_cmd), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__NOT_FOUND);
    }

    SECTION("only reserved method - wrong request header RSV")
    {
        // Reserved method with wrong RSV in request header -> NOT_FOUND
        CurseTracker tracker{};
        uint8_t wrong_rsv[] = { 0x05, 0x01, 0x50, 0x05, 0x01, 0x01 };  // RSV=0x01 is wrong
        CHECK(false == CurseBook::socks_curse(wrong_rsv, sizeof(wrong_rsv), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__NOT_FOUND);
    }

    SECTION("only reserved method - wrong request header ATYP")
    {
        // Reserved method with wrong ATYP in request header -> NOT_FOUND
        CurseTracker tracker{};
        uint8_t wrong_atyp[] = { 0x05, 0x01, 0x50, 0x05, 0x01, 0x00, 0x02 };  // ATYP=0x02 is invalid
        CHECK(false == CurseBook::socks_curse(wrong_atyp, sizeof(wrong_atyp), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__NOT_FOUND);
    }

}

TEST_CASE("socks5 invalid input", "[SocksCurse]")
{
    SECTION("zero methods")
    {
        CurseTracker tracker{};
        CHECK(false == CurseBook::socks_curse(socks5_zero_methods, sizeof(socks5_zero_methods), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__NOT_FOUND);
    }

    SECTION("0xFF method (server-only)")
    {
        CurseTracker tracker{};
        CHECK(false == CurseBook::socks_curse(socks5_ff_method, sizeof(socks5_ff_method), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__NOT_FOUND);
    }

    SECTION("wrong version")
    {
        CurseTracker tracker{};
        CHECK(false == CurseBook::socks_curse(invalid_version, sizeof(invalid_version), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__NOT_FOUND);
    }

    SECTION("too many methods (> 32)")
    {
        CurseTracker tracker{};
        uint8_t too_many[] = { 0x05, 0x40 };  // 64 methods > 32 limit
        CHECK(false == CurseBook::socks_curse(too_many, sizeof(too_many), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__NOT_FOUND);
    }

    SECTION("LPD false positive - 0x0A as extra byte after greeting")
    {
        // Real-world LPD: 05 05 05 05 41 41 00 0a (8 bytes from actual traffic)
        // NMETHODS=5, methods: 05,05,41,41,00, then extra byte 0x0A (LF terminator)
        // This mimics SOCKS5 but is actually printer protocol
        CurseTracker tracker{};
        uint8_t lpd_pattern[] = { 0x05, 0x05, 0x05, 0x05, 0x41, 0x41, 0x00, 0x0A };
        
        CHECK(false == CurseBook::socks_curse(lpd_pattern, sizeof(lpd_pattern), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__NOT_FOUND);
    }

    SECTION("LPD false positive - 0x0A as method value")
    {
        // Real-world LPD: 05 05 05 05 00 0a (6 bytes)
        // NMETHODS=5, methods: 05,05,05,00,0x0A
        // 0x0A as a method value is LPD line feed terminator
        CurseTracker tracker{};
        uint8_t lpd_with_lf_method[] = { 0x05, 0x05, 0x05, 0x05, 0x00, 0x0A };
        
        CHECK(false == CurseBook::socks_curse(lpd_with_lf_method, sizeof(lpd_with_lf_method), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__NOT_FOUND);
    }

    SECTION("SOCKS5 greeting with 0x00 after - should accept")
    {
        // Real SOCKS5 from socks_sessions PCAP: 05 06 00 01 00 00 00 00 [00]
        // NMETHODS=6, methods: 00,01,00,00,00,00 (has common method 0x00)
        // Extra 0x00 byte should NOT be rejected (only 0x0A is LPD-specific)
        CurseTracker tracker{};
        uint8_t with_null[] = { 0x05, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };
        
        CHECK(true == CurseBook::socks_curse(with_null, sizeof(with_null), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__FOUND);
        CHECK(tracker.socks.has_common == true);
    }

    SECTION("repeated common method - needs request header to confirm")
    {
        // Repeated common method (0x00) needs request header to confirm
        // This is "stupid but valid" - a client sending duplicate NO_AUTH
        CurseTracker tracker{};
        uint8_t all_same[] = { 0x05, 0x02, 0x00, 0x00, 0x05, 0x01, 0x00, 0x01 };  // greeting + request
        CHECK(true == CurseBook::socks_curse(all_same, sizeof(all_same), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__FOUND);
        CHECK(tracker.socks.has_common == true);
        CHECK(tracker.socks.unique_methods == 1);
        CHECK(tracker.socks.saw_duplicate == true);
    }

    SECTION("duplicates OK if multiple unique methods")
    {
        // Duplicates are fine as long as there are multiple unique methods
        CurseTracker tracker{};
        uint8_t with_dups[] = { 0x05, 0x04, 0x00, 0x00, 0x01, 0x01, 0x05, 0x01, 0x00, 0x01 };  // greeting + request
        CHECK(true == CurseBook::socks_curse(with_dups, sizeof(with_dups), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__FOUND);
        CHECK(tracker.socks.unique_methods == 2);
        CHECK(tracker.socks.saw_duplicate == true);
        CHECK(tracker.socks.has_common == true);
    }

    SECTION("nmethods=5 with common method - needs request header")
    {
        // nmethods=5 is fine if it has common methods, but needs request header
        CurseTracker tracker{};
        uint8_t valid_5methods[] = { 0x05, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01, 0x00, 0x01 };
        CHECK(true == CurseBook::socks_curse(valid_5methods, sizeof(valid_5methods), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__FOUND);
        CHECK(tracker.socks.has_common == true);
    }

    SECTION("nmethods=1 with single method - needs request header")
    {
        // Single method needs request header to confirm
        CurseTracker tracker{};
        uint8_t single[] = { 0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01 };  // greeting + request
        CHECK(true == CurseBook::socks_curse(single, sizeof(single), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__FOUND);
    }

    SECTION("pattern attack - all identical methods (the real attack)")
    {
        // This is the actual attack pattern: 0x05 0x05 0x05 0x05 0x05 0x05
        // VER=5, NMETHODS=5, all 5 methods are 0x05
        // Rejected because nmethods >= 2 but unique_methods == 1
        CurseTracker tracker{};
        uint8_t all_fives[] = { 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05 };
        CHECK(false == CurseBook::socks_curse(all_fives, sizeof(all_fives), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__NOT_FOUND);
        CHECK(tracker.socks.unique_methods == 1);
    }

    SECTION("nmethods=5 first_method=0x05 but mixed methods - needs request header")
    {
        // nmethods=5 with first method=0x05 is ALLOWED if it has common methods
        // This was previously rejected by the overfitting rule
        CurseTracker tracker{};
        uint8_t mixed[] = { 0x05, 0x05, 0x05, 0x00, 0x01, 0x02, 0x03, 0x05, 0x01, 0x00, 0x01 };  // greeting + request
        CHECK(true == CurseBook::socks_curse(mixed, sizeof(mixed), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__FOUND);
        CHECK(tracker.socks.has_common == true);
        CHECK(tracker.socks.unique_methods == 5);
    }
}

TEST_CASE("socks4 and socks4a detection", "[SocksCurse]")
{
    SECTION("SOCKS4 CONNECT")
    {
        CurseTracker tracker{};
        CHECK(true == CurseBook::socks_curse(socks4_connect_with_userid, 
            sizeof(socks4_connect_with_userid), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__FOUND);
        CHECK(tracker.socks.version == 0x04);
        CHECK(tracker.socks.command == SOCKS_CMD_CONNECT);
        CHECK(tracker.socks.port == 443);
        CHECK(tracker.socks.userid_length == 4);
        CHECK(tracker.socks.is_socks4a == false);
    }

    SECTION("SOCKS4 BIND - port 0 allowed")
    {
        // RFC 1928: port 0 means server chooses
        CurseTracker tracker{};
        CHECK(true == CurseBook::socks_curse(socks4_bind, sizeof(socks4_bind), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__FOUND);
        CHECK(tracker.socks.command == SOCKS_CMD_BIND);
        CHECK(tracker.socks.port == 0);
    }

    SECTION("SOCKS4a with domain")
    {
        // RFC 1928: SOCKS4a uses IP 0.0.0.x to signal domain name follows
        CurseTracker tracker{};
        CHECK(true == CurseBook::socks_curse(socks4a_with_userid, sizeof(socks4a_with_userid), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__FOUND);
        CHECK(tracker.socks.is_socks4a == true);
        CHECK(tracker.socks.userid_length == 4);
        CHECK(tracker.socks.domain_length == 8);
    }
}

TEST_CASE("socks4 invalid input", "[SocksCurse]")
{
    SECTION("invalid command")
    {
        CurseTracker tracker{};
        CHECK(false == CurseBook::socks_curse(socks4_invalid_cmd, sizeof(socks4_invalid_cmd), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__NOT_FOUND);
    }

    SECTION("CONNECT with port 0")
    {
        CurseTracker tracker{};
        CHECK(false == CurseBook::socks_curse(socks4_connect_port0, sizeof(socks4_connect_port0), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__NOT_FOUND);
    }

    SECTION("loopback IP")
    {
        CurseTracker tracker{};
        CHECK(false == CurseBook::socks_curse(socks4_loopback, sizeof(socks4_loopback), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__NOT_FOUND);
    }

    SECTION("multicast IP")
    {
        CurseTracker tracker{};
        CHECK(false == CurseBook::socks_curse(socks4_multicast, sizeof(socks4_multicast), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__NOT_FOUND);
    }

    SECTION("0.0.0.0 IP")
    {
        CurseTracker tracker{};
        CHECK(false == CurseBook::socks_curse(socks4_zero_ip, sizeof(socks4_zero_ip), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__NOT_FOUND);
    }

    SECTION("invalid 0.x.x.x IP")
    {
        CurseTracker tracker{};
        CHECK(false == CurseBook::socks_curse(socks4_invalid_zero_ip, sizeof(socks4_invalid_zero_ip), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__NOT_FOUND);
    }

    SECTION("non-printable userid (allowed)")
    {
        // Non-printable bytes in USERID are ALLOWED per SOCKS4 RFC
        CurseTracker tracker{};
        CHECK(true == CurseBook::socks_curse(socks4_nonprintable_userid, sizeof(socks4_nonprintable_userid), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__FOUND);
    }

    SECTION("socks4a empty domain")
    {
        CurseTracker tracker{};
        CHECK(false == CurseBook::socks_curse(socks4a_empty_domain, sizeof(socks4a_empty_domain), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__NOT_FOUND);
    }
}

TEST_CASE("not_found state is sticky", "[SocksCurse]")
{
    CurseTracker tracker{};
    // First, fail detection
    CHECK(false == CurseBook::socks_curse(invalid_version, sizeof(invalid_version), &tracker));
    CHECK(tracker.socks.state == SOCKS_STATE__NOT_FOUND);
    
    // Even with valid data, should stay NOT_FOUND
    CHECK(false == CurseBook::socks_curse(socks5_1method, sizeof(socks5_1method), &tracker));
    CHECK(tracker.socks.state == SOCKS_STATE__NOT_FOUND);
}

TEST_CASE("socks4 length boundaries", "[SocksCurse]")
{
    SECTION("userid 255 bytes - max allowed")
    {
        // VER + CMD + PORT + IP + 255 userid bytes + NULL
        uint8_t socks4_max_userid[1 + 1 + 2 + 4 + 255 + 1];
        socks4_max_userid[0] = 0x04;  // version
        socks4_max_userid[1] = 0x01;  // CONNECT
        socks4_max_userid[2] = 0x00;  // port MSB
        socks4_max_userid[3] = 0x50;  // port LSB (80)
        socks4_max_userid[4] = 0xC0;  // IP 192.168.1.1
        socks4_max_userid[5] = 0xA8;
        socks4_max_userid[6] = 0x01;
        socks4_max_userid[7] = 0x01;
        for (int i = 0; i < 255; i++)
            socks4_max_userid[8 + i] = 'A';  // 255 'A's
        socks4_max_userid[sizeof(socks4_max_userid) - 1] = 0x00;  // NULL terminator
        
        CurseTracker tracker{};
        CHECK(true == CurseBook::socks_curse(socks4_max_userid, sizeof(socks4_max_userid), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__FOUND);
        CHECK(tracker.socks.userid_length == 255);
    }

    SECTION("domain 255 bytes - max allowed")
    {
        // SOCKS4a: VER + CMD + PORT + SOCKS4a_IP + USERID(empty) + 255 domain bytes + NULL
        uint8_t socks4a_max_domain[1 + 1 + 2 + 4 + 1 + 255 + 1];
        socks4a_max_domain[0] = 0x04;  // version
        socks4a_max_domain[1] = 0x01;  // CONNECT
        socks4a_max_domain[2] = 0x00;  // port MSB
        socks4a_max_domain[3] = 0x50;  // port LSB
        socks4a_max_domain[4] = 0x00;  // SOCKS4a indicator
        socks4a_max_domain[5] = 0x00;
        socks4a_max_domain[6] = 0x00;
        socks4a_max_domain[7] = 0x01;
        socks4a_max_domain[8] = 0x00;  // empty userid
        for (int i = 0; i < 255; i++)
            socks4a_max_domain[9 + i] = 'a';  // 255 'a's
        socks4a_max_domain[sizeof(socks4a_max_domain) - 1] = 0x00;  // NULL terminator
        
        CurseTracker tracker{};
        CHECK(true == CurseBook::socks_curse(socks4a_max_domain, sizeof(socks4a_max_domain), &tracker));
        CHECK(tracker.socks.state == SOCKS_STATE__FOUND);
        CHECK(tracker.socks.domain_length == 255);
    }

    SECTION("userid 256 bytes - reject")
    {
        INFO("Testing that 256-byte USERID is rejected even with NULL terminator present");
        // VER + CMD + PORT + IP + 256 userid bytes + NULL
        // Proves rejection is due to length, not missing terminator
        uint8_t socks4_over_userid[1 + 1 + 2 + 4 + 256 + 1];
        socks4_over_userid[0] = 0x04;  // version
        socks4_over_userid[1] = 0x01;  // CONNECT
        socks4_over_userid[2] = 0x00;  // port MSB
        socks4_over_userid[3] = 0x50;  // port LSB
        socks4_over_userid[4] = 0xC0;  // IP 192.168.1.1
        socks4_over_userid[5] = 0xA8;
        socks4_over_userid[6] = 0x01;
        socks4_over_userid[7] = 0x01;
        for (int i = 0; i < 256; i++)
            socks4_over_userid[8 + i] = 'A';  // 256 'A's
        socks4_over_userid[sizeof(socks4_over_userid) - 1] = 0x00;  // NULL terminator
        
        CurseTracker tracker{};
        // Should fail when 256th byte is processed (userid_length >= 255)
        // Even with terminator present, over-limit is rejected
        CHECK(false == CurseBook::socks_curse(socks4_over_userid, sizeof(socks4_over_userid), &tracker));
        INFO("Expected NOT_FOUND, got state=" << static_cast<int>(tracker.socks.state));
        CHECK(tracker.socks.state == SOCKS_STATE__NOT_FOUND);
    }

    SECTION("domain 256 bytes - reject")
    {
        // SOCKS4a: RFC 1928 limit is 255 bytes
        uint8_t socks4a_over_domain[1 + 1 + 2 + 4 + 1 + 256 + 1];
        socks4a_over_domain[0] = 0x04;  // version
        socks4a_over_domain[1] = 0x01;  // CONNECT
        socks4a_over_domain[2] = 0x00;  // port MSB
        socks4a_over_domain[3] = 0x50;  // port LSB
        socks4a_over_domain[4] = 0x00;  // SOCKS4a indicator
        socks4a_over_domain[5] = 0x00;
        socks4a_over_domain[6] = 0x00;
        socks4a_over_domain[7] = 0x01;
        socks4a_over_domain[8] = 0x00;  // empty userid
        for (int i = 0; i < 256; i++)
            socks4a_over_domain[9 + i] = 'a';  // 256 'a's
        socks4a_over_domain[sizeof(socks4a_over_domain) - 1] = 0x00;  // NULL terminator
        
        CurseTracker tracker{};
        // Should fail when 256th domain byte is processed (domain_length >= 255)
        // Even with terminator present, over-limit is rejected
        CHECK(false == CurseBook::socks_curse(socks4a_over_domain, sizeof(socks4a_over_domain), &tracker));
        INFO("Expected NOT_FOUND, got state=" << static_cast<int>(tracker.socks.state));
        CHECK(tracker.socks.state == SOCKS_STATE__NOT_FOUND);
    }
}

#endif

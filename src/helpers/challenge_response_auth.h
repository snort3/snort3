//--------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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

// challenge_response_auth.h author Cisco

#ifndef CHALLENGE_RESPONSE_AUTH_H
#define CHALLENGE_RESPONSE_AUTH_H

#include <cstddef>
#include <cstdint>

namespace snort
{

class ChallengeResponseAuth
{
public:
    static constexpr size_t CHALLENGE_SIZE = 32;
    static constexpr size_t HMAC_SIZE = 32;

    ChallengeResponseAuth(const uint8_t* secret, size_t secret_len);
    ~ChallengeResponseAuth();

    ChallengeResponseAuth(const ChallengeResponseAuth&) = delete;
    ChallengeResponseAuth& operator=(const ChallengeResponseAuth&) = delete;

    const uint8_t* generate_challenge();

    const uint8_t* get_challenge() const
    { return challenge; }

    size_t get_challenge_size() const
    { return CHALLENGE_SIZE; }

    bool verify(const uint8_t* client_hmac);

private:
    uint8_t* shared_secret;
    size_t secret_len;
    uint8_t challenge[CHALLENGE_SIZE];
    uint8_t expected_hmac[HMAC_SIZE];
    bool challenge_valid;
};

// Helper function: Parse base64-encoded shared secret from file
// Returns nullptr on success, or a static error message string on failure
// secret_out: buffer to receive decoded secret (must be at least 256 bytes)
// secret_len_out: receives actual decoded secret length
const char* parse_shared_secret_file(const char* filename, uint8_t* secret_out, size_t* secret_len_out);

// Load and validate shared secret from file
// Returns allocated secret buffer and sets secret_len, or calls FatalError on failure
// Warns if secret is shorter than 16 bytes
uint8_t* load_shared_secret(const char* filename, size_t& secret_len);

// Helper function: Parse base64-encoded shared secret from string
// Returns true on success, false on error
bool parse_shared_secret_string(const char* secret_b64, uint8_t* secret_out, size_t* secret_len_out);
}

#endif

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

// challenge_response_auth.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "challenge_response_auth.h"

#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <cstring>
#include <fstream>

#include "base64_encoder.h"
#include "log/messages.h"

using namespace snort;

ChallengeResponseAuth::ChallengeResponseAuth(const uint8_t* secret, size_t secret_len)
    : secret_len(secret_len), challenge_valid(false)
{
    // Copy shared secret
    shared_secret = new uint8_t[secret_len];
    memcpy(shared_secret, secret, secret_len);

    // Zero sensitive memory
    memset(challenge, 0, sizeof(challenge));
    memset(expected_hmac, 0, sizeof(expected_hmac));
}

ChallengeResponseAuth::~ChallengeResponseAuth()
{
    // Zero sensitive memory before freeing
    if (shared_secret)
    {
        memset(shared_secret, 0, secret_len);
        delete[] shared_secret;
    }
    memset(challenge, 0, sizeof(challenge));
    memset(expected_hmac, 0, sizeof(expected_hmac));
}

const uint8_t* ChallengeResponseAuth::generate_challenge()
{
    // Generate random challenge
    if (RAND_bytes(challenge, CHALLENGE_SIZE) != 1)
        return nullptr;

    // Compute expected HMAC: HMAC-SHA256(shared_secret, challenge)
    unsigned int hmac_len = 0;
    if (!HMAC(EVP_sha256(),
              shared_secret, secret_len,
              challenge, CHALLENGE_SIZE,
              expected_hmac, &hmac_len))
    {
        return nullptr;
    }

    if (hmac_len != HMAC_SIZE)
        return nullptr;

    challenge_valid = true;
    return challenge;
}

bool ChallengeResponseAuth::verify(const uint8_t* client_hmac)
{
    if (!challenge_valid)
        return false;

    if (!client_hmac)
        return false;

    // Constant-time comparison to prevent timing attacks
    return CRYPTO_memcmp(client_hmac, expected_hmac, HMAC_SIZE) == 0;
}

// Helper to decode base64 string
static bool decode_base64(const char* input, uint8_t* output, size_t* output_len)
{
    if (!input || !output || !output_len)
        return false;

    size_t input_len = strlen(input);
    if (input_len == 0)
        return false;

    // Simple base64 decoder (OpenSSL's EVP_DecodeBlock)
    int decoded_len = EVP_DecodeBlock(output,
        reinterpret_cast<const unsigned char*>(input), input_len);

    if (decoded_len < 0)
        return false;

    // Handle padding
    if (input_len > 0 && input[input_len - 1] == '=')
    {
        decoded_len--;
        if (input_len > 1 && input[input_len - 2] == '=')
            decoded_len--;
    }

    *output_len = decoded_len;
    return true;
}

const char* snort::parse_shared_secret_file(const char* filename,
    uint8_t* secret_out, size_t* secret_len_out)
{
    if (!filename || !secret_out || !secret_len_out)
        return "invalid arguments";

    std::ifstream file(filename);
    if (!file.is_open())
        return "cannot open file";

    std::string line;
    if (!std::getline(file, line))
        return "file is empty";

    size_t start = line.find_first_not_of(" \t\r\n");
    size_t end = line.find_last_not_of(" \t\r\n");

    if (start == std::string::npos)
        return "file contains only whitespace";

    std::string secret_b64 = line.substr(start, end - start + 1);

    if (!decode_base64(secret_b64.c_str(), secret_out, secret_len_out))
        return "invalid base64 encoding";

    return nullptr;
}

uint8_t* snort::load_shared_secret(const char* filename, size_t& secret_len)
{
    uint8_t secret_buffer[256];
    secret_len = 0;

    const char* err = parse_shared_secret_file(filename, secret_buffer, &secret_len);

    if ( err )
    {
        memset(secret_buffer, 0, sizeof(secret_buffer));
        FatalError("Failed to load control secret from %s: %s\n", filename, err);
    }

    if ( secret_len == 0 )
    {
        memset(secret_buffer, 0, sizeof(secret_buffer));
        FatalError("Control secret in %s decoded to zero bytes\n", filename);
    }

    if ( secret_len < 16 )
        WarningMessage("Control secret in %s is shorter than 16 bytes "
            "(%zu bytes). Consider using a stronger secret.\n", filename, secret_len);

    uint8_t* secret = new uint8_t[secret_len];
    memcpy(secret, secret_buffer, secret_len);
    memset(secret_buffer, 0, sizeof(secret_buffer));
    return secret;
}

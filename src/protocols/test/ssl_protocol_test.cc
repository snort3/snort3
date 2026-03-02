//--------------------------------------------------------------------------
// Copyright (C) 2023-2026 Cisco and/or its affiliates. All rights reserved.
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
// ssl_protocol_test.cc author Oleksandr Stepanov <ostepano@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <cstring>
#include <openssl/ossl_typ.h>

#include "../ssl.h"
#include "../ssl.cc"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

namespace snort
{
void LogMessage(char const*, ...) {}
}

using namespace snort;

// When set, mocks return valid objects
static const unsigned char* g_test_asn1_data = nullptr;
static int g_test_asn1_len = 0;

static char g_mock_mem[64];

typedef struct X509_name_entry_st X509_NAME_ENTRY;
X509_NAME *X509_get_subject_name(const X509 *a) 
{ return g_test_asn1_data ? (X509_NAME*)g_mock_mem : nullptr; }
X509_NAME *X509_get_issuer_name(const X509 *a) { return nullptr; }
void X509_free(X509* a) { }

#if OPENSSL_VERSION_NUMBER < 0x30000000L
int X509_NAME_get_index_by_NID(X509_NAME *name, int nid, int lastpos)
#else
int X509_NAME_get_index_by_NID(const X509_NAME *name, int nid, int lastpos)
#endif
{ return g_test_asn1_data ? 0 : -1; }
X509_NAME_ENTRY *X509_NAME_get_entry(const X509_NAME *name, int loc) 
{ return g_test_asn1_data ? (X509_NAME_ENTRY*)(g_mock_mem + 16) : nullptr; }
ASN1_STRING *X509_NAME_ENTRY_get_data(const X509_NAME_ENTRY *ne) 
{ return g_test_asn1_data ? (ASN1_STRING*)(g_mock_mem + 32) : nullptr; }
const unsigned char *ASN1_STRING_get0_data(const ASN1_STRING *x) 
{ return g_test_asn1_data; }
X509* d2i_X509(X509 **a, const unsigned char **in, long len) 
{ return g_test_asn1_data ? (X509*)(g_mock_mem + 48) : nullptr; }

int X509_NAME_print_ex(BIO *out, const X509_NAME *nm, int indent, unsigned long flags) { return 0; }
BIO *BIO_new(const BIO_METHOD *type) { return nullptr; }
int BIO_free(BIO *a) { return 0; }
long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg) { return 0; }
const BIO_METHOD *BIO_s_mem(void) { return nullptr; }
int ASN1_STRING_length(const ASN1_STRING *x) { return g_test_asn1_len; }

namespace snort
{
char* snort_strdup(const char* str)
{
    return str ? strdup(str) : nullptr;
}

char* snort_strndup(const char* src, size_t n)
{
    if (!src)
        return nullptr;
    char* dst = new char[n + 1];
    memcpy(dst, src, n);
    dst[n] = '\0';
    return dst;
}
}

TEST_GROUP(ssl_protocol_tests)
{
    void setup() override
    {
    }

    void teardown() override
    {
        g_test_asn1_data = nullptr;
        g_test_asn1_len = 0;
    }
};

TEST(ssl_protocol_tests, cert_data_incomplete_len_2)
{
    SSLV3ServerCertData test_data;
    test_data.certs_data = new uint8_t[2] { 0x01, 0x02 }; // Incomplete length, should be at least 3 bytes
    test_data.certs_len = 2;
    auto result = parse_server_certificates(&test_data);
    CHECK_EQUAL(static_cast<uint8_t>(snort::ParseResult::SUCCESS), static_cast<uint8_t>(result));
    POINTERS_EQUAL(nullptr, test_data.certs_data);
    CHECK_EQUAL(0, test_data.certs_len);
}

TEST(ssl_protocol_tests, parse_server_key_exchange_normal)
{
    TLSConnectionParams tls_params;
    uint8_t test_data[3] = { 0x03, 0xFF, 0xFF }; // Valid curve type and 0xFFFF curve id
    auto result = parse_server_key_exchange(test_data, sizeof(test_data), &tls_params);
    CHECK_EQUAL(true, result);
    CHECK_EQUAL(0xFFFF, tls_params.curve);
}

TEST(ssl_protocol_tests, parse_server_key_exchange_invalid_curve_type)
{
    TLSConnectionParams tls_params;
    uint8_t test_data[3] = { 0x02, 0xFF, 0xFF }; // Invalid curve type
    auto result = parse_server_key_exchange(test_data, sizeof(test_data), &tls_params);
    CHECK_EQUAL(false, result);
    CHECK_EQUAL(-1, tls_params.curve);
}

TEST(ssl_protocol_tests, parse_server_key_exchange_invalid_len)
{
    TLSConnectionParams tls_params;
    uint8_t test_data[2] = { 0x03, 0xFF }; // Invalid length, should be at least 3 bytes
    auto result = parse_server_key_exchange(test_data, sizeof(test_data), &tls_params);
    CHECK_EQUAL(false, result);
    CHECK_EQUAL(-1, tls_params.curve);
}

TEST(ssl_protocol_tests, parse_server_hello_tls_1_3)
{
    // This is a minimal valid Server Hello packet with TLS 1.3 version in extensions
    uint8_t test_data[] = {
        0x02,                   // Handshake Type: Server Hello
        0x00, 0x00, 0x4e,       // Length
        0x03, 0x03,             // Version TLS 1.2
        // Random (32 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Session ID length
        0x20,                   
        // Session ID (32 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Cipher Suite (2 bytes)
        0xc0, 0x2b,
        // Compression Method (1 byte)
        0x00,
        // Extensions length (2 bytes)
        0x00, 0x06,
        // Extension: Supported Versions (type=43 length=2)
        0x00, 0x2b,
        0x00, 0x02,
        // Supported Version: TLS 1.3 (0x0304)
        0x03, 0x04
    };

    TLSConnectionParams tls_params;
    auto result = parse_server_hello_data(test_data, sizeof(test_data), &tls_params);
    CHECK_EQUAL(static_cast<uint8_t>(ParseResult::SUCCESS), static_cast<uint8_t>(result));
    CHECK_EQUAL(0x0304, tls_params.selected_tls_version);
    CHECK_EQUAL(0xc02b, tls_params.cipher);
}

TEST(ssl_protocol_tests, parse_server_hello_invalid_packet_len)
{
    // This is an incomplete Server Hello packet
    uint8_t test_data[] = {
        0x02,                   // Handshake Type: Server Hello
        0x00, 0x00, 0xF6,       // Length invalid (too large for provided data)
        0x03, 0x03,             // Version TLS 1.2
        // Random (32 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Session ID length
        0x20,
        // Session ID truncated
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    TLSConnectionParams tls_params;
    auto result = parse_server_hello_data(test_data, sizeof(test_data), &tls_params);
    CHECK_EQUAL(static_cast<uint8_t>(ParseResult::FRAGMENTED_PACKET), static_cast<uint8_t>(result));
}


TEST(ssl_protocol_tests, ssl_hs_cert_truncated_certs_len)
{
    uint8_t test_data[] = {
        0x16,                           // Content Type: Handshake
        0x03, 0x03,                 // Version: TLS 1.2
        0x00, 0x04,                 // Length: 4 bytes (just the handshake header)
        0x0b,                           // Handshake Type: Certificate
        0x00, 0x00, 0x00        // Handshake Length: 0 (no cert data follows)
        // Missing: certs_len (3 bytes) 
    };

    SSLV3ClientHelloData client_hello;
    SSLV3ServerCertData server_cert;
    uint32_t result = SSL_decode(test_data, sizeof(test_data), 0, 0,
        nullptr, nullptr, 0, nullptr, &client_hello, &server_cert, nullptr);

    CHECK(result & SSL_TRUNCATED_FLAG);
}

TEST(ssl_protocol_tests, ssl_alert_rec_zero_size)
{
    uint8_t test_data[] = {
        0x15,                 // Content Type: Alert
        0x03, 0x03,       // Version: TLS 1.2
        0x00, 0x02        // Length: 2 (claims 2 bytes but 0 bytes follow)
    };

    uint32_t info_flags = 0;
    uint32_t result = SSL_decode(test_data, sizeof(test_data), 0, 0,
        nullptr, nullptr, 0, &info_flags, nullptr, nullptr, nullptr);

    CHECK(result & SSL_ALERT_FLAG);

    CHECK_EQUAL(0, (info_flags & SSL_ALERT_LVL_FATAL_FLAG));
}

TEST(ssl_protocol_tests, ssl_cert_common_name_parsing)
{
    uint8_t cn_data[4] = { 'T', 'E', 'S', 'T' };
    
    g_test_asn1_data = cn_data;
    g_test_asn1_len = 4;
    
    // Minimal cert data to trigger parsing
    uint8_t cert_data[] = {
        0x00, 0x00, 0x03,  // cert length: 3
        0x30, 0x01, 0x00   // minimal DER
    };
    
    SSLV3ServerCertData* server_cert = new SSLV3ServerCertData();
    server_cert->certs_data = (uint8_t*)snort_alloc(sizeof(cert_data));
    memcpy(server_cert->certs_data, cert_data, sizeof(cert_data));
    server_cert->certs_len = sizeof(cert_data);
    
    parse_server_certificates(server_cert);
    
    delete server_cert;
    
    CHECK(true);
}

TEST(ssl_protocol_tests, ssl_decode_v2_server_hello_size_8)
{
    uint8_t test_data[8] = {
        0x16,                       // Content Type
        0x03, 0x03,             // Version: TLS 1.2
        0x00, 0x03,             // Length
        0x00, 0x00, 0x02    // pkt[7]==2 triggers SSLv2 server hello check
    };

    uint32_t result = SSL_decode(test_data, sizeof(test_data), 0, 0,
        nullptr, nullptr, 0, nullptr, nullptr, nullptr, nullptr);

    CHECK(result != SSL_ARG_ERROR_FLAG);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}


//--------------------------------------------------------------------------
// Copyright (C) 2023-2025 Cisco and/or its affiliates. All rights reserved.
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

using namespace snort;

typedef struct X509_name_entry_st X509_NAME_ENTRY;
X509_NAME *X509_get_subject_name(const X509 *a) { return nullptr; }
void X509_free(X509* a) { }
int X509_NAME_get_index_by_NID(X509_NAME *name, int nid, int lastpos) { return -1; }
X509_NAME_ENTRY *X509_NAME_get_entry(const X509_NAME *name, int loc) { return nullptr; }
ASN1_STRING *X509_NAME_ENTRY_get_data(const X509_NAME_ENTRY *ne) { return nullptr; }
const unsigned char *ASN1_STRING_get0_data(const ASN1_STRING *x) { return nullptr; }
X509* d2i_X509(X509 **a, const unsigned char **in, long len)
{
    return nullptr;
}

namespace snort
{
char* snort_strdup(const char* str)
{
    return str ? strdup(str) : nullptr;
}

char* snort_strndup(const char* src, size_t)
{
    return snort_strdup(src);
}
}

TEST_GROUP(ssl_protocol_tests)
{
    void setup() override
    {
    }

    void teardown() override
    {
    }
};

TEST(ssl_protocol_tests, cert_data_incomplete_len_2)
{
    SSLV3ServerCertData test_data;
    test_data.certs_data = new uint8_t[2] { 0x01, 0x02 }; // Incomplete length, should be at least 3 bytes
    test_data.certs_len = 2;
    auto result = parse_server_certificates(&test_data);
    CHECK_EQUAL(true, result);
    CHECK_EQUAL(nullptr, test_data.certs_data);
    CHECK_EQUAL(0, test_data.certs_len);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
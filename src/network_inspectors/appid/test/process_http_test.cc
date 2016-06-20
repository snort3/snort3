//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "appid_api.h"
#include "fw_appid.h"

extern void appIdApiInit(struct AppIdApi*);

AppIdApi appIdApi;

static void appIdTestSetup()
{
#ifdef REMOVED_WHILE_NOT_IN_USE
    static SessionAPI sessionAPI = { 0 };
    static StreamAPI streamAPI = { 0 };

    testFilesPath = getenv("APPID_TESTS_PATH");

    if (testFilesPath == nullptr)
    {
        printf("Env variable APPID_TESTS_PATH is not set. Exiting ...\n");
        exit(-1);
    }

    strcpy(rnaConfPath, testFilesPath);
    strcat(rnaConfPath, "/rna.conf");

    _dpd.tokenSplit = mSplit;
    _dpd.tokenFree = mSplitFree;
    LogMessage = logMsg;
    _dpd.errMsg = errMsg;
    _dpd.debugMsg = debugMsg;
    _dpd.addProtocolReference = addProtocolReference;
    _dpd.addPreproc = addPreproc;
    _dpd.getParserPolicy = getParserPolicy;
    _dpd.getDefaultPolicy = getDefaultPolicy;
    _dpd.isAppIdRequired = isAppIdRequired;
    _dpd.getSnortInstance = getSnortInstance;
    _dpd.findProtocolReference = findProtocolReference;

    sessionAPI.enable_preproc_all_ports = enable_preproc_all_ports;
    sessionAPI.get_application_data = get_application_data;
    sessionAPI.set_application_data = set_application_data;
    sessionAPI.get_packet_direction = get_packet_direction;
    sessionAPI.get_session_flags = get_session_flags;
    sessionAPI.get_session_ip_address = get_session_ip_address;
    sessionAPI.get_application_protocol_id = get_application_protocol_id;
    sessionAPI.get_http_xff_precedence = get_http_xff_precedence;
    _dpd.sessionAPI = &sessionAPI;

    streamAPI.is_session_decrypted = is_session_decrypted;
    streamAPI.set_application_id = set_application_id;
    streamAPI.is_session_http2 = is_session_http2;
    _dpd.streamAPI = &streamAPI;

    _dpd.searchAPI = &searchAPI;
#endif

    appIdApiInit(&appIdApi);
}

#ifdef REMOVED_WHILE_NOT_IN_USE
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <check.h>

#include "parser/mstring.h"

#include "appid_config.h"

#include "external_apis.h"
#include "fw_appid.h"
#include "session_file.h"

#if 1 // FIXIT-M hacks
// not sure where this is defined; outside the appid tree probably
using ControlDataSendFunc = void (*)();
#endif

extern void AppIdReload(struct _SnortConfig* sc, char* args, void** new_config);
extern void* AppIdReloadSwap(struct _SnortConfig* sc, void* swap_config);
extern void AppIdReloadFree(void* old_context);
extern int AppIdReconfigure(uint16_t type, const uint8_t* data, uint32_t length,
    void** new_context,
    char* statusBuf, int statusBuf_len);
extern int AppIdReconfigureSwap(uint16_t type, void* new_context, void** old_context);
extern void AppIdReconfigureFree(uint16_t type, void* old_context, struct _THREAD_ELEMENT* te,
    ControlDataSendFunc f);
#endif

#ifdef REMOVED_WHILE_NOT_IN_USE
extern int processHTTPPacket(Packet* p, AppIdData* session, int direction,
    HttpParsedHeaders* const headers, const AppIdConfig* pConfig);
extern void sfiph_build(Packet* p, const void* hdr, int family);
extern void pickHttpXffAddress(Packet* p, AppIdData* appIdSession,
    ThirdPartyAppIDAttributeData* attribute_data);

// FIXIT: use APIs instead of using global
extern AppIdData* pAppIdData;

static char* testFilesPath = nullptr;
static char rnaConfPath[PATH_MAX] = { 0 };

static void testProcessHttpPacket(const char* useragent, const char* host, const char* referer,
    const char* trailer)
{
    // FIXIT-M J these need to be cleared, probably
    Packet p;
    AppIdData session;

    char buf[1024];
    int bufLen;

    session.common.flags = 0x311380;
    session.hsession = (decltype(session.hsession))snort_calloc(sizeof(httpSession));
    if (host)
    {
        session.hsession->host = snort_strdup(host);
        strcpy(buf, "http://");
        strcat(buf, host);
        if (trailer)
            strcat(buf, trailer);
        else
            strcat(buf, "/");
        session.hsession->url = snort_strdup(buf);
    }
    if (useragent)
        session.hsession->useragent = snort_strdup(useragent);
    if (referer)
        session.hsession->referer = snort_strdup(referer);
    session.hsession->uri = snort_strdup("/");
    session.hsession->cookie = snort_strdup(
        "s_vi=[CS]v1|25B026B7851D124A-6000012D802520B2[CE]; CG=US:MD:Laurel; mbox=check#true#1336576860|session#1336576799559-724714#1336578660; SelectedEdition=www; rsi_segs_ttn=A09801_10001|A09801_10313; ug="
        "4faa8b240a5fef0aa5147448c8005347; ugs=1; tnr:usrvtstg01=1336576805411%7C0%7C0%7C1%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C1%7Cf%7C"
        "1%7C4%7C1336576805411; tnr:sesctmp01=1336576805411; s_cc=true; s_sq=%5B%5BB%5D%5D; adDEmas=R08&broadband&gblx.net&73&gbr&826027&0&10198&-&-&-&15275&; adDEon=true; s_ppv=13");
    session.serviceAppId = APP_ID_NONE;
    session.payloadAppId = APP_ID_NONE;
    session.tpPayloadAppId = 1190;
    session.scan_flags = 0x26;
    session.ClientAppId = 0;

    strcpy(buf, "GET / HTTP/1.1\r\n");
    strcat(buf, "Host: ");
    strcat(buf, host);
    strcat(buf, "\r\nUser-Agent: ");
    strcat(buf, useragent);
    if (referer)
    {
        strcat(buf, "\r\nReferer: ");
        strcat(buf, referer);
    }
    strcat(buf, "\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n");
    strcat(buf,
        "Accept-Language: en-us,en;q=0.5\r\nAccept-Encoding: gzip,deflate\r\nAccept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n");
    strcat(buf, "Keep-Alive: 115\r\nConnection: keep-alive\r\n");
    bufLen = strlen(buf);
    strncat(buf,
        "Cookie: s_vi=[CS]v1|25B026B7851D124A-6000012D802520B2[CE]; CG=US:MD:Laurel; mbox=check#true#1336576860|session#1336576799559-724714#1336578660; SelectedEdition=www; rsi_segs_ttn=A09801_10001|A09801_10313; ug=4faa8b240a5fef0aa5147448c8005347; ugs=1; tnr:usrvtstg01=1336576805411%7C0%7C0%7C1%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C0%7C1%7Cf%7C1%7C4%7C1336576805411; tnr:sesctmp01=1336576805411; s_cc=true; s_sq=%5B%5BB%5D%5D; adDEmas=R08&broadband&gblx.net&73&gbr&826027&0&10198&-&-&-&15275&; adDEon=true; s_ppv=13\r\n\r\n",
        sizeof(buf) - bufLen - 1);

    p.data = (decltype(p.data))snort_strdup(buf);
    p.dsize = strlen((const char*)p.data);

    processHTTPPacket(&p, &session, APP_ID_FROM_INITIATOR, nullptr, pAppidActiveConfig);

    if (host)
    {
        snort_free(session.hsession->host);
        snort_free(session.hsession->url);
    }
    if (referer)
        snort_free(session.hsession->referer);
    if (useragent)
        snort_free(session.hsession->useragent);
    snort_free(session.hsession->uri);
    snort_free(session.hsession->cookie);
    snort_free(session.hsession);

    snort_free((uint8_t*)p.data);
}

START_TEST(HttpTest)
{
    memset(&appidStaticConfig, 0, sizeof(appidStaticConfig));

    strcpy(appidStaticConfig.conf_file, rnaConfPath);
    strcpy(appidStaticConfig.app_id_detector_path, testFilesPath);

    AppIdCommonInit(&appidStaticConfig);

    testProcessHttpPacket(
        "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.2.7) Gecko/20100715 Ubuntu/9.04 (jaunty) Firefox/3.6.7",
        "www.cnn.com",
        nullptr, nullptr);
    testProcessHttpPacket(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.1.17 (KHTML, like Gecko) Version/7.1 Safari/537.85.10",
        "www.cnn.com",
        nullptr, nullptr);
    testProcessHttpPacket(
        "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)",
        "www.cnn.com",
        nullptr, nullptr);

    AppIdCommonFini();
}

END_TEST

#ifdef REMOVED_WHILE_NOT_IN_USE
START_TEST(HttpAfterReloadTest)
{
    AppIdConfig* pNewConfig = nullptr;
    AppIdConfig* pOldConfig = nullptr;

    memset(&appidStaticConfig, 0, sizeof(appidStaticConfig));

    strcpy(appidStaticConfig.conf_file, rnaConfPath);
    strcpy(appidStaticConfig.app_id_detector_path, testFilesPath);

    AppIdCommonInit(&appidStaticConfig);

    AppIdReload(nullptr, nullptr, (void**)&pNewConfig);
    pOldConfig = AppIdReloadSwap(nullptr, pNewConfig);
    AppIdReloadFree(pOldConfig);

    testProcessHttpPacket(
        "Mozilla/5.0 (Windows NT 6.0; rv:2.0) Gecko/20100101 Firefox/4.0 Opera 12.14",
        "www.cnn.com",
        nullptr, nullptr);
    testProcessHttpPacket(
        "Mozilla/5.0 (BlackBerry; U; BlackBerry 9900; en) AppleWebKit/534.11+ (KHTML, like Gecko) Version/7.1.0.346 Mobile Safari/534.11+",
        "www.cnn.com",
        nullptr, nullptr);
    testProcessHttpPacket(
        "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36",
        "www.cnn.com",
        nullptr, nullptr);

    AppIdCommonFini();
}

END_TEST START_TEST(HttpAfterReconfigureTest)
{
    AppIdConfig* pNewConfig = nullptr;
    AppIdConfig* pOldConfig = nullptr;

    memset(&appidStaticConfig, 0, sizeof(appidStaticConfig));

    strcpy(appidStaticConfig.conf_file, rnaConfPath);
    strcpy(appidStaticConfig.app_id_detector_path, testFilesPath);

    AppIdCommonInit(&appidStaticConfig);

    AppIdReconfigure(0, nullptr, 0, (void**)&pNewConfig, nullptr, 0);
    AppIdReconfigureSwap(0, pNewConfig, (void**)&pOldConfig);
    AppIdReconfigureFree(0, pOldConfig, nullptr, nullptr);

    testProcessHttpPacket("Wget/1.9.1",
        "www.cnn.com",
        nullptr, nullptr);
    testProcessHttpPacket(
        "Mozilla/5.0 (Linux; U; Android 4.0.3; ko-kr; LG-L160L Build/IML74K) AppleWebkit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30",
        "www.cnn.com",
        nullptr, nullptr);

    AppIdCommonFini();
}

END_TEST START_TEST(HttpAfterReloadReconfigureTest)
{
    AppIdConfig* pNewConfig = nullptr;
    AppIdConfig* pOldConfig = nullptr;

    memset(&appidStaticConfig, 0, sizeof(appidStaticConfig));

    strcpy(appidStaticConfig.conf_file, rnaConfPath);
    strcpy(appidStaticConfig.app_id_detector_path, testFilesPath);

    AppIdCommonInit(&appidStaticConfig);

    AppIdReload(nullptr, nullptr, (void**)&pNewConfig);
    pOldConfig = AppIdReloadSwap(nullptr, pNewConfig);
    AppIdReloadFree(pOldConfig);

    pNewConfig = nullptr;
    pOldConfig = nullptr;

    AppIdReconfigure(0, nullptr, 0, (void**)&pNewConfig, nullptr, 0);
    AppIdReconfigureSwap(0, pNewConfig, (void**)&pOldConfig);
    AppIdReconfigureFree(0, pOldConfig, nullptr, nullptr);

    testProcessHttpPacket(
        "Mozilla/5.0 (Linux; U; Android 4.0.3; ko-kr; LG-L160L Build/IML74K) AppleWebkit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30",
        "www.123.com",
        "http://www.cnn.com", nullptr);
    testProcessHttpPacket(
        "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.2.7) Gecko/20100715 Ubuntu/9.04 (jaunty) Firefox/3.6.7",
        "www.cnn.com",
        nullptr, "/tech?a=1&b=2");

    AppIdCommonFini();
}

END_TEST START_TEST(HttpXffTest)
{
    Packet p = { 0 };
    AppIdData session = { 0 };
    httpSession hsession = { 0 };
    ThirdPartyAppIDAttributeData tpData = { 0 };
    SFIP_RET status;
    sfaddr_t* xffAddr = sfaddr_alloc("1.1.1.1", &status);

    // Only X-Forwarded-For
    session.hsession = &hsession;
    tpData.numXffFields = 1;
    tpData.xffFieldValue[0].field = HTTP_XFF_FIELD_X_FORWARDED_FOR;
    tpData.xffFieldValue[0].value = "1.1.1.1";
    pickHttpXffAddress(&p, &session, &tpData);
    ck_assert_int_eq(sfip_compare(session.hsession->xffAddr, xffAddr), SFIP_EQUAL);
    sfaddr_free(session.hsession->xffAddr);

    // Only True-Client-IP
    memset(&p, 0, sizeof(p));
    memset(&session, 0, sizeof(session));
    memset(&hsession, 0, sizeof(hsession));
    memset(&tpData, 0, sizeof(tpData));
    session.hsession = &hsession;
    tpData.numXffFields = 1;
    tpData.xffFieldValue[0].field = HTTP_XFF_FIELD_TRUE_CLIENT_IP;
    tpData.xffFieldValue[0].value = "1.1.1.1";
    pickHttpXffAddress(&p, &session, &tpData);
    ck_assert_int_eq(sfip_compare(session.hsession->xffAddr, xffAddr), SFIP_EQUAL);
    sfaddr_free(session.hsession->xffAddr);

    // X-Forwarded-For and True-Client-IP
    memset(&p, 0, sizeof(p));
    memset(&session, 0, sizeof(session));
    memset(&hsession, 0, sizeof(hsession));
    memset(&tpData, 0, sizeof(tpData));
    session.hsession = &hsession;
    tpData.numXffFields = 2;
    tpData.xffFieldValue[0].field = HTTP_XFF_FIELD_TRUE_CLIENT_IP;
    tpData.xffFieldValue[0].value = "2.2.2.2";
    tpData.xffFieldValue[1].field = HTTP_XFF_FIELD_X_FORWARDED_FOR;
    tpData.xffFieldValue[1].value = "1.1.1.1";
    pickHttpXffAddress(&p, &session, &tpData);
    ck_assert_int_eq(sfip_compare(session.hsession->xffAddr, xffAddr), SFIP_EQUAL);
    sfaddr_free(session.hsession->xffAddr);

    // Comma-separated list in X-Forwarded-For
    memset(&p, 0, sizeof(p));
    memset(&session, 0, sizeof(session));
    memset(&hsession, 0, sizeof(hsession));
    memset(&tpData, 0, sizeof(tpData));
    session.hsession = &hsession;
    tpData.numXffFields = 1;
    tpData.xffFieldValue[0].field = HTTP_XFF_FIELD_X_FORWARDED_FOR;
    tpData.xffFieldValue[0].value = snort_strdup("1.1.1.1, 2.2.2.2");
    pickHttpXffAddress(&p, &session, &tpData);
    ck_assert_int_eq(sfip_compare(session.hsession->xffAddr, xffAddr), SFIP_EQUAL);
    snort_free(tpData.xffFieldValue[0].value);
    sfaddr_free(session.hsession->xffAddr);

    // Custom XFF
    static char* defaultXffPrecedence[] = { "Custom-XFF", HTTP_XFF_FIELD_X_FORWARDED_FOR,
                                            HTTP_XFF_FIELD_TRUE_CLIENT_IP };
    memset(&p, 0, sizeof(p));
    memset(&session, 0, sizeof(session));
    memset(&hsession, 0, sizeof(hsession));
    memset(&tpData, 0, sizeof(tpData));
    session.hsession = &hsession;
    session.hsession->xffPrecedence = defaultXffPrecedence;
    session.hsession->numXffFields = 3;
    tpData.numXffFields = 2;
    tpData.xffFieldValue[0].field = HTTP_XFF_FIELD_X_FORWARDED_FOR;
    tpData.xffFieldValue[0].value = "2.2.2.2";
    tpData.xffFieldValue[1].field = "Custom-XFF";
    tpData.xffFieldValue[1].value = "1.1.1.1";
    pickHttpXffAddress(&p, &session, &tpData);
    ck_assert_int_eq(sfip_compare(session.hsession->xffAddr, xffAddr), SFIP_EQUAL);
    sfaddr_free(session.hsession->xffAddr);

    sfaddr_free(xffAddr);

    snort_free((uint8_t*)p.data);
}

#endif

static void sessionTcaseSetup(void)
{
    memset(&appidStaticConfig, 0, sizeof(appidStaticConfig));

    strcpy(appidStaticConfig.conf_file, rnaConfPath);
    strcpy(appidStaticConfig.app_id_detector_path, testFilesPath);

    AppIdCommonInit(&appidStaticConfig);
}

static void sessionTcaseClean(void)
{
    AppIdCommonFini();
}

static Suite* setupAppIdSuite(void)
{
    Suite* appIdSuite;
    TCase* frameworkTcase;
    TCase* httpTcase;
    TCase* sessionTcase;

    appIdSuite = suite_create("AppId");

    // Create Framework test case
    frameworkTcase = tcase_create("FrameworkTestCase");
    tcase_add_checked_fixture(frameworkTcase, nullptr, nullptr);

    // Add tests to Framework test case
    tcase_add_test(frameworkTcase, ConfigParseTest);
    tcase_add_test(frameworkTcase, InitFiniTest);
    tcase_add_test(frameworkTcase, ReloadTest);
    tcase_add_test(frameworkTcase, ReconfigureTest);

    suite_add_tcase(appIdSuite, frameworkTcase);

    // Create Http test case
    httpTcase = tcase_create("HttpTestCase");
    tcase_add_checked_fixture(httpTcase, nullptr, nullptr);

    // Add tests to Http test case
    tcase_add_test(httpTcase, HttpTest);
    tcase_add_test(httpTcase, HttpAfterReloadTest);
    tcase_add_test(httpTcase, HttpAfterReconfigureTest);
    tcase_add_test(httpTcase, HttpAfterReloadReconfigureTest);
    tcase_add_test(httpTcase, HttpXffTest);

    suite_add_tcase(appIdSuite, httpTcase);

    // Create Session test case
    sessionTcase = tcase_create("SessionTestCase");
    tcase_add_checked_fixture(sessionTcase, nullptr, nullptr);

    // Add tests to Session test case
    tcase_add_test(sessionTcase, AimSessionTest);
    tcase_add_test(sessionTcase, CnnSessionTest);
    tcase_add_test(sessionTcase, DnsSessionTest);
    tcase_add_test(sessionTcase, ImapSessionTest);
    tcase_add_test(sessionTcase, MdnsSessionTest);
    tcase_add_test(sessionTcase, MsnSessionTest);
    tcase_add_test(sessionTcase, NetbiosNsSessionTest);
    tcase_add_test(sessionTcase, NetbiosSsSessionTest);
    tcase_add_test(sessionTcase, PatternSessionTest);
    tcase_add_test(sessionTcase, Pop3SessionTest);
    tcase_add_test(sessionTcase, RfbSessionTest);
    tcase_add_test(sessionTcase, RtpSessionTest);
    tcase_add_test(sessionTcase, SmtpSessionTest);
    tcase_add_test(sessionTcase, TimbuktuSessionTest);
    tcase_add_test(sessionTcase, WebexSessionTest);
    tcase_add_test(sessionTcase, YmSessionTest);

    suite_add_tcase(appIdSuite, sessionTcase);

    return appIdSuite;
}

#endif

int main()
{
#ifdef REMOVED_WHILE_NOT_IN_USE
    int opt, debug = 0;
    int numberFailed;
    Suite* appIdSuite;
    SRunner* appIdRunner;

    while ((opt = getopt(argc, argv, "dh")) != -1)
    {
        switch (opt)
        {
        case 'd':
            debug = 1;
            break;
        case 'h':
            printf(
                "Usage:\n\
    -d: Run test in no fork mode for debugging in gdb.\n\
    -h: This text.\n");
            return EXIT_SUCCESS;
        }
    }
#endif

    appIdTestSetup();

#ifdef REMOVED_WHILE_NOT_IN_USE
    // Create a test runner for AppId suite
    appIdSuite = setupAppIdSuite();
    appIdRunner = srunner_create(appIdSuite);

    if (debug)
    {
        srunner_set_fork_status(appIdRunner, CK_NOFORK);
    }

    // Set test results format to TAP and specify file name
    srunner_set_tap(appIdRunner, "AppIdTests.tap~");

    // Run test cases in AppId suite
    srunner_run(appIdRunner, nullptr, "FrameworkTestCase", CK_NORMAL);

    system("cp AppIdTests.tap~ AppIdTests.tap");

    srunner_run(appIdRunner, nullptr, "HttpTestCase", CK_NORMAL);

    system("cat AppIdTests.tap~ >> AppIdTests.tap");

    sessionTcaseSetup();
    srunner_run(appIdRunner, nullptr, "SessionTestCase", CK_NORMAL);
    sessionTcaseClean();

    system("cat AppIdTests.tap~ >> AppIdTests.tap");

    numberFailed = srunner_ntests_failed(appIdRunner);
    srunner_free(appIdRunner);
    return (numberFailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
#endif
}


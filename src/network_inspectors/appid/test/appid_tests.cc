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

extern int processHTTPPacket(Packet* p, AppIdData* session, int direction,
    HttpParsedHeaders* const headers, const AppIdConfig* pConfig);
extern void appIdApiInit(struct AppIdApi*);
extern void sfiph_build(Packet* p, const void* hdr, int family);
extern void pickHttpXffAddress(Packet* p, AppIdData* appIdSession,
    ThirdPartyAppIDAttributeData* attribute_data);

AppIdApi appIdApi;

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

void testFwAppIdSearch(const char* fileName)
{
    Packet pkt;
    Flow flow;

    FILE* file;
    HttpParsedHeaders* httpHeader = nullptr;
    AppId service;
    bool isLoginSuccessful;
    char* userName;
    char* serviceVendor;
    char* serviceVersion;
    RNAServiceSubtype* serviceSubtype;
    int moreData = 0;
    char filePath[PATH_MAX];

    strcpy(filePath, testFilesPath);
    strcat(filePath, "/sessions/");
    strcat(filePath, fileName);

    file = fopen(filePath, "r");
    assert(file != nullptr);

    do
    {
        sessionFileReadSession(file, &flow);
        moreData = sessionFileReadPacket(file, &pkt, &httpHeader);

        pkt.flow = &flow;

        sfiph_build(&pkt, &pkt.ip4h, pkt.family);

        if (httpHeader)
        {
            httpHeaderCallback(&pkt, httpHeader);
        }
        else
        {
            fwAppIdSearch(&pkt);
        }

        if (pkt.data)
            snort_free((uint8_t*)pkt.data);
        memset(&pkt, 0, sizeof(pkt));

        if (httpHeader)
        {
            if (httpHeader->host.start)
                snort_free((uint8_t*)httpHeader->host.start);
            if (httpHeader->url.start)
                snort_free((uint8_t*)httpHeader->url.start);
            if (httpHeader->method.start)
                snort_free((uint8_t*)httpHeader->method.start);
            if (httpHeader->userAgent.start)
                snort_free((uint8_t*)httpHeader->userAgent.start);
            if (httpHeader->referer.start)
                snort_free((uint8_t*)httpHeader->referer.start);
            if (httpHeader->via.start)
                snort_free((uint8_t*)httpHeader->via.start);
            if (httpHeader->responseCode.start)
                snort_free((uint8_t*)httpHeader->responseCode.start);
            if (httpHeader->server.start)
                snort_free((uint8_t*)httpHeader->server.start);
            if (httpHeader->xWorkingWith.start)
                snort_free((uint8_t*)httpHeader->xWorkingWith.start);
            if (httpHeader->contentType.start)
                snort_free((uint8_t*)httpHeader->contentType.start);
            snort_free(httpHeader);
            httpHeader = nullptr;
        }
    }
    while (moreData != -1);

    LogMessage("==========================================================\n");
    LogMessage("App name = %s\n", appGeAppName(appIdApi.geServiceAppId(pAppIdData)));
    LogMessage("AppId = %d\n", appGeAppId(appGeAppName(appIdApi.geServiceAppId(pAppIdData))));
    LogMessage("Service AppId = %d\n", appIdApi.geServiceAppId(pAppIdData));
    LogMessage("Only Service AppId = %d\n", appIdApi.getOnlyServiceAppId(pAppIdData));
    LogMessage("Misc AppId = %d\n", appIdApi.getMiscAppId(pAppIdData));
    LogMessage("Client AppId = %d\n", appIdApi.getClientAppId(pAppIdData));
    LogMessage("Payload AppId = %d\n", appIdApi.getPayloadAppId(pAppIdData));
    LogMessage("Referred AppId = %d\n", appIdApi.getReferredAppId(pAppIdData));
    LogMessage("Fw Service AppId = %d\n", appIdApi.getFwServiceAppId(pAppIdData));
    LogMessage("Fw Misc AppId = %d\n", appIdApi.getFwMiscAppId(pAppIdData));
    LogMessage("Fw Client AppId = %d\n", appIdApi.getFwClientAppId(pAppIdData));
    LogMessage("Fw Payload AppId = %d\n", appIdApi.getFwPayloadAppId(pAppIdData));
    LogMessage("Fw Referred AppId = %d\n", appIdApi.getFwReferredAppId(pAppIdData));
    LogMessage("Is Session SSL Decrypted = %d\n", appIdApi.isSessionSslDecrypted(pAppIdData));
    LogMessage("Is AppId Inspecting Session = %d\n", appIdApi.isAppIdInspectingSession(
        pAppIdData));
    LogMessage("Is AppId Available = %d\n", appIdApi.isAppIdAvailable(pAppIdData));
    userName = appIdApi.getUserName(pAppIdData, &service, &isLoginSuccessful);
    LogMessage("User name = %s, service = %d, isLoginSuccessful = %d\n",
        userName, service, isLoginSuccessful);
    LogMessage("Client version = %s\n", appIdApi.geClientVersion(pAppIdData));
    // TODO: Is the flag argument correct?
    LogMessage("Session attribute = %" PRIx64 "\n", appIdApi.getAppIdSessionAttribute(pAppIdData,
        0));
    LogMessage("Flow type = %08X\n", appIdApi.getFlowType(pAppIdData));
    appIdApi.geServiceInfo(pAppIdData, &serviceVendor, &serviceVersion, &serviceSubtype);
    LogMessage("Service vendor = %s, version = %s\n",
        serviceVendor, serviceVersion);
    LogMessage("Service port = %d\n", appIdApi.geServicePort(pAppIdData));
    LogMessage("Service IP = %s\n", inet_ntoa(appIdApi.geServiceIp(pAppIdData)));
    LogMessage("HTTP user agent = %s\n", appIdApi.getHttpUserAgent(pAppIdData));
    LogMessage("HTTP host = %s\n", appIdApi.getHttpHost(pAppIdData));
    LogMessage("HTTP URL = %s\n", appIdApi.getHttpUrl(pAppIdData));
    LogMessage("HTTP referer = %s\n", appIdApi.getHttpReferer(pAppIdData));
    LogMessage("TLS host = %s\n", appIdApi.getTlsHost(pAppIdData));
    LogMessage("NetBIOS name = %s\n", appIdApi.getNetbiosName(pAppIdData));

    fclose(file);
}

START_TEST(ConfigParseTest)
{
    memset(&appidStaticConfig, 0, sizeof(appidStaticConfig));

    appIdConfigParse(
        "conf rna.conf, debug yes, dump_ports, memcap 0, app_stats_filename stats, app_stats_period 60, app_stats_rollover_size 100000, app_stats_rollover_time 60, app_detector_dir appid, instance_id 1, thirdparty_appid_dir thirdparty_appid");

    ck_assert_str_eq(appidStaticConfig.conf_file, "rna.conf");
    ck_assert_int_eq(appidStaticConfig.app_id_debug, 1);
    ck_assert_int_eq(appidStaticConfig.app_id_dump_ports, 1);
    ck_assert_uint_eq(appidStaticConfig.memcap, (32*1024*1024ULL));
    ck_assert_str_eq(appidStaticConfig.app_stats_filename, "stats");
    ck_assert_uint_eq(appidStaticConfig.app_stats_period, 60);
    ck_assert_uint_eq(appidStaticConfig.app_stats_rollover_size, 100000);
    ck_assert_uint_eq(appidStaticConfig.app_stats_rollover_time, 60);
    ck_assert_str_eq(appidStaticConfig.app_id_detector_path, "appid");
    ck_assert_uint_eq(appidStaticConfig.instance_id, 1);
    ck_assert_str_eq(appidStaticConfig.appid_thirdparty_dir, "thirdparty_appid");
}
END_TEST START_TEST(InitFiniTest)
{
    memset(&appidStaticConfig, 0, sizeof(appidStaticConfig));

    strcpy(appidStaticConfig.conf_file, rnaConfPath);
    strcpy(appidStaticConfig.app_id_detector_path, testFilesPath);

    AppIdCommonInit(&appidStaticConfig);
    AppIdCommonFini();
}

END_TEST START_TEST(ReloadTest)
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

    AppIdCommonFini();
}

END_TEST START_TEST(ReconfigureTest)
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

    AppIdCommonFini();
}

END_TEST START_TEST(HttpTest)
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

END_TEST START_TEST(HttpAfterReloadTest)
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

END_TEST START_TEST(AimSessionTest)
{
    testFwAppIdSearch("aim.ssn");

    ck_assert_str_eq(appGeAppName(appIdApi.geServiceAppId(pAppIdData)), "AOL Instant Messenger");
    ck_assert_uint_eq(appIdApi.geServiceAppId(pAppIdData), APP_ID_AOL_INSTANT_MESSENGER);
    ck_assert_uint_eq(appIdApi.getClientAppId(pAppIdData), APP_ID_AOL_INSTANT_MESSENGER);

    appSharedDataDelete(pAppIdData);
    pAppIdData = nullptr;
}

END_TEST START_TEST(CnnSessionTest)
{
    testFwAppIdSearch("cnn.ssn");

    ck_assert_str_eq(appGeAppName(appIdApi.geServiceAppId(pAppIdData)), "HTTP");
    ck_assert_uint_eq(appIdApi.geServiceAppId(pAppIdData), APP_ID_HTTP);
    ck_assert_uint_eq(appIdApi.getClientAppId(pAppIdData), APP_ID_FIREFOX);
    ck_assert_uint_eq(appIdApi.getPayloadAppId(pAppIdData), 1190); // CNN app
    ck_assert_str_eq(appIdApi.getHttpHost(pAppIdData), "www.cnn.com");

    appSharedDataDelete(pAppIdData);
    pAppIdData = nullptr;
}

END_TEST START_TEST(DnsSessionTest)
{
    testFwAppIdSearch("dns.ssn");

    ck_assert_str_eq(appGeAppName(appIdApi.geServiceAppId(pAppIdData)), "DNS");
    ck_assert_uint_eq(appIdApi.geServiceAppId(pAppIdData), APP_ID_DNS);
    ck_assert_uint_eq(appIdApi.getClientAppId(pAppIdData), APP_ID_DNS);
    ck_assert_uint_eq(appIdApi.geServicePort(pAppIdData), 53);

    appSharedDataDelete(pAppIdData);
    pAppIdData = nullptr;
}

END_TEST START_TEST(ImapSessionTest)
{
    testFwAppIdSearch("imap.ssn");

    // TODO: Investigate why IMAP appids are not showing up

    appSharedDataDelete(pAppIdData);
    pAppIdData = nullptr;
}

END_TEST START_TEST(MdnsSessionTest)
{
    testFwAppIdSearch("mdns.ssn");

    ck_assert_str_eq(appGeAppName(appIdApi.geServiceAppId(pAppIdData)), "MDNS");
    ck_assert_uint_eq(appIdApi.geServiceAppId(pAppIdData), APP_ID_MDNS);
    ck_assert_uint_eq(appIdApi.geServicePort(pAppIdData), 5353);

    appSharedDataDelete(pAppIdData);
    pAppIdData = nullptr;
}

END_TEST START_TEST(MsnSessionTest)
{
    testFwAppIdSearch("msn.ssn");

    ck_assert_str_eq(appGeAppName(appIdApi.geServiceAppId(pAppIdData)), "MSN Messenger");
    ck_assert_uint_eq(appIdApi.geServiceAppId(pAppIdData), APP_ID_MSN_MESSENGER);

    appSharedDataDelete(pAppIdData);
    pAppIdData = nullptr;
}

END_TEST START_TEST(NetbiosNsSessionTest)
{
    testFwAppIdSearch("netbios_ns.ssn");

    // TODO: Investigate why NetBIOS name service appids are not showing up

    appSharedDataDelete(pAppIdData);
    pAppIdData = nullptr;
}

END_TEST START_TEST(NetbiosSsSessionTest)
{
    testFwAppIdSearch("netbios_ss.ssn");

    // TODO: Investigate why NetBIOS ss appids are not showing up

    appSharedDataDelete(pAppIdData);
    pAppIdData = nullptr;
}

END_TEST START_TEST(PatternSessionTest)
{
    testFwAppIdSearch("pattern.ssn");

    ck_assert_str_eq(appGeAppName(appIdApi.geServiceAppId(pAppIdData)), "3Com AMP3");
    ck_assert_uint_eq(appIdApi.geServiceAppId(pAppIdData), 3000);
    ck_assert_uint_eq(appIdApi.getClientAppId(pAppIdData), 3000);

    appSharedDataDelete(pAppIdData);
    pAppIdData = nullptr;
}

END_TEST START_TEST(Pop3SessionTest)
{
    testFwAppIdSearch("pop3.ssn");

    ck_assert_str_eq(appGeAppName(appIdApi.geServiceAppId(pAppIdData)), "POP3");
    ck_assert_uint_eq(appIdApi.geServiceAppId(pAppIdData), APP_ID_POP3);
    ck_assert_uint_eq(appIdApi.geServicePort(pAppIdData), 110);

    appSharedDataDelete(pAppIdData);
    pAppIdData = nullptr;
}

END_TEST START_TEST(RfbSessionTest)
{
    testFwAppIdSearch("rfb.ssn");

    ck_assert_str_eq(appGeAppName(appIdApi.geServiceAppId(pAppIdData)), "RFB");
    ck_assert_uint_eq(appIdApi.geServiceAppId(pAppIdData), APP_ID_VNC_RFB);
    ck_assert_uint_eq(appIdApi.getClientAppId(pAppIdData), APP_ID_VNC);
    ck_assert_uint_eq(appIdApi.geServicePort(pAppIdData), 5900);

    appSharedDataDelete(pAppIdData);
    pAppIdData = nullptr;
}

END_TEST START_TEST(RtpSessionTest)
{
    testFwAppIdSearch("rtp.ssn");

    // TODO: Investigate why RTP appids are not showing up

    appSharedDataDelete(pAppIdData);
    pAppIdData = nullptr;
}

END_TEST START_TEST(SmtpSessionTest)
{
    testFwAppIdSearch("smtp.ssn");

    ck_assert_str_eq(appGeAppName(appIdApi.geServiceAppId(pAppIdData)), "SMTP");
    ck_assert_uint_eq(appIdApi.geServiceAppId(pAppIdData), APP_ID_SMTP);
    ck_assert_uint_eq(appIdApi.geServicePort(pAppIdData), 25);

    appSharedDataDelete(pAppIdData);
    pAppIdData = nullptr;
}

END_TEST START_TEST(TimbuktuSessionTest)
{
    testFwAppIdSearch("timbuktu.ssn");

    ck_assert_str_eq(appGeAppName(appIdApi.geServiceAppId(pAppIdData)), "Timbuktu");
    ck_assert_uint_eq(appIdApi.geServiceAppId(pAppIdData), APP_ID_TIMBUKTU);
    ck_assert_uint_eq(appIdApi.geServiceAppId(pAppIdData), APP_ID_TIMBUKTU);
    ck_assert_uint_eq(appIdApi.geServicePort(pAppIdData), 407);

    appSharedDataDelete(pAppIdData);
    pAppIdData = nullptr;
}

END_TEST START_TEST(WebexSessionTest)
{
    testFwAppIdSearch("webex.ssn");

    ck_assert_str_eq(appGeAppName(appIdApi.geServiceAppId(pAppIdData)), "HTTP");
    ck_assert_uint_eq(appIdApi.geServiceAppId(pAppIdData), APP_ID_HTTP);
    ck_assert_uint_eq(appIdApi.getClientAppId(pAppIdData), 2932); // WebEx
    ck_assert_uint_eq(appIdApi.getPayloadAppId(pAppIdData), 2932); // WebEx

    appSharedDataDelete(pAppIdData);
    pAppIdData = nullptr;
}

END_TEST START_TEST(YmSessionTest)
{
    testFwAppIdSearch("ym.ssn");

    // TODO: Investigate why Yahoo messenger appids are not showing up

    appSharedDataDelete(pAppIdData);
    pAppIdData = nullptr;
}

END_TEST

static void appIdTestSetup(void)
{
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

    appIdApiInit(&appIdApi);
}

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

int main(int argc, char* argv[])
{
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

    appIdTestSetup();

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
}


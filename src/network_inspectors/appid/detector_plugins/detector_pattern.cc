//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// detector_pattern.cc author Sourcefire Inc.

#include "detector_pattern.h"
#include "app_info_table.h"
#include "client_plugins/client_app_base.h"
#include "service_plugins/service_api.h"

#include "log/messages.h"
#include "main/snort_debug.h"
#include "utils/util.h"

static THREAD_LOCAL ServicePortPattern service_port_patterns;
static THREAD_LOCAL ClientPortPattern clientPortPattern;

static int service_validate(ServiceValidationArgs* args);
static int csdPatternTreeSearch(const uint8_t* data, uint16_t size, IpProtocol protocol, Packet* pkt,
    const RNAServiceElement** serviceData, bool isClient);
static int pattern_service_init(const InitServiceAPI* const iniServiceApi);
static void pattern_service_clean();
static CLIENT_APP_RETCODE client_init(const InitClientAppAPI* const init_api, SF_LIST* config);
static CLIENT_APP_RETCODE client_init_tcp(const InitClientAppAPI* const init_api, SF_LIST* config);
static CLIENT_APP_RETCODE client_validate(const uint8_t* data, uint16_t size, const int dir,
    AppIdSession* asd, Packet* pkt, Detector* userData);
static void client_clean();
static const InitServiceAPI* iniServiceApi;
static const InitClientAppAPI* iniClientApi;

static const RNAServiceElement svc_element =
{
    nullptr,
    &service_validate,
    nullptr,
    DETECTOR_TYPE_PATTERN,
    1,
    1,
    0,
    "pattern",
};

RNAServiceValidationModule pattern_service_mod =
{
    "pattern",
    &pattern_service_init,
    nullptr,
    nullptr,
    nullptr,
    0,
    &pattern_service_clean,
    0
};

// client side
RNAClientAppModule pattern_udp_client_mod =
{
    "pattern",
    IpProtocol::UDP,
    &client_init,
    &client_clean,
    &client_validate,
    0,
    nullptr,
    nullptr,
    0,
    nullptr,
    0,
    0
};

RNAClientAppModule pattern_tcp_client_mod =
{
    "pattern",
    IpProtocol::TCP,
    &client_init_tcp,
    nullptr,
    &client_validate,
    0,
    nullptr,
    nullptr,
    0,
    nullptr,
    0,
    0
};

static void FreePattern(Pattern* pattern)
{
    if (pattern)
    {
        if (pattern->data)
            snort_free(pattern->data);
        snort_free(pattern);
    }
}

static void FreePatternService(PatternService* ps)
{
    Pattern* pattern;
    PortNode* port;

    if (ps)
    {
        while ((pattern = ps->pattern))
        {
            ps->pattern = pattern->next;
            FreePattern(pattern);
        }
        while ((port = ps->port))
        {
            ps->port = port->next;
            snort_free(port);
        }
        snort_free(ps);
    }
}

static void read_patterns(PortPatternNode* portPatternList, PatternService** serviceList)
{
    PatternService* ps = nullptr;
    Pattern* pattern;
    PortNode* port;
    PortPatternNode* pNode;
    char* lastName = nullptr;
    short lastPort = 0;
    IpProtocol lastProto = IpProtocol::PROTO_NOT_SET;
    bool newPs;

    for (pNode = portPatternList; pNode; pNode = pNode->next)
    {
        newPs = false;
        if (!ps || !lastName || strcmp(lastName, pNode->detectorName)
            || lastProto != pNode->protocol)
        {
            ps = (PatternService*)snort_calloc(sizeof(PatternService));
            lastName = pNode->detectorName;
            lastProto = pNode->protocol;
            newPs = true;
            ps->id = pNode->appId;
            ps->proto = pNode->protocol;
            ps->next = *serviceList;
            *serviceList = ps;
        }

        if (pNode->port && (newPs || lastPort != pNode->port))
        {
            port = (PortNode*)snort_calloc(sizeof(PortNode));
            port->port = pNode->port;
            port->next = ps->port;
            lastPort = pNode->port;
            ps->port = port;
        }

        pattern = (Pattern*)snort_calloc(sizeof(Pattern));
        pattern->data = (uint8_t*)snort_calloc(pNode->length);
        memcpy(pattern->data, pNode->pattern, pNode->length);
        pattern->length = pNode->length;
        if (pattern->length > ps->longest)
            ps->longest = pattern->length;
        pattern->ps = ps;
        pattern->offset = pNode->offset;
        pattern->next = ps->pattern;
        ps->pattern = pattern;
        AppInfoManager::get_instance().set_app_info_active(ps->id);
    }
}

// Register ports for detectors which have a pattern associated with it.
static void install_ports(PatternService* serviceList, const InitServiceAPI* const iniServiceApi)
{
    PatternService* ps;
    PortNode* port;
    RNAServiceValidationPort pp = { &service_validate, 0, IpProtocol::PROTO_NOT_SET, 0 };

    for (ps = serviceList; ps; ps = ps->next)
    {
        if (!ps->port)
            continue;

        for (port = ps->port; port; port = port->next)
        {
            pp.port = port->port;
            pp.proto = (IpProtocol)ps->proto;
            if (iniServiceApi->AddPort(&pp, &pattern_service_mod))
                ErrorMessage("Failed to add port - %d:%u:%d\n",ps->id,
                		(unsigned)pp.port, (uint8_t)pp.proto);
            else
            {
                DebugFormat(DEBUG_LOG,"Installed ports - %d:%u:%u\n",
                		ps->id, (unsigned)pp.port, (unsigned)pp.proto);
            }
        }
    }
}

static void RegisterPattern(SearchTool** patterns, Pattern* pattern)
{
    if (!*patterns)
    {
        *patterns = new SearchTool("ac_full");
        if (!*patterns)
        {
            ErrorMessage("Error initializing the pattern table\n");
            return;
        }
    }

    (*patterns)->add((char*)pattern->data, pattern->length, pattern, false);
}

void insert_service_port_pattern(PortPatternNode* pPattern)
{
    PortPatternNode** prev;
    PortPatternNode** curr;
    prev = nullptr;

    for (curr = &service_port_patterns.luaInjectedPatterns; *curr; prev = curr, curr = &((*curr)->next))
    {
        if (strcmp(pPattern->detectorName, (*curr)->detectorName) || pPattern->protocol < (*curr)->protocol
                || pPattern->port < (*curr)->port)
            break;
    }

    if (prev)
    {
        pPattern->next = (*prev)->next;
        (*prev)->next = pPattern;
    }
    else
    {
        pPattern->next = *curr;
        *curr = pPattern;
    }
}

void clean_service_port_patterns()
{
    PortPatternNode* tmp;

    while ((tmp = service_port_patterns.luaInjectedPatterns))
    {
        service_port_patterns.luaInjectedPatterns = tmp->next;
        snort_free(tmp->pattern);
        snort_free(tmp->detectorName);
        snort_free(tmp);
    }
}


void insert_client_port_pattern(PortPatternNode* pPattern)
{
    //insert ports in order.
    {
        PortPatternNode** prev;
        PortPatternNode** curr;
        prev = nullptr;
        for (curr = &clientPortPattern.luaInjectedPatterns; *curr; prev = curr, curr = &((*curr)->next))
        {
            if (strcmp(pPattern->detectorName, (*curr)->detectorName) || pPattern->protocol < (*curr)->protocol
                    || pPattern->port < (*curr)->port)
                break;
        }
        if (prev)
        {
            pPattern->next = (*prev)->next;
            (*prev)->next = pPattern;
        }
        else
        {
            pPattern->next = *curr;
            *curr = pPattern;
        }
    }
}

void clean_client_port_patterns()
{
    PortPatternNode* tmp;

    while ((tmp = clientPortPattern.luaInjectedPatterns))
    {
        clientPortPattern.luaInjectedPatterns = tmp->next;
        snort_free(tmp->pattern);
        snort_free(tmp->detectorName);
        snort_free(tmp);
    }
}

// Creates unique subset of services registered on ports, and then creates pattern trees.
static void createServicePatternTrees()
{
    PatternService* ps;
    Pattern* pattern;
    PortNode* port;
    unsigned i;

    for (ps = service_port_patterns.servicePortPattern; ps; ps = ps->next)
    {
        for (port = ps->port; port; port = port->next)
        {
            for (pattern = ps->pattern; pattern; pattern = pattern->next)
            {
                if (ps->proto == IpProtocol::TCP)
                    RegisterPattern(&service_port_patterns.tcpPortPatternTree[port->port],
                            pattern);
                else
                    RegisterPattern(&service_port_patterns.udpPortPatternTree[port->port],
                        pattern);
            }
        }
    }

    for (i = 0; i < 65536; i++)
    {
        if (service_port_patterns.tcpPortPatternTree[i])
        {
            for (ps = service_port_patterns.servicePortPattern; ps; ps = ps->next)
            {
                if (ps->port || (ps->proto != IpProtocol::TCP))
                    continue;

                for (pattern = ps->pattern; pattern; pattern = pattern->next)
                    RegisterPattern(&service_port_patterns.tcpPortPatternTree[i], pattern);
            }

            service_port_patterns.tcpPortPatternTree[i]->prep();
        }

        if (service_port_patterns.udpPortPatternTree[i])
        {
            for (ps = service_port_patterns.servicePortPattern; ps; ps = ps->next)
            {
                if (ps->port || (ps->proto != IpProtocol::UDP))
                    continue;

                for (pattern = ps->pattern; pattern; pattern = pattern->next)
                    RegisterPattern(&service_port_patterns.udpPortPatternTree[i], pattern);
            }

            service_port_patterns.udpPortPatternTree[i]->prep();
        }
    }
}

static void createClientPatternTrees()
{
    PatternService* ps;
    Pattern* pattern;

    for (ps = clientPortPattern.servicePortPattern; ps; ps = ps->next)
    {
        for (pattern = ps->pattern; pattern; pattern = pattern->next)
        {
            if (ps->proto == IpProtocol::TCP)
                RegisterPattern(&clientPortPattern.tcp_patterns, pattern);
            else
                RegisterPattern(&clientPortPattern.udp_patterns, pattern);
        }
    }
}

static void registerServicePatterns()
{
    PatternService* ps;
    Pattern* pattern;

    /**Register patterns with no associated ports, to RNA and local
     * pattern tree. Register patterns with ports with local pattern
     * tree only.
     */
    for (ps = service_port_patterns.servicePortPattern; ps; ps = ps->next)
    {
        if (!ps->port)
        {
            for (pattern = ps->pattern; pattern; pattern = pattern->next)
            {
                if (pattern->data && pattern->length)
                {
                    if (ps->proto == IpProtocol::TCP)
                    {
                        DebugFormat(DEBUG_LOG,"Adding pattern with length %u\n",pattern->length);
                        iniServiceApi->RegisterPattern(&service_validate, IpProtocol::TCP,
                            pattern->data, pattern->length, pattern->offset, "pattern");
                        RegisterPattern(&service_port_patterns.tcp_patterns, pattern);
                    }
                    else
                    {
                        DebugFormat(DEBUG_LOG,"Adding pattern with length %u\n",pattern->length);
                        iniServiceApi->RegisterPattern(&service_validate, IpProtocol::UDP,
                            pattern->data, pattern->length, pattern->offset, "pattern");
                        RegisterPattern(&service_port_patterns.udp_patterns, pattern);
                    }
                }
            }
        }
        else
        {
            for (pattern = ps->pattern; pattern; pattern = pattern->next)
                ps->count++;
        }
    }
    if (service_port_patterns.tcp_patterns)
        service_port_patterns.tcp_patterns->prep();

    if (service_port_patterns.udp_patterns)
        service_port_patterns.udp_patterns->prep();
}

static void registerClientPatterns()
{
    PatternService* ps;
    Pattern* pattern;

    /**Register patterns with no associated ports, to RNA and local
     * pattern tree. Register patterns with ports with local pattern
     * tree only.
     */
    for (ps = clientPortPattern.servicePortPattern; ps; ps = ps->next)
    {
        for (pattern = ps->pattern; pattern; pattern = pattern->next)
        {
            if (pattern->data && pattern->length)
            {
                if (ps->proto == IpProtocol::TCP)
                {
                    DebugFormat(DEBUG_LOG,"Adding pattern with length %u\n",pattern->length);
                    iniClientApi->RegisterPattern(&client_validate, IpProtocol::TCP, pattern->data,
                        pattern->length,
                        pattern->offset);
                    RegisterPattern(&clientPortPattern.tcp_patterns, pattern);
                }
                else
                {
                    DebugFormat(DEBUG_LOG,"Adding pattern with length %u\n",pattern->length);
                    iniClientApi->RegisterPattern(&client_validate, IpProtocol::UDP, pattern->data,
                        pattern->length, pattern->offset);
                    RegisterPattern(&clientPortPattern.udp_patterns, pattern);
                }
            }
            ps->count++;
        }
    }
    if (clientPortPattern.tcp_patterns)
        clientPortPattern.tcp_patterns->prep();

    if (clientPortPattern.udp_patterns)
        clientPortPattern.udp_patterns->prep();
}

static void dumpPatterns(const char* name, PatternService* pList)
{
    UNUSED(name);
    PatternService* ps;
    Pattern* pattern;

    /**Register patterns with no associated ports, to RNA and local
     * pattern tree. Register patterns with ports with local pattern
     * tree only.
     */

    DebugFormat(DEBUG_LOG,"Adding pattern for \"%s\"\n",name);
    for (ps = pList; ps; ps = ps->next)
    {
        for (pattern = ps->pattern; pattern; pattern = pattern->next)
        {
            DebugFormat(DEBUG_LOG,"\t%s, %u\n",pattern->data, pattern->length);
            if (pattern->data && pattern->length)
            {
                DebugFormat(DEBUG_LOG,"\t\t%s, %u\n",pattern->data, pattern->length);
            }
        }
    }
}

void finalize_client_port_patterns()
{

    read_patterns(clientPortPattern.luaInjectedPatterns, &clientPortPattern.servicePortPattern);
    createClientPatternTrees();
    registerClientPatterns();
    dumpPatterns("Client", clientPortPattern.servicePortPattern);
}

void finalize_service_port_patterns()
{
    read_patterns(service_port_patterns.luaInjectedPatterns, &service_port_patterns.servicePortPattern);
    install_ports(service_port_patterns.servicePortPattern, iniServiceApi);
    createServicePatternTrees();
    registerServicePatterns();
    dumpPatterns("Server", service_port_patterns.servicePortPattern);
}

static int pattern_service_init(const InitServiceAPI* const init_api)
{
    iniServiceApi = init_api;

    DebugFormat(DEBUG_LOG,"Initializing with instance %u\n",iniServiceApi->instance_id);

    return 0;
}

static void pattern_service_clean()
{
    PatternService* ps;

    if ( service_port_patterns.servicePortPattern )
    {
        unsigned i;

        if (service_port_patterns.tcp_patterns)
        {
            delete service_port_patterns.tcp_patterns;
            service_port_patterns.tcp_patterns = nullptr;
        }
        if (service_port_patterns.udp_patterns)
        {
            delete service_port_patterns.udp_patterns;
            service_port_patterns.udp_patterns = nullptr;
        }
        for (i = 0; i < 65536; i++)
        {
            if (service_port_patterns.tcpPortPatternTree[i])
            {
                delete service_port_patterns.tcpPortPatternTree[i];
                service_port_patterns.tcpPortPatternTree[i] = nullptr;
            }
            if (service_port_patterns.udpPortPatternTree[i])
            {
                delete service_port_patterns.udpPortPatternTree[i];
                service_port_patterns.udpPortPatternTree[i] = nullptr;
            }
        }
        while (service_port_patterns.servicePortPattern)
        {
            ps = service_port_patterns.servicePortPattern;
            service_port_patterns.servicePortPattern = ps->next;
            FreePatternService(ps);
        }
    }
}

struct PServiceMatch
{
    /**Matches are aggregated by PatternService first and then by patterns. next is used to walk
       matches by PatternService*/
    PServiceMatch* next;

    /**Walks matches by pattern within a PatternService. */
    PServiceMatch* ps_next;

    Pattern* data;
};

static PServiceMatch* free_servicematch_list;

static int pattern_match(void* id, void*, int index, void* data, void*)
{
    PServiceMatch** matches = (PServiceMatch**)data;
    Pattern* pd = (Pattern*)id;
    PServiceMatch* psm;
    PServiceMatch* sm;

    if (pd->offset >= 0 && pd->offset != index)
        return 0;

    /*find if previously this PS was matched. */
    for (psm=*matches; psm; psm=psm->next)
        if (psm->data->ps == pd->ps)
            break;

    if (psm)
    {
        /*walks patterns within a PatternService. */
        for (sm=psm; sm; sm=sm->ps_next)
            if (sm->data == pd)
                return 0;

        if (free_servicematch_list)
        {
            sm = free_servicematch_list;
            free_servicematch_list = sm->next;
            memset(sm, 0, sizeof(*sm));
        }
        else
            sm = (PServiceMatch*)snort_calloc(sizeof(PServiceMatch));

        sm->data = pd;
        sm->ps_next = psm->ps_next;
        psm->ps_next = sm;
        return 0;
    }
    else if (free_servicematch_list)
    {
        sm = free_servicematch_list;
        free_servicematch_list = sm->next;
        memset(sm, 0, sizeof(*sm));
    }
    else
        sm = (PServiceMatch*)snort_calloc(sizeof(PServiceMatch));

    sm->data = pd;
    sm->next = *matches;
    *matches = sm;
    return 0;
}

static int csdPatternTreeSearch(const uint8_t* data, uint16_t size, IpProtocol protocol,
    Packet* pkt, const RNAServiceElement** serviceData, bool isClient)
{
    SearchTool* patternTree = nullptr;
    PatternService* ps;
    PServiceMatch* matches = nullptr;
    PServiceMatch* sm;
    PServiceMatch* psm;
    Pattern* pattern;

    if (!data || !pkt || !size)
        return 0;

    *serviceData = nullptr;

    if (!isClient)
    {
        if (protocol == IpProtocol::UDP)
            patternTree = service_port_patterns.udpPortPatternTree[pkt->ptrs.sp];
        else
            patternTree = service_port_patterns.tcpPortPatternTree[pkt->ptrs.sp];
    }

    if (!patternTree)
    {
        if (protocol == IpProtocol::UDP)
            patternTree = (isClient) ? clientPortPattern.udp_patterns :
                service_port_patterns.udp_patterns;
        else
            patternTree = (isClient) ? clientPortPattern.tcp_patterns :
                service_port_patterns.tcp_patterns;
    }

    if (patternTree)
    {
        patternTree->find_all((char*)data, size, &pattern_match, false, (void*)&matches);
    }

    if (matches == nullptr)
        return 0;

    /* match highest count and then longest pattern. */
    ps = nullptr;
    for (sm = matches; sm; sm = sm->next)
    {
        /* walk all patterns in PatternService */
        for (pattern = sm->data->ps->pattern; pattern; pattern = pattern->next)
        {
            for (psm = sm; psm; psm = psm->ps_next)
                if (pattern == psm->data)
                    break;
            if (psm == nullptr)
                break;
        }

        if (pattern == nullptr)    /*all patterns in PatternService were matched */
        {
            if (ps)
            {
                if (sm->data->ps->count > ps->count)
                    ps = sm->data->ps;
                else if (sm->data->ps->count == ps->count && sm->data->ps->longest > ps->longest)
                    ps = sm->data->ps;
            }
            else
                ps = sm->data->ps;
        }
    }

    /*free match list */
    while (matches)
    {
        while (matches->ps_next)
        {
            sm = matches->ps_next;
            matches->ps_next = sm->ps_next;
            sm->next = free_servicematch_list;
            free_servicematch_list = sm;
        }
        sm = matches;
        matches = sm->next;
        sm->next = free_servicematch_list;
        free_servicematch_list = sm;
    }

    if (ps == nullptr)
        return 0;
    *serviceData = &svc_element;
    return ps->id;
}

static int service_validate(ServiceValidationArgs* args)
{
    uint32_t id;
    const RNAServiceElement* service = nullptr;
    AppIdSession* asd = args->asd;
    const uint8_t* data = args->data;
    Packet* pkt = args->pkt;
    const int dir = args->dir;
    uint16_t size = args->size;

    if (!data || !pattern_service_mod.api || !asd || !pkt)
        return SERVICE_ENULL;
    if (!size)
        goto inprocess;
    if (dir != APP_ID_FROM_RESPONDER)
        goto inprocess;

    id = csdPatternTreeSearch(data, size, asd->protocol, pkt, &service, false);
    if (!id)
        goto fail;

    pattern_service_mod.api->add_service(asd, pkt, dir, &svc_element, id, nullptr, nullptr,
        nullptr);
    return SERVICE_SUCCESS;

inprocess:
    pattern_service_mod.api->service_inprocess(asd, pkt, dir, &svc_element);
    return SERVICE_INPROCESS;

fail:
    pattern_service_mod.api->fail_service(asd, pkt, dir, &svc_element,
        pattern_service_mod.flow_data_index);
    return SERVICE_NOMATCH;
}

static CLIENT_APP_RETCODE client_init(const InitClientAppAPI* const init_api, SF_LIST*)
{
    iniClientApi = init_api;

    return CLIENT_APP_SUCCESS;
}

static CLIENT_APP_RETCODE client_init_tcp(const InitClientAppAPI* const, SF_LIST*)
{
    return CLIENT_APP_SUCCESS;
}

static void client_clean()
{
    if (clientPortPattern.servicePortPattern)
    {
        if (clientPortPattern.tcp_patterns)
        {
            delete clientPortPattern.tcp_patterns;
            clientPortPattern.tcp_patterns = nullptr;
        }

        if (clientPortPattern.udp_patterns)
        {
            delete clientPortPattern.udp_patterns;
            clientPortPattern.udp_patterns = nullptr;
        }
    }
}

static CLIENT_APP_RETCODE client_validate(const uint8_t* data, uint16_t size, const int dir,
    AppIdSession* asd, Packet* pkt, Detector*)
{
    AppId id;
    const RNAServiceElement* service = nullptr;

    if (!data || !asd || !pkt)
        return CLIENT_APP_ENULL;
    if (!size)
        goto inprocess;
    if (dir == APP_ID_FROM_RESPONDER)
        goto inprocess;

    id = csdPatternTreeSearch(data, size, asd->protocol, pkt, &service, true);
    if (!id)
        goto fail;

    pattern_tcp_client_mod.api->add_app(asd, id, id, nullptr);
    return CLIENT_APP_SUCCESS;

inprocess:
    return CLIENT_APP_INPROCESS;

fail:
    return CLIENT_APP_EINVALID;
}


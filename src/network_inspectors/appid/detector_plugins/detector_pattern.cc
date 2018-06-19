//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detector_pattern.h"

#include "app_info_table.h"
#include "log/messages.h"
#include "protocols/packet.h"
#include "search_engines/search_tool.h"

using namespace snort;

static PatternServiceDetector* service_pattern_detector;
static PatternClientDetector* client_pattern_detector;

static void dumpPatterns(const char* name, PatternService* pList)
{
    UNUSED(name);

    trace_logf(appid_module,"Adding pattern for \"%s\"\n", name);
    for (PatternService* ps = pList; ps; ps = ps->next)
        for (Pattern* pattern = ps->pattern; pattern; pattern = pattern->next)
            if (pattern->data && pattern->length)
            {
                trace_logf(appid_module,"\t\t%s, %u\n",pattern->data, pattern->length);
            }
}

static void free_pattern_service(PatternService* ps)
{
    if (ps)
    {
        Pattern* pattern;
        PortNode* port;

        while ((pattern = ps->pattern))
        {
            ps->pattern = pattern->next;
            if (pattern->data)
                snort_free(pattern->data);
            snort_free(pattern);
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
    char* lastName = nullptr;
    short lastPort = 0;
    IpProtocol lastProto = IpProtocol::PROTO_NOT_SET;

    for (PortPatternNode* pNode = portPatternList; pNode; pNode = pNode->next)
    {
        bool newPs = false;

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
            PortNode* port = (PortNode*)snort_calloc(sizeof(PortNode));
            port->port = pNode->port;
            port->next = ps->port;
            lastPort = pNode->port;
            ps->port = port;
        }

        Pattern* pattern = (Pattern*)snort_calloc(sizeof(Pattern));
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

static void register_pattern(snort::SearchTool** patterns, Pattern* pattern)
{
    if (!*patterns)
    {
        *patterns = new snort::SearchTool("ac_full", true);
        if (!*patterns)
        {
            snort::ErrorMessage("Error initializing the pattern table\n");
            return;
        }
    }

    (*patterns)->add((char*)pattern->data, pattern->length, pattern, false);
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

static int pattern_match(void* id, void*, int match_end_pos, void* data, void*)
{
    PServiceMatch** matches = (PServiceMatch**)data;
    Pattern* pd = (Pattern*)id;
    PServiceMatch* psm;
    PServiceMatch* sm;

    //  Ignore matches that don't start at the expected position.
    if (pd->offset >= 0 && pd->offset != (match_end_pos - (int)pd->length))
        return 0;

    /*find if previously this PS was matched. */
    for (psm = *matches; psm; psm = psm->next)
        if (psm->data->ps == pd->ps)
            break;

    if (psm)
    {
        /*walks patterns within a PatternService. */
        for (sm = psm; sm; sm = sm->ps_next)
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

static int csd_pattern_tree_search(const uint8_t* data, uint16_t size, snort::SearchTool* patternTree)
{
    PServiceMatch* matches = nullptr;

    if ( !size )
        return 0;

    if (patternTree)
        patternTree->find_all((const char*)data, size, &pattern_match, false, (void*)&matches);

    if (matches == nullptr)
        return 0;

    /* match highest count and then longest pattern. */
    PatternService* ps = nullptr;
    for (PServiceMatch* sm = matches; sm; sm = sm->next)
    {
        Pattern* pattern;

        /* walk all patterns in PatternService */
        for (pattern = sm->data->ps->pattern; pattern; pattern = pattern->next)
        {
            PServiceMatch* psm;

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
        PServiceMatch* sm = nullptr;

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

    return ps->id;
}

// Creates unique subset of services registered on ports, and then creates pattern trees.
void PatternServiceDetector::create_service_pattern_trees()
{
    for (PatternService* ps = servicePortPattern; ps; ps = ps->next)
        for (PortNode* port = ps->port; port; port = port->next)
            for (Pattern* pattern = ps->pattern; pattern; pattern = pattern->next)
                if (ps->proto == IpProtocol::TCP)
                    register_pattern(&tcpPortPatternTree[port->port],
                        pattern);
                else
                    register_pattern(&udpPortPatternTree[port->port],
                        pattern);

    for (unsigned i = 0; i < 65536; i++)
    {
        if (tcpPortPatternTree[i])
        {
            for (PatternService* ps = servicePortPattern; ps; ps = ps->next)
            {
                if (ps->port || (ps->proto != IpProtocol::TCP))
                    continue;

                for (Pattern* pattern = ps->pattern; pattern; pattern = pattern->next)
                    register_pattern(&tcpPortPatternTree[i], pattern);
            }

            tcpPortPatternTree[i]->prep();
        }

        if (udpPortPatternTree[i])
        {
            for (PatternService* ps = servicePortPattern; ps; ps = ps->next)
            {
                if (ps->port || (ps->proto != IpProtocol::UDP))
                    continue;

                for (Pattern* pattern = ps->pattern; pattern; pattern = pattern->next)
                    register_pattern(&udpPortPatternTree[i], pattern);
            }

            udpPortPatternTree[i]->prep();
        }
    }
}

void PatternServiceDetector::register_service_patterns()
{
    /**Register patterns with no associated ports, to RNA and local
     * pattern tree. Register patterns with ports with local pattern
     * tree only.
     */
    for (PatternService* ps = servicePortPattern; ps; ps = ps->next)
    {
        if (!ps->port)
        {
            for (Pattern* pattern = ps->pattern; pattern; pattern = pattern->next)
            {
                if (pattern->data && pattern->length)
                {
                    if (ps->proto == IpProtocol::TCP)
                    {
                        handler->register_tcp_pattern(this, pattern->data, pattern->length,
                            pattern->offset, 0);
                        register_pattern(&tcp_pattern_matcher, pattern);
                    }
                    else
                    {
                        handler->register_udp_pattern(this, pattern->data, pattern->length,
                            pattern->offset, 0);
                        register_pattern(&udp_pattern_matcher, pattern);
                    }
                }
            }
        }
        else
        {
            for (Pattern* pattern = ps->pattern; pattern; pattern = pattern->next)
                ps->count++;
        }
    }

    if (tcp_pattern_matcher)
        tcp_pattern_matcher->prep();

    if (udp_pattern_matcher)
        udp_pattern_matcher->prep();
}

// Register ports for detectors which have a pattern associated with it.
void PatternServiceDetector::install_ports(PatternService* serviceList)
{
    ServiceDetectorPort pp = { 0, IpProtocol::PROTO_NOT_SET, false };

    for (PatternService* ps = serviceList; ps; ps = ps->next)
    {
        if (!ps->port)
            continue;

        for (PortNode* port = ps->port; port; port = port->next)
        {
            pp.port = port->port;
            pp.proto = (IpProtocol)ps->proto;
            handler->add_service_port(this, pp);
        }
    }
}

void PatternServiceDetector::insert_service_port_pattern(PortPatternNode* pPattern)
{
    PortPatternNode** prev = nullptr;
    PortPatternNode** curr;

    for (curr = &service_pattern_detector->luaInjectedPatterns;
        *curr; prev = curr, curr = &((*curr)->next))
    {
        if (strcmp(pPattern->detectorName, (*curr)->detectorName) || pPattern->protocol <
            (*curr)->protocol
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

void PatternServiceDetector::finalize_service_port_patterns()
{
    read_patterns(service_pattern_detector->luaInjectedPatterns,
        &service_pattern_detector->servicePortPattern);
    service_pattern_detector->install_ports(service_pattern_detector->servicePortPattern);
    service_pattern_detector->create_service_pattern_trees();
    service_pattern_detector->register_service_patterns();
    dumpPatterns("Server", service_pattern_detector->servicePortPattern);
}

PatternServiceDetector::PatternServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "pattern";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_PATTERN;

    service_pattern_detector = this;
    handler->register_detector(name, this, proto);
}

PatternServiceDetector::~PatternServiceDetector()
{
    if ( servicePortPattern )
    {
        delete tcp_pattern_matcher;
        delete udp_pattern_matcher;

        for (unsigned i = 0; i < 65536; i++)
        {
            if (tcpPortPatternTree[i])
                delete tcpPortPatternTree[i];
            if (udpPortPatternTree[i])
                delete udpPortPatternTree[i];
        }

        PatternService* ps;
        while (servicePortPattern)
        {
            ps = servicePortPattern;
            servicePortPattern = ps->next;
            free_pattern_service(ps);
        }
    }

    PortPatternNode* tmp;
    while ((tmp = luaInjectedPatterns))
    {
        luaInjectedPatterns = tmp->next;
        snort_free(tmp->pattern);
        snort_free(tmp->detectorName);
        snort_free(tmp);
    }
}

int PatternServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    snort::SearchTool* patternTree = nullptr;

    if (!args.data )
        return APPID_ENULL;
    if (!args.size || (args.dir != APP_ID_FROM_RESPONDER) )
    {
        service_inprocess(args.asd, args.pkt, args.dir);
        return APPID_INPROCESS;
    }

    if (args.asd.protocol == IpProtocol::UDP)
    {
        patternTree = udpPortPatternTree[args.pkt->ptrs.sp];
        if (!patternTree)
            patternTree = udp_pattern_matcher;
    }
    else
    {
        patternTree = tcpPortPatternTree[args.pkt->ptrs.sp];
        if (!patternTree)
            patternTree = tcp_pattern_matcher;
    }

    uint32_t id = csd_pattern_tree_search(args.data, args.size, patternTree);
    if (!id)
    {
        fail_service(args.asd, args.pkt, args.dir);
        return APPID_NOMATCH;
    }

    return add_service(args.asd, args.pkt, args.dir, id);
}

PatternClientDetector::PatternClientDetector(ClientDiscovery* cdm)
{
    handler = cdm;
    name = "pattern";
    proto = IpProtocol::TCP;

    client_pattern_detector = this;
    handler->register_detector(name, this, proto);
}

PatternClientDetector::~PatternClientDetector()
{
    if (servicePortPattern)
    {
        if (tcp_pattern_matcher)
        {
            delete tcp_pattern_matcher;
            tcp_pattern_matcher = nullptr;
        }

        if (udp_pattern_matcher)
        {
            delete udp_pattern_matcher;
            udp_pattern_matcher = nullptr;
        }

        PatternService* ps;
        while (servicePortPattern)
        {
            ps = servicePortPattern;
            servicePortPattern = ps->next;
            free_pattern_service(ps);
        }
    }
    PortPatternNode* tmp;
    while ((tmp = luaInjectedPatterns))
    {
        luaInjectedPatterns = tmp->next;
        snort_free(tmp->pattern);
        snort_free(tmp->detectorName);
        snort_free(tmp);
    }
}

int PatternClientDetector::validate(AppIdDiscoveryArgs& args)
{
    if (!args.size || args.dir == APP_ID_FROM_RESPONDER)
        return APPID_INPROCESS;

    snort::SearchTool* patternTree = (args.asd.protocol == IpProtocol::UDP) ?
        udp_pattern_matcher : tcp_pattern_matcher;
    AppId id = csd_pattern_tree_search(args.data, args.size, patternTree);
    if (!id)
        return APPID_EINVALID;

    add_app(args.asd, id, id, nullptr);
    return APPID_SUCCESS;
}

void PatternClientDetector::create_client_pattern_trees()
{
    for (PatternService* ps = servicePortPattern; ps; ps = ps->next)
    {
        for ( Pattern* pattern = ps->pattern; pattern; pattern = pattern->next)
        {
            if (ps->proto == IpProtocol::TCP)
                register_pattern(&tcp_pattern_matcher, pattern);
            else
                register_pattern(&udp_pattern_matcher, pattern);
        }
    }
}

void PatternClientDetector::insert_client_port_pattern(PortPatternNode* port_pattern)
{
    //insert ports in order.
    PortPatternNode** prev = nullptr;
    PortPatternNode** curr;
    for (curr = &client_pattern_detector->luaInjectedPatterns;
        *curr; prev = curr, curr = &((*curr)->next))
    {
        if (strcmp(port_pattern->detectorName, (*curr)->detectorName)
            || port_pattern->protocol < (*curr)->protocol
            || port_pattern->port < (*curr)->port)
            break;
    }

    if (prev)
    {
        port_pattern->next = (*prev)->next;
        (*prev)->next = port_pattern;
    }
    else
    {
        port_pattern->next = *curr;
        *curr = port_pattern;
    }
}

// Register patterns with no associated ports, to RNA and local pattern tree. Register
// patterns with ports with local pattern tree only.
void PatternClientDetector::register_client_patterns()
{
    for (PatternService* ps = servicePortPattern; ps; ps = ps->next)
        for (Pattern* pattern = ps->pattern; pattern; pattern = pattern->next)
        {
            if (pattern->data && pattern->length)
            {
                if (ps->proto == IpProtocol::TCP)
                {
                    handler->register_tcp_pattern(this, pattern->data, pattern->length,
                        pattern->offset, 0);
                    register_pattern(&tcp_pattern_matcher, pattern);
                }
                else
                {
                    handler->register_udp_pattern(this, pattern->data, pattern->length,
                        pattern->offset, 0);
                    register_pattern(&udp_pattern_matcher, pattern);
                }
            }
            ps->count++;
        }

    if (tcp_pattern_matcher)
        tcp_pattern_matcher->prep();

    if (udp_pattern_matcher)
        udp_pattern_matcher->prep();
}

void PatternClientDetector::finalize_client_port_patterns()
{
    read_patterns(client_pattern_detector->luaInjectedPatterns,
        &client_pattern_detector->servicePortPattern);
    client_pattern_detector->create_client_pattern_trees();
    client_pattern_detector->register_client_patterns();
    dumpPatterns("Client", client_pattern_detector->servicePortPattern);
}


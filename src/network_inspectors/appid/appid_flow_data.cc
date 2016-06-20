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

// appid_flow_data.cc author Sourcefire Inc.

#include "appid_flow_data.h"
#include "fw_appid.h"
#include "appid_stats.h"
#include "service_plugins/service_base.h"

#include "log/messages.h"
#include "stream/stream_api.h"
#include "sfip/sf_ip.h"
#include "utils/util.h"

unsigned AppIdData::flow_id = 0;

static AppIdFlowData* fd_free_list;

AppIdData::~AppIdData()
{
	appSharedDataDelete();
}

void AppIdData::appHttpFieldClear()
{
    if (hsession == nullptr)
        return;

    if (hsession->referer)
    {
        snort_free(hsession->referer);
        hsession->referer = nullptr;
    }
    if (hsession->cookie)
    {
        snort_free(hsession->cookie);
        hsession->cookie = nullptr;
    }
    if (hsession->url)
    {
        snort_free(hsession->url);
        hsession->url = nullptr;
    }
    if (hsession->useragent)
    {
        snort_free(hsession->useragent);
        hsession->useragent = nullptr;
    }
    if (hsession->host)
    {
        snort_free(hsession->host);
        hsession->host = nullptr;
    }
    if (hsession->uri)
    {
        snort_free(hsession->uri);
        hsession->uri = nullptr;
    }
    if (hsession->content_type)
    {
        snort_free(hsession->content_type);
        hsession->content_type = nullptr;
    }
    if (hsession->location)
    {
        snort_free(hsession->location);
        hsession->location = nullptr;
    }
    if (hsession->body)
    {
        snort_free(hsession->body);
        hsession->body = nullptr;
    }
    if (hsession->req_body)
    {
        snort_free(hsession->req_body);
        hsession->req_body = nullptr;
    }
    if (hsession->xffAddr)
    {
        sfip_free(hsession->xffAddr);
        hsession->xffAddr = nullptr;
    }
}

void AppIdData::appHttpSessionDataFree()
{
    int i;

    if (hsession == nullptr)
        return;

    appHttpFieldClear();

    for (i = 0; i < NUMBER_OF_PTYPES; i++)
    {
        if (nullptr != hsession->new_field[i])
        {
            snort_free(hsession->new_field[i]);
            hsession->new_field[i] = nullptr;
        }
    }
    if (hsession->fflow)
    {
        snort_free(hsession->fflow);
        hsession->fflow = nullptr;
    }
    if (hsession->via)
    {
        snort_free(hsession->via);
        hsession->via = nullptr;
    }
    if (hsession->content_type)
    {
        snort_free(hsession->content_type);
        hsession->content_type = nullptr;
    }
    if (hsession->response_code)
    {
        snort_free(hsession->response_code);
        hsession->response_code = nullptr;
    }

    snort_free(hsession);
    hsession = nullptr;
}

void AppIdData::appDNSSessionDataFree()
{
	if (dsession )
	{
		if (dsession->host)
		{
			snort_free(dsession->host);
			dsession->host = nullptr;
		}
		snort_free(dsession);
		dsession = nullptr;
	}
}

void AppIdData::appTlsSessionDataFree()
{
	if (tsession )
	{
		if (tsession->tls_host)
			snort_free(tsession->tls_host);
		if (tsession->tls_cname)
			snort_free(tsession->tls_cname);
		if (tsession->tls_orgUnit)
			snort_free(tsession->tls_orgUnit);
		snort_free(tsession);
		tsession = nullptr;
	}
}

void AppIdData::AppIdFlowdataFree()
{
    AppIdFlowData* tmp_fd;

    while ((tmp_fd = flowData))
    {
        flowData = tmp_fd->next;
        if (tmp_fd->fd_data && tmp_fd->fd_free)
            tmp_fd->fd_free(tmp_fd->fd_data);
        tmp_fd->next = fd_free_list;
        fd_free_list = tmp_fd;
    }
}

void AppIdData::appSharedDataDelete()
{
	RNAServiceSubtype* rna_service_subtype;

	/*check daq flag */
	appIdStatsUpdate(this);

	if (ssn)
		FailInProcessService(this, pAppidActiveConfig);
	AppIdFlowdataFree();

	if (thirdparty_appid_module)
	{
		thirdparty_appid_module->session_delete(tpsession, 0);
		tpsession = nullptr;
	}

	snort_free(clientVersion);
	snort_free(serviceVendor);
	snort_free(serviceVersion);
	snort_free(netbios_name);
	while ((rna_service_subtype = subtype))
	{
		subtype = rna_service_subtype->next;
		snort_free(*(void**)&rna_service_subtype->service);
		snort_free(*(void**)&rna_service_subtype->vendor);
		snort_free(*(void**)&rna_service_subtype->version);
		snort_free(rna_service_subtype);
	}
	if (candidate_service_list)
	{
		sflist_free(candidate_service_list);
		candidate_service_list = nullptr;
	}

	if (candidate_client_list)
	{
		sflist_free(candidate_client_list);
		candidate_client_list = nullptr;
	}
	snort_free(username);
	snort_free(netbiosDomain);
	snort_free(payloadVersion);
	appHttpSessionDataFree();
	appTlsSessionDataFree();
	appDNSSessionDataFree();
	tsession = nullptr;

	snort_free(firewallEarlyData);
	firewallEarlyData = nullptr;

	// should be freed by flow
	// appSharedDataFree(sharedData);
}

void AppIdFlowdataFini()
{
    AppIdFlowData* tmp_fd;

    while ((tmp_fd = fd_free_list))
    {
        fd_free_list = fd_free_list->next;
        snort_free(tmp_fd);
    }
}

void* AppIdFlowdataGet(AppIdData* flowp, unsigned id)
{
    AppIdFlowData* tmp_fd;

    for (tmp_fd = flowp->flowData; tmp_fd && tmp_fd->fd_id != id; tmp_fd = tmp_fd->next)
        ;
    return tmp_fd ? tmp_fd->fd_data : nullptr;
}

void* AppIdFlowdataRemove(AppIdData* flowp, unsigned id)
{
    AppIdFlowData** pfd;
    AppIdFlowData* fd;

    for (pfd = &flowp->flowData; *pfd && (*pfd)->fd_id != id; pfd = &(*pfd)->next)
        ;
    if ((fd = *pfd))
    {
        *pfd = fd->next;
        fd->next = fd_free_list;
        fd_free_list = fd;
        return fd->fd_data;
    }
    return nullptr;
}

void AppIdFlowdataDelete(AppIdData* flowp, unsigned id)
{
    AppIdFlowData** pfd;
    AppIdFlowData* fd;

    for (pfd = &flowp->flowData; *pfd && (*pfd)->fd_id != id; pfd = &(*pfd)->next)
        ;
    if ((fd = *pfd))
    {
        *pfd = fd->next;
        if (fd->fd_data && fd->fd_free)
            fd->fd_free(fd->fd_data);
        fd->next = fd_free_list;
        fd_free_list = fd;
    }
}

void AppIdFlowdataDeleteAllByMask(AppIdData* flowp, unsigned mask)
{
    AppIdFlowData** pfd;
    AppIdFlowData* fd;

    pfd = &flowp->flowData;
    while (*pfd)
    {
        if ((*pfd)->fd_id & mask)
        {
            fd = *pfd;
            *pfd = fd->next;
            if (fd->fd_data && fd->fd_free)
                fd->fd_free(fd->fd_data);
            fd->next = fd_free_list;
            fd_free_list = fd;
        }
        else
        {
            pfd = &(*pfd)->next;
        }
    }
}

int AppIdFlowdataAdd(AppIdData* flowp, void* data, unsigned id, AppIdFreeFCN fcn)
{
    AppIdFlowData* tmp_fd;

    if (fd_free_list)
    {
        tmp_fd = fd_free_list;
        fd_free_list = tmp_fd->next;
    }
    else
        tmp_fd = (AppIdFlowData*)snort_alloc(sizeof(AppIdFlowData));

    tmp_fd->fd_id = id;
    tmp_fd->fd_data = data;
    tmp_fd->fd_free = fcn;
    tmp_fd->next = flowp->flowData;
    flowp->flowData = tmp_fd;
    return 0;
}

int AppIdFlowdataAddId(AppIdData* flowp, uint16_t port, const RNAServiceElement* svc_element)
{
    if (flowp->serviceData)
        return -1;
    flowp->serviceData = svc_element;
    flowp->service_port = port;
    return 0;
}

#ifdef RNA_DEBUG_EXPECTED_FLOWS
static void flowAppSharedDataDelete(AppIdData* sharedData)
{
    _dpd.errMsg("Deleting %p\n",sharedData);
    appSharedDataDelete(sharedData);
}

#endif

AppIdData* AppIdEarlySessionCreate(
    AppIdData*, const Packet* /*ctrlPkt*/, const sfip_t* cliIp, uint16_t cliPort,
    const sfip_t* srvIp, uint16_t srvPort, IpProtocol proto, int16_t app_id, int /*flags*/)
{
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    // FIXIT - not needed  until crtlPkt expectedSession is supported
    //struct _ExpectNode** node;
    enum PktType protocol = ( enum PktType )proto;

    if (app_id_debug_session_flag)
    {
        sfip_ntop(cliIp, src_ip, sizeof(src_ip));
        sfip_ntop(srvIp, dst_ip, sizeof(dst_ip));
    }

    AppIdData* data = appSharedDataAlloc(proto, cliIp);
    data->common.policyId = appIdPolicyId;

    // FIXIT - expect session control packet support not ported to snort3 yet
    //node = (flags & APPID_EARLY_SESSION_FLAG_FW_RULE) ? &ctrlPkt->expectedSession : nullptr;

    // FIXIT - 2.9.x set_application_protocol_id_expected has several new parameters, need to look
    // into what is required to support those here.
    if (stream.set_application_protocol_id_expected(/*crtlPkt,*/ cliIp, cliPort, srvIp, srvPort,
        protocol, app_id, data) )
    {
        if (app_id_debug_session_flag)
            LogMessage("AppIdDbg %s failed to create a related flow for %s-%u -> %s-%u %u\n",
                app_id_debug_session,
                src_ip, (unsigned)cliPort, dst_ip, (unsigned)srvPort, (unsigned)proto);
        data->appSharedDataDelete();
        return nullptr;
    }
    else if (app_id_debug_session_flag)
        LogMessage("AppIdDbg %s created a related flow for %s-%u -> %s-%u %u\n",
            app_id_debug_session,
            src_ip, (unsigned)cliPort, dst_ip, (unsigned)srvPort, (unsigned)proto);

    return data;
}


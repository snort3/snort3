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

// detector_base.cc author Sourcefire Inc.

#include "detector_base.h"

#include "client_plugins/client_app_base.h"
#include "detector_api.h"
#include "log/messages.h"
#include "service_plugins/service_base.h"

static void* detector_flowdata_get(AppIdData* flowp, unsigned detector_id);
static int detector_flowdata_add(AppIdData* flowp, void* data, unsigned detector_id,
    AppIdFreeFCN fcn);

static const DetectorApi detector_api
{
    &detector_flowdata_get,
    &detector_flowdata_add,
};

extern RNADetectorValidationModule imap_detector_mod;
extern RNADetectorValidationModule pop3_detector_mod;
extern RNADetectorValidationModule kerberos_detector_mod;
extern RNADetectorValidationModule pattern_detector_mod;

static RNADetectorValidationModule* static_detector_list[]
{
#ifdef REMOVED_WHILE_NOT_IN_USE
    &imap_detector_mod,
    &pop3_detector_mod,
    &kerberos_detector_mod
#endif
    nullptr
};

/**callback function for initializing static and dynamic detectors.
 */
static int detectorLoadCallback(void* symbol)
{
    static THREAD_LOCAL unsigned detector_module_index = 0;
    RNADetectorValidationModule* svm = (RNADetectorValidationModule*)symbol;

    if (detector_module_index >= 65536)
    {
        ErrorMessage("Maximum number of detector modules exceeded");
        return -1;
    }
    if (svm->service)
    {
        if (serviceLoadCallback(svm->service))
        {
            return -1;
        }
    }

    if (svm->client)
    {
        if (ClientAppLoadCallback(svm->client))
        {
            return -1;
        }
    }

    svm->api = &detector_api;
    svm->flow_data_index = detector_module_index | APPID_SESSION_DATA_DETECTOR_MODSTATE_BIT;
//    svm->streamAPI = _dpd.streamAPI;  FIXIT - removed to permit compilation.
    detector_module_index++;

    return 0;
}

int LoadDetectorModules(const char** )
{
    unsigned i;

    for (i=0; i<sizeof(static_detector_list)/sizeof(*static_detector_list); i++)
    {
        if (static_detector_list[i] && detectorLoadCallback(static_detector_list[i]))
            return -1;
    }

    return 0;
}

/**
* A method to get client app specific state data from a flow
*
* @param flow the flow that contains the data
*
* @return RNA flow data structure for success
*/
static void* detector_flowdata_get(AppIdData* flowp, unsigned detector_id)
{
    return AppIdFlowdataGet(flowp, detector_id);
}

/**
* A method to add client app specific state data to a flow
*
* @param flow the flow to which the data is added
* @param data the data to add
* @param id the data identifier
*
* @return RNA flow data structure for success
*/
static int detector_flowdata_add(AppIdData* flowp, void* data, unsigned detector_id,
    AppIdFreeFCN fcn)
{
    return AppIdFlowdataAdd(flowp, data, detector_id, fcn);
}


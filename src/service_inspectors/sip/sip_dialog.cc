//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2011-2013 Sourcefire, Inc.
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

// sip_dialog.cc author Hui Cao <huica@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sip_dialog.h"

#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "framework/data_bus.h"
#include "protocols/packet.h"
#include "protocols/vlan.h"
#include "pub_sub/sip_events.h"
#include "stream/stream.h"
#include "utils/util.h"

#include "sip.h"
#include "sip_module.h"

using namespace snort;

static void SIP_updateMedias(SIP_MediaSession*, SIP_MediaList*);
static int SIP_compareMedias(SIP_MediaDataList, SIP_MediaDataList);
static bool SIP_checkMediaChange(SIPMsg* sipMsg, SIP_DialogData* dialog);
static int SIP_processRequest(SIPMsg*, SIP_DialogData*, SIP_DialogList*, Packet*, SIP_PROTO_CONF*);
static int SIP_processInvite(SIPMsg*, SIP_DialogData*, SIP_DialogList*);
static int SIP_processACK(SIPMsg*, SIP_DialogData*, SIP_DialogList*, Packet*, SIP_PROTO_CONF*);
static int SIP_processResponse(SIPMsg*, SIP_DialogData*, SIP_DialogList*, Packet*, SIP_PROTO_CONF*);
static int SIP_ignoreChannels(SIP_DialogData*, Packet* p, SIP_PROTO_CONF*);
static SIP_DialogData* SIP_addDialog(SIPMsg*, SIP_DialogData*, SIP_DialogList*);
static int SIP_deleteDialog(SIP_DialogData*, SIP_DialogList*);

/********************************************************************
 * Function: SIP_processRequest()
 *
 *  Based on the new received sip request message, update the dialog information.
 *  Note: dialog is created through dialog
 * Arguments:
 *  SIPMsg *        - sip request message
 *  SIP_DialogData* - dialog to be updated,
 *  Packet*  - the packet
 *
 * Returns:
 *  true: request message has been processed correctly
 *  false: request message has not been processed correctly
 ********************************************************************/
static int SIP_processRequest(SIPMsg* sipMsg, SIP_DialogData* dialog, SIP_DialogList* dList,
    Packet* p, SIP_PROTO_CONF* config)
{
    SIPMethodsFlag methodFlag;
    int ret = true;

    assert (nullptr != sipMsg);

    /*If dialog not exist, create one */
    if ((nullptr == dialog)&&(SIP_METHOD_CANCEL != sipMsg->methodFlag))
    {
        // Clang analyzer is false positive, dlist->head is updated after free
        // (Use of memory after it is freed)
        dialog = SIP_addDialog(sipMsg, dList->head, dList); // ... FIXIT-W
    }

    methodFlag = sipMsg->methodFlag;

    sip_stats.requests[TOTAL_REQUESTS]++;
    if (methodFlag > 0 && methodFlag < NUM_OF_REQUEST_TYPES)
        sip_stats.requests[methodFlag]++;

    switch (methodFlag)
    {
    case SIP_METHOD_INVITE:

        ret = SIP_processInvite(sipMsg, dialog, dList);

        break;

    case SIP_METHOD_CANCEL:

        if (nullptr == dialog)
            return false;
        /*dialog can be deleted in the early state*/
        if ((SIP_DLG_EARLY == dialog->state)||(SIP_DLG_INVITING == dialog->state)
            || (SIP_DLG_CREATE == dialog->state))
            SIP_deleteDialog(dialog, dList);

        break;

    case SIP_METHOD_ACK:

        SIP_processACK(sipMsg, dialog, dList, p, config);

        break;

    case SIP_METHOD_BYE:

        if (SIP_DLG_ESTABLISHED == dialog->state)
            dialog->state = SIP_DLG_TERMINATING;
        break;

    default:

        break;
    }
    return ret;
}

/********************************************************************
 * Function: SIP_processInvite()
 *
 *  Based on the new received sip invite request message, update the dialog information.
 *  Note: dialog is created through dialog
 * Arguments:
 *  SIPMsg *        - sip request message
 *  SIP_DialogData* - dialog to be updated,
 *   SIP_DialogList*- dialog list
 * Returns:
 *  true:
 *  false:
 ********************************************************************/
static int SIP_processInvite(SIPMsg* sipMsg, SIP_DialogData* dialog, SIP_DialogList* dList)
{
    bool ret = true;

    if (nullptr == dialog)
        return false;

    /*Check for the invite replay attack: authenticated invite without challenge*/
    // check whether this invite has authorization information
    if ((SIP_DLG_AUTHENCATING != dialog->state) && (nullptr != sipMsg->authorization))
    {
        DetectionEngine::queue_event(GID_SIP, SIP_EVENT_AUTH_INVITE_REPLAY_ATTACK);
        return false;
    }
    if (SIP_DLG_ESTABLISHED == dialog->state)
    {
        /* this is the case of re-INVITE*/
        // create a temporary new dialog before the current dialog
        dialog = SIP_addDialog(sipMsg, dialog, dList);
        dialog->state =  SIP_DLG_REINVITING;
        return true;
    }
    /*Check for the fake busy attack:  change media session before dialog established*/
    else if ((SIP_DLG_INVITING == dialog->state) || (SIP_DLG_EARLY == dialog->state)
        || (SIP_DLG_REINVITING == dialog->state)|| (SIP_DLG_AUTHENCATING == dialog->state))
    {
        ret = SIP_checkMediaChange(sipMsg, dialog);
        if (false == ret)
            DetectionEngine::queue_event(GID_SIP, SIP_EVENT_AUTH_INVITE_DIFF_SESSION);
        SIP_updateMedias(sipMsg->mediaSession, &dialog->mediaSessions);
    }
    else if (SIP_DLG_TERMINATED == dialog->state)
    {
        SIP_updateMedias(sipMsg->mediaSession, &dialog->mediaSessions);
    }
    dialog->state = SIP_DLG_INVITING;
    return ret;
}

/********************************************************************
 * Function: SIP_processACK()
 *
 *  Based on the new received sip ACK request message, update the dialog information.
 *  Note: dialog is created through dialog
 * Arguments:
 *  SIPMsg *        - sip request message
 *  SIP_DialogData* - dialog to be updated,
 *  SIP_DialogList* - dialog list
 *  Packet*  - the packet
 * Returns:
 *  true:
 *  false:
 ********************************************************************/
static int SIP_processACK(SIPMsg* sipMsg, SIP_DialogData* dialog, SIP_DialogList*, Packet* p,
    SIP_PROTO_CONF* config)
{
    if (nullptr == dialog)
        return false;

    if (SIP_DLG_ESTABLISHED == dialog->state)
    {
        if ((SIP_METHOD_INVITE == dialog->creator)&&(SIP_checkMediaChange(sipMsg, dialog) ==
            false))
        {
            SIP_updateMedias(sipMsg->mediaSession, &dialog->mediaSessions);
            SIP_ignoreChannels(dialog, p, config);
            sipMsg->mediaUpdated = true;
        }
    }
    return true;
}

/********************************************************************
 * Function: SIP_processResponse()
 *
 *  Based on the new received sip response message, update the dialog information.
 *
 * Arguments:
 *  SIPMsg *        - sip response message
 *  SIP_DialogData* - dialog to be updated,
 *  Packet*  - the packet
 *
 * Returns:
 *  true:
 *  false:
 ********************************************************************/
static int SIP_processResponse(SIPMsg* sipMsg, SIP_DialogData* dialog, SIP_DialogList* dList,
    Packet* p, SIP_PROTO_CONF* config)
{
    int statusType;
    SIP_DialogData* currDialog = dialog;

    assert (nullptr != sipMsg);

    statusType = sipMsg->status_code / 100;

    sip_stats.responses[TOTAL_RESPONSES]++;
    if (statusType < NUM_OF_RESPONSE_TYPES)
        sip_stats.responses[statusType]++;

    if (nullptr == dialog)
        return false;

    if (sipMsg->status_code > 0)
        dialog->status_code = sipMsg->status_code;

    switch (statusType)
    {
    case 0:
        break;
    case RESPONSE1XX:

        if (SIP_DLG_CREATE == currDialog->state)
            currDialog->state = SIP_DLG_EARLY;
        SIP_updateMedias(sipMsg->mediaSession, &dialog->mediaSessions);
        break;
    case RESPONSE2XX:

        if (SIP_DLG_REINVITING == currDialog->state)
        {
            SIP_deleteDialog(currDialog->nextD, dList);
            if (SIP_checkMediaChange(sipMsg, dialog) == false)
            {
                SIP_updateMedias(sipMsg->mediaSession, &dialog->mediaSessions);
                SIP_ignoreChannels(currDialog, p, config);
                sipMsg->mediaUpdated = true;
            }
            currDialog->state = SIP_DLG_ESTABLISHED;
        }
        else if (SIP_DLG_TERMINATING == currDialog->state)
        {
            SIP_deleteDialog(currDialog, dList);
            return true;
        }
        else
        {
            if ((SIP_METHOD_INVITE == currDialog->creator)&&
                (SIP_checkMediaChange(sipMsg, dialog) == false))
            {
                SIP_updateMedias(sipMsg->mediaSession, &dialog->mediaSessions);
                SIP_ignoreChannels(currDialog, p, config);
                sipMsg->mediaUpdated = true;
            }
            currDialog->state = SIP_DLG_ESTABLISHED;
        }
        break;
    case RESPONSE3XX:
    case RESPONSE4XX:
    case RESPONSE5XX:
    case RESPONSE6XX:

        // If authentication is required
        if ((401 == sipMsg->status_code) || (407 == sipMsg->status_code))
        {
            currDialog->state = SIP_DLG_AUTHENCATING;
        }
        /*Failed re-Invite will resume to the original state*/
        else if (SIP_DLG_REINVITING == currDialog->state)
        {
            SIP_deleteDialog(currDialog, dList);
        }
        else
            currDialog->state = SIP_DLG_TERMINATED;

        break;

    default:
        break;
    }

    return true;
}

/********************************************************************
 * Function: SIP_checkMediaChange()
 *
 *  Based on the new received sip invite request message, check whether SDP has been changed
 *
 * Arguments:
 *  SIPMsg *        - sip request message
 *  SIP_DialogData* - dialog to be updated,
 *
 * Returns:
 *  true: media not changed
 *  false: media changed
 ********************************************************************/
static bool SIP_checkMediaChange(SIPMsg* sipMsg, SIP_DialogData* dialog)
{
    SIP_MediaSession* medias;

    // Compare the medias (SDP part)
    if (nullptr == sipMsg->mediaSession)
        return true;

    medias = dialog->mediaSessions;
    while (nullptr != medias)
    {
        if (sipMsg->mediaSession->sessionID == medias->sessionID)
            break;
        medias = medias->nextS;
    }

    if (nullptr == medias)
    {
        // Can't find the media session by ID, SDP has been changed.
        return false;
    }
    // The media content has been changed
    if (0 != SIP_compareMedias(medias->medias, sipMsg->mediaSession->medias))
        return false;

    return true;
}

/********************************************************************
 * Function: SIP_ignoreChannels
 *
 * Ignore the channels in the current dialog: for a dialog,there will be media
 * sessions, one from each side of conversation
 *
 * Arguments:
 *  SIP_DialogData * - the current dialog
 *
 *
 * Returns:
 *   true: the channel has been ignored
 *   false: the channel has not been ignored
 *
 ********************************************************************/
static int SIP_ignoreChannels(SIP_DialogData* dialog, Packet* p, SIP_PROTO_CONF* config)
{
    SIP_MediaData* mdataA,* mdataB;

    if (0 == config->ignoreChannel)
        return false;

    // check the first media session
    if (nullptr == dialog->mediaSessions)
        return false;
    // check the second media session
    if (nullptr == dialog->mediaSessions->nextS)
        return false;

    mdataA = dialog->mediaSessions->medias;
    mdataB = dialog->mediaSessions->nextS->medias;
    sip_stats.ignoreSessions++;
    while ((nullptr != mdataA)&&(nullptr != mdataB))
    {
        //void *ssn;
        /* Call into Streams to mark data channel as something to ignore. */
        Flow* ssn = Stream::get_flow(
            PktType::UDP, IpProtocol::UDP, &mdataA->maddress,
            mdataA->mport, &mdataB->maddress, mdataB->mport,
            (p->proto_bits & PROTO_BIT__VLAN) ? layer::get_vlan_layer(p)->vid() : 0,
            (p->proto_bits & PROTO_BIT__MPLS) ? p->ptrs.mplsHdr.label : 0,
            p->pkth->address_space_id);
        if (ssn)
        {
            ssn->set_ignore_direction(SSN_DIR_BOTH);
        }
        else
        {
            Stream::ignore_flow(p, p->flow->pkt_type, p->get_ip_proto_next(), &mdataA->maddress,
                mdataA->mport, &mdataB->maddress, mdataB->mport, SSN_DIR_BOTH, SipFlowData::inspector_id);
        }
        sip_stats.ignoreChannels++;
        mdataA = mdataA->nextM;
        mdataB = mdataB->nextM;
    }
    return true;
}

/********************************************************************
 * Function: SIP_compareMedias
 *
 * Compare two media list
 *
 * Arguments:
 *  SIPMsg * - the message used to create a dialog
 *  SIP_DialogData * - the current dialog location
 *  SIP_DialogList * - the dialogs to be added.
 *
 *
 * Returns:
 *   1: not the same
 *   0: the same
 *
 ********************************************************************/
static int SIP_compareMedias(SIP_MediaDataList mlistA, SIP_MediaDataList mlistB)
{
    SIP_MediaData* mdataA,* mdataB;
    mdataA = mlistA;
    mdataB = mlistB;
    while ((nullptr != mdataA) && (nullptr != mdataB))
    {
        if (mdataA->maddress.compare(mdataB->maddress) != SFIP_EQUAL)
            break;
        if ((mdataA->mport != mdataB->mport)|| (mdataA->numPort != mdataB->numPort))
            break;
        mdataA = mdataA->nextM;
        mdataB = mdataB->nextM;
    }
    if ((nullptr == mdataA) && (nullptr == mdataB))
        return 0;
    else
        return 1;
}

/********************************************************************
 * Function: SIP_updateMedias()
 *
 *  Based on the new received media session information, update the media list.
 *  If not in the current list, created one and add it to the head.
 *
 * Arguments:
 *  SIP_MediaSession*  - media session
 *  SIP_MediaList*     - media session list to be updated,
 *
 * Returns:
 *
 ********************************************************************/
static void SIP_updateMedias(SIP_MediaSession* mSession, SIP_MediaList* dList)
{
    SIP_MediaSession* currSession, * preSession = nullptr;

    if (nullptr == mSession)
        return;
  
    mSession->savedFlag = SIP_SESSION_SAVED;
    // Find out the media session based on session id
    currSession = *dList;
    while (nullptr != currSession)
    {
        if (currSession->sessionID == mSession->sessionID)
            break;
        
        preSession = currSession;
        currSession = currSession->nextS;
    }
    // if this is a new session data, add to the list head
    if (nullptr == currSession)
    {
        mSession->nextS = *dList;
        *dList = mSession;
    }
    else
    {
        // if this session needs to be updated
        mSession->nextS = currSession->nextS;
        // if this is the header, update the new header
        if (nullptr == preSession)
            *dList = mSession;
        else
            preSession->nextS = mSession;

        // Clear the old session
        currSession->nextS = nullptr;
        sip_freeMediaSession(currSession);
    }
}

/********************************************************************
 * Function: SIP_addDialog
 *
 * Add a sip dialog before the current dialog
 *
 * Arguments:
 *  SIPMsg * - the message used to create a dialog
 *  SIP_DialogData * - the current dialog location
 *  SIP_DialogList * - the dialogs to be added.
 *
 *
 * Returns: None
 *
 ********************************************************************/
static SIP_DialogData* SIP_addDialog(SIPMsg* sipMsg, SIP_DialogData* currDialog,
    SIP_DialogList* dList)
{
    SIP_DialogData* dialog;

    sip_stats.dialogs++;
    dialog = (SIP_DialogData*)snort_calloc(sizeof(SIP_DialogData));

    // Add to the head
    dialog->nextD = currDialog;
    if (nullptr != currDialog)
    {
        dialog->prevD = currDialog->prevD;
        if (nullptr != currDialog->prevD)
            currDialog->prevD->nextD = dialog;
        else
            dList->head = dialog;  // become the head
        currDialog->prevD = dialog;
    }
    else
    {
        // The first dialog
        dialog->prevD = nullptr;
        dList->head = dialog;
    }
    dialog->dlgID = sipMsg->dlgID;
    dialog->creator = sipMsg->methodFlag;
    dialog->state = SIP_DLG_CREATE;

    SIP_updateMedias(sipMsg->mediaSession, &dialog->mediaSessions);
    dList->num_dialogs++;
    return dialog;
}

/********************************************************************
 * Function: SIP_deleteDialog
 *
 * Delete a sip dialog from the list
 *
 * Arguments:
 *  SIP_DialogData * - the current dialog to be deleted
 *  SIP_DialogList * - the dialog list.
 *
 * Returns: None
 *
 ********************************************************************/
static int SIP_deleteDialog(SIP_DialogData* currDialog, SIP_DialogList* dList)
{
    if ((nullptr == currDialog)||(nullptr == dList))
        return false;

    // If this is the header
    if (nullptr ==  currDialog->prevD)
    {
        if (nullptr != currDialog->nextD)
            currDialog->nextD->prevD = nullptr;
        dList->head = currDialog->nextD;
    }
    else
    {
        currDialog->prevD->nextD = currDialog->nextD;
        if (nullptr != currDialog->nextD)
            currDialog->nextD->prevD = currDialog->prevD;
    }
    sip_freeMediaList(currDialog->mediaSessions);
    snort_free(currDialog);
    if ( dList->num_dialogs > 0)
        dList->num_dialogs--;
    return true;
}

static void sip_publish_data_bus(
    const Packet* p, const SIPMsg* sip_msg, const SIP_DialogData* dialog)
{
    SipEvent event(p, sip_msg, dialog);
    DataBus::publish(SIP_EVENT_TYPE_SIP_DIALOG_KEY, event, p->flow);
}

/********************************************************************
 * Function: SIP_updateDialog()
 *
 *  Based on the new received sip message, update the dialog information.
 *  If not in the current list, created one and add it to the head.
 *
 * Arguments:
 *  SIPMsg *        - sip message
 *  SIP_DialogList* - dialog list to be updated,
 *
 * Returns:
 *  true: dialog has been updated
 *  false: dialog has not been updated
 ********************************************************************/
int SIP_updateDialog(SIPMsg* sipMsg, SIP_DialogList* dList, Packet* p, SIP_PROTO_CONF* config)
{
    SIP_DialogData* dialog;
    SIP_DialogData* oldDialog = nullptr;
    int ret;

    if ((nullptr == sipMsg)||(0 == sipMsg->dlgID.callIdHash))
        return false;

    dialog = dList->head;

    /*Find out the dialog in the dialog list*/

    while (nullptr != dialog)
    {
        if (sipMsg->dlgID.callIdHash == dialog->dlgID.callIdHash)
            break;
        
        oldDialog = dialog;
        dialog = dialog->nextD;
    }

    /*If the number of dialogs exceeded, release the oldest one*/
    if ((dList->num_dialogs >= config->maxNumDialogsInSession) && (!dialog))
    {
        DetectionEngine::queue_event(GID_SIP, SIP_EVENT_MAX_DIALOGS_IN_A_SESSION);
        SIP_deleteDialog(oldDialog, dList);
    }

    /*Update the  dialog information*/

    if (sipMsg->status_code == 0)
        ret = SIP_processRequest(sipMsg, dialog, dList, p, config);
    else if (sipMsg->status_code > 0)
        ret = SIP_processResponse(sipMsg, dialog, dList, p, config);
    else
        ret = false;

    for (dialog = dList->head; dialog; dialog = dialog->nextD)
    {
        if (sipMsg->dlgID.callIdHash == dialog->dlgID.callIdHash)
            break;
    }
    sip_publish_data_bus(p, sipMsg, dialog);

    return ret;
}

/********************************************************************
 * Function: sip_freeDialogs
 *
 * Frees a sip dialog
 *
 * Arguments:
 *  SIP_DialogList
 *      The dialogs to free.
 *
 * Returns: None
 *
 ********************************************************************/
void sip_freeDialogs(SIP_DialogList* list)
{
    SIP_DialogData* nextNode;
    SIP_DialogData* curNode = list->head;

    while (nullptr != curNode)
    {
        nextNode = curNode->nextD;
        sip_freeMediaList(curNode->mediaSessions);
        snort_free(curNode);
        curNode = nextNode;
    }
}


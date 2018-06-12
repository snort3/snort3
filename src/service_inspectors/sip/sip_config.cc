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

// sip_config.cc author Hui Cao <huica@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sip_config.h"

#include "log/messages.h"
#include "main/snort_debug.h"
#include "utils/util.h"

using namespace snort;

#define SIP_SEPERATORS       "()<>@,;:\\/[]?={}\" "

static SIPMethodNode* SIP_AddMethodToList(
    const char* methodName, SIPMethodsFlag methodConf, SIPMethodlist* p_methodList);

/*
 *  method names defined by standard, 14 methods defined up to Mar. 2011
 *  The first 6 methods are standard defined by RFC3261
 */

SIPMethod StandardMethods[] =
{
    { "invite", SIP_METHOD_INVITE },
    { "cancel",SIP_METHOD_CANCEL },
    { "ack", SIP_METHOD_ACK },
    { "bye", SIP_METHOD_BYE },
    { "register", SIP_METHOD_REGISTER },
    { "options",SIP_METHOD_OPTIONS },
    { "refer", SIP_METHOD_REFER },
    { "subscribe", SIP_METHOD_SUBSCRIBE },
    { "update", SIP_METHOD_UPDATE },
    { "join", SIP_METHOD_JOIN },
    { "info", SIP_METHOD_INFO },
    { "message", SIP_METHOD_MESSAGE },
    { "notify", SIP_METHOD_NOTIFY },
    { "prack", SIP_METHOD_PRACK },
    { nullptr, SIP_METHOD_NULL }
};

static SIPMethodsFlag currentUseDefineMethod = SIP_METHOD_USER_DEFINE;

static int SIP_findMethod(const char* token, SIPMethod* methods)
{
    int i = 0;
    while (nullptr != methods[i].name)
    {
        if ((strlen(token) == strlen(methods[i].name))&&
            (strncasecmp(methods[i].name, token, strlen(token)) == 0))
            return i;
        i++;
    }
    return METHOD_NOT_FOUND;
}

/*
 *  The first 6 methods are standard defined by RFC3261
 *  We use those first 6 methods as default
 *
 */
void SIP_SetDefaultMethods(SIP_PROTO_CONF* config)
{
    int i;
    config->methodsConfig = SIP_METHOD_DEFAULT;
    for (i = 0; i < 6; i++)
    {
        if (SIP_AddMethodToList(StandardMethods[i].name,
            StandardMethods[i].methodFlag, &config->methods) == nullptr)
        {
            FatalError("Failed to add SIP default method: %s.\n", StandardMethods[i].name);
        }
    }
}

/********************************************************************
 * Function: SIP_ParseMethods()
 *
 * Parses the methods to detect
 *
 *
 * Arguments:
 *  char **
 *      Pointer to the pointer to the current position in the
 *      configuration line.  This is updated to the current position
 *      after parsing the methods list.
 *  SIPMethods*
 *      Flag for the methods.
 *      NULL flag if not a valid method type
 * Returns:
 *
 ********************************************************************/
void SIP_ParseMethods(const char* cur_tokenp, uint32_t* methodsConfig, SIPMethodlist* pmethods)
{
    int i_method;

    /* If the user specified methods, remove default methods for now since
     * it now needs to be set explicitly. */
    *methodsConfig =  SIP_METHOD_NULL;
    // Check whether this is a standard method

    i_method = SIP_findMethod(cur_tokenp, StandardMethods);
    if (METHOD_NOT_FOUND != i_method )
    {
        *methodsConfig |= 1 << (StandardMethods[i_method].methodFlag - 1);
        if (SIP_AddMethodToList(cur_tokenp,
            StandardMethods[i_method].methodFlag, pmethods) == nullptr)
        {
            ParseError("Failed to add SIP method: %s.", cur_tokenp);
        }
    }
    else
    {
        if (SIP_AddUserDefinedMethod(cur_tokenp, methodsConfig, pmethods) == nullptr)
        {
            ParseError("Failed to add user defined SIP method: %s.", cur_tokenp);
        }
    }
}

static SIPMethodNode* SIP_AddMethodToList(
    const char* methodName, SIPMethodsFlag methodConf, SIPMethodlist* p_methodList)
{
    if ( !methodName )
        return nullptr;

    int methodLen = strlen(methodName);
    SIPMethodNode* method = *p_methodList;
    SIPMethodNode* lastMethod = *p_methodList;

    while (method)
    {
        // Already in the list, return
        if ( !strcasecmp(method->methodName, methodName) )
            return method;

        lastMethod = method;
        method =  method->nextm;
    }

    method = (SIPMethodNode*)snort_calloc(sizeof(*method));
    method->methodName = snort_strdup(methodName);
    method->methodLen = methodLen;
    method->methodFlag = methodConf;
    method->nextm = nullptr;

    // The first method, point to the first created one
    if ( !*p_methodList )
        *p_methodList =  method;

    else
        lastMethod->nextm = method;

    return method;
}

/********************************************************************
 * Function: SIP_AddUserDefinedMethod
 *
 * Add a user defined method
 *
 * Arguments:
 *  char *: the method name
 *  SIPMethodlist *: the list to be added
 *
 * Returns: user defined method
 *
 ********************************************************************/
SIPMethodNode* SIP_AddUserDefinedMethod(
    const char* methodName, uint32_t* methodsConfig, SIPMethodlist* pmethods)
{
    int i = 0;
    SIPMethodNode* method;

    /*Check whether all the chars are defined by RFC2616*/
    while (methodName[i])
    {
        if (iscntrl(methodName[i])|(nullptr != strchr(SIP_SEPERATORS,methodName[i]))| (methodName[i] <
            0) )
        {
            ParseError("Bad character included in the User defined method \n");
            return nullptr;
        }
        i++;
    }
    if (currentUseDefineMethod > SIP_METHOD_USER_DEFINE_MAX)
    {
        ParseError("Exceeded max number of user defined methods \n");
        return nullptr;
    }
    *methodsConfig |= 1 << (currentUseDefineMethod - 1);
    method = SIP_AddMethodToList(methodName, currentUseDefineMethod, pmethods);
    currentUseDefineMethod = (SIPMethodsFlag)(currentUseDefineMethod + 1);
    return method;
}

void SIP_DeleteMethods(SIPMethodNode* node)
{
    while (node)
    {
        SIPMethodNode* next = node->nextm;
        snort_free(node->methodName);
        snort_free(node);
        node = next;
    }
}


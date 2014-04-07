/*
** Copyright (C) 2006-2013 Sourcefire, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

/*
 * Author: Steven Sturges
 * sf_attribute_table.y
 */

/*
 *
 * AttributeTable
 *
 * YACC Grammar/language definition
 */

%{
#include <stdio.h>  /* for snprintf() on os x */
#include <stdlib.h>
#include <string.h>
#include "sftarget_data.h"

/*#include "snort_debug.h" FIXIT */
#define DEBUG_WRAP(x)  /* FIXIT */

#define YYSTACK_USE_ALLOCA 0

/* define the initial stack-sizes */

#ifdef YYMAXDEPTH
#undef YYMAXDEPTH
#define YYMAXDEPTH  70000
#else
#define YYMAXDEPTH  70000
#endif

extern ServiceClient sfat_client_or_service;
extern char *sfat_grammar_error;

extern int sfat_lex();
extern void sfat_error(char*);

static inline char* string_copy (char* dest, const char* src, size_t n)
{
    strncpy(dest, src, n);
    dest[n-1] = '\0';
    return dest;
}
%}

%union
{
  char stringValue[SFAT_BUFSZ];
  uint32_t numericValue;
  AttributeData data;
  MapData mapEntry;
}

%token SF_AT_COMMENT
%token SF_AT_WHITESPACE

%token SF_START_SNORT_ATTRIBUTES
%token SF_END_SNORT_ATTRIBUTES

%token SF_AT_START_MAP_TABLE
%token SF_AT_END_MAP_TABLE
%token SF_AT_START_ENTRY
%token SF_AT_END_ENTRY
%token SF_AT_START_ENTRY_ID
%token SF_AT_END_ENTRY_ID
%token SF_AT_START_ENTRY_VALUE
%token SF_AT_END_ENTRY_VALUE

%token SF_AT_START_ATTRIBUTE_TABLE
%token SF_AT_END_ATTRIBUTE_TABLE
%token SF_AT_START_HOST
%token SF_AT_END_HOST
%token SF_AT_START_HOST_IP
%token SF_AT_END_HOST_IP
%token <stringValue>  SF_AT_STRING
%token <numericValue> SF_AT_NUMERIC
/*
%token <stringValue> SF_AT_IPv4
%token <stringValue> SF_AT_IPv4CIDR
*/
%token SF_AT_IPv6
%token SF_AT_IPv6Cidr
%token SF_AT_START_OS
%token SF_AT_END_OS
%token SF_AT_START_ATTRIBUTE_VALUE
%token SF_AT_END_ATTRIBUTE_VALUE
%token SF_AT_START_ATTRIBUTE_ID
%token SF_AT_END_ATTRIBUTE_ID
%token SF_AT_START_CONFIDENCE
%token SF_AT_END_CONFIDENCE
%token SF_AT_START_NAME
%token SF_AT_END_NAME
%token SF_AT_START_VENDOR
%token SF_AT_END_VENDOR
%token SF_AT_START_VERSION
%token SF_AT_END_VERSION
%token SF_AT_START_FRAG_POLICY
%token SF_AT_END_FRAG_POLICY
%token SF_AT_START_STREAM_POLICY
%token SF_AT_END_STREAM_POLICY
%token SF_AT_START_SERVICES
%token SF_AT_END_SERVICES
%token SF_AT_START_SERVICE
%token SF_AT_END_SERVICE
%token SF_AT_START_CLIENTS
%token SF_AT_END_CLIENTS
%token SF_AT_START_CLIENT
%token SF_AT_END_CLIENT
%token SF_AT_START_IPPROTO
%token SF_AT_END_IPPROTO
%token SF_AT_START_PORT
%token SF_AT_END_PORT
%token SF_AT_START_PROTOCOL
%token SF_AT_END_PROTOCOL
%token SF_AT_START_APPLICATION
%token SF_AT_END_APPLICATION

%type <mapEntry> MapEntryData
%type <data> AttributeInfo
%type <stringValue> MapValue
%type <numericValue> MapId
%type <stringValue> AttributeValueString
%type <numericValue> AttributeValueNumber
%type <numericValue> AttributeConfidence
%type <numericValue> AttributeId

%%  /*  Grammar rules and actions follow  */

/* The Main Grammar... Either a mapping table and attribute table,
 * or just the attribute table by itself. */
AttributeGrammar:
  SnortAttributes
  {
    YYACCEPT;
  };

SnortAttributes:
  SF_START_SNORT_ATTRIBUTES MappingTable AttributeTable SF_END_SNORT_ATTRIBUTES
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "SnortAttributes: Got Attribute Map & Table\n"););
  }
  |
  SF_START_SNORT_ATTRIBUTES AttributeTable SF_END_SNORT_ATTRIBUTES
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "SnortAttributes: Got Attribute Table\n"););
  };

/* The name-id map table for data reduction */
MappingTable:
  SF_AT_START_MAP_TABLE ListOfMapEntries SF_AT_END_MAP_TABLE
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Got Attribute Map\n"););
  };

ListOfMapEntries:
   {
     DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Empty Mapping Table\n"););
   }
   | MapEntry ListOfMapEntries;

MapEntry:
  MapEntryStart MapEntryData MapEntryEnd
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "MapEntry: Name: %s, Id %d\n",
        $2.s_mapvalue, $2.l_mapid););
    SFAT_AddMapEntry(&$2);
  };

MapEntryStart:
  SF_AT_START_ENTRY;

MapEntryEnd:
  SF_AT_END_ENTRY;

MapEntryData:
  MapId MapValue
  {
    $$.l_mapid = $1;
    string_copy($$.s_mapvalue, $2, SFAT_BUFSZ);
  };

MapValue:
  SF_AT_START_ENTRY_VALUE SF_AT_STRING SF_AT_END_ENTRY_VALUE
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "MapValue: %s\n", $2);)
    string_copy($$, $2, SFAT_BUFSZ);
  };

MapId:
  SF_AT_START_ENTRY_ID SF_AT_NUMERIC SF_AT_END_ENTRY_ID
  {
    $$ = $2;
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "MapId: %d\n", $2););
  };

/* The table of hosts and their respective attributes */
AttributeTable:
  SF_AT_START_ATTRIBUTE_TABLE ListOfHosts SF_AT_END_ATTRIBUTE_TABLE
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Got Attribute Table\n"););
  };

ListOfHosts:
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "EmptyHostEntry\n"););
  }
  | ListOfHosts HostEntry;

HostEntry:
  HostEntryStart HostEntryData HostEntryEnd
  {
    if (SFAT_AddHostEntryToMap() != SFAT_OK)
    {
        YYABORT;
    }
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Host Added\n"););
  };

HostEntryStart:
  SF_AT_START_HOST
  {
    /* Callback to create a host entry object */
    SFAT_CreateHostEntry();
  };

HostEntryEnd:
  SF_AT_END_HOST;

HostEntryData:
  IpCidr HostOS ServiceList ClientList
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "HostEntryData\n"););
  }
  |
  IpCidr HostOS ClientList
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "HostEntryData: No Services\n"););
  }
  |
  IpCidr HostOS ServiceList
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "HostEntryData: No Clients\n"););
  }
  |
  IpCidr HostOS
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "HostEntryData: No Services or Clients\n"););
  }
  ;

IpCidr:
  SF_AT_START_HOST_IP SF_AT_STRING SF_AT_END_HOST_IP
  {
    /* Convert IP/CIDR to Snort IPCidr Object */
    /* determine the number of bits (done in SetHostIp4) */
    if (SFAT_SetHostIp($2) != SFAT_OK)
    {
        YYABORT;
    }
  };

HostOS:
  SF_AT_START_OS OSAttributes SF_AT_END_OS;
  
OSAttributes: OSAttribute | OSAttributes OSAttribute;

OSAttribute: OSName | OSVendor | OSVersion | OSStreamPolicy | OSFragPolicy;

OSName:
  SF_AT_START_NAME AttributeInfo SF_AT_END_NAME
  {
    /* Copy OSName */
    DEBUG_WRAP(PrintAttributeData("OS:Name", &$2););
    SFAT_SetOSAttribute(&$2, HOST_INFO_OS);
  };

OSVendor:
  SF_AT_START_VENDOR AttributeInfo SF_AT_END_VENDOR
  {
    /* Copy OSVendor */
    DEBUG_WRAP(PrintAttributeData("OS:Vendor", &$2););
    SFAT_SetOSAttribute(&$2, HOST_INFO_VENDOR);
  };

OSVersion:
  SF_AT_START_VERSION AttributeInfo SF_AT_END_VERSION
  {
    /* Copy OSVersion */
    DEBUG_WRAP(PrintAttributeData("OS:Version", &$2););
    SFAT_SetOSAttribute(&$2, HOST_INFO_VERSION);
  };

OSFragPolicy:
  SF_AT_START_FRAG_POLICY SF_AT_STRING SF_AT_END_FRAG_POLICY
  {
    /* Copy OSFragPolicy */
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "OS:FragPolicy: %s\n", $2););
    SFAT_SetOSPolicy($2, HOST_INFO_FRAG_POLICY);
  };

OSStreamPolicy:
  SF_AT_START_STREAM_POLICY SF_AT_STRING SF_AT_END_STREAM_POLICY
  {
    /* Copy OSStreamPolicy */
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "OS:StreamPolicy: %s\n", $2););
    SFAT_SetOSPolicy($2, HOST_INFO_STREAM_POLICY);
  };

AttributeInfo:
  AttributeValueString
  {
        $$.type = ATTRIBUTE_NAME; 
        $$.confidence = 100;
        string_copy($$.value.s_value, $1, SFAT_BUFSZ);
  }
  | AttributeValueString AttributeConfidence
  {
        $$.type = ATTRIBUTE_NAME; 
        $$.confidence = $2;
        string_copy($$.value.s_value, $1, SFAT_BUFSZ);
  }
  | AttributeValueNumber AttributeConfidence
  {
        $$.type = ATTRIBUTE_NAME; 
        $$.confidence = $2;
        snprintf($$.value.s_value, SFAT_BUFSZ, "%d", $1);
        $$.value.s_value[SFAT_BUFSZ-1] = '\0';
  }
  | AttributeValueNumber
  {
        $$.type = ATTRIBUTE_NAME; 
        $$.confidence = 100;
        snprintf($$.value.s_value, SFAT_BUFSZ, "%d", $1);
        $$.value.s_value[SFAT_BUFSZ-1] = '\0';
  }
  | AttributeId AttributeConfidence
  {
        char *mapped_name;
        $$.confidence = $2;
        mapped_name = SFAT_LookupAttributeNameById($1);
        if (!mapped_name)
        {
            $$.type = ATTRIBUTE_ID; 
            $$.value.l_value = $1;
            /*FatalError("Unknown/Invalid Attribute ID %d\n", $1); */
            sfat_grammar_error = "Unknown/Invalid Attribute ID";
            YYABORT;
        }
        else
        {
            /* Copy String */
            $$.type = ATTRIBUTE_NAME; 
            string_copy($$.value.s_value, mapped_name, SFAT_BUFSZ);
        }
  }
  | AttributeId 
  {
        char *mapped_name;
        $$.confidence = 100;
        mapped_name = SFAT_LookupAttributeNameById($1);
        if (!mapped_name)
        {
            $$.type = ATTRIBUTE_ID; 
            $$.value.l_value = $1;
            /*FatalError("Unknown/Invalid Attribute ID %d\n", $1); */
            sfat_grammar_error = "Unknown/Invalid Attribute ID";
            YYABORT;
        }
        else
        {
            /* Copy String */
            $$.type = ATTRIBUTE_NAME; 
            string_copy($$.value.s_value, mapped_name, SFAT_BUFSZ);
        }
  };

AttributeValueString:
  SF_AT_START_ATTRIBUTE_VALUE SF_AT_STRING SF_AT_END_ATTRIBUTE_VALUE
  {
        string_copy($$, $2, SFAT_BUFSZ);
  };

AttributeValueNumber:
  SF_AT_START_ATTRIBUTE_VALUE  SF_AT_END_ATTRIBUTE_VALUE
  {
        $$ = 0;
  }
  | SF_AT_START_ATTRIBUTE_VALUE SF_AT_NUMERIC SF_AT_END_ATTRIBUTE_VALUE
  {
        $$ = $2;
  };
  
AttributeId:
  SF_AT_START_ATTRIBUTE_ID SF_AT_NUMERIC SF_AT_END_ATTRIBUTE_ID
      {
        /* Copy numeric */
        $$ = $2;
      };

AttributeConfidence:
  SF_AT_START_CONFIDENCE SF_AT_NUMERIC SF_AT_END_CONFIDENCE
  {
    /* Copy numeric */
    $$ = $2;
  };

ServiceList:
  ServiceListStart ServiceListData ServiceListEnd 
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "ServiceList (complete)\n"););
  };

ServiceListStart:
  SF_AT_START_SERVICES
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Start ServiceList\n"););
    sfat_client_or_service = ATTRIBUTE_SERVICE;
  };

ServiceListEnd:
  SF_AT_END_SERVICES
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "End ServiceList\n"););
  };
  
ServiceListData:
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "EmptyService\n"););
  }
  | Service ServiceListData
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Service ServiceListData\n"););
  };

Service:
  ServiceStart ServiceData ServiceEnd
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Service Adding Complete\n"););
    SFAT_AddApplicationData();
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Service Added\n"););
  };

ServiceStart:
  SF_AT_START_SERVICE
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Service Start\n"););
    SFAT_CreateApplicationEntry();
  };

ServiceEnd:
  SF_AT_END_SERVICE
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Service End\n"););
  };

ServiceData:
  ServiceDataRequired
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Service Data (no application)\n"););
  }
  | ServiceDataRequired Application
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Service Data (application)\n"););
  };

ServiceDataRequired:
  IPProtocol Protocol Port
  {
    /* Order independent */
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Service Data Required (IPProto Proto Port)\n"););
  }
  | IPProtocol Port Protocol
  {
    /* Order independent */
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Service Data Required (IPProto Port Proto)\n"););
  }
  | Protocol IPProtocol Port
  {
    /* Order independent */
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Service Data Required (Proto IPProto Port)\n"););
  }
  | Protocol Port IPProtocol
  {
    /* Order independent */
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Service Data Required (Proto Port IPProto)\n"););
  }
  | Port Protocol IPProtocol
  {
    /* Order independent */
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Service Data Required (Port Proto IPProto)\n"););
  }
  | Port IPProtocol Protocol
  {
    /* Order independent */
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Service Data Required (Port IPProto Proto)\n"););
  };

IPProtocol:
  SF_AT_START_IPPROTO AttributeInfo SF_AT_END_IPPROTO
  {
    /* Store IPProto Info */
    DEBUG_WRAP(PrintAttributeData("IPProto", &$2););
    SFAT_SetApplicationAttribute(&$2, APPLICATION_ENTRY_IPPROTO);
  };

Protocol:
  SF_AT_START_PROTOCOL AttributeInfo SF_AT_END_PROTOCOL
  {
    /* Store Protocol Info */
    DEBUG_WRAP(PrintAttributeData("Protocol", &$2););
    SFAT_SetApplicationAttribute(&$2, APPLICATION_ENTRY_PROTO);
  };

Port:
  SF_AT_START_PORT AttributeInfo SF_AT_END_PORT
  {
    /* Store Port Info */
    DEBUG_WRAP(PrintAttributeData("Port", &$2););
    SFAT_SetApplicationAttribute(&$2, APPLICATION_ENTRY_PORT);
  };

Application:
  SF_AT_START_APPLICATION AttributeInfo SF_AT_END_APPLICATION
  {
    /* Store Application Info */
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Application\n"));
    DEBUG_WRAP(PrintAttributeData("Application", &$2););
    SFAT_SetApplicationAttribute(&$2, APPLICATION_ENTRY_APPLICATION);
  }
  | SF_AT_START_APPLICATION AttributeInfo Version SF_AT_END_APPLICATION
  {
    /* Store Application Info */
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Application with Version\n"));
    DEBUG_WRAP(PrintAttributeData("Application", &$2););
    SFAT_SetApplicationAttribute(&$2, APPLICATION_ENTRY_APPLICATION);
  };

Version:
  SF_AT_START_VERSION AttributeInfo SF_AT_END_VERSION
  {
    /* Store Version Info */
    DEBUG_WRAP(PrintAttributeData("Version", &$2););
    SFAT_SetApplicationAttribute(&$2, APPLICATION_ENTRY_VERSION);
  };

ClientList:
  ClientListStart ClientListData ClientListEnd
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "ClientList (complete)\n"););
  };

ClientListStart:
  SF_AT_START_CLIENTS
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Start ClientList\n"););
    sfat_client_or_service = ATTRIBUTE_CLIENT;
  };

ClientListEnd:
  SF_AT_END_CLIENTS
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "End ClientList\n"););
  };

ClientListData:
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "EmptyClient\n"););
  }
  | Client ClientListData
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Client ClientListData\n"););
  };

Client:
  ClientStart ClientData ClientEnd
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Client Adding Complete\n"););
    SFAT_AddApplicationData();
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Client Added\n"););
  };

ClientStart:
  SF_AT_START_CLIENT
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Client Start\n"););
    SFAT_CreateApplicationEntry();
  };

ClientEnd:
  SF_AT_END_CLIENT
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Client End\n"););
  };

ClientData:
  ClientDataRequired
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Client Data (no application)\n"););
  }
  | ClientDataRequired Application
  {
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Client Data (application)\n"););
  };

ClientDataRequired:
  Protocol
  {
    /* Order independent */
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Client Data Required (Proto)\n"););
  }
  | IPProtocol Protocol
  {
    /* Order independent */
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Client Data Required (IPProto Proto)\n"););
  }
  | Protocol IPProtocol
  {
    /* Order independent */
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Client Data Required (Proto IPProto)\n"););
  };

%%
/*
int yywrap(void)
{
    return 1;
}
*/


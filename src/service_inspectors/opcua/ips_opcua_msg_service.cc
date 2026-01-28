//--------------------------------------------------------------------------
// Copyright (C) 2025-2026 Cisco and/or its affiliates. All rights reserved.
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

// ips_opcua_msg_service.cc author Jared Rittle <jared.rittle@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hash_key_operations.h"
#include "protocols/packet.h"
#include "profiler/profiler.h"

#include "opcua_session.h"

using namespace snort;

static const char* s_name = "opcua_msg_service";

//-------------------------------------------------------------------------
// msg_service lookup
//-------------------------------------------------------------------------

struct OpcuaMsgServiceMap
{
    const char* name;
    OpcuaMsgServiceType type;
};

static OpcuaMsgServiceMap opcua_msg_service_map[] =
{
    { "DataTypeDefinition", OPCUA_MSG_SERVICE_DATA_TYPE_DEFINITION },
    { "StructureDefinition", OPCUA_MSG_SERVICE_STRUCTURE_DEFINITION },
    { "EnumDefinition", OPCUA_MSG_SERVICE_ENUM_DEFINITION },
    { "DataSetMetaDataType", OPCUA_MSG_SERVICE_DATA_SET_META_DATA_TYPE },
    { "DataTypeDescription", OPCUA_MSG_SERVICE_DATA_TYPE_DESCRIPTION },
    { "StructureDescription", OPCUA_MSG_SERVICE_STRUCTURE_DESCRIPTION },
    { "EnumDescription", OPCUA_MSG_SERVICE_ENUM_DESCRIPTION },
    { "RolePermissionType", OPCUA_MSG_SERVICE_ROLE_PERMISSION_TYPE },
    { "Node", OPCUA_MSG_SERVICE_NODE },
    { "ObjectNode", OPCUA_MSG_SERVICE_OBJECT_NODE },
    { "ObjectTypeNode", OPCUA_MSG_SERVICE_OBJECT_TYPE_NODE },
    { "VariableNode", OPCUA_MSG_SERVICE_VARIABLE_NODE },
    { "VariableTypeNode", OPCUA_MSG_SERVICE_VARIABLE_TYPE_NODE },
    { "ReferenceTypeNode", OPCUA_MSG_SERVICE_REFERENCE_TYPE_NODE },
    { "MethodNode", OPCUA_MSG_SERVICE_METHOD_NODE },
    { "ViewNode", OPCUA_MSG_SERVICE_VIEW_NODE },
    { "DataTypeNode", OPCUA_MSG_SERVICE_DATA_TYPE_NODE },
    { "ReferenceNode", OPCUA_MSG_SERVICE_REFERENCE_NODE },
    { "Argument", OPCUA_MSG_SERVICE_ARGUMENT },
    { "StatusResult", OPCUA_MSG_SERVICE_STATUS_RESULT },
    { "UserTokenPolicy", OPCUA_MSG_SERVICE_USER_TOKEN_POLICY },
    { "ApplicationDescription", OPCUA_MSG_SERVICE_APPLICATION_DESCRIPTION },
    { "EndpointDescription", OPCUA_MSG_SERVICE_ENDPOINT_DESCRIPTION },
    { "UserIdentityToken", OPCUA_MSG_SERVICE_USER_IDENTITY_TOKEN },
    { "AnonymousIdentityToken", OPCUA_MSG_SERVICE_ANONYMOUS_IDENTITY_TOKEN },
    { "UserNameIdentityToken", OPCUA_MSG_SERVICE_USER_NAME_IDENTITY_TOKEN },
    { "X509IdentityToken", OPCUA_MSG_SERVICE_X509_IDENTITY_TOKEN },
    { "EndpointConfiguration", OPCUA_MSG_SERVICE_ENDPOINT_CONFIGURATION },
    { "BuildInfo", OPCUA_MSG_SERVICE_BUILD_INFO },
    { "SignedSoftwareCertificate", OPCUA_MSG_SERVICE_SIGNED_SOFTWARE_CERTIFICATE },
    { "NodeAttributes", OPCUA_MSG_SERVICE_NODE_ATTRIBUTES },
    { "ObjectAttributes", OPCUA_MSG_SERVICE_OBJECT_ATTRIBUTES },
    { "VariableAttributes", OPCUA_MSG_SERVICE_VARIABLE_ATTRIBUTES },
    { "MethodAttributes", OPCUA_MSG_SERVICE_METHOD_ATTRIBUTES },
    { "ObjectTypeAttributes", OPCUA_MSG_SERVICE_OBJECT_TYPE_ATTRIBUTES },
    { "VariableTypeAttributes", OPCUA_MSG_SERVICE_VARIABLE_TYPE_ATTRIBUTES },
    { "ReferenceTypeAttributes", OPCUA_MSG_SERVICE_REFERENCE_TYPE_ATTRIBUTES },
    { "DataTypeAttributes", OPCUA_MSG_SERVICE_DATA_TYPE_ATTRIBUTES },
    { "ViewAttributes", OPCUA_MSG_SERVICE_VIEW_ATTRIBUTES },
    { "AddNodesItem", OPCUA_MSG_SERVICE_ADD_NODES_ITEM },
    { "AddReferencesItem", OPCUA_MSG_SERVICE_ADD_REFERENCES_ITEM },
    { "DeleteNodesItem", OPCUA_MSG_SERVICE_DELETE_NODES_ITEM },
    { "DeleteReferencesItem", OPCUA_MSG_SERVICE_DELETE_REFERENCES_ITEM },
    { "RequestHeader", OPCUA_MSG_SERVICE_REQUEST_HEADER },
    { "ResponseHeader", OPCUA_MSG_SERVICE_RESPONSE_HEADER },
    { "ServiceFault", OPCUA_MSG_SERVICE_SERVICE_FAULT },
    { "FindServersRequest", OPCUA_MSG_SERVICE_FIND_SERVERS_REQUEST },
    { "FindServersResponse", OPCUA_MSG_SERVICE_FIND_SERVERS_RESPONSE },
    { "GetEndpointsRequest", OPCUA_MSG_SERVICE_GET_ENDPOINTS_REQUEST },
    { "GetEndpointsResponse", OPCUA_MSG_SERVICE_GET_ENDPOINTS_RESPONSE },
    { "RegisteredServer", OPCUA_MSG_SERVICE_REGISTERED_SERVER },
    { "RegisterServerRequest", OPCUA_MSG_SERVICE_REGISTER_SERVER_REQUEST },
    { "RegisterServerResponse", OPCUA_MSG_SERVICE_REGISTER_SERVER_RESPONSE },
    { "ChannelSecurityToken", OPCUA_MSG_SERVICE_CHANNEL_SECURITY_TOKEN },
    { "OpenSecureChannelRequest", OPCUA_MSG_SERVICE_OPEN_SECURE_CHANNEL_REQUEST },
    { "OpenSecureChannelResponse", OPCUA_MSG_SERVICE_OPEN_SECURE_CHANNEL_RESPONSE },
    { "CloseSecureChannelRequest", OPCUA_MSG_SERVICE_CLOSE_SECURE_CHANNEL_REQUEST },
    { "CloseSecureChannelResponse", OPCUA_MSG_SERVICE_CLOSE_SECURE_CHANNEL_RESPONSE },
    { "SignatureData", OPCUA_MSG_SERVICE_SIGNATURE_DATA },
    { "CreateSessionRequest", OPCUA_MSG_SERVICE_CREATE_SESSION_REQUEST },
    { "CreateSessionResponse", OPCUA_MSG_SERVICE_CREATE_SESSION_RESPONSE },
    { "ActivateSessionRequest", OPCUA_MSG_SERVICE_ACTIVATE_SESSION_REQUEST },
    { "ActivateSessionResponse", OPCUA_MSG_SERVICE_ACTIVATE_SESSION_RESPONSE },
    { "CloseSessionRequest", OPCUA_MSG_SERVICE_CLOSE_SESSION_REQUEST },
    { "CloseSessionResponse", OPCUA_MSG_SERVICE_CLOSE_SESSION_RESPONSE },
    { "CancelRequest", OPCUA_MSG_SERVICE_CANCEL_REQUEST },
    { "CancelResponse", OPCUA_MSG_SERVICE_CANCEL_RESPONSE },
    { "AddNodesResult", OPCUA_MSG_SERVICE_ADD_NODES_RESULT },
    { "AddNodesRequest", OPCUA_MSG_SERVICE_ADD_NODES_REQUEST },
    { "AddNodesResponse", OPCUA_MSG_SERVICE_ADD_NODES_RESPONSE },
    { "AddReferencesRequest", OPCUA_MSG_SERVICE_ADD_REFERENCES_REQUEST },
    { "AddReferencesResponse", OPCUA_MSG_SERVICE_ADD_REFERENCES_RESPONSE },
    { "DeleteNodesRequest", OPCUA_MSG_SERVICE_DELETE_NODES_REQUEST },
    { "DeleteNodesResponse", OPCUA_MSG_SERVICE_DELETE_NODES_RESPONSE },
    { "DeleteReferencesRequest", OPCUA_MSG_SERVICE_DELETE_REFERENCES_REQUEST },
    { "DeleteReferencesResponse", OPCUA_MSG_SERVICE_DELETE_REFERENCES_RESPONSE },
    { "ViewDescription", OPCUA_MSG_SERVICE_VIEW_DESCRIPTION },
    { "BrowseDescription", OPCUA_MSG_SERVICE_BROWSE_DESCRIPTION },
    { "ReferenceDescription", OPCUA_MSG_SERVICE_REFERENCE_DESCRIPTION },
    { "BrowseResult", OPCUA_MSG_SERVICE_BROWSE_RESULT },
    { "BrowseRequest", OPCUA_MSG_SERVICE_BROWSE_REQUEST },
    { "BrowseResponse", OPCUA_MSG_SERVICE_BROWSE_RESPONSE },
    { "BrowseNextRequest", OPCUA_MSG_SERVICE_BROWSE_NEXT_REQUEST },
    { "BrowseNextResponse", OPCUA_MSG_SERVICE_BROWSE_NEXT_RESPONSE },
    { "RelativePathElement", OPCUA_MSG_SERVICE_RELATIVE_PATH_ELEMENT },
    { "RelativePath", OPCUA_MSG_SERVICE_RELATIVE_PATH },
    { "BrowsePath", OPCUA_MSG_SERVICE_BROWSE_PATH },
    { "BrowsePathTarget", OPCUA_MSG_SERVICE_BROWSE_PATH_TARGET },
    { "BrowsePathResult", OPCUA_MSG_SERVICE_BROWSE_PATH_RESULT },
    { "TranslateBrowsePathsToNodeIdsRequest", OPCUA_MSG_SERVICE_TRANSLATE_BROWSE_PATHS_TO_NODE_IDS_REQUEST },
    { "TranslateBrowsePathsToNodeIdsResponse", OPCUA_MSG_SERVICE_TRANSLATE_BROWSE_PATHS_TO_NODE_IDS_RESPONSE },
    { "RegisterNodesRequest", OPCUA_MSG_SERVICE_REGISTER_NODES_REQUEST },
    { "RegisterNodesResponse", OPCUA_MSG_SERVICE_REGISTER_NODES_RESPONSE },
    { "UnregisterNodesRequest", OPCUA_MSG_SERVICE_UNREGISTER_NODES_REQUEST },
    { "UnregisterNodesResponse", OPCUA_MSG_SERVICE_UNREGISTER_NODES_RESPONSE },
    { "QueryDataDescription", OPCUA_MSG_SERVICE_QUERY_DATA_DESCRIPTION },
    { "NodeTypeDescription", OPCUA_MSG_SERVICE_NODE_TYPE_DESCRIPTION },
    { "QueryDataSet", OPCUA_MSG_SERVICE_QUERY_DATA_SET },
    { "NodeReference", OPCUA_MSG_SERVICE_NODE_REFERENCE },
    { "ContentFilterElement", OPCUA_MSG_SERVICE_CONTENT_FILTER_ELEMENT },
    { "ContentFilter", OPCUA_MSG_SERVICE_CONTENT_FILTER },
    { "FilterOperand", OPCUA_MSG_SERVICE_FILTER_OPERAND },
    { "ElementOperand", OPCUA_MSG_SERVICE_ELEMENT_OPERAND },
    { "LiteralOperand", OPCUA_MSG_SERVICE_LITERAL_OPERAND },
    { "AttributeOperand", OPCUA_MSG_SERVICE_ATTRIBUTE_OPERAND },
    { "SimpleAttributeOperand", OPCUA_MSG_SERVICE_SIMPLE_ATTRIBUTE_OPERAND },
    { "ContentFilterElementResult", OPCUA_MSG_SERVICE_CONTENT_FILTER_ELEMENT_RESULT },
    { "ContentFilterResult", OPCUA_MSG_SERVICE_CONTENT_FILTER_RESULT },
    { "ParsingResult", OPCUA_MSG_SERVICE_PARSING_RESULT },
    { "QueryFirstRequest", OPCUA_MSG_SERVICE_QUERY_FIRST_REQUEST },
    { "QueryFirstResponse", OPCUA_MSG_SERVICE_QUERY_FIRST_RESPONSE },
    { "QueryNextRequest", OPCUA_MSG_SERVICE_QUERY_NEXT_REQUEST },
    { "QueryNextResponse", OPCUA_MSG_SERVICE_QUERY_NEXT_RESPONSE },
    { "ReadValueId", OPCUA_MSG_SERVICE_READ_VALUE_ID },
    { "ReadRequest", OPCUA_MSG_SERVICE_READ_REQUEST },
    { "ReadResponse", OPCUA_MSG_SERVICE_READ_RESPONSE },
    { "HistoryReadValueId", OPCUA_MSG_SERVICE_HISTORY_READ_VALUE_ID },
    { "HistoryReadResult", OPCUA_MSG_SERVICE_HISTORY_READ_RESULT },
    { "HistoryReadDetails", OPCUA_MSG_SERVICE_HISTORY_READ_DETAILS },
    { "ReadEventDetails", OPCUA_MSG_SERVICE_READ_EVENT_DETAILS },
    { "ReadRawModifiedDetails", OPCUA_MSG_SERVICE_READ_RAW_MODIFIED_DETAILS },
    { "ReadProcessedDetails", OPCUA_MSG_SERVICE_READ_PROCESSED_DETAILS },
    { "ReadAtTimeDetails", OPCUA_MSG_SERVICE_READ_AT_TIME_DETAILS },
    { "HistoryData", OPCUA_MSG_SERVICE_HISTORY_DATA },
    { "HistoryEvent", OPCUA_MSG_SERVICE_HISTORY_EVENT },
    { "HistoryReadRequest", OPCUA_MSG_SERVICE_HISTORY_READ_REQUEST },
    { "HistoryReadResponse", OPCUA_MSG_SERVICE_HISTORY_READ_RESPONSE },
    { "WriteValue", OPCUA_MSG_SERVICE_WRITE_VALUE },
    { "WriteRequest", OPCUA_MSG_SERVICE_WRITE_REQUEST },
    { "WriteResponse", OPCUA_MSG_SERVICE_WRITE_RESPONSE },
    { "HistoryUpdateDetails", OPCUA_MSG_SERVICE_HISTORY_UPDATE_DETAILS },
    { "UpdateDataDetails", OPCUA_MSG_SERVICE_UPDATE_DATA_DETAILS },
    { "UpdateEventDetails", OPCUA_MSG_SERVICE_UPDATE_EVENT_DETAILS },
    { "DeleteRawModifiedDetails", OPCUA_MSG_SERVICE_DELETE_RAW_MODIFIED_DETAILS },
    { "DeleteAtTimeDetails", OPCUA_MSG_SERVICE_DELETE_AT_TIME_DETAILS },
    { "DeleteEventDetails", OPCUA_MSG_SERVICE_DELETE_EVENT_DETAILS },
    { "HistoryUpdateResult", OPCUA_MSG_SERVICE_HISTORY_UPDATE_RESULT },
    { "HistoryUpdateRequest", OPCUA_MSG_SERVICE_HISTORY_UPDATE_REQUEST },
    { "HistoryUpdateResponse", OPCUA_MSG_SERVICE_HISTORY_UPDATE_RESPONSE },
    { "CallMethodRequest", OPCUA_MSG_SERVICE_CALL_METHOD_REQUEST },
    { "CallMethodResult", OPCUA_MSG_SERVICE_CALL_METHOD_RESULT },
    { "CallRequest", OPCUA_MSG_SERVICE_CALL_REQUEST },
    { "CallResponse", OPCUA_MSG_SERVICE_CALL_RESPONSE },
    { "MonitoringFilter", OPCUA_MSG_SERVICE_MONITORING_FILTER },
    { "DataChangeFilter", OPCUA_MSG_SERVICE_DATA_CHANGE_FILTER },
    { "EventFilter", OPCUA_MSG_SERVICE_EVENT_FILTER },
    { "AggregateFilter", OPCUA_MSG_SERVICE_AGGREGATE_FILTER },
    { "MonitoringFilterResult", OPCUA_MSG_SERVICE_MONITORING_FILTER_RESULT },
    { "EventFilterResult", OPCUA_MSG_SERVICE_EVENT_FILTER_RESULT },
    { "AggregateFilterResult", OPCUA_MSG_SERVICE_AGGREGATE_FILTER_RESULT },
    { "MonitoringParameters", OPCUA_MSG_SERVICE_MONITORING_PARAMETERS },
    { "MonitoredItemCreateRequest", OPCUA_MSG_SERVICE_MONITORED_ITEM_CREATE_REQUEST },
    { "MonitoredItemCreateResult", OPCUA_MSG_SERVICE_MONITORED_ITEM_CREATE_RESULT },
    { "CreateMonitoredItemsRequest", OPCUA_MSG_SERVICE_CREATE_MONITORED_ITEMS_REQUEST },
    { "CreateMonitoredItemsResponse", OPCUA_MSG_SERVICE_CREATE_MONITORED_ITEMS_RESPONSE },
    { "MonitoredItemModifyRequest", OPCUA_MSG_SERVICE_MONITORED_ITEM_MODIFY_REQUEST },
    { "MonitoredItemModifyResult", OPCUA_MSG_SERVICE_MONITORED_ITEM_MODIFY_RESULT },
    { "ModifyMonitoredItemsRequest", OPCUA_MSG_SERVICE_MODIFY_MONITORED_ITEMS_REQUEST },
    { "ModifyMonitoredItemsResponse", OPCUA_MSG_SERVICE_MODIFY_MONITORED_ITEMS_RESPONSE },
    { "SetMonitoringModeRequest", OPCUA_MSG_SERVICE_SET_MONITORING_MODE_REQUEST },
    { "SetMonitoringModeResponse", OPCUA_MSG_SERVICE_SET_MONITORING_MODE_RESPONSE },
    { "SetTriggeringRequest", OPCUA_MSG_SERVICE_SET_TRIGGERING_REQUEST },
    { "SetTriggeringResponse", OPCUA_MSG_SERVICE_SET_TRIGGERING_RESPONSE },
    { "DeleteMonitoredItemsRequest", OPCUA_MSG_SERVICE_DELETE_MONITORED_ITEMS_REQUEST },
    { "DeleteMonitoredItemsResponse", OPCUA_MSG_SERVICE_DELETE_MONITORED_ITEMS_RESPONSE },
    { "CreateSubscriptionRequest", OPCUA_MSG_SERVICE_CREATE_SUBSCRIPTION_REQUEST },
    { "CreateSubscriptionResponse", OPCUA_MSG_SERVICE_CREATE_SUBSCRIPTION_RESPONSE },
    { "ModifySubscriptionRequest", OPCUA_MSG_SERVICE_MODIFY_SUBSCRIPTION_REQUEST },
    { "ModifySubscriptionResponse", OPCUA_MSG_SERVICE_MODIFY_SUBSCRIPTION_RESPONSE },
    { "SetPublishingModeRequest", OPCUA_MSG_SERVICE_SET_PUBLISHING_MODE_REQUEST },
    { "SetPublishingModeResponse", OPCUA_MSG_SERVICE_SET_PUBLISHING_MODE_RESPONSE },
    { "NotificationMessage", OPCUA_MSG_SERVICE_NOTIFICATION_MESSAGE },
    { "MonitoredItemNotification", OPCUA_MSG_SERVICE_MONITORED_ITEM_NOTIFICATION },
    { "DataChangeNotification", OPCUA_MSG_SERVICE_DATA_CHANGE_NOTIFICATION },
    { "StatusChangeNotification", OPCUA_MSG_SERVICE_STATUS_CHANGE_NOTIFICATION },
    { "SubscriptionAcknowledgement", OPCUA_MSG_SERVICE_SUBSCRIPTION_ACKNOWLEDGEMENT },
    { "PublishRequest", OPCUA_MSG_SERVICE_PUBLISH_REQUEST },
    { "PublishResponse", OPCUA_MSG_SERVICE_PUBLISH_RESPONSE },
    { "RepublishRequest", OPCUA_MSG_SERVICE_REPUBLISH_REQUEST },
    { "RepublishResponse", OPCUA_MSG_SERVICE_REPUBLISH_RESPONSE },
    { "TransferResult", OPCUA_MSG_SERVICE_TRANSFER_RESULT },
    { "TransferSubscriptionsRequest", OPCUA_MSG_SERVICE_TRANSFER_SUBSCRIPTIONS_REQUEST },
    { "TransferSubscriptionsResponse", OPCUA_MSG_SERVICE_TRANSFER_SUBSCRIPTIONS_RESPONSE },
    { "DeleteSubscriptionsRequest", OPCUA_MSG_SERVICE_DELETE_SUBSCRIPTIONS_REQUEST },
    { "DeleteSubscriptionsResponse", OPCUA_MSG_SERVICE_DELETE_SUBSCRIPTIONS_RESPONSE },
    { "RedundantServerDataType", OPCUA_MSG_SERVICE_REDUNDANT_SERVER_DATA_TYPE },
    { "SamplingIntervalDiagnosticsDataType", OPCUA_MSG_SERVICE_SAMPLING_INTERVAL_DIAGNOSTICS_DATA_TYPE },
    { "ServerDiagnosticsSummaryDataType", OPCUA_MSG_SERVICE_SERVER_DIAGNOSTICS_SUMMARY_DATA_TYPE },
    { "ServerStatusDataType", OPCUA_MSG_SERVICE_SERVER_STATUS_DATA_TYPE },
    { "SessionDiagnosticsDataType", OPCUA_MSG_SERVICE_SESSION_DIAGNOSTICS_DATA_TYPE },
    { "SessionSecurityDiagnosticsDataType", OPCUA_MSG_SERVICE_SESSION_SECURITY_DIAGNOSTICS_DATA_TYPE },
    { "ServiceCounterDataType", OPCUA_MSG_SERVICE_SERVICE_COUNTER_DATA_TYPE },
    { "SubscriptionDiagnosticsDataType", OPCUA_MSG_SERVICE_SUBSCRIPTION_DIAGNOSTICS_DATA_TYPE },
    { "ModelChangeStructureDataType", OPCUA_MSG_SERVICE_MODEL_CHANGE_STRUCTURE_DATA_TYPE },
    { "Range", OPCUA_MSG_SERVICE_RANGE },
    { "EUInformation", OPCUA_MSG_SERVICE_E_U_INFORMATION },
    { "Annotation", OPCUA_MSG_SERVICE_ANNOTATION },
    { "ProgramDiagnosticDataType", OPCUA_MSG_SERVICE_PROGRAM_DIAGNOSTIC_DATA_TYPE },
    { "SemanticChangeStructureDataType", OPCUA_MSG_SERVICE_SEMANTIC_CHANGE_STRUCTURE_DATA_TYPE },
    { "EventNotificationList", OPCUA_MSG_SERVICE_EVENT_NOTIFICATION_LIST },
    { "EventFieldList", OPCUA_MSG_SERVICE_EVENT_FIELD_LIST },
    { "HistoryEventFieldList", OPCUA_MSG_SERVICE_HISTORY_EVENT_FIELD_LIST },
    { "IssuedIdentityToken", OPCUA_MSG_SERVICE_ISSUED_IDENTITY_TOKEN },
    { "NotificationData", OPCUA_MSG_SERVICE_NOTIFICATION_DATA },
    { "AggregateConfiguration", OPCUA_MSG_SERVICE_AGGREGATE_CONFIGURATION },
    { "EnumValueType", OPCUA_MSG_SERVICE_ENUM_VALUE_TYPE },
    { "TimeZoneDataType", OPCUA_MSG_SERVICE_TIME_ZONE_DATA_TYPE },
    { "ModificationInfo", OPCUA_MSG_SERVICE_MODIFICATION_INFO },
    { "HistoryModifiedData", OPCUA_MSG_SERVICE_HISTORY_MODIFIED_DATA },
    { "UpdateStructureDataDetails", OPCUA_MSG_SERVICE_UPDATE_STRUCTURE_DATA_DETAILS },
    { "InstanceNode", OPCUA_MSG_SERVICE_INSTANCE_NODE },
    { "TypeNode", OPCUA_MSG_SERVICE_TYPE_NODE },
    { "EndpointUrlListDataType", OPCUA_MSG_SERVICE_ENDPOINT_URL_LIST_DATA_TYPE },
    { "NetworkGroupDataType", OPCUA_MSG_SERVICE_NETWORK_GROUP_DATA_TYPE },
    { "AxisInformation", OPCUA_MSG_SERVICE_AXIS_INFORMATION },
    { "XVType", OPCUA_MSG_SERVICE_X_V_TYPE },
    { "ComplexNumberType", OPCUA_MSG_SERVICE_COMPLEX_NUMBER_TYPE },
    { "DoubleComplexNumberType", OPCUA_MSG_SERVICE_DOUBLE_COMPLEX_NUMBER_TYPE },
    { "ServerOnNetwork", OPCUA_MSG_SERVICE_SERVER_ON_NETWORK },
    { "FindServersOnNetworkRequest", OPCUA_MSG_SERVICE_FIND_SERVERS_ON_NETWORK_REQUEST },
    { "FindServersOnNetworkResponse", OPCUA_MSG_SERVICE_FIND_SERVERS_ON_NETWORK_RESPONSE },
    { "RegisterServer2Request", OPCUA_MSG_SERVICE_REGISTER_SERVER2_REQUEST },
    { "RegisterServer2Response", OPCUA_MSG_SERVICE_REGISTER_SERVER2_RESPONSE },
    { "TrustListDataType", OPCUA_MSG_SERVICE_TRUST_LIST_DATA_TYPE },
    { "OptionSet", OPCUA_MSG_SERVICE_OPTION_SET },
    { "Union", OPCUA_MSG_SERVICE_UNION },
    { "DiscoveryConfiguration", OPCUA_MSG_SERVICE_DISCOVERY_CONFIGURATION },
    { "MdnsDiscoveryConfiguration", OPCUA_MSG_SERVICE_MDNS_DISCOVERY_CONFIGURATION },
    { "PublishedVariableDataType", OPCUA_MSG_SERVICE_PUBLISHED_VARIABLE_DATA_TYPE },
    { "FieldMetaData", OPCUA_MSG_SERVICE_FIELD_META_DATA },
    { "StructureField", OPCUA_MSG_SERVICE_STRUCTURE_FIELD },
    { "EnumField", OPCUA_MSG_SERVICE_ENUM_FIELD },
    { "KeyValuePair", OPCUA_MSG_SERVICE_KEY_VALUE_PAIR },
    { "ConfigurationVersionDataType", OPCUA_MSG_SERVICE_CONFIGURATION_VERSION_DATA_TYPE },
    { "FieldTargetDataType", OPCUA_MSG_SERVICE_FIELD_TARGET_DATA_TYPE },
    { "TestScalarStructure", OPCUA_MSG_SERVICE_TEST_SCALAR_STRUCTURE },
    { "TestArrayStructure", OPCUA_MSG_SERVICE_TEST_ARRAY_STRUCTURE },
    { "TestStructure", OPCUA_MSG_SERVICE_TEST_STRUCTURE },
    { "TestAbstractStructure", OPCUA_MSG_SERVICE_TEST_ABSTRACT_STRUCTURE },
    { "TestConcreteStructure", OPCUA_MSG_SERVICE_TEST_CONCRETE_STRUCTURE },
    { "SimpleTypeDescription", OPCUA_MSG_SERVICE_SIMPLE_TYPE_DESCRIPTION },
    { "UABinaryFileDataType", OPCUA_MSG_SERVICE_U_A_BINARY_FILE_DATA_TYPE },
    { "BrokerConnectionTransportDataType", OPCUA_MSG_SERVICE_BROKER_CONNECTION_TRANSPORT_DATA_TYPE },
    { "EndpointType", OPCUA_MSG_SERVICE_ENDPOINT_TYPE },
    { "DataTypeSchemaHeader", OPCUA_MSG_SERVICE_DATA_TYPE_SCHEMA_HEADER },
    { "PublishedDataSetDataType", OPCUA_MSG_SERVICE_PUBLISHED_DATA_SET_DATA_TYPE },
    { "PublishedDataSetSourceDataType", OPCUA_MSG_SERVICE_PUBLISHED_DATA_SET_SOURCE_DATA_TYPE },
    { "PublishedDataItemsDataType", OPCUA_MSG_SERVICE_PUBLISHED_DATA_ITEMS_DATA_TYPE },
    { "PublishedEventsDataType", OPCUA_MSG_SERVICE_PUBLISHED_EVENTS_DATA_TYPE },
    { "DataSetWriterDataType", OPCUA_MSG_SERVICE_DATA_SET_WRITER_DATA_TYPE },
    { "DataSetWriterTransportDataType", OPCUA_MSG_SERVICE_DATA_SET_WRITER_TRANSPORT_DATA_TYPE },
    { "DataSetWriterMessageDataType", OPCUA_MSG_SERVICE_DATA_SET_WRITER_MESSAGE_DATA_TYPE },
    { "PubSubGroupDataType", OPCUA_MSG_SERVICE_PUB_SUB_GROUP_DATA_TYPE },
    { "WriterGroupTransportDataType", OPCUA_MSG_SERVICE_WRITER_GROUP_TRANSPORT_DATA_TYPE },
    { "WriterGroupMessageDataType", OPCUA_MSG_SERVICE_WRITER_GROUP_MESSAGE_DATA_TYPE },
    { "PubSubConnectionDataType", OPCUA_MSG_SERVICE_PUB_SUB_CONNECTION_DATA_TYPE },
    { "ConnectionTransportDataType", OPCUA_MSG_SERVICE_CONNECTION_TRANSPORT_DATA_TYPE },
    { "ReaderGroupTransportDataType", OPCUA_MSG_SERVICE_READER_GROUP_TRANSPORT_DATA_TYPE },
    { "ReaderGroupMessageDataType", OPCUA_MSG_SERVICE_READER_GROUP_MESSAGE_DATA_TYPE },
    { "DataSetReaderDataType", OPCUA_MSG_SERVICE_DATA_SET_READER_DATA_TYPE },
    { "DataSetReaderTransportDataType", OPCUA_MSG_SERVICE_DATA_SET_READER_TRANSPORT_DATA_TYPE },
    { "DataSetReaderMessageDataType", OPCUA_MSG_SERVICE_DATA_SET_READER_MESSAGE_DATA_TYPE },
    { "SubscribedDataSetDataType", OPCUA_MSG_SERVICE_SUBSCRIBED_DATA_SET_DATA_TYPE },
    { "TargetVariablesDataType", OPCUA_MSG_SERVICE_TARGET_VARIABLES_DATA_TYPE },
    { "SubscribedDataSetMirrorDataType", OPCUA_MSG_SERVICE_SUBSCRIBED_DATA_SET_MIRROR_DATA_TYPE },
    { "UadpWriterGroupMessageDataType", OPCUA_MSG_SERVICE_UADP_WRITER_GROUP_MESSAGE_DATA_TYPE },
    { "UadpDataSetWriterMessageDataType", OPCUA_MSG_SERVICE_UADP_DATA_SET_WRITER_MESSAGE_DATA_TYPE },
    { "UadpDataSetReaderMessageDataType", OPCUA_MSG_SERVICE_UADP_DATA_SET_READER_MESSAGE_DATA_TYPE },
    { "JsonWriterGroupMessageDataType", OPCUA_MSG_SERVICE_JSON_WRITER_GROUP_MESSAGE_DATA_TYPE },
    { "JsonDataSetWriterMessageDataType", OPCUA_MSG_SERVICE_JSON_DATA_SET_WRITER_MESSAGE_DATA_TYPE },
    { "JsonDataSetReaderMessageDataType", OPCUA_MSG_SERVICE_JSON_DATA_SET_READER_MESSAGE_DATA_TYPE },
    { "BrokerWriterGroupTransportDataType", OPCUA_MSG_SERVICE_BROKER_WRITER_GROUP_TRANSPORT_DATA_TYPE },
    { "BrokerDataSetWriterTransportDataType", OPCUA_MSG_SERVICE_BROKER_DATA_SET_WRITER_TRANSPORT_DATA_TYPE },
    { "BrokerDataSetReaderTransportDataType", OPCUA_MSG_SERVICE_BROKER_DATA_SET_READER_TRANSPORT_DATA_TYPE },
    { "IdentityMappingRuleType", OPCUA_MSG_SERVICE_IDENTITY_MAPPING_RULE_TYPE },
    { "SessionlessInvokeRequestType", OPCUA_MSG_SERVICE_SESSIONLESS_INVOKE_REQUEST_TYPE },
    { "DatagramConnectionTransportDataType", OPCUA_MSG_SERVICE_DATAGRAM_CONNECTION_TRANSPORT_DATA_TYPE },
    { "AdditionalParametersType", OPCUA_MSG_SERVICE_ADDITIONAL_PARAMETERS_TYPE },
    { "EphemeralKeyType", OPCUA_MSG_SERVICE_EPHEMERAL_KEY_TYPE },
    { "GenericAttributeValue", OPCUA_MSG_SERVICE_GENERIC_ATTRIBUTE_VALUE },
    { "GenericAttributes", OPCUA_MSG_SERVICE_GENERIC_ATTRIBUTES },
    { "DecimalDataType", OPCUA_MSG_SERVICE_DECIMAL_DATA_TYPE },
    { "ActionTargetDataType", OPCUA_MSG_SERVICE_ACTION_TARGET_DATA_TYPE },
    { "PublishedActionDataType", OPCUA_MSG_SERVICE_PUBLISHED_ACTION_DATA_TYPE },
    { "ActionMethodDataType", OPCUA_MSG_SERVICE_ACTION_METHOD_DATA_TYPE },
    { "SortRuleElement", OPCUA_MSG_SERVICE_SORT_RULE_ELEMENT },
    { "ReadEventDetailsSorted", OPCUA_MSG_SERVICE_READ_EVENT_DETAILS_SORTED },
    { "PublishedActionMethodDataType", OPCUA_MSG_SERVICE_PUBLISHED_ACTION_METHOD_DATA_TYPE },
    { "RationalNumber", OPCUA_MSG_SERVICE_RATIONAL_NUMBER },
    { "Vector", OPCUA_MSG_SERVICE_VECTOR },
    { "ThreeDVector", OPCUA_MSG_SERVICE_THREE_D_VECTOR },
    { "CartesianCoordinates", OPCUA_MSG_SERVICE_CARTESIAN_COORDINATES },
    { "ThreeDCartesianCoordinates", OPCUA_MSG_SERVICE_THREE_D_CARTESIAN_COORDINATES },
    { "Orientation", OPCUA_MSG_SERVICE_ORIENTATION },
    { "ThreeDOrientation", OPCUA_MSG_SERVICE_THREE_D_ORIENTATION },
    { "Frame", OPCUA_MSG_SERVICE_FRAME },
    { "ThreeDFrame", OPCUA_MSG_SERVICE_THREE_D_FRAME },
    { "DtlsPubSubConnectionDataType", OPCUA_MSG_SERVICE_DTLS_PUB_SUB_CONNECTION_DATA_TYPE },
    { "LldpManagementAddressTxPortType", OPCUA_MSG_SERVICE_LLDP_MANAGEMENT_ADDRESS_TX_PORT_TYPE },
    { "LldpManagementAddressType", OPCUA_MSG_SERVICE_LLDP_MANAGEMENT_ADDRESS_TYPE },
    { "LldpTlvType", OPCUA_MSG_SERVICE_LLDP_TLV_TYPE },
    { "TestUnion", OPCUA_MSG_SERVICE_TEST_UNION },
    { "TestOptionalFields", OPCUA_MSG_SERVICE_TEST_OPTIONAL_FIELDS },
    { "SessionlessInvokeResponseType", OPCUA_MSG_SERVICE_SESSIONLESS_INVOKE_RESPONSE_TYPE },
    { "WriterGroupDataType", OPCUA_MSG_SERVICE_WRITER_GROUP_DATA_TYPE },
    { "NetworkAddressDataType", OPCUA_MSG_SERVICE_NETWORK_ADDRESS_DATA_TYPE },
    { "NetworkAddressUrlDataType", OPCUA_MSG_SERVICE_NETWORK_ADDRESS_URL_DATA_TYPE },
    { "ReaderGroupDataType", OPCUA_MSG_SERVICE_READER_GROUP_DATA_TYPE },
    { "PubSubConfigurationDataType", OPCUA_MSG_SERVICE_PUB_SUB_CONFIGURATION_DATA_TYPE },
    { "DatagramWriterGroupTransportDataType", OPCUA_MSG_SERVICE_DATAGRAM_WRITER_GROUP_TRANSPORT_DATA_TYPE },
    { "AliasNameDataType", OPCUA_MSG_SERVICE_ALIAS_NAME_DATA_TYPE },
    { "ReadAnnotationDataDetails", OPCUA_MSG_SERVICE_READ_ANNOTATION_DATA_DETAILS },
    { "CurrencyUnitType", OPCUA_MSG_SERVICE_CURRENCY_UNIT_TYPE },
    { "StandaloneSubscribedDataSetRefDataType", OPCUA_MSG_SERVICE_STANDALONE_SUBSCRIBED_DATA_SET_REF_DATA_TYPE },
    { "StandaloneSubscribedDataSetDataType", OPCUA_MSG_SERVICE_STANDALONE_SUBSCRIBED_DATA_SET_DATA_TYPE },
    { "SecurityGroupDataType", OPCUA_MSG_SERVICE_SECURITY_GROUP_DATA_TYPE },
    { "PubSubConfiguration2DataType", OPCUA_MSG_SERVICE_PUB_SUB_CONFIGURATION2_DATA_TYPE },
    { "QosDataType", OPCUA_MSG_SERVICE_QOS_DATA_TYPE },
    { "TransmitQosDataType", OPCUA_MSG_SERVICE_TRANSMIT_QOS_DATA_TYPE },
    { "TransmitQosPriorityDataType", OPCUA_MSG_SERVICE_TRANSMIT_QOS_PRIORITY_DATA_TYPE },
    { "ReceiveQosDataType", OPCUA_MSG_SERVICE_RECEIVE_QOS_DATA_TYPE },
    { "ReceiveQosPriorityDataType", OPCUA_MSG_SERVICE_RECEIVE_QOS_PRIORITY_DATA_TYPE },
    { "DatagramConnectionTransport2DataType", OPCUA_MSG_SERVICE_DATAGRAM_CONNECTION_TRANSPORT2_DATA_TYPE },
    { "DatagramWriterGroupTransport2DataType", OPCUA_MSG_SERVICE_DATAGRAM_WRITER_GROUP_TRANSPORT2_DATA_TYPE },
    { "DatagramDataSetReaderTransportDataType", OPCUA_MSG_SERVICE_DATAGRAM_DATA_SET_READER_TRANSPORT_DATA_TYPE },
    { "ProgramDiagnostic2DataType", OPCUA_MSG_SERVICE_PROGRAM_DIAGNOSTIC2_DATA_TYPE },
    { "PortableQualifiedName", OPCUA_MSG_SERVICE_PORTABLE_QUALIFIED_NAME },
    { "PortableNodeId", OPCUA_MSG_SERVICE_PORTABLE_NODE_ID },
    { "UnsignedRationalNumber", OPCUA_MSG_SERVICE_UNSIGNED_RATIONAL_NUMBER },
    { "UserManagementDataType", OPCUA_MSG_SERVICE_USER_MANAGEMENT_DATA_TYPE },
    { "PriorityMappingEntryType", OPCUA_MSG_SERVICE_PRIORITY_MAPPING_ENTRY_TYPE },
    { "PublishedDataSetCustomSourceDataType", OPCUA_MSG_SERVICE_PUBLISHED_DATA_SET_CUSTOM_SOURCE_DATA_TYPE },
    { "PubSubKeyPushTargetDataType", OPCUA_MSG_SERVICE_PUB_SUB_KEY_PUSH_TARGET_DATA_TYPE },
    { "PubSubConfigurationRefDataType", OPCUA_MSG_SERVICE_PUB_SUB_CONFIGURATION_REF_DATA_TYPE },
    { "PubSubConfigurationValueDataType", OPCUA_MSG_SERVICE_PUB_SUB_CONFIGURATION_VALUE_DATA_TYPE },
    { "TransactionErrorType", OPCUA_MSG_SERVICE_TRANSACTION_ERROR_TYPE },
    { "BitFieldDefinition", OPCUA_MSG_SERVICE_BIT_FIELD_DEFINITION },
    { "AnnotationDataType", OPCUA_MSG_SERVICE_ANNOTATION_DATA_TYPE },
    { "LinearConversionDataType", OPCUA_MSG_SERVICE_LINEAR_CONVERSION_DATA_TYPE },
    { "QuantityDimension", OPCUA_MSG_SERVICE_QUANTITY_DIMENSION },
    { "ReferenceDescriptionDataType", OPCUA_MSG_SERVICE_REFERENCE_DESCRIPTION_DATA_TYPE },
    { "ReferenceListEntryDataType", OPCUA_MSG_SERVICE_REFERENCE_LIST_ENTRY_DATA_TYPE },
    { "ReadEventDetails2", OPCUA_MSG_SERVICE_READ_EVENT_DETAILS2 },
    { "HistoryModifiedEvent", OPCUA_MSG_SERVICE_HISTORY_MODIFIED_EVENT },
};

static bool get_msg_service(const char* s, OpcuaMsgServiceType& t)
{
    constexpr size_t max = (sizeof(opcua_msg_service_map) / sizeof(OpcuaMsgServiceMap));

    for (size_t i = 0; i < max; ++i)
    {
        if (strcmp(s, opcua_msg_service_map[i].name) == 0)
        {
            t = opcua_msg_service_map[i].type;
            return true;
        }
    }
    return false;
}

//-------------------------------------------------------------------------
// msg_service option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats opcua_msg_service_prof;

class OpcuaMsgServiceOption: public IpsOption
{
public:
    OpcuaMsgServiceOption(OpcuaMsgServiceType v) :
        IpsOption(s_name)
    {
        msg_service = v;
    }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

public:
    OpcuaMsgServiceType msg_service;
};

uint32_t OpcuaMsgServiceOption::hash() const
{
    uint32_t a = (uint32_t)msg_service, b = IpsOption::hash(), c = 0;

    mix(a, b, c);
    finalize(a, b, c);

    return c;
}

bool OpcuaMsgServiceOption::operator==(const IpsOption& ips) const
{
    if (!IpsOption::operator==(ips))
    {
        return false;
    }

    const OpcuaMsgServiceOption& rhs = (const OpcuaMsgServiceOption&) ips;
    return (msg_service == rhs.msg_service);
}

IpsOption::EvalStatus OpcuaMsgServiceOption::eval(Cursor&, Packet* p)
{
    // cppcheck-suppress unreadVariable
    RuleProfile profile(opcua_msg_service_prof);

    if ( !p->flow || !p->is_full_pdu() )
    {
        return NO_MATCH;
    }

    OpcuaFlowData* opcuafd = (OpcuaFlowData*) p->flow->get_flow_data(OpcuaFlowData::inspector_id);
    if ( !opcuafd )
    {
        return NO_MATCH;
    }

    OpcuaPacketDataDirectionType direction;
    if ( p->is_from_client() )
    {
        direction = OPCUA_PACKET_DATA_DIRECTION_CLIENT;
    }
    else if ( p->is_from_server() )
    {
        direction = OPCUA_PACKET_DATA_DIRECTION_SERVER;
    }
    else
    {
        return NO_MATCH;
    }

    const OpcuaSessionData* ssn_data = opcuafd->get_ssn_data_by_direction(direction);
    if ( ssn_data == nullptr )
    {
        return NO_MATCH;
    }

    // the concept of a msg_service only exists in the MSG pdu type
    if ( ssn_data->msg_type == OPCUA_MSG_MSG )
    {
        // this rule option only works on default service types, so the namespace index must be zero
        // custom combinations can use other rule options
        if ( ssn_data->node_namespace_index == OPCUA_DEFAULT_NAMESPACE_INDEX )
        {
            if ( msg_service == ssn_data->node_id )
            {
               return MATCH;
            }
        }
    }

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~", Parameter::PT_STRING, nullptr, nullptr,
      "message service to match" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to check the OPC UA message service"

class OpcuaMsgServiceModule: public Module
{
public:
    OpcuaMsgServiceModule() :
        Module(s_name, s_help, s_params)
    {
    }

    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    {
        return &opcua_msg_service_prof;
    }

    Usage get_usage() const override
    {
        return DETECT;
    }

public:
    OpcuaMsgServiceType msg_service = OPCUA_MSG_SERVICE_UNDEFINED;
};

bool OpcuaMsgServiceModule::set(const char*, Value& v, SnortConfig*)
{
    assert(v.is("~"));
    OpcuaMsgServiceType t;

    if ( get_msg_service(v.get_string(), t) )
    {
        msg_service = t;
        return true;
    }

    return false;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new OpcuaMsgServiceModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* opt_ctor(Module* m, IpsInfo&)
{
    const OpcuaMsgServiceModule* mod = (const OpcuaMsgServiceModule*) m;
    return new OpcuaMsgServiceOption(mod->msg_service);
}

static void opt_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi ips_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0,
    PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    opt_ctor,
    opt_dtor,
    nullptr
};

const BaseApi* ips_opcua_msg_service = &ips_api.base;


struct S7commFuncMap
{
    const char* name;
    uint8_t func;
};

/* Mapping of name -> message type for 's7comm_func' option. */
static S7commFuncMap s7comm_func_map[] =
{
    { "job_request",    0x01 },
    { "ack",            0x02 },
    { "ack_data",       0x03 },
    { "userdata",       0x07 }
};


struct S7commErrorClassMap
{
    const char* name;
    uint8_t error_class;
};

static S7commErrorClassMap s7comm_error_class_map[] =
{
    { "no_error",                        0x00 },
    { "application_relationship_error",  0x81 },
    { "object_definition_error",         0x82 },
    { "no_resources_available_error",    0x83 },
    { "error_on_service_processing",     0x84 },
    { "error_on_supplies",               0x85 },
    { "access_error",                    0x87 }
};
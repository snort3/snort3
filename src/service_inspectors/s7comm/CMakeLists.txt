set( FILE_LIST
    s7comm.cc
    s7comm.h
    s7comm_decode.cc
    s7comm_decode.h
    s7comm_module.cc
    s7comm_module.h
    s7comm_paf.cc
    s7comm_paf.h
    ips_s7comm_content.cc
    ips_s7comm_func.cc
    ips_s7comm_error_code.cc
    ips_s7comm_error_class.cc
    ips_s7comm_pdu_ref.cc
    ips_s7comm_parameter_length.cc
    ips_s7comm_data_length.cc
    ips_s7comm_function_code.cc
    ips_s7comm_item_count.cc
    ips_s7comm_di_data_length.cc
    ips_s7comm_di_data.cc
    ips_s7comm_di_error_code.cc
    ips_s7comm_di_variable_type.cc
    ips_s7comm_pi_address.cc
    ips_s7comm_pi_area.cc
    ips_s7comm_pi_db_number.cc
    ips_s7comm_pi_length.cc
    ips_s7comm_pi_syntax_id.cc
    ips_s7comm_pi_transport_size.cc
    ips_s7comm_pi_var_length.cc
    ips_s7comm_pi_var_type.cc
)

if (STATIC_INSPECTORS)
    add_library(s7comm OBJECT ${FILE_LIST})

else (STATIC_INSPECTORS)
    add_dynamic_module(s7comm inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)
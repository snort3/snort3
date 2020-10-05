
add_subdirectory (data_types)

add_library( conversion_data OBJECT
    dt_data.h
    dt_data.cc
    dt_rule_api.h
    dt_rule_api.cc
    dt_state_api.h
    dt_state_api.cc
    dt_table_api.h
    dt_table_api.cc
)


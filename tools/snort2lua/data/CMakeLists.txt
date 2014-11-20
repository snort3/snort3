
add_subdirectory (data_types)

add_library( conversion_data
    dt_data.h
    dt_data.cc
    dt_table_api.h
    dt_table_api.cc
    dt_rule_api.h
    dt_rule_api.cc
)

target_link_libraries( conversion_data
    data_types
)

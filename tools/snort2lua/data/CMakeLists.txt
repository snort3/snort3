
add_subdirectory (data_types)

add_library( conversion_data OBJECT
    dt_data.h
    dt_data.cc
    dt_table_api.h
    dt_table_api.cc
    dt_rule_api.h
    dt_rule_api.cc
)


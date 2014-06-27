
add_subdirectory(rule)

add_library( conversion_data
    dt_data.h
    dt_data.cc
    dt_var.h
    dt_var.cc
    dt_table.h
    dt_table.cc
    dt_option.h
    dt_option.cc
    dt_comment.h
    dt_comment.cc
    dt_rule.h
    dt_rule.cc
)

target_link_libraries( conversion_data
    rule_data
)

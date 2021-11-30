
add_subdirectory(address_space_selector)
add_subdirectory(tenant_selector)

set(STATIC_POLICY_SELECTOR_PLUGINS
    $<TARGET_OBJECTS:address_space_selector>
    $<TARGET_OBJECTS:tenant_selector>
    CACHE INTERNAL "STATIC_POLICY_SELECTOR_PLUGINS"
)

add_library( policy_selectors OBJECT
    int_set_to_string.h
    parse_int_set.h
    policy_selectors.cc
    policy_selectors.h
)

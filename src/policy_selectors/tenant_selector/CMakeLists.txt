
set(FILE_LIST
    tenant_selection.cc
    tenant_selection.h
    tenant_selector.cc
    tenant_selector_module.cc
    tenant_selector_module.h
)

add_library(tenant_selector OBJECT ${FILE_LIST})


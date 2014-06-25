
if(SNORT_FOUND)
    include_directories(${SNORT_INCLUDE_DIR})
endif()

set(EX_INSTALL_PATH "lib/snort_examples")

add_subdirectory(codecs)
add_subdirectory(inspectors)
add_subdirectory(ips_options)
add_subdirectory(loggers)
add_subdirectory(search_engines)
add_subdirectory(so_rules)

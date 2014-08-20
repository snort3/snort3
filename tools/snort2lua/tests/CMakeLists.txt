

# FIXIT: delete
enable_testing()

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/snort.conf.in"
    "${CMAKE_CURRENT_BINARY_DIR}/snort.conf"
    IMMEDIATE @ONLY)


set (OPEN_SOURCE_RULES "${CMAKE_CURRENT_LIST_DIR}/open_source.rule")
set (OPEN_SOURCE_LUA_CONF "${CMAKE_CURRENT_BINARY_DIR}/open_source_rules.lua")
set (OPEN_SOURCE_LUA_RULES "${CMAKE_CURRENT_BINARY_DIR}/ofpen_source_rules.rules")
set (OPEN_SOURCE_LUA_ERRORS "${CMAKE_CURRENT_BINARY_DIR}/open_source_rules.rej")

add_custom_target (open_source_rules
    DEPENDS snort2lua
    COMMAND $<TARGET_FILE:snort2lua> -c ${OPEN_SOURCE_RULES} -o ${OPEN_SOURCE_LUA_CONF} -r ${OPEN_SOURCE_LUA_RULES} -e ${OPEN_SOURCE_LUA_ERRORS}
    COMMENT "converting open source rules to Snort++ open source rules"
)


#add_test (ctest_build_snort_rules "${CMAKE_COMMAND}" --build ${CMAKE_BINARY_DIR} --target open_source_rules)
#add_test (NAME ctest_open_source_rules COMMAND $<TARGET_FILE:snort> -c ${OPEN_SOURCE_LUA_CONF})
#set_tests_properties (ctest_open_source_rules PROPERTIES DEPENDS ctest_build_snort_rules)


#  Testing Snort.conf



#  The following two tests run the snort.conf.in file through snort2lua,
#  and then runs the resulting converted file through Snort++ as a
#  a configuration file.

set (TEST_CONF_CONF "${CMAKE_CURRENT_BINARY_DIR}/snort.conf")
set (TEST_CONF_LUA "${CMAKE_CURRENT_BINARY_DIR}/snort.lua")
set (TEST_CONF_REJ "${CMAKE_CURRENT_BINARY_DIR}/snort.rej")


add_test (NAME ctest_snort2lua
            COMMAND $<TARGET_FILE:snort2lua> -c ${TEST_CONF_CONF} -o ${TEST_CONF_LUA} -e ${TEST_CONF_REJ} -a -p -s -t
            WORKING_DIRECTORY ${CMAKE_CURENT_BINARY_DIR})
add_test (NAME ctest_snort_conf COMMAND $<TARGET_FILE:snort> -c ${TEST_CONF_LUA})

# adding dependcies
set_tests_properties(ctest_snort2lua PROPERTIES DEPENDS snort2lua )
set_tests_properties(ctest_snort_conf PROPERTIES DEPENDS ctest_snort2lua)



# TESTING RULES

set (OPEN_SOURCE_RULES "${CMAKE_CURRENT_LIST_DIR}/open_source.rule")
set (OPEN_SOURCE_LUA_CONF "${CMAKE_CURRENT_BINARY_DIR}/open_source_rules.lua")
set (OPEN_SOURCE_LUA_RULES "${CMAKE_CURRENT_BINARY_DIR}/open_source_rules.rules")
set (OPEN_SOURCE_LUA_ERRORS "${CMAKE_CURRENT_BINARY_DIR}/open_source_rules.rej")

add_custom_target (open_source_rules
    DEPENDS snort2lua
    COMMAND $<TARGET_FILE:snort2lua> -c ${OPEN_SOURCE_RULES} -o ${OPEN_SOURCE_LUA_CONF} -r ${OPEN_SOURCE_LUA_RULES} -e ${OPEN_SOURCE_LUA_ERRORS}
    COMMENT "converting open source rules to Snort++ open source rules"
)

# FIXIT-L J  beging testing this when we support all of these rules!
#add_test (
#    NAME ctest_snort2lua_rules
#    COMMAND $<TARGET_FILE:snort2lua>
#        -c ${OPEN_SOURCE_RULES}
#        -o ${OPEN_SOURCE_LUA_CONF}
#        -e ${OPEN_SOURCE_LUA_ERRORS}
#        -r ${OPEN_SOURCE_LUA_RULES}
#        -a -s -t   # output everything, right rules and data to a single out file
#    WORKING_DIRECTORY ${CMAKE_CURENT_BINARY_DIR}
#)

#  This test will always fail
#add_test (
#    NAME ctest_snort_rule
#    COMMAND $<TARGET_FILE:snort> -c ${OPEN_SOURCE_LUA_CONF}
#    WORKING_DIRECTORY ${CMAKE_CURENT_BINARY_DIR}
#)

#set_tests_properties(ctest_snort2lua_rules PROPERTIES DEPENDS snort2lua )
#set_tests_properties(ctest_snort_rule PROPERTIES DEPENDS "ctest_snort2lua_rules;snort")


#  Testing Snort.conf


#  The following two tests run the snort.conf.in file through snort2lua,
#  and then runs the resulting converted file through Snort++ as a
#  a configuration file.

if (UNIX)
    execute_process (
        COMMAND id -u
        OUTPUT_VARIABLE UID
    )
endif()

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/snort.conf.in"
    "${CMAKE_CURRENT_BINARY_DIR}/snort.conf"
    IMMEDIATE @ONLY)

set (TEST_CONF_CONF "${CMAKE_CURRENT_BINARY_DIR}/snort.conf")
set (TEST_CONF_LUA "${CMAKE_CURRENT_BINARY_DIR}/snort.lua")
set (TEST_CONF_REJ "${CMAKE_CURRENT_BINARY_DIR}/snort.rej")

# so Snort++ won't choke on block.html
execute_process (COMMAND ${CMAKE_COMMAND} -E touch "${CMAKE_CURRENT_BINARY_DIR}/block.html")
execute_process (COMMAND ${CMAKE_COMMAND} -E touch "${CMAKE_CURRENT_BINARY_DIR}/filter")

add_test (
    NAME ctest_snort2lua_conf
    COMMAND $<TARGET_FILE:snort2lua>
        -c ${TEST_CONF_CONF}
        -o ${TEST_CONF_LUA}
        -e ${TEST_CONF_REJ}
        -a -s -t # output everything, right rules and data to a single out file
    WORKING_DIRECTORY ${CMAKE_CURENT_BINARY_DIR})
add_test (NAME ctest_snort_conf COMMAND $<TARGET_FILE:snort> -c ${TEST_CONF_LUA} --pedantic)

# adding dependcies
set_tests_properties(ctest_snort2lua_conf PROPERTIES DEPENDS snort2lua )
set_tests_properties(ctest_snort_conf PROPERTIES DEPENDS "ctest_snort2lua_conf;snort")


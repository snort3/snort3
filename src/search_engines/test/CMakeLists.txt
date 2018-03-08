
add_cpputest( search_tool_test
    SOURCES
        ../ac_bnfa.cc
        ../bnfa_search.cc
        ../search_tool.cc
)

if ( HAVE_HYPERSCAN )
    add_cpputest( hyperscan_test
        SOURCES ../hyperscan.cc
        LIBS ${HS_LIBRARIES}
    )
endif()

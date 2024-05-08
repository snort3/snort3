
add_cpputest( ac_bnfa_test
    SOURCES
        mpse_test_stubs.cc
        mpse_test_stubs.h
        ../ac_bnfa.cc
        ../bnfa_search.cc
        ../search_tool.cc
        ../../framework/module.cc
        ../../framework/mpse.cc
)

add_cpputest( search_tool_test
    SOURCES
        mpse_test_stubs.cc
        mpse_test_stubs.h
        ../ac_full.cc
        ../acsmx2.cc
        ../search_tool.cc
        ../../framework/module.cc
        ../../framework/mpse.cc
)

if ( HAVE_HYPERSCAN )
    add_cpputest( hyperscan_test
        SOURCES
            mpse_test_stubs.cc
            mpse_test_stubs.h
            ../hyperscan.cc
            ../../framework/module.cc
            ../../framework/mpse.cc
            ../../helpers/scratch_allocator.cc
            ../../helpers/hyper_scratch_allocator.cc
        LIBS ${HS_LIBRARIES}
    )
    add_cpputest( hyper_tool_test
        SOURCES
            mpse_test_stubs.cc
            mpse_test_stubs.h
            ../hyperscan.cc
            ../search_tool.cc
            ../../framework/module.cc
            ../../framework/mpse.cc
            ../../helpers/scratch_allocator.cc
            ../../helpers/hyper_scratch_allocator.cc
        LIBS ${HS_LIBRARIES}
    )
endif()


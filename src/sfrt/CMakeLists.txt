
if ( ENABLE_UNIT_TESTS )
    set(TEST_FILES sfrt_test.cc)
endif()

add_library ( sfrt OBJECT
    sfrt.cc
    sfrt.h
    sfrt_dir.cc
    sfrt_dir.h
    sfrt_flat.cc
    sfrt_flat.h
    sfrt_flat_dir.cc
    sfrt_flat_dir.h
    ${TEST_FILES}
)


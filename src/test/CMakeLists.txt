message("\ttest")


if ( TESTING_ENABLED )

#find_package(GCOV)

message ("cmake path = ..${CMAKE_MODULE_PATH}..")

#SET (CHECK_DIR "${CMAKE_MODULE_PATH}")
find_package(CHECK)
find_package(GCOV)


# build sf_ip_test



# BUILDING SF_IP_TEST:


add_executable (sf_ip_test sf_ip_test.cc)
add_compile_flags (sf_ip_test "--std=gnu++11 -O0 -Wall -fprofile-arcs -ftest-coverage -DSF_IP_TEST -C ${CMAKE_CURRENT_BINARY_DIR}")
add_link_flags (sf_ip_test "-g -O0 -Wall -fprofile-arcs -ftest-coverage -DSF_IP_TEST")
target_link_libraries ( sf_ip_test
    policy
    sfrt
    sfip
    utils
    ${CHECK_LIBRARY}
    ${MATH_LIBRARY}
)


# BUILDING SFTHD_TEST

#add_executable ( sfthd_test
#    sfthd_test.cc
#    unit_hacks.cc
#    unit_hacks.h
#    ${CMAKE_SOURCE_DIR}/src/filters/sfthd.cc
#)

#add_compile_flags (sfthd_test "-DSFTHD_TEST")
#target_link_libraries ( sfthd_test
#    policy
#    sfrt
#    sfip
#    utils
#    ${CHECK_LIBRARY}
#    ${MATH_LIBRARY}
#)

# BUILDDING SFRF_TEST

#add_executable (sfrf_test
#    sfrf_test.cc
#    unit_hacks.cc 
#    unit_hacks.h 
#    ${CMAKE_SOURCE_DIR}/src/filters/sfrf.cc
#)
#add_compile_flags (sfrf_test "-DSFRF_TEST")
#target_link_libraries ( sfrf_test
#    policy
#    sfrt
#    sfip
#    utils
#    ${CHECK_LIBRARY}
#    ${MATH_LIBRARY}
#)


# BUILDING SFRF_TEST
#add_executable ( sfrt_test sfrt_test.cc )
#target_link_libraries (sfrf_test
#    policy
#    sfrt
#    sfip
#    utils
#    ${CHECK_LIBRARY}
#    ${MATH_LIBRARY}
#)


ADD_CUSTOM_TARGET( check
    COMMAND "${CMAKE_CURRENT_BINARY_DIR}/sf_ip_test"
#    COMMAND "${CMAKE_CURRENT_BINARY_DIR}/sfthd_test"
#    COMMAND "${CMAKE_CURRENT_BINARY_DIR}/sfrf_test"
#    COMMAND "${CMAKE_CURRENT_BINARY_DIR}/sfrt_test"
    DEPENDS sf_ip_test
#            sfthd_test
#            sfrf_test
#            sfrt_test
)



# BUILDING AND RUNNING GCOV PROJECTS

message ("CHECK_LIBRARY = ${CHECK_LIBRARY}")
message ("MATH_LIBRARY = ${MATH_LIBRARY}")


add_executable ( sf_ip_gcov_prog
    ../sfip/sf_ip.cc
    sf_ip_test.cc
)
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/..")
add_compile_flags (sf_ip_gcov_prog "--std=gnu++11 -O0 -Wall -fprofile-arcs -ftest-coverage -DSF_IP_TEST -C ${CMAKE_CURRENT_BINARY_DIR}")
add_link_flags (sf_ip_gcov_prog "-g -O0 -Wall -fprofile-arcs -ftest-coverage -DSF_IP_TEST")
#CFLAGS="-g -O0 -Wall -W -fprofile-arcs -ftest-coverage"
#LDFLAGS="-fprofile-arcs -ftest-coverage"
target_link_libraries ( sf_ip_gcov_prog
    ${CHECK_LIBRARY}
    ${MATH_LIBRARY}
)

message ("current binary directory is ${CMAKE_CURRENT_BINARY_DIR}")

ADD_CUSTOM_TARGET ( sf_ip_gcov
    COMMAND "${CMAKE_CURRENT_BINARY_DIR}/sf_ip_gcov_prog"
    COMMAND ${GCOV_EXECUTABLE}
            -o ${CMAKE_CURRENT_BINARY_DIR} 
            ${CMAKE_SOURCE_DIR}/src/sfip/sf_ip.cc
    COMMAND ${GCOV_EXECUTABLE}
            -o ${CMAKE_CURRENT_BINARY_DIR} 
            ${CMAKE_CURRENT_SOURCE_DIR}/sf_ip_test.cc
    DEPENDS sf_ip_gcov_prog
)


#ADD_CUSTOM_TARGET ( gcov_tests 
#    DEPENDS sf_ip_gcov
#            sfthc_gcov
#            sfrf_gcov
#            sfrt_gcov
#)


#sf_ip_gcov:
#	g++ -g -O0 -Wall -fprofile-arcs -ftest-coverage -o sf_ip_test -DSF_IP_TEST -lm -lcheck -I.. ../sf_ip.cc sf_ip_test.cc 
#	./sf_ip_test
#	gcov ../sf_ip.cc
#	gcov sf_ip_test.cc

#sfthd_gcov:
#	g++ -g -O0 -Wall -fprofile-arcs -ftest-coverage -o sfthd_test -lm -lcheck -I.. -I../.. sfthd_test.cc ../sfthd.cc $(top_builddir)/src/utils/libutils.a
#	./sfthd_test
#	gcov ../sfthd.cc
#	gcov sfthd_test.cc

#sfrf_gcov:
#	g++ -g -O0 -Wall -fprofile-arcs -ftest-coverage -o sfrf_test -lm -lcheck -I.. -I../.. sfrf_test.cc ../sfrf.cc $(top_builddir)/src/utils/libutils.a
#	./sfrf_test
#	gcov ../sfrf.cc
#	gcov sfrf_test.cc
	
#sfrt_gcov:
#	g++ -g -O0 -Wall -fprofile-arcs -ftest-coverage -o sfrt_test -lm -lcheck -I.. -I../.. sfrt_test.cc ../sfrt.cc 
#	./sfrt_test
#	gcov ../sfrt.cc
#	gcov sfrt_test.cc

endif( TESTING_ENABLED)

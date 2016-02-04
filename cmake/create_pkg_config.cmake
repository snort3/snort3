

# creating pkg-config module.  these will all be substituted into snort.pc

foreach(flag COMPILE_DEFINITIONS COMPILE_FLAGS COMPILE_OPTIONS)
    set(CPPFLAGS "${CPPFLAGS} ${${flag}}")
endforeach()

get_target_property(snort_includes snort INCLUDE_DIRECTORIES) 
get_target_property(compile_definitions snort COMPILE_DEFINITIONS) 
get_directory_property( dir_defs DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} COMPILE_DEFINITIONS)

string (REPLACE ";" " -I" TMP_FLAGS  "-I${EXTERNAL_INCLUDES}")
string (REPLACE ";" " -D" TMP_DEFS  "-D${dir_defs}")
string (REPLACE ";" " " LIBS  "${EXTERNAL_LIBRARIES}")

set(CPPFLAGS "${CPPFLAGS} ${TMP_FLAGS} ${TMP_DEFS}")
set(prefix "${CMAKE_INSTALL_PREFIX}")
set(execprefix "\${prefix}")
set(bindir "\${prefix}/bin")
set(includedir "\${prefix}/${INCLUDE_INSTALL_PATH}")
set(libdir "\${prefix}/snort")



# setting and install the pkg-config information

configure_file(
    "${CMAKE_SOURCE_DIR}/snort.pc.in"
    "${CMAKE_BINARY_DIR}/snort.pc"
    @ONLY)

install (FILES ${CMAKE_BINARY_DIR}/snort.pc
    DESTINATION "lib/pkgconfig/"
)
